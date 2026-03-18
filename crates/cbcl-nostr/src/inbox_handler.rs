//! Core message dispatch for inbound kind 21111 events.
//!
//! Receives raw Nostr events from relay subscriptions, runs them through a
//! validation pipeline (signature → kind → performative → dialect), and
//! emits typed [`InboundMessage`] values that the application layer can
//! route by performative type.
//!
//! Unknown dialect tags are rejected unless the dialect is already installed
//! in the local [`DialectRegistry`], matching cbcl-rs registry search-order
//! semantics (reverse-order / last-installed-wins).

#![forbid(unsafe_code)]

use cbcl_core::dialect::DialectRegistry;
use cbcl_core::sexpr::SExpr;

use crate::event_signing::{self, SigningError};
use crate::event_types::{
    validate_performative, AgentMessage, Event, EventTypeError, PerformativeError, Tag,
    KIND_AGENT_MESSAGE,
};
use crate::sexpr_codec::{self, CodecError};

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors that can occur while processing an inbound event.
#[derive(Debug, thiserror::Error)]
pub enum InboxError {
    /// The event kind is not 21111.
    #[error("wrong event kind: expected {}, got {got}", KIND_AGENT_MESSAGE)]
    WrongKind { got: u64 },

    /// Schnorr signature or event-id verification failed.
    #[error("signature verification failed: {0}")]
    Signature(#[from] SigningError),

    /// The event could not be wrapped as an [`AgentMessage`].
    #[error("event type error: {0}")]
    EventType(#[from] EventTypeError),

    /// Content could not be parsed as an S-expression.
    #[error("codec error: {0}")]
    Codec(#[from] CodecError),

    /// Performative tag validation failed.
    #[error("performative error: {0}")]
    Performative(#[from] PerformativeError),

    /// The message references a dialect that is not installed locally.
    #[error("unknown dialect: \"{0}\" is not installed in the local registry")]
    UnknownDialect(String),
}

// ---------------------------------------------------------------------------
// InboundMessage — the output of the pipeline
// ---------------------------------------------------------------------------

/// A fully validated inbound agent message, ready for application-layer routing.
#[derive(Debug, Clone)]
pub struct InboundMessage {
    /// The typed agent message (kind 21111 with parsed tags).
    pub message: AgentMessage,
    /// The validated performative (head symbol / tag value).
    pub performative: String,
    /// Parsed S-expression content.
    pub content: SExpr,
    /// The relay URL the event arrived from (if known).
    pub relay_url: Option<String>,
}

// ---------------------------------------------------------------------------
// InboxHandler
// ---------------------------------------------------------------------------

/// Processes raw inbound Nostr events through the CBCL validation pipeline.
///
/// The pipeline stages are:
/// 1. **Kind check** — must be kind 21111
/// 2. **Signature verification** — NIP-01 event id + Schnorr sig
/// 3. **AgentMessage wrapping** — parse tags into typed [`Tag`] values
/// 4. **Content parsing** — decode S-expression with fuel limits
/// 5. **Performative validation** — tag must match content head symbol
/// 6. **Dialect gate** — if a `["dialect", name]` tag is present, the
///    dialect must exist in the local registry
///
/// All stages are synchronous and infallible in terms of I/O — only
/// cryptographic and structural checks are performed.
pub struct InboxHandler {
    registry: DialectRegistry,
}

impl InboxHandler {
    /// Create a new handler backed by the given dialect registry.
    pub fn new(registry: DialectRegistry) -> Self {
        Self { registry }
    }

    /// Returns a shared reference to the dialect registry.
    pub fn registry(&self) -> &DialectRegistry {
        &self.registry
    }

    /// Returns a mutable reference to the dialect registry, e.g. to install
    /// new dialects at runtime.
    pub fn registry_mut(&mut self) -> &mut DialectRegistry {
        &mut self.registry
    }

    /// Process a raw [`Event`] through the full validation pipeline.
    ///
    /// On success, returns an [`InboundMessage`] with the validated
    /// performative and parsed content. The `relay_url` field is set from
    /// the provided argument.
    ///
    /// On failure, returns an [`InboxError`] describing which stage rejected
    /// the event.
    pub fn process(
        &self,
        event: Event,
        relay_url: Option<String>,
    ) -> Result<InboundMessage, InboxError> {
        // 1. Kind check (fast-reject before expensive crypto).
        if event.kind != KIND_AGENT_MESSAGE {
            return Err(InboxError::WrongKind { got: event.kind });
        }

        // 2. Signature verification.
        event_signing::verify_event(&event)?;

        // 3. Wrap as AgentMessage (parses tags).
        let message = AgentMessage::from_event(event)?;

        // 4. Parse S-expression content.
        let content = sexpr_codec::decode(&message.event.content)?;

        // 5. Validate performative tag ↔ content head symbol.
        let performative = validate_performative(&message)?;

        // 6. Dialect gate — reject unknown dialect tags.
        self.check_dialect(&message)?;

        Ok(InboundMessage {
            message,
            performative,
            content,
            relay_url,
        })
    }

    /// Check that every dialect tag on the message references an installed
    /// dialect. Core performatives (tell, ask, reply, ok, error, cancel,
    /// hello, bye) do not require a dialect tag, but if one is present it
    /// must be resolvable.
    fn check_dialect(&self, message: &AgentMessage) -> Result<(), InboxError> {
        for tag in &message.tags {
            if let Tag::Dialect(name) = tag {
                if self.registry.find_by_name(name).is_none() {
                    return Err(InboxError::UnknownDialect(name.clone()));
                }
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Convenience: batch processing
// ---------------------------------------------------------------------------

impl InboxHandler {
    /// Process multiple events, collecting successes and failures separately.
    ///
    /// Useful when draining the relay pool's event channel.
    pub fn process_batch(
        &self,
        events: impl IntoIterator<Item = (Event, Option<String>)>,
    ) -> (Vec<InboundMessage>, Vec<(Event, InboxError)>) {
        let mut ok = Vec::new();
        let mut err = Vec::new();
        for (event, relay_url) in events {
            let event_clone = event.clone();
            match self.process(event, relay_url) {
                Ok(msg) => ok.push(msg),
                Err(e) => err.push((event_clone, e)),
            }
        }
        (ok, err)
    }
}

// ---------------------------------------------------------------------------
// Performative routing helpers
// ---------------------------------------------------------------------------

/// Categorization of a performative for routing purposes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PerformativeKind {
    /// Directed assertions: tell
    Tell,
    /// Questions: ask
    Ask,
    /// Answers to questions: reply
    Reply,
    /// Positive acknowledgement: ok
    Ok,
    /// Error report: error
    Error,
    /// Cancellation: cancel
    Cancel,
    /// Broadcast greeting: hello
    Hello,
    /// Broadcast farewell: bye
    Bye,
    /// Dialect-extended performative (not one of the 8 core).
    Extended,
}

impl PerformativeKind {
    /// Classify a performative string into a [`PerformativeKind`].
    pub fn classify(performative: &str) -> Self {
        match performative {
            "tell" => Self::Tell,
            "ask" => Self::Ask,
            "reply" => Self::Reply,
            "ok" => Self::Ok,
            "error" => Self::Error,
            "cancel" => Self::Cancel,
            "hello" => Self::Hello,
            "bye" => Self::Bye,
            _ => Self::Extended,
        }
    }

    /// Returns `true` if this is a broadcast performative (no recipient).
    pub fn is_broadcast(&self) -> bool {
        matches!(self, Self::Hello | Self::Bye)
    }
}

impl InboundMessage {
    /// Classify the performative of this message for routing.
    pub fn kind(&self) -> PerformativeKind {
        PerformativeKind::classify(&self.performative)
    }

    /// Returns the sender's public key.
    pub fn sender(&self) -> &str {
        &self.message.event.pubkey
    }

    /// Returns the thread id, if present.
    pub fn thread(&self) -> Option<&str> {
        self.message.tags.iter().find_map(|t| match t {
            Tag::Thread(id) => Some(id.as_str()),
            _ => None,
        })
    }

    /// Returns the dialect name, if present.
    pub fn dialect(&self) -> Option<&str> {
        self.message.tags.iter().find_map(|t| match t {
            Tag::Dialect(name) => Some(name.as_str()),
            _ => None,
        })
    }

    /// Returns the referenced event id (reply-to), if present.
    pub fn in_reply_to(&self) -> Option<&str> {
        self.message.tags.iter().find_map(|t| match t {
            Tag::Event(eid) => Some(eid.as_str()),
            _ => None,
        })
    }

    /// Returns the recipient public key, if present.
    pub fn recipient(&self) -> Option<&str> {
        self.message.tags.iter().find_map(|t| match t {
            Tag::PubKey(pk) => Some(pk.as_str()),
            _ => None,
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event_signing::sign_event;
    use crate::event_types::KIND_AGENT_DIALECT;

    /// Generate a keypair and return (secret_key_hex, pubkey_hex).
    fn gen_keypair() -> (String, String) {
        crate::event_signing::generate_keypair()
    }

    /// Build a signed kind 21111 event.
    fn signed_message(
        sk: &str,
        tags: Vec<Vec<String>>,
        content: &str,
    ) -> Event {
        let mut event = Event {
            id: String::new(),
            pubkey: String::new(),
            created_at: 0,
            kind: KIND_AGENT_MESSAGE,
            tags,
            content: content.to_string(),
            sig: String::new(),
        };
        sign_event(&mut event, sk, 1_700_000_000).unwrap();
        event
    }

    fn handler() -> InboxHandler {
        InboxHandler::new(DialectRegistry::new())
    }

    // ====================================================================
    // Happy path
    // ====================================================================

    #[test]
    fn process_valid_tell() {
        let (sk, pk) = gen_keypair();
        let h = handler();
        let event = signed_message(
            &sk,
            vec![
                vec!["p".into(), "deadbeef".repeat(8)],
                vec!["performative".into(), "tell".into()],
            ],
            r#"(tell "hello")"#,
        );
        let result = h.process(event, Some("wss://relay.example.com".into()));
        let msg = result.unwrap();
        assert_eq!(msg.performative, "tell");
        assert_eq!(msg.kind(), PerformativeKind::Tell);
        assert_eq!(msg.sender(), pk);
        assert_eq!(msg.relay_url.as_deref(), Some("wss://relay.example.com"));
    }

    #[test]
    fn process_all_core_performatives() {
        let (sk, _pk) = gen_keypair();
        let h = handler();
        let cases = [
            ("tell", r#"(tell "hi")"#),
            ("ask", r#"(ask "q?")"#),
            ("reply", r#"(reply "a")"#),
            ("ok", "(ok)"),
            ("error", r#"(error "bad")"#),
            ("cancel", "(cancel)"),
            ("hello", "(hello)"),
            ("bye", "(bye)"),
        ];
        for (perf, content) in cases {
            let event = signed_message(
                &sk,
                vec![vec!["performative".into(), perf.into()]],
                content,
            );
            let msg = h.process(event, None).unwrap();
            assert_eq!(msg.performative, perf, "failed for {perf}");
        }
    }

    #[test]
    fn process_with_thread_and_reply_to() {
        let (sk, _pk) = gen_keypair();
        let h = handler();
        let event = signed_message(
            &sk,
            vec![
                vec!["performative".into(), "reply".into()],
                vec!["thread".into(), "conv-42".into()],
                vec!["e".into(), "abcd".repeat(16)],
                vec!["p".into(), "beef".repeat(16)],
            ],
            r#"(reply "done")"#,
        );
        let msg = h.process(event, None).unwrap();
        assert_eq!(msg.thread(), Some("conv-42"));
        assert_eq!(msg.in_reply_to(), Some(&"abcd".repeat(16) as &str));
        assert_eq!(msg.recipient(), Some(&"beef".repeat(16) as &str));
    }

    // ====================================================================
    // Wrong kind
    // ====================================================================

    #[test]
    fn reject_wrong_kind() {
        let (sk, _pk) = gen_keypair();
        let h = handler();
        let mut event = signed_message(
            &sk,
            vec![vec!["performative".into(), "tell".into()]],
            r#"(tell "hi")"#,
        );
        // Tamper the kind — signature will be wrong but we hit kind check first.
        event.kind = KIND_AGENT_DIALECT;
        let err = h.process(event, None).unwrap_err();
        assert!(matches!(err, InboxError::WrongKind { got: KIND_AGENT_DIALECT }));
    }

    // ====================================================================
    // Signature failure
    // ====================================================================

    #[test]
    fn reject_bad_signature() {
        let (sk, _pk) = gen_keypair();
        let h = handler();
        let mut event = signed_message(
            &sk,
            vec![vec!["performative".into(), "tell".into()]],
            r#"(tell "hi")"#,
        );
        // Tamper the content after signing.
        event.content = r#"(tell "tampered")"#.to_string();
        let err = h.process(event, None).unwrap_err();
        assert!(matches!(err, InboxError::Signature(_)));
    }

    // ====================================================================
    // Performative errors
    // ====================================================================

    #[test]
    fn reject_missing_performative_tag() {
        let (sk, _pk) = gen_keypair();
        let h = handler();
        let event = signed_message(
            &sk,
            vec![vec!["p".into(), "beef".repeat(16)]],
            r#"(tell "hi")"#,
        );
        let err = h.process(event, None).unwrap_err();
        assert!(matches!(err, InboxError::Performative(PerformativeError::MissingTag)));
    }

    #[test]
    fn reject_performative_mismatch() {
        let (sk, _pk) = gen_keypair();
        let h = handler();
        let event = signed_message(
            &sk,
            vec![vec!["performative".into(), "tell".into()]],
            r#"(ask "hmm")"#,
        );
        let err = h.process(event, None).unwrap_err();
        assert!(matches!(err, InboxError::Performative(PerformativeError::Mismatch { .. })));
    }

    #[test]
    fn reject_empty_content() {
        let (sk, _pk) = gen_keypair();
        let h = handler();
        let event = signed_message(
            &sk,
            vec![vec!["performative".into(), "tell".into()]],
            "",
        );
        let err = h.process(event, None).unwrap_err();
        assert!(matches!(err, InboxError::Codec(_)));
    }

    #[test]
    fn reject_no_head_symbol() {
        let (sk, _pk) = gen_keypair();
        let h = handler();
        let event = signed_message(
            &sk,
            vec![vec!["performative".into(), "tell".into()]],
            "()",
        );
        let err = h.process(event, None).unwrap_err();
        assert!(matches!(
            err,
            InboxError::Performative(PerformativeError::NoHeadSymbol)
        ));
    }

    // ====================================================================
    // Dialect gating
    // ====================================================================

    #[test]
    fn reject_unknown_dialect() {
        let (sk, _pk) = gen_keypair();
        let h = handler();
        let event = signed_message(
            &sk,
            vec![
                vec!["performative".into(), "negotiate".into()],
                vec!["dialect".into(), "commerce".into()],
            ],
            r#"(negotiate :price 100)"#,
        );
        let err = h.process(event, None).unwrap_err();
        assert!(matches!(err, InboxError::UnknownDialect(ref name) if name == "commerce"));
    }

    #[test]
    fn accept_installed_dialect() {
        let (sk, _pk) = gen_keypair();
        let mut h = handler();

        // Install a dialect that defines "negotiate".
        let dialect = cbcl_core::dialect::Dialect {
            name: "commerce".into(),
            extends: vec!["cbcl-base".into()],
            author: None,
            performatives: vec![cbcl_core::dialect::PerformativeDef {
                name: "negotiate".into(),
                params: vec![],
                template: cbcl_core::sexpr::SExpr::List(vec![
                    cbcl_core::sexpr::SExpr::Atom(cbcl_core::sexpr::Atom::Symbol(
                        "tell".into(),
                    )),
                ]),
            }],
            resources: cbcl_core::dialect::ResourceBounds {
                max_depth: 16,
                max_expansion_size: 4096,
                verification_time_ms: 500,
            },
            examples: vec![],
            signature: None,
            hash: None,
            protocol: None,
        };
        h.registry_mut().install(dialect).unwrap();

        let event = signed_message(
            &sk,
            vec![
                vec!["performative".into(), "negotiate".into()],
                vec!["dialect".into(), "commerce".into()],
            ],
            r#"(negotiate :price 100)"#,
        );
        let msg = h.process(event, None).unwrap();
        assert_eq!(msg.performative, "negotiate");
        assert_eq!(msg.dialect(), Some("commerce"));
        assert_eq!(msg.kind(), PerformativeKind::Extended);
    }

    #[test]
    fn core_performative_without_dialect_tag_ok() {
        let (sk, _pk) = gen_keypair();
        let h = handler();
        // Core performative with no dialect tag should pass.
        let event = signed_message(
            &sk,
            vec![vec!["performative".into(), "tell".into()]],
            r#"(tell "hi")"#,
        );
        assert!(h.process(event, None).is_ok());
    }

    // ====================================================================
    // Batch processing
    // ====================================================================

    #[test]
    fn batch_processing() {
        let (sk, _pk) = gen_keypair();
        let h = handler();
        let good = signed_message(
            &sk,
            vec![vec!["performative".into(), "tell".into()]],
            r#"(tell "hi")"#,
        );
        let bad = signed_message(
            &sk,
            vec![vec!["performative".into(), "tell".into()]],
            r#"(ask "mismatch")"#,
        );
        let events = vec![
            (good, Some("wss://r1".into())),
            (bad, Some("wss://r2".into())),
        ];
        let (ok, err) = h.process_batch(events);
        assert_eq!(ok.len(), 1);
        assert_eq!(err.len(), 1);
        assert_eq!(ok[0].performative, "tell");
    }

    // ====================================================================
    // PerformativeKind
    // ====================================================================

    #[test]
    fn performative_kind_classify() {
        assert_eq!(PerformativeKind::classify("tell"), PerformativeKind::Tell);
        assert_eq!(PerformativeKind::classify("ask"), PerformativeKind::Ask);
        assert_eq!(PerformativeKind::classify("reply"), PerformativeKind::Reply);
        assert_eq!(PerformativeKind::classify("ok"), PerformativeKind::Ok);
        assert_eq!(PerformativeKind::classify("error"), PerformativeKind::Error);
        assert_eq!(PerformativeKind::classify("cancel"), PerformativeKind::Cancel);
        assert_eq!(PerformativeKind::classify("hello"), PerformativeKind::Hello);
        assert_eq!(PerformativeKind::classify("bye"), PerformativeKind::Bye);
        assert_eq!(PerformativeKind::classify("negotiate"), PerformativeKind::Extended);
    }

    #[test]
    fn broadcast_performatives() {
        assert!(PerformativeKind::Hello.is_broadcast());
        assert!(PerformativeKind::Bye.is_broadcast());
        assert!(!PerformativeKind::Tell.is_broadcast());
        assert!(!PerformativeKind::Extended.is_broadcast());
    }

    // ====================================================================
    // InboundMessage accessors
    // ====================================================================

    #[test]
    fn inbound_message_no_optional_tags() {
        let (sk, pk) = gen_keypair();
        let h = handler();
        let event = signed_message(
            &sk,
            vec![vec!["performative".into(), "hello".into()]],
            "(hello)",
        );
        let msg = h.process(event, None).unwrap();
        assert_eq!(msg.sender(), pk);
        assert_eq!(msg.thread(), None);
        assert_eq!(msg.dialect(), None);
        assert_eq!(msg.in_reply_to(), None);
        assert_eq!(msg.recipient(), None);
        assert!(msg.kind().is_broadcast());
    }
}
