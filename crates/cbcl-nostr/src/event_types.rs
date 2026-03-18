//! Typed wrappers for CBCL-over-Nostr event kinds.
//!
//! Defines Rust types for the two CBCL event kinds:
//!
//! - **Kind 21111 (`AgentMessage`)** — ephemeral agent-to-agent messages
//!   carrying CBCL S-expressions (tell, ask, reply, etc.).
//! - **Kind 31111 (`AgentDialect`)** — parameterized-replaceable events
//!   that publish a CBCL dialect definition (grammar, vocabulary, rules).
//!
//! Both wrap a common [`Event`] struct that mirrors the NIP-01 event
//! structure, plus a strongly-typed [`Tag`] enum for the tag tuples used
//! by this protocol.

#![forbid(unsafe_code)]

use cbcl_core::sexpr::{Atom, SExpr};
use serde::{Deserialize, Serialize};

use crate::sexpr_codec;

// ---------------------------------------------------------------------------
// Event kinds
// ---------------------------------------------------------------------------

/// Nostr event kind for CBCL agent messages (ephemeral).
pub const KIND_AGENT_MESSAGE: u64 = 21111;

/// Nostr event kind for CBCL agent dialect definitions (parameterized-replaceable).
pub const KIND_AGENT_DIALECT: u64 = 31111;

// ---------------------------------------------------------------------------
// NIP-01 event
// ---------------------------------------------------------------------------

/// A Nostr event following the NIP-01 structure.
///
/// All fields use their canonical Nostr JSON types. The `tags` field stores
/// raw string arrays; use [`Tag::parse`] to convert individual tag tuples
/// into the strongly-typed [`Tag`] enum.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    /// 32-byte lowercase hex event id (SHA-256 of serialized event).
    pub id: String,
    /// 32-byte lowercase hex public key of the event creator.
    pub pubkey: String,
    /// Unix timestamp in seconds.
    pub created_at: u64,
    /// Event kind number.
    pub kind: u64,
    /// Array of tag tuples, each a `Vec<String>`.
    pub tags: Vec<Vec<String>>,
    /// Event payload (CBCL S-expression for our kinds).
    pub content: String,
    /// 64-byte lowercase hex Schnorr signature.
    pub sig: String,
}

// ---------------------------------------------------------------------------
// Tag enum
// ---------------------------------------------------------------------------

/// Strongly-typed representation of tag tuples used by CBCL Nostr events.
///
/// Each variant corresponds to a single-letter or named tag key and carries
/// the parsed values from the tag tuple.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Tag {
    /// `["p", <hex-pubkey>]` — references a participant.
    PubKey(String),

    /// `["performative", <verb>]` — CBCL speech-act verb (tell, ask, reply, …).
    Performative(String),

    /// `["thread", <thread-id>]` — conversation thread identifier.
    Thread(String),

    /// `["e", <hex-event-id>]` — references another event (reply-to, etc.).
    Event(String),

    /// `["dialect", <dialect-identifier>]` — names the dialect in use.
    Dialect(String),

    /// `["t", <hashtag>]` — generic hashtag / topic.
    Hashtag(String),

    /// `["amount", <millisats>]` — payment amount in millisatoshis.
    Amount(String),

    /// `["L", <namespace>]` — NIP-32 label namespace.
    LabelNamespace(String),

    /// `["l", <label>, <namespace>]` — NIP-32 label value within a namespace.
    Label(String, String),

    /// Any tag not covered by the variants above.
    Unknown(Vec<String>),
}

impl Tag {
    /// Parse a raw tag tuple (`Vec<String>`) into a typed [`Tag`].
    ///
    /// Returns [`Tag::Unknown`] for unrecognized tag keys or tuples
    /// with insufficient elements for their expected arity.
    pub fn parse(raw: &[String]) -> Tag {
        match raw.first().map(String::as_str) {
            Some("p") if raw.len() >= 2 => Tag::PubKey(raw[1].clone()),
            Some("performative") if raw.len() >= 2 => Tag::Performative(raw[1].clone()),
            Some("thread") if raw.len() >= 2 => Tag::Thread(raw[1].clone()),
            Some("e") if raw.len() >= 2 => Tag::Event(raw[1].clone()),
            Some("dialect") if raw.len() >= 2 => Tag::Dialect(raw[1].clone()),
            Some("t") if raw.len() >= 2 => Tag::Hashtag(raw[1].clone()),
            Some("amount") if raw.len() >= 2 => Tag::Amount(raw[1].clone()),
            Some("L") if raw.len() >= 2 => Tag::LabelNamespace(raw[1].clone()),
            Some("l") if raw.len() >= 3 => Tag::Label(raw[1].clone(), raw[2].clone()),
            _ => Tag::Unknown(raw.to_vec()),
        }
    }

    /// Serialize this tag back into a raw tag tuple.
    pub fn to_raw(&self) -> Vec<String> {
        match self {
            Tag::PubKey(pk) => vec!["p".into(), pk.clone()],
            Tag::Performative(v) => vec!["performative".into(), v.clone()],
            Tag::Thread(id) => vec!["thread".into(), id.clone()],
            Tag::Event(eid) => vec!["e".into(), eid.clone()],
            Tag::Dialect(d) => vec!["dialect".into(), d.clone()],
            Tag::Hashtag(h) => vec!["t".into(), h.clone()],
            Tag::Amount(a) => vec!["amount".into(), a.clone()],
            Tag::LabelNamespace(ns) => vec!["L".into(), ns.clone()],
            Tag::Label(l, ns) => vec!["l".into(), l.clone(), ns.clone()],
            Tag::Unknown(raw) => raw.clone(),
        }
    }
}

// ---------------------------------------------------------------------------
// Performative extraction and validation
// ---------------------------------------------------------------------------

/// The eight core CBCL performatives defined by the base specification.
pub const CORE_PERFORMATIVES: &[&str] = &[
    "tell", "ask", "reply", "ok", "error", "cancel", "hello", "bye",
];

/// Returns `true` if `name` is one of the eight core CBCL performatives.
pub fn is_core_performative(name: &str) -> bool {
    CORE_PERFORMATIVES.contains(&name)
}

/// Extract the performative (head symbol) from a parsed S-expression.
///
/// The performative is the first element of the top-level list, which must
/// be a `Symbol` atom. Returns `None` if the expression is not a list,
/// the list is empty, or the first element is not a symbol.
pub fn extract_performative(sexpr: &SExpr) -> Option<&str> {
    match sexpr {
        SExpr::List(items) => match items.first() {
            Some(SExpr::Atom(Atom::Symbol(s))) => Some(s.as_str()),
            _ => None,
        },
        _ => None,
    }
}

/// Errors from performative validation.
#[derive(Debug, thiserror::Error)]
pub enum PerformativeError {
    /// Content could not be parsed as an S-expression.
    #[error("codec error: {0}")]
    Codec(#[from] sexpr_codec::CodecError),

    /// No `["performative", _]` tag found on the event.
    #[error("missing performative tag")]
    MissingTag,

    /// Content S-expression has no extractable head symbol.
    #[error("no head symbol in content")]
    NoHeadSymbol,

    /// The performative tag value does not match the content head symbol.
    #[error("performative mismatch: tag says \"{tag}\" but content head is \"{head}\"")]
    Mismatch { tag: String, head: String },
}

/// Validate that the performative tag on an [`AgentMessage`] matches the
/// head symbol of its content S-expression.
///
/// Parses `event.content`, extracts the head symbol, finds the
/// `["performative", _]` tag, and checks they agree. Accepts both core
/// and dialect-extended performatives — the only requirement is that
/// the tag and the content head match.
pub fn validate_performative(msg: &AgentMessage) -> Result<String, PerformativeError> {
    let tag_value = msg
        .tags
        .iter()
        .find_map(|t| match t {
            Tag::Performative(v) => Some(v.as_str()),
            _ => None,
        })
        .ok_or(PerformativeError::MissingTag)?;

    let sexpr = sexpr_codec::decode(&msg.event.content)?;
    let head = extract_performative(&sexpr).ok_or(PerformativeError::NoHeadSymbol)?;

    if head != tag_value {
        return Err(PerformativeError::Mismatch {
            tag: tag_value.to_string(),
            head: head.to_string(),
        });
    }

    Ok(tag_value.to_string())
}

// ---------------------------------------------------------------------------
// Typed event wrappers
// ---------------------------------------------------------------------------

/// A kind-21111 agent message event.
///
/// Wraps a NIP-01 [`Event`] whose `content` contains a CBCL S-expression
/// and whose tags include at least one `p` tag (recipient) and a
/// `performative` tag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentMessage {
    /// The underlying NIP-01 event.
    pub event: Event,
    /// Parsed tags from `event.tags`.
    pub tags: Vec<Tag>,
}

/// A kind-31111 agent dialect definition event.
///
/// Wraps a NIP-01 [`Event`] whose `content` contains a CBCL dialect
/// S-expression (grammar, vocabulary, rules) and whose tags include
/// a `dialect` tag naming the dialect.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentDialect {
    /// The underlying NIP-01 event.
    pub event: Event,
    /// Parsed tags from `event.tags`.
    pub tags: Vec<Tag>,
}

// ---------------------------------------------------------------------------
// Validation errors
// ---------------------------------------------------------------------------

/// Errors from constructing typed event wrappers.
#[derive(Debug, thiserror::Error)]
pub enum EventTypeError {
    /// The event kind does not match the expected kind for this wrapper.
    #[error("wrong kind: expected {expected}, got {got}")]
    WrongKind { expected: u64, got: u64 },
}

// ---------------------------------------------------------------------------
// Constructors
// ---------------------------------------------------------------------------

impl AgentMessage {
    /// Wrap a NIP-01 event as an [`AgentMessage`].
    ///
    /// Returns an error if `event.kind` is not [`KIND_AGENT_MESSAGE`].
    pub fn from_event(event: Event) -> Result<Self, EventTypeError> {
        if event.kind != KIND_AGENT_MESSAGE {
            return Err(EventTypeError::WrongKind {
                expected: KIND_AGENT_MESSAGE,
                got: event.kind,
            });
        }
        let tags = event.tags.iter().map(|t| Tag::parse(t)).collect();
        Ok(Self { event, tags })
    }
}

impl AgentDialect {
    /// Wrap a NIP-01 event as an [`AgentDialect`].
    ///
    /// Returns an error if `event.kind` is not [`KIND_AGENT_DIALECT`].
    pub fn from_event(event: Event) -> Result<Self, EventTypeError> {
        if event.kind != KIND_AGENT_DIALECT {
            return Err(EventTypeError::WrongKind {
                expected: KIND_AGENT_DIALECT,
                got: event.kind,
            });
        }
        let tags = event.tags.iter().map(|t| Tag::parse(t)).collect();
        Ok(Self { event, tags })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_event(kind: u64, tags: Vec<Vec<String>>, content: &str) -> Event {
        Event {
            id: "a".repeat(64),
            pubkey: "b".repeat(64),
            created_at: 1700000000,
            kind,
            tags,
            content: content.to_string(),
            sig: "c".repeat(128),
        }
    }

    // ====================================================================
    // Tag parsing
    // ====================================================================

    #[test]
    fn parse_p_tag() {
        let raw = vec!["p".into(), "abc123".into()];
        assert_eq!(Tag::parse(&raw), Tag::PubKey("abc123".into()));
    }

    #[test]
    fn parse_performative_tag() {
        let raw = vec!["performative".into(), "tell".into()];
        assert_eq!(Tag::parse(&raw), Tag::Performative("tell".into()));
    }

    #[test]
    fn parse_thread_tag() {
        let raw = vec!["thread".into(), "conv-17".into()];
        assert_eq!(Tag::parse(&raw), Tag::Thread("conv-17".into()));
    }

    #[test]
    fn parse_e_tag() {
        let raw = vec!["e".into(), "def456".into()];
        assert_eq!(Tag::parse(&raw), Tag::Event("def456".into()));
    }

    #[test]
    fn parse_dialect_tag() {
        let raw = vec!["dialect".into(), "commerce".into()];
        assert_eq!(Tag::parse(&raw), Tag::Dialect("commerce".into()));
    }

    #[test]
    fn parse_t_tag() {
        let raw = vec!["t".into(), "cbcl".into()];
        assert_eq!(Tag::parse(&raw), Tag::Hashtag("cbcl".into()));
    }

    #[test]
    fn parse_amount_tag() {
        let raw = vec!["amount".into(), "1000".into()];
        assert_eq!(Tag::parse(&raw), Tag::Amount("1000".into()));
    }

    #[test]
    fn parse_label_namespace_tag() {
        let raw = vec!["L".into(), "cbcl.dialect".into()];
        assert_eq!(Tag::parse(&raw), Tag::LabelNamespace("cbcl.dialect".into()));
    }

    #[test]
    fn parse_label_tag() {
        let raw = vec!["l".into(), "commerce".into(), "cbcl.dialect".into()];
        assert_eq!(
            Tag::parse(&raw),
            Tag::Label("commerce".into(), "cbcl.dialect".into())
        );
    }

    #[test]
    fn parse_label_tag_insufficient_arity() {
        // "l" with only 1 value falls back to Unknown
        let raw = vec!["l".into(), "commerce".into()];
        assert_eq!(Tag::parse(&raw), Tag::Unknown(raw));
    }

    #[test]
    fn parse_unknown_tag() {
        let raw = vec!["x".into(), "foo".into()];
        assert_eq!(Tag::parse(&raw), Tag::Unknown(raw.clone()));
    }

    #[test]
    fn parse_empty_tag() {
        let raw: Vec<String> = vec![];
        assert_eq!(Tag::parse(&raw), Tag::Unknown(raw));
    }

    // ====================================================================
    // Tag round-trip (parse → to_raw → parse)
    // ====================================================================

    #[test]
    fn tag_round_trip() {
        let tags = vec![
            vec!["p".into(), "abc".into()],
            vec!["performative".into(), "ask".into()],
            vec!["thread".into(), "t-1".into()],
            vec!["e".into(), "def".into()],
            vec!["dialect".into(), "commerce".into()],
            vec!["t".into(), "cbcl".into()],
            vec!["amount".into(), "5000".into()],
            vec!["L".into(), "ns".into()],
            vec!["l".into(), "val".into(), "ns".into()],
        ];
        for raw in &tags {
            let parsed = Tag::parse(raw);
            let back = parsed.to_raw();
            let reparsed = Tag::parse(&back);
            assert_eq!(parsed, reparsed, "round-trip failed for {raw:?}");
        }
    }

    // ====================================================================
    // AgentMessage
    // ====================================================================

    #[test]
    fn agent_message_from_event_ok() {
        let event = make_event(
            KIND_AGENT_MESSAGE,
            vec![
                vec!["p".into(), "recipient".into()],
                vec!["performative".into(), "tell".into()],
                vec!["thread".into(), "conv-1".into()],
            ],
            r#"(tell @recipient "hello")"#,
        );
        let msg = AgentMessage::from_event(event).unwrap();
        assert_eq!(msg.tags.len(), 3);
        assert_eq!(msg.tags[0], Tag::PubKey("recipient".into()));
        assert_eq!(msg.tags[1], Tag::Performative("tell".into()));
        assert_eq!(msg.tags[2], Tag::Thread("conv-1".into()));
    }

    #[test]
    fn agent_message_wrong_kind() {
        let event = make_event(KIND_AGENT_DIALECT, vec![], "()");
        let err = AgentMessage::from_event(event).unwrap_err();
        assert!(matches!(
            err,
            EventTypeError::WrongKind {
                expected: KIND_AGENT_MESSAGE,
                got: KIND_AGENT_DIALECT,
            }
        ));
    }

    // ====================================================================
    // AgentDialect
    // ====================================================================

    #[test]
    fn agent_dialect_from_event_ok() {
        let event = make_event(
            KIND_AGENT_DIALECT,
            vec![
                vec!["dialect".into(), "commerce".into()],
                vec!["L".into(), "cbcl.dialect".into()],
                vec!["l".into(), "commerce".into(), "cbcl.dialect".into()],
            ],
            "(meta (define commerce :extends cbcl-base))",
        );
        let dialect = AgentDialect::from_event(event).unwrap();
        assert_eq!(dialect.tags.len(), 3);
        assert_eq!(dialect.tags[0], Tag::Dialect("commerce".into()));
        assert_eq!(
            dialect.tags[1],
            Tag::LabelNamespace("cbcl.dialect".into())
        );
        assert_eq!(
            dialect.tags[2],
            Tag::Label("commerce".into(), "cbcl.dialect".into())
        );
    }

    #[test]
    fn agent_dialect_wrong_kind() {
        let event = make_event(KIND_AGENT_MESSAGE, vec![], "()");
        let err = AgentDialect::from_event(event).unwrap_err();
        assert!(matches!(
            err,
            EventTypeError::WrongKind {
                expected: KIND_AGENT_DIALECT,
                got: KIND_AGENT_MESSAGE,
            }
        ));
    }

    // ====================================================================
    // Performative extraction
    // ====================================================================

    #[test]
    fn extract_performative_tell() {
        let expr = sexpr_codec::decode(r#"(tell @bob "hello")"#).unwrap();
        assert_eq!(extract_performative(&expr), Some("tell"));
    }

    #[test]
    fn extract_performative_ask() {
        let expr = sexpr_codec::decode(r#"(ask @alice "status?")"#).unwrap();
        assert_eq!(extract_performative(&expr), Some("ask"));
    }

    #[test]
    fn extract_performative_dialect_extended() {
        let expr = sexpr_codec::decode(r#"(negotiate @bob :price 100)"#).unwrap();
        assert_eq!(extract_performative(&expr), Some("negotiate"));
    }

    #[test]
    fn extract_performative_empty_list() {
        let expr = sexpr_codec::decode("()").unwrap();
        assert_eq!(extract_performative(&expr), None);
    }

    #[test]
    fn extract_performative_bare_atom() {
        let expr = SExpr::Atom(Atom::Symbol("tell".into()));
        assert_eq!(extract_performative(&expr), None);
    }

    #[test]
    fn extract_performative_non_symbol_head() {
        let expr = sexpr_codec::decode(r#"("not-a-symbol" @bob)"#).unwrap();
        assert_eq!(extract_performative(&expr), None);
    }

    // ====================================================================
    // Core performative check
    // ====================================================================

    #[test]
    fn core_performatives_recognized() {
        for &p in CORE_PERFORMATIVES {
            assert!(is_core_performative(p), "{p} should be core");
        }
    }

    #[test]
    fn dialect_performative_not_core() {
        assert!(!is_core_performative("negotiate"));
        assert!(!is_core_performative("propose"));
    }

    // ====================================================================
    // Performative validation
    // ====================================================================

    #[test]
    fn validate_performative_ok() {
        let event = make_event(
            KIND_AGENT_MESSAGE,
            vec![
                vec!["p".into(), "recipient".into()],
                vec!["performative".into(), "tell".into()],
            ],
            r#"(tell @recipient "hello")"#,
        );
        let msg = AgentMessage::from_event(event).unwrap();
        assert_eq!(validate_performative(&msg).unwrap(), "tell");
    }

    #[test]
    fn validate_performative_all_core() {
        let cases = [
            ("tell", r#"(tell @bob "hi")"#),
            ("ask", r#"(ask @bob "q?")"#),
            ("reply", r#"(reply @bob "a")"#),
            ("ok", "(ok)"),
            ("error", r#"(error "bad")"#),
            ("cancel", "(cancel)"),
            ("hello", "(hello)"),
            ("bye", "(bye)"),
        ];
        for (perf, content) in cases {
            let event = make_event(
                KIND_AGENT_MESSAGE,
                vec![vec!["performative".into(), perf.into()]],
                content,
            );
            let msg = AgentMessage::from_event(event).unwrap();
            assert_eq!(
                validate_performative(&msg).unwrap(),
                perf,
                "failed for {perf}"
            );
        }
    }

    #[test]
    fn validate_performative_dialect_extended() {
        let event = make_event(
            KIND_AGENT_MESSAGE,
            vec![vec!["performative".into(), "negotiate".into()]],
            r#"(negotiate @bob :price 100)"#,
        );
        let msg = AgentMessage::from_event(event).unwrap();
        assert_eq!(validate_performative(&msg).unwrap(), "negotiate");
    }

    #[test]
    fn validate_performative_mismatch() {
        let event = make_event(
            KIND_AGENT_MESSAGE,
            vec![vec!["performative".into(), "tell".into()]],
            r#"(ask @bob "hmm")"#,
        );
        let msg = AgentMessage::from_event(event).unwrap();
        let err = validate_performative(&msg).unwrap_err();
        assert!(matches!(err, PerformativeError::Mismatch { .. }));
    }

    #[test]
    fn validate_performative_missing_tag() {
        let event = make_event(
            KIND_AGENT_MESSAGE,
            vec![vec!["p".into(), "someone".into()]],
            r#"(tell @someone "hi")"#,
        );
        let msg = AgentMessage::from_event(event).unwrap();
        let err = validate_performative(&msg).unwrap_err();
        assert!(matches!(err, PerformativeError::MissingTag));
    }

    #[test]
    fn validate_performative_empty_content() {
        let event = make_event(
            KIND_AGENT_MESSAGE,
            vec![vec!["performative".into(), "tell".into()]],
            "",
        );
        let msg = AgentMessage::from_event(event).unwrap();
        let err = validate_performative(&msg).unwrap_err();
        assert!(matches!(err, PerformativeError::Codec(_)));
    }

    #[test]
    fn validate_performative_no_head_symbol() {
        let event = make_event(
            KIND_AGENT_MESSAGE,
            vec![vec!["performative".into(), "tell".into()]],
            "()",
        );
        let msg = AgentMessage::from_event(event).unwrap();
        let err = validate_performative(&msg).unwrap_err();
        assert!(matches!(err, PerformativeError::NoHeadSymbol));
    }

    // ====================================================================
    // Event serde round-trip
    // ====================================================================

    #[test]
    fn event_serde_round_trip() {
        let event = make_event(
            KIND_AGENT_MESSAGE,
            vec![
                vec!["p".into(), "abc".into()],
                vec!["performative".into(), "tell".into()],
            ],
            r#"(tell @abc "hi")"#,
        );
        let json = serde_json::to_string(&event).unwrap();
        let back: Event = serde_json::from_str(&json).unwrap();
        assert_eq!(event, back);
    }
}
