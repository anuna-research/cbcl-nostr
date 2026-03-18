//! Builder API for constructing kind 21111 agent message events.
//!
//! Accepts performative + recipient + content body + optional thread/dialect
//! and produces a complete unsigned [`Event`] with correct tags and
//! S-expression content. Broadcast performatives (`hello`, `bye`) omit
//! the `p` tag.

#![forbid(unsafe_code)]

use cbcl_core::sexpr::{Atom, SExpr};

use crate::event_types::{Event, KIND_AGENT_MESSAGE, Tag};
use crate::sexpr_codec;

// ---------------------------------------------------------------------------
// Broadcast performatives
// ---------------------------------------------------------------------------

/// Performatives that are broadcast (no specific recipient).
const BROADCAST_PERFORMATIVES: &[&str] = &["hello", "bye"];

/// Returns `true` if the given performative is a broadcast type (no `p` tag).
fn is_broadcast(performative: &str) -> bool {
    BROADCAST_PERFORMATIVES.contains(&performative)
}

// ---------------------------------------------------------------------------
// Builder error
// ---------------------------------------------------------------------------

/// Errors from building an agent message event.
#[derive(Debug, thiserror::Error)]
pub enum BuilderError {
    /// Performative string is empty.
    #[error("performative must not be empty")]
    EmptyPerformative,

    /// A non-broadcast performative requires a recipient.
    #[error("non-broadcast performative \"{0}\" requires a recipient")]
    MissingRecipient(String),

    /// A broadcast performative must not have a recipient.
    #[error("broadcast performative \"{0}\" must not have a recipient")]
    UnexpectedRecipient(String),
}

// ---------------------------------------------------------------------------
// MessageBuilder
// ---------------------------------------------------------------------------

/// Builder for constructing unsigned kind 21111 agent message events.
///
/// # Examples
///
/// ```
/// use cbcl_core::sexpr::{Atom, SExpr};
/// use cbcl_nostr::message_builder::MessageBuilder;
///
/// // Directed message
/// let event = MessageBuilder::new("tell")
///     .recipient("abcd1234")
///     .body(vec![SExpr::Atom(Atom::Str("hello".into()))])
///     .thread("conv-17")
///     .build()
///     .unwrap();
///
/// // Broadcast message
/// let event = MessageBuilder::new("hello")
///     .build()
///     .unwrap();
/// ```
pub struct MessageBuilder {
    performative: String,
    recipient: Option<String>,
    body: Vec<SExpr>,
    thread: Option<String>,
    dialect: Option<String>,
    extra_tags: Vec<Tag>,
}

impl MessageBuilder {
    /// Create a new builder with the given performative verb.
    pub fn new(performative: &str) -> Self {
        Self {
            performative: performative.to_string(),
            recipient: None,
            body: Vec::new(),
            thread: None,
            dialect: None,
            extra_tags: Vec::new(),
        }
    }

    /// Set the recipient public key (hex). Required for non-broadcast performatives.
    pub fn recipient(mut self, pubkey: &str) -> Self {
        self.recipient = Some(pubkey.to_string());
        self
    }

    /// Set the body elements (arguments after the performative in the S-expression).
    pub fn body(mut self, body: Vec<SExpr>) -> Self {
        self.body = body;
        self
    }

    /// Set the conversation thread identifier.
    pub fn thread(mut self, thread_id: &str) -> Self {
        self.thread = Some(thread_id.to_string());
        self
    }

    /// Set the dialect identifier.
    pub fn dialect(mut self, dialect: &str) -> Self {
        self.dialect = Some(dialect.to_string());
        self
    }

    /// Add an extra tag to the event.
    pub fn tag(mut self, tag: Tag) -> Self {
        self.extra_tags.push(tag);
        self
    }

    /// Build the unsigned event.
    ///
    /// Returns an [`Event`] with kind 21111, correct tags, and serialized
    /// S-expression content. The `id`, `pubkey`, `created_at`, and `sig`
    /// fields are left as placeholders (empty strings / zero) for the
    /// caller to fill after signing.
    pub fn build(self) -> Result<Event, BuilderError> {
        if self.performative.is_empty() {
            return Err(BuilderError::EmptyPerformative);
        }

        let broadcast = is_broadcast(&self.performative);

        if !broadcast && self.recipient.is_none() {
            return Err(BuilderError::MissingRecipient(self.performative));
        }
        if broadcast && self.recipient.is_some() {
            return Err(BuilderError::UnexpectedRecipient(self.performative));
        }

        // Build tags
        let mut tags: Vec<Tag> = Vec::new();

        if let Some(ref pk) = self.recipient {
            tags.push(Tag::PubKey(pk.clone()));
        }

        tags.push(Tag::Performative(self.performative.clone()));

        if let Some(ref thread_id) = self.thread {
            tags.push(Tag::Thread(thread_id.clone()));
        }

        if let Some(ref dialect) = self.dialect {
            tags.push(Tag::Dialect(dialect.clone()));
        }

        tags.extend(self.extra_tags);

        // Build content S-expression: (performative ...body)
        let mut items = Vec::with_capacity(1 + self.body.len());
        items.push(SExpr::Atom(Atom::Symbol(self.performative)));
        items.extend(self.body);
        let content = sexpr_codec::encode(&SExpr::List(items));

        // Build raw tags
        let raw_tags: Vec<Vec<String>> = tags.iter().map(Tag::to_raw).collect();

        Ok(Event {
            id: String::new(),
            pubkey: String::new(),
            created_at: 0,
            kind: KIND_AGENT_MESSAGE,
            tags: raw_tags,
            content,
            sig: String::new(),
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event_types::{AgentMessage, validate_performative};

    #[test]
    fn build_tell_message() {
        let event = MessageBuilder::new("tell")
            .recipient("abc123")
            .body(vec![
                SExpr::Atom(Atom::Symbol("@abc123".into())),
                SExpr::Atom(Atom::Str("hello".into())),
            ])
            .thread("conv-17")
            .build()
            .unwrap();

        assert_eq!(event.kind, KIND_AGENT_MESSAGE);
        assert_eq!(event.content, r#"(tell @abc123 "hello")"#);
        assert_eq!(event.tags.len(), 3);
        assert_eq!(Tag::parse(&event.tags[0]), Tag::PubKey("abc123".into()));
        assert_eq!(
            Tag::parse(&event.tags[1]),
            Tag::Performative("tell".into())
        );
        assert_eq!(Tag::parse(&event.tags[2]), Tag::Thread("conv-17".into()));
    }

    #[test]
    fn build_ask_with_dialect() {
        let event = MessageBuilder::new("ask")
            .recipient("def456")
            .body(vec![
                SExpr::Atom(Atom::Symbol("@def456".into())),
                SExpr::Atom(Atom::Str("price?".into())),
            ])
            .dialect("commerce")
            .build()
            .unwrap();

        assert_eq!(event.tags.len(), 3);
        assert_eq!(Tag::parse(&event.tags[2]), Tag::Dialect("commerce".into()));
    }

    #[test]
    fn build_hello_broadcast() {
        let event = MessageBuilder::new("hello").build().unwrap();

        assert_eq!(event.kind, KIND_AGENT_MESSAGE);
        assert_eq!(event.content, "(hello)");
        assert_eq!(event.tags.len(), 1);
        assert_eq!(
            Tag::parse(&event.tags[0]),
            Tag::Performative("hello".into())
        );
    }

    #[test]
    fn build_bye_broadcast() {
        let event = MessageBuilder::new("bye").build().unwrap();

        assert_eq!(event.content, "(bye)");
        assert_eq!(event.tags.len(), 1);
        assert_eq!(
            Tag::parse(&event.tags[0]),
            Tag::Performative("bye".into())
        );
    }

    #[test]
    fn build_broadcast_with_body() {
        let event = MessageBuilder::new("hello")
            .body(vec![SExpr::Atom(Atom::Str("I'm agent-007".into()))])
            .build()
            .unwrap();

        assert_eq!(event.content, r#"(hello "I'm agent-007")"#);
    }

    #[test]
    fn build_broadcast_rejects_recipient() {
        let err = MessageBuilder::new("hello")
            .recipient("abc123")
            .build()
            .unwrap_err();

        assert!(matches!(err, BuilderError::UnexpectedRecipient(_)));
    }

    #[test]
    fn build_directed_requires_recipient() {
        let err = MessageBuilder::new("tell").build().unwrap_err();
        assert!(matches!(err, BuilderError::MissingRecipient(_)));
    }

    #[test]
    fn build_empty_performative_rejected() {
        let err = MessageBuilder::new("").build().unwrap_err();
        assert!(matches!(err, BuilderError::EmptyPerformative));
    }

    #[test]
    fn build_dialect_extended_performative() {
        let event = MessageBuilder::new("negotiate")
            .recipient("abc123")
            .body(vec![
                SExpr::Atom(Atom::Symbol("@abc123".into())),
                SExpr::Atom(Atom::Keyword("price".into())),
                SExpr::Atom(Atom::Num(100)),
            ])
            .dialect("commerce")
            .build()
            .unwrap();

        assert_eq!(event.content, "(negotiate @abc123 :price 100)");
    }

    #[test]
    fn build_with_extra_tags() {
        let event = MessageBuilder::new("tell")
            .recipient("abc123")
            .body(vec![SExpr::Atom(Atom::Str("hi".into()))])
            .tag(Tag::Hashtag("cbcl".into()))
            .tag(Tag::Event("ref-event-id".into()))
            .build()
            .unwrap();

        assert_eq!(event.tags.len(), 4); // p, performative, t, e
        assert_eq!(Tag::parse(&event.tags[2]), Tag::Hashtag("cbcl".into()));
        assert_eq!(
            Tag::parse(&event.tags[3]),
            Tag::Event("ref-event-id".into())
        );
    }

    #[test]
    fn built_event_validates_performative() {
        let event = MessageBuilder::new("tell")
            .recipient("abc123")
            .body(vec![
                SExpr::Atom(Atom::Symbol("@abc123".into())),
                SExpr::Atom(Atom::Str("hello".into())),
            ])
            .build()
            .unwrap();

        let msg = AgentMessage::from_event(event).unwrap();
        assert_eq!(validate_performative(&msg).unwrap(), "tell");
    }

    #[test]
    fn built_broadcast_validates_performative() {
        let event = MessageBuilder::new("hello").build().unwrap();
        let msg = AgentMessage::from_event(event).unwrap();
        assert_eq!(validate_performative(&msg).unwrap(), "hello");
    }

    #[test]
    fn unsigned_fields_are_placeholders() {
        let event = MessageBuilder::new("hello").build().unwrap();
        assert!(event.id.is_empty());
        assert!(event.pubkey.is_empty());
        assert_eq!(event.created_at, 0);
        assert!(event.sig.is_empty());
    }

    #[test]
    fn build_all_core_performatives() {
        let directed = ["tell", "ask", "reply", "ok", "error", "cancel"];
        let broadcast = ["hello", "bye"];

        for perf in directed {
            let event = MessageBuilder::new(perf)
                .recipient("abc123")
                .build()
                .unwrap();
            assert_eq!(event.kind, KIND_AGENT_MESSAGE);
            let msg = AgentMessage::from_event(event).unwrap();
            assert_eq!(validate_performative(&msg).unwrap(), perf);
        }

        for perf in broadcast {
            let event = MessageBuilder::new(perf).build().unwrap();
            assert_eq!(event.kind, KIND_AGENT_MESSAGE);
            let msg = AgentMessage::from_event(event).unwrap();
            assert_eq!(validate_performative(&msg).unwrap(), perf);
        }
    }

    #[test]
    fn build_with_nested_body() {
        let event = MessageBuilder::new("tell")
            .recipient("abc123")
            .body(vec![SExpr::List(vec![
                SExpr::Atom(Atom::Symbol("data".into())),
                SExpr::Atom(Atom::Num(42)),
                SExpr::Atom(Atom::Bool(true)),
            ])])
            .build()
            .unwrap();

        assert_eq!(event.content, "(tell (data 42 #t))");
    }
}
