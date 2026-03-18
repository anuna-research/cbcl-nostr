//! Commerce dialect: quote/accept/reject/counter/invoice/paid performatives
//! with a negotiation state machine.
//!
//! Provides:
//! - [`COMMERCE_PERFORMATIVES`] — the six commerce speech-act verbs.
//! - [`NegotiationState`] — state machine tracking deal lifecycle.
//! - [`commerce_dialect`] — builds the CBCL `Dialect` struct for commerce.
//! - [`commerce_dialect_event`] — builds an unsigned kind 31111 event
//!   publishing the commerce dialect.
//! - [`wrap_commerce`] / [`unwrap_commerce`] — `(lang commerce ...)` envelope.
//! - [`CommerceMessageBuilder`] — convenience builder for commerce messages.

#![forbid(unsafe_code)]

use cbcl_core::dialect::{Dialect, PerformativeDef, ResourceBounds};
use cbcl_core::sexpr::{Atom, SExpr};

use crate::dialect_negotiation::DialectBuilder;
use crate::event_types::{Event, Tag};
use crate::message_builder::{BuilderError, MessageBuilder};
use crate::sexpr_codec;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// The six commerce performatives defined by NIP-XX.
pub const COMMERCE_PERFORMATIVES: &[&str] = &[
    "quote",
    "accept-quote",
    "reject-quote",
    "counter",
    "invoice",
    "paid",
];

/// The dialect name used in tags and `(lang ...)` envelopes.
pub const COMMERCE_DIALECT_NAME: &str = "commerce";

/// Returns `true` if `name` is one of the six commerce performatives.
pub fn is_commerce_performative(name: &str) -> bool {
    COMMERCE_PERFORMATIVES.contains(&name)
}

// ---------------------------------------------------------------------------
// Negotiation state machine
// ---------------------------------------------------------------------------

/// Lifecycle state of a commerce negotiation.
///
/// ```text
/// open → quoted → accepted  → working → completed → invoiced → paid
///                 rejected
///                 countered → quoted → ...
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NegotiationState {
    /// Initial state — no quote has been sent yet.
    Open,
    /// A quote has been sent, awaiting buyer response.
    Quoted,
    /// The buyer accepted the quote.
    Accepted,
    /// The buyer rejected the quote (terminal).
    Rejected,
    /// The buyer countered with a new price/terms.
    Countered,
    /// Work is underway after acceptance.
    Working,
    /// Work has been completed, ready for invoicing.
    Completed,
    /// An invoice has been issued, awaiting payment.
    Invoiced,
    /// Payment has been confirmed (terminal).
    Paid,
}

/// Errors from invalid state transitions.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TransitionError {
    /// The performative is not valid from the current state.
    #[error("invalid transition: cannot apply \"{performative}\" in state {state:?}")]
    InvalidTransition {
        state: NegotiationState,
        performative: String,
    },

    /// The performative is not a recognized commerce verb.
    #[error("unknown commerce performative: \"{0}\"")]
    UnknownPerformative(String),
}

impl NegotiationState {
    /// Returns `true` if this is a terminal state (no further transitions).
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Rejected | Self::Paid)
    }

    /// Apply a commerce performative and return the new state.
    ///
    /// Valid transitions:
    /// - `Open`      + `quote`        → `Quoted`
    /// - `Quoted`    + `accept-quote` → `Accepted`
    /// - `Quoted`    + `reject-quote` → `Rejected`
    /// - `Quoted`    + `counter`      → `Countered`
    /// - `Countered` + `quote`        → `Quoted`
    /// - `Accepted`  + `quote`        → `Working` (work begins implicitly)
    /// - `Working`   + `invoice`      → `Invoiced` (skip Completed for direct invoice)
    /// - `Completed` + `invoice`      → `Invoiced`
    /// - `Invoiced`  + `paid`         → `Paid`
    ///
    /// Additionally, an explicit transition to `Working` and `Completed` is
    /// supported via dedicated helpers.
    pub fn apply(self, performative: &str) -> Result<Self, TransitionError> {
        if !is_commerce_performative(performative) {
            return Err(TransitionError::UnknownPerformative(
                performative.to_string(),
            ));
        }

        let next = match (self, performative) {
            // Quoting
            (Self::Open, "quote") => Self::Quoted,
            (Self::Countered, "quote") => Self::Quoted,

            // Buyer responses
            (Self::Quoted, "accept-quote") => Self::Accepted,
            (Self::Quoted, "reject-quote") => Self::Rejected,
            (Self::Quoted, "counter") => Self::Countered,

            // Invoicing
            (Self::Accepted, "invoice") => Self::Invoiced,
            (Self::Working, "invoice") => Self::Invoiced,
            (Self::Completed, "invoice") => Self::Invoiced,

            // Payment
            (Self::Invoiced, "paid") => Self::Paid,

            _ => {
                return Err(TransitionError::InvalidTransition {
                    state: self,
                    performative: performative.to_string(),
                });
            }
        };

        Ok(next)
    }

    /// Transition to `Working` (only valid from `Accepted`).
    pub fn begin_work(self) -> Result<Self, TransitionError> {
        match self {
            Self::Accepted => Ok(Self::Working),
            _ => Err(TransitionError::InvalidTransition {
                state: self,
                performative: "begin-work".to_string(),
            }),
        }
    }

    /// Transition to `Completed` (only valid from `Working`).
    pub fn complete_work(self) -> Result<Self, TransitionError> {
        match self {
            Self::Working => Ok(Self::Completed),
            _ => Err(TransitionError::InvalidTransition {
                state: self,
                performative: "complete-work".to_string(),
            }),
        }
    }
}

// ---------------------------------------------------------------------------
// Dialect definition
// ---------------------------------------------------------------------------

/// Build the CBCL `Dialect` struct for the commerce dialect.
///
/// Defines six performatives with their parameter lists and effect templates:
/// - `quote (item price currency)` → `(effect quote-item)`
/// - `accept-quote (quote-ref)` → `(effect accept-offer)`
/// - `reject-quote (quote-ref reason)` → `(effect reject-offer)`
/// - `counter (quote-ref price currency)` → `(effect counter-offer)`
/// - `invoice (invoice-ref amount currency)` → `(effect issue-invoice)`
/// - `paid (invoice-ref tx-ref)` → `(effect confirm-payment)`
pub fn commerce_dialect() -> Dialect {
    Dialect {
        name: COMMERCE_DIALECT_NAME.into(),
        extends: vec!["cbcl".into()],
        author: Some("@commerce".into()),
        performatives: vec![
            PerformativeDef {
                name: "quote".into(),
                params: vec![
                    SExpr::Atom(Atom::Symbol("item".into())),
                    SExpr::Atom(Atom::Symbol("price".into())),
                    SExpr::Atom(Atom::Symbol("currency".into())),
                ],
                template: SExpr::List(vec![
                    SExpr::Atom(Atom::Symbol("effect".into())),
                    SExpr::Atom(Atom::Symbol("quote-item".into())),
                ]),
            },
            PerformativeDef {
                name: "accept-quote".into(),
                params: vec![SExpr::Atom(Atom::Symbol("quote-ref".into()))],
                template: SExpr::List(vec![
                    SExpr::Atom(Atom::Symbol("effect".into())),
                    SExpr::Atom(Atom::Symbol("accept-offer".into())),
                ]),
            },
            PerformativeDef {
                name: "reject-quote".into(),
                params: vec![
                    SExpr::Atom(Atom::Symbol("quote-ref".into())),
                    SExpr::Atom(Atom::Symbol("reason".into())),
                ],
                template: SExpr::List(vec![
                    SExpr::Atom(Atom::Symbol("effect".into())),
                    SExpr::Atom(Atom::Symbol("reject-offer".into())),
                ]),
            },
            PerformativeDef {
                name: "counter".into(),
                params: vec![
                    SExpr::Atom(Atom::Symbol("quote-ref".into())),
                    SExpr::Atom(Atom::Symbol("price".into())),
                    SExpr::Atom(Atom::Symbol("currency".into())),
                ],
                template: SExpr::List(vec![
                    SExpr::Atom(Atom::Symbol("effect".into())),
                    SExpr::Atom(Atom::Symbol("counter-offer".into())),
                ]),
            },
            PerformativeDef {
                name: "invoice".into(),
                params: vec![
                    SExpr::Atom(Atom::Symbol("invoice-ref".into())),
                    SExpr::Atom(Atom::Symbol("amount".into())),
                    SExpr::Atom(Atom::Symbol("currency".into())),
                ],
                template: SExpr::List(vec![
                    SExpr::Atom(Atom::Symbol("effect".into())),
                    SExpr::Atom(Atom::Symbol("issue-invoice".into())),
                ]),
            },
            PerformativeDef {
                name: "paid".into(),
                params: vec![
                    SExpr::Atom(Atom::Symbol("invoice-ref".into())),
                    SExpr::Atom(Atom::Symbol("tx-ref".into())),
                ],
                template: SExpr::List(vec![
                    SExpr::Atom(Atom::Symbol("effect".into())),
                    SExpr::Atom(Atom::Symbol("confirm-payment".into())),
                ]),
            },
        ],
        resources: ResourceBounds {
            max_depth: 16,
            max_expansion_size: 1024,
            verification_time_ms: 50,
        },
        examples: vec![],
        signature: None,
        hash: None,
        protocol: None,
    }
}

/// Build an unsigned kind 31111 event publishing the commerce dialect.
pub fn commerce_dialect_event() -> Event {
    DialectBuilder::from_dialect(&commerce_dialect()).build()
}

// ---------------------------------------------------------------------------
// (lang commerce ...) envelope
// ---------------------------------------------------------------------------

/// Wrap an S-expression in a `(lang commerce <inner>)` envelope.
pub fn wrap_commerce(inner: &SExpr) -> SExpr {
    SExpr::List(vec![
        SExpr::Atom(Atom::Symbol("lang".into())),
        SExpr::Atom(Atom::Symbol(COMMERCE_DIALECT_NAME.into())),
        inner.clone(),
    ])
}

/// Unwrap a `(lang commerce <inner>)` envelope, returning the inner expression.
///
/// Returns `None` if the expression is not a well-formed commerce envelope.
pub fn unwrap_commerce(sexpr: &SExpr) -> Option<&SExpr> {
    match sexpr {
        SExpr::List(items) if items.len() == 3 => {
            let is_lang = matches!(&items[0], SExpr::Atom(Atom::Symbol(s)) if s == "lang");
            let is_commerce =
                matches!(&items[1], SExpr::Atom(Atom::Symbol(s)) if s == COMMERCE_DIALECT_NAME);
            if is_lang && is_commerce {
                Some(&items[2])
            } else {
                None
            }
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// CommerceMessageBuilder
// ---------------------------------------------------------------------------

/// Convenience builder for commerce dialect messages.
///
/// Wraps [`MessageBuilder`] to automatically set the `dialect` tag to
/// `"commerce"` and wrap the content in `(lang commerce ...)`.
pub struct CommerceMessageBuilder {
    performative: String,
    recipient: Option<String>,
    body: Vec<SExpr>,
    thread: Option<String>,
    extra_tags: Vec<Tag>,
}

impl CommerceMessageBuilder {
    /// Create a new commerce message builder.
    ///
    /// The `performative` should be one of the six commerce performatives.
    pub fn new(performative: &str) -> Self {
        Self {
            performative: performative.to_string(),
            recipient: None,
            body: Vec::new(),
            thread: None,
            extra_tags: Vec::new(),
        }
    }

    /// Set the recipient public key.
    pub fn recipient(mut self, pubkey: &str) -> Self {
        self.recipient = Some(pubkey.to_string());
        self
    }

    /// Set the body elements (arguments after the performative).
    pub fn body(mut self, body: Vec<SExpr>) -> Self {
        self.body = body;
        self
    }

    /// Set the conversation thread identifier.
    pub fn thread(mut self, thread_id: &str) -> Self {
        self.thread = Some(thread_id.to_string());
        self
    }

    /// Add an extra tag.
    pub fn tag(mut self, tag: Tag) -> Self {
        self.extra_tags.push(tag);
        self
    }

    /// Build the unsigned event.
    ///
    /// The content is wrapped as `(lang commerce (performative ...body))`.
    /// The `dialect` tag is automatically set to `"commerce"`.
    pub fn build(self) -> Result<Event, BuilderError> {
        // Build the inner S-expression: (performative ...body)
        let mut inner_items = Vec::with_capacity(1 + self.body.len());
        inner_items.push(SExpr::Atom(Atom::Symbol(self.performative.clone())));
        inner_items.extend(self.body);
        let inner = SExpr::List(inner_items);

        // Wrap in (lang commerce ...)
        let wrapped = wrap_commerce(&inner);
        let content = sexpr_codec::encode(&wrapped);

        // Use a "tell" performative for the outer event (the commerce
        // performative lives inside the lang envelope) but tag with the
        // actual commerce performative for filtering.
        let mut builder = MessageBuilder::new("tell");

        if let Some(ref pk) = self.recipient {
            builder = builder.recipient(pk);
        }

        // Set empty body — content is overridden below
        builder = builder.dialect(COMMERCE_DIALECT_NAME);

        if let Some(ref tid) = self.thread {
            builder = builder.thread(tid);
        }

        // Add the commerce performative as a hashtag for discoverability
        builder = builder.tag(Tag::Hashtag(self.performative.clone()));

        for t in self.extra_tags {
            builder = builder.tag(t);
        }

        let mut event = builder.build()?;

        // Override the content with our wrapped commerce S-expression
        event.content = content;

        Ok(event)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ====================================================================
    // Commerce performative check
    // ====================================================================

    #[test]
    fn commerce_performatives_recognized() {
        for &p in COMMERCE_PERFORMATIVES {
            assert!(is_commerce_performative(p), "{p} should be commerce");
        }
    }

    #[test]
    fn core_performatives_not_commerce() {
        assert!(!is_commerce_performative("tell"));
        assert!(!is_commerce_performative("ask"));
        assert!(!is_commerce_performative("hello"));
    }

    // ====================================================================
    // NegotiationState — valid transitions
    // ====================================================================

    #[test]
    fn open_to_quoted() {
        let state = NegotiationState::Open.apply("quote").unwrap();
        assert_eq!(state, NegotiationState::Quoted);
    }

    #[test]
    fn quoted_to_accepted() {
        let state = NegotiationState::Quoted.apply("accept-quote").unwrap();
        assert_eq!(state, NegotiationState::Accepted);
    }

    #[test]
    fn quoted_to_rejected() {
        let state = NegotiationState::Quoted.apply("reject-quote").unwrap();
        assert_eq!(state, NegotiationState::Rejected);
    }

    #[test]
    fn quoted_to_countered() {
        let state = NegotiationState::Quoted.apply("counter").unwrap();
        assert_eq!(state, NegotiationState::Countered);
    }

    #[test]
    fn countered_to_quoted() {
        let state = NegotiationState::Countered.apply("quote").unwrap();
        assert_eq!(state, NegotiationState::Quoted);
    }

    #[test]
    fn accepted_to_invoiced() {
        let state = NegotiationState::Accepted.apply("invoice").unwrap();
        assert_eq!(state, NegotiationState::Invoiced);
    }

    #[test]
    fn working_to_invoiced() {
        let state = NegotiationState::Working.apply("invoice").unwrap();
        assert_eq!(state, NegotiationState::Invoiced);
    }

    #[test]
    fn completed_to_invoiced() {
        let state = NegotiationState::Completed.apply("invoice").unwrap();
        assert_eq!(state, NegotiationState::Invoiced);
    }

    #[test]
    fn invoiced_to_paid() {
        let state = NegotiationState::Invoiced.apply("paid").unwrap();
        assert_eq!(state, NegotiationState::Paid);
    }

    // ====================================================================
    // NegotiationState — full lifecycle
    // ====================================================================

    #[test]
    fn full_happy_path() {
        let state = NegotiationState::Open;
        let state = state.apply("quote").unwrap();
        let state = state.apply("accept-quote").unwrap();
        let state = state.begin_work().unwrap();
        let state = state.complete_work().unwrap();
        let state = state.apply("invoice").unwrap();
        let state = state.apply("paid").unwrap();
        assert_eq!(state, NegotiationState::Paid);
        assert!(state.is_terminal());
    }

    #[test]
    fn counter_then_accept_path() {
        let state = NegotiationState::Open;
        let state = state.apply("quote").unwrap();
        let state = state.apply("counter").unwrap();
        let state = state.apply("quote").unwrap();
        let state = state.apply("accept-quote").unwrap();
        let state = state.apply("invoice").unwrap();
        let state = state.apply("paid").unwrap();
        assert_eq!(state, NegotiationState::Paid);
    }

    #[test]
    fn rejection_path() {
        let state = NegotiationState::Open;
        let state = state.apply("quote").unwrap();
        let state = state.apply("reject-quote").unwrap();
        assert_eq!(state, NegotiationState::Rejected);
        assert!(state.is_terminal());
    }

    #[test]
    fn direct_invoice_after_acceptance() {
        // Skip working/completed — go straight to invoice
        let state = NegotiationState::Open;
        let state = state.apply("quote").unwrap();
        let state = state.apply("accept-quote").unwrap();
        let state = state.apply("invoice").unwrap();
        let state = state.apply("paid").unwrap();
        assert_eq!(state, NegotiationState::Paid);
    }

    // ====================================================================
    // NegotiationState — invalid transitions
    // ====================================================================

    #[test]
    fn open_cannot_accept() {
        let err = NegotiationState::Open.apply("accept-quote").unwrap_err();
        assert!(matches!(err, TransitionError::InvalidTransition { .. }));
    }

    #[test]
    fn open_cannot_invoice() {
        let err = NegotiationState::Open.apply("invoice").unwrap_err();
        assert!(matches!(err, TransitionError::InvalidTransition { .. }));
    }

    #[test]
    fn quoted_cannot_invoice() {
        let err = NegotiationState::Quoted.apply("invoice").unwrap_err();
        assert!(matches!(err, TransitionError::InvalidTransition { .. }));
    }

    #[test]
    fn rejected_is_terminal() {
        let err = NegotiationState::Rejected.apply("quote").unwrap_err();
        assert!(matches!(err, TransitionError::InvalidTransition { .. }));
    }

    #[test]
    fn paid_is_terminal() {
        let err = NegotiationState::Paid.apply("quote").unwrap_err();
        assert!(matches!(err, TransitionError::InvalidTransition { .. }));
    }

    #[test]
    fn unknown_performative_rejected() {
        let err = NegotiationState::Open.apply("negotiate").unwrap_err();
        assert!(matches!(err, TransitionError::UnknownPerformative(_)));
    }

    // ====================================================================
    // NegotiationState — begin_work / complete_work
    // ====================================================================

    #[test]
    fn begin_work_from_accepted() {
        let state = NegotiationState::Accepted.begin_work().unwrap();
        assert_eq!(state, NegotiationState::Working);
    }

    #[test]
    fn begin_work_from_open_fails() {
        let err = NegotiationState::Open.begin_work().unwrap_err();
        assert!(matches!(err, TransitionError::InvalidTransition { .. }));
    }

    #[test]
    fn complete_work_from_working() {
        let state = NegotiationState::Working.complete_work().unwrap();
        assert_eq!(state, NegotiationState::Completed);
    }

    #[test]
    fn complete_work_from_accepted_fails() {
        let err = NegotiationState::Accepted.complete_work().unwrap_err();
        assert!(matches!(err, TransitionError::InvalidTransition { .. }));
    }

    // ====================================================================
    // NegotiationState — is_terminal
    // ====================================================================

    #[test]
    fn terminal_states() {
        assert!(!NegotiationState::Open.is_terminal());
        assert!(!NegotiationState::Quoted.is_terminal());
        assert!(!NegotiationState::Accepted.is_terminal());
        assert!(NegotiationState::Rejected.is_terminal());
        assert!(!NegotiationState::Countered.is_terminal());
        assert!(!NegotiationState::Working.is_terminal());
        assert!(!NegotiationState::Completed.is_terminal());
        assert!(!NegotiationState::Invoiced.is_terminal());
        assert!(NegotiationState::Paid.is_terminal());
    }

    // ====================================================================
    // Dialect definition
    // ====================================================================

    #[test]
    fn commerce_dialect_has_six_performatives() {
        let dialect = commerce_dialect();
        assert_eq!(dialect.name, "commerce");
        assert_eq!(dialect.extends, vec!["cbcl"]);
        assert_eq!(dialect.performatives.len(), 6);
        let names: Vec<&str> = dialect.performatives.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(
            names,
            vec!["quote", "accept-quote", "reject-quote", "counter", "invoice", "paid"]
        );
    }

    #[test]
    fn commerce_dialect_performative_params() {
        let dialect = commerce_dialect();
        // quote has 3 params
        assert_eq!(dialect.performatives[0].params.len(), 3);
        // accept-quote has 1 param
        assert_eq!(dialect.performatives[1].params.len(), 1);
        // reject-quote has 2 params
        assert_eq!(dialect.performatives[2].params.len(), 2);
        // counter has 3 params
        assert_eq!(dialect.performatives[3].params.len(), 3);
        // invoice has 3 params
        assert_eq!(dialect.performatives[4].params.len(), 3);
        // paid has 2 params
        assert_eq!(dialect.performatives[5].params.len(), 2);
    }

    #[test]
    fn commerce_dialect_event_is_kind_31111() {
        let event = commerce_dialect_event();
        assert_eq!(event.kind, 31111);
        let tags: Vec<Tag> = event.tags.iter().map(|t| Tag::parse(t)).collect();
        assert!(tags.contains(&Tag::Dialect("commerce".into())));
    }

    #[test]
    fn commerce_dialect_installs_in_registry() {
        use cbcl_core::dialect::DialectRegistry;
        let dialect = commerce_dialect();
        let mut registry = DialectRegistry::new();
        registry.install(dialect).unwrap();
        assert!(registry.find_by_name("commerce").is_some());
        for &perf in COMMERCE_PERFORMATIVES {
            assert!(
                registry.find_performative_dialect(perf).is_some(),
                "performative {perf} should be findable"
            );
        }
    }

    // ====================================================================
    // (lang commerce ...) envelope
    // ====================================================================

    #[test]
    fn wrap_unwrap_round_trip() {
        let inner = SExpr::List(vec![
            SExpr::Atom(Atom::Symbol("quote".into())),
            SExpr::Atom(Atom::Keyword("item".into())),
            SExpr::Atom(Atom::Str("widget".into())),
            SExpr::Atom(Atom::Keyword("price".into())),
            SExpr::Atom(Atom::Num(1000)),
        ]);
        let wrapped = wrap_commerce(&inner);
        let unwrapped = unwrap_commerce(&wrapped).unwrap();
        assert_eq!(unwrapped, &inner);
    }

    #[test]
    fn wrap_produces_correct_structure() {
        let inner = SExpr::List(vec![SExpr::Atom(Atom::Symbol("quote".into()))]);
        let wrapped = wrap_commerce(&inner);
        let content = sexpr_codec::encode(&wrapped);
        assert_eq!(content, "(lang commerce (quote))");
    }

    #[test]
    fn unwrap_rejects_wrong_dialect() {
        let expr = SExpr::List(vec![
            SExpr::Atom(Atom::Symbol("lang".into())),
            SExpr::Atom(Atom::Symbol("planning".into())),
            SExpr::List(vec![SExpr::Atom(Atom::Symbol("propose".into()))]),
        ]);
        assert!(unwrap_commerce(&expr).is_none());
    }

    #[test]
    fn unwrap_rejects_non_lang() {
        let expr = SExpr::List(vec![
            SExpr::Atom(Atom::Symbol("tell".into())),
            SExpr::Atom(Atom::Str("hello".into())),
        ]);
        assert!(unwrap_commerce(&expr).is_none());
    }

    #[test]
    fn unwrap_rejects_atom() {
        let expr = SExpr::Atom(Atom::Symbol("quote".into()));
        assert!(unwrap_commerce(&expr).is_none());
    }

    #[test]
    fn unwrap_rejects_wrong_arity() {
        let expr = SExpr::List(vec![
            SExpr::Atom(Atom::Symbol("lang".into())),
            SExpr::Atom(Atom::Symbol("commerce".into())),
        ]);
        assert!(unwrap_commerce(&expr).is_none());
    }

    // ====================================================================
    // CommerceMessageBuilder
    // ====================================================================

    #[test]
    fn build_quote_message() {
        let event = CommerceMessageBuilder::new("quote")
            .recipient("abc123")
            .body(vec![
                SExpr::Atom(Atom::Keyword("item".into())),
                SExpr::Atom(Atom::Str("widget".into())),
                SExpr::Atom(Atom::Keyword("price".into())),
                SExpr::Atom(Atom::Num(1000)),
                SExpr::Atom(Atom::Keyword("currency".into())),
                SExpr::Atom(Atom::Str("sats".into())),
            ])
            .build()
            .unwrap();

        assert_eq!(
            event.content,
            r#"(lang commerce (quote :item "widget" :price 1000 :currency "sats"))"#
        );
        let tags: Vec<Tag> = event.tags.iter().map(|t| Tag::parse(t)).collect();
        assert!(tags.contains(&Tag::Dialect("commerce".into())));
        assert!(tags.contains(&Tag::Hashtag("quote".into())));
    }

    #[test]
    fn build_accept_quote_message() {
        let event = CommerceMessageBuilder::new("accept-quote")
            .recipient("abc123")
            .body(vec![
                SExpr::Atom(Atom::Keyword("quote-ref".into())),
                SExpr::Atom(Atom::Str("q-123".into())),
            ])
            .build()
            .unwrap();

        assert_eq!(
            event.content,
            r#"(lang commerce (accept-quote :quote-ref "q-123"))"#
        );
    }

    #[test]
    fn build_invoice_message_with_amount_tag() {
        let event = CommerceMessageBuilder::new("invoice")
            .recipient("abc123")
            .body(vec![
                SExpr::Atom(Atom::Keyword("invoice-ref".into())),
                SExpr::Atom(Atom::Str("inv-456".into())),
                SExpr::Atom(Atom::Keyword("amount".into())),
                SExpr::Atom(Atom::Num(50000)),
            ])
            .tag(Tag::Amount("50000".into()))
            .build()
            .unwrap();

        let tags: Vec<Tag> = event.tags.iter().map(|t| Tag::parse(t)).collect();
        assert!(tags.contains(&Tag::Amount("50000".into())));
    }

    #[test]
    fn build_paid_message() {
        let event = CommerceMessageBuilder::new("paid")
            .recipient("abc123")
            .body(vec![
                SExpr::Atom(Atom::Keyword("invoice-ref".into())),
                SExpr::Atom(Atom::Str("inv-456".into())),
                SExpr::Atom(Atom::Keyword("tx-ref".into())),
                SExpr::Atom(Atom::Str("tx-789".into())),
            ])
            .build()
            .unwrap();

        assert_eq!(
            event.content,
            r#"(lang commerce (paid :invoice-ref "inv-456" :tx-ref "tx-789"))"#
        );
    }

    #[test]
    fn build_with_thread() {
        let event = CommerceMessageBuilder::new("quote")
            .recipient("abc123")
            .body(vec![SExpr::Atom(Atom::Str("widget".into()))])
            .thread("deal-42")
            .build()
            .unwrap();

        let tags: Vec<Tag> = event.tags.iter().map(|t| Tag::parse(t)).collect();
        assert!(tags.contains(&Tag::Thread("deal-42".into())));
    }

    #[test]
    fn build_requires_recipient() {
        let err = CommerceMessageBuilder::new("quote").build().unwrap_err();
        assert!(matches!(err, BuilderError::MissingRecipient(_)));
    }

    #[test]
    fn build_counter_message() {
        let event = CommerceMessageBuilder::new("counter")
            .recipient("seller123")
            .body(vec![
                SExpr::Atom(Atom::Keyword("quote-ref".into())),
                SExpr::Atom(Atom::Str("q-123".into())),
                SExpr::Atom(Atom::Keyword("price".into())),
                SExpr::Atom(Atom::Num(800)),
                SExpr::Atom(Atom::Keyword("currency".into())),
                SExpr::Atom(Atom::Str("sats".into())),
            ])
            .build()
            .unwrap();

        assert_eq!(
            event.content,
            r#"(lang commerce (counter :quote-ref "q-123" :price 800 :currency "sats"))"#
        );
    }

    #[test]
    fn build_reject_quote_message() {
        let event = CommerceMessageBuilder::new("reject-quote")
            .recipient("seller123")
            .body(vec![
                SExpr::Atom(Atom::Keyword("quote-ref".into())),
                SExpr::Atom(Atom::Str("q-123".into())),
                SExpr::Atom(Atom::Keyword("reason".into())),
                SExpr::Atom(Atom::Str("too expensive".into())),
            ])
            .build()
            .unwrap();

        assert_eq!(
            event.content,
            r#"(lang commerce (reject-quote :quote-ref "q-123" :reason "too expensive"))"#
        );
    }

    // ====================================================================
    // End-to-end: dialect event → install → use
    // ====================================================================

    #[test]
    fn end_to_end_publish_install_use() {
        use cbcl_core::dialect::DialectRegistry;
        use crate::dialect_negotiation::install_dialect_event;

        // 1. Build the dialect event
        let mut event = commerce_dialect_event();
        // Simulate relay by filling required fields
        event.id = "a".repeat(64);
        event.pubkey = "b".repeat(64);
        event.created_at = 1700000000;
        event.sig = "c".repeat(128);

        // 2. Install the dialect
        let mut registry = DialectRegistry::new();
        let installed = install_dialect_event(event, &mut registry).unwrap();
        assert_eq!(installed.name, "commerce");
        assert_eq!(installed.performatives.len(), 6);

        // 3. Build a commerce message
        let msg_event = CommerceMessageBuilder::new("quote")
            .recipient("buyer123")
            .body(vec![
                SExpr::Atom(Atom::Keyword("item".into())),
                SExpr::Atom(Atom::Str("widget".into())),
                SExpr::Atom(Atom::Keyword("price".into())),
                SExpr::Atom(Atom::Num(1000)),
            ])
            .thread("deal-1")
            .build()
            .unwrap();

        // 4. Verify the content is wrapped
        let sexpr = sexpr_codec::decode(&msg_event.content).unwrap();
        let inner = unwrap_commerce(&sexpr).unwrap();
        let head = match inner {
            SExpr::List(items) => match &items[0] {
                SExpr::Atom(Atom::Symbol(s)) => s.as_str(),
                _ => panic!("expected symbol head"),
            },
            _ => panic!("expected list"),
        };
        assert_eq!(head, "quote");

        // 5. Verify the performative is known to the registry
        assert!(registry.find_performative_dialect("quote").is_some());
    }

    // ====================================================================
    // Multiple counter rounds
    // ====================================================================

    #[test]
    fn multiple_counter_rounds() {
        let mut state = NegotiationState::Open;
        state = state.apply("quote").unwrap();
        state = state.apply("counter").unwrap();
        state = state.apply("quote").unwrap();
        state = state.apply("counter").unwrap();
        state = state.apply("quote").unwrap();
        state = state.apply("accept-quote").unwrap();
        assert_eq!(state, NegotiationState::Accepted);
    }
}
