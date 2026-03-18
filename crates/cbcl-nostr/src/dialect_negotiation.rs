//! Dialect negotiation: publish, discover, parse, and install CBCL dialects.
//!
//! Provides:
//! - [`DialectBuilder`] — fluent builder for kind 31111 addressable dialect events.
//! - [`dialect_filter`] / [`dialect_filter_by_name`] — NIP-01 subscription filters
//!   that query relays by `L`/`l` namespace tags.
//! - [`parse_dialect_event`] — extract a [`Dialect`] from an [`AgentDialect`] event.
//! - [`install_dialect_event`] — verify, parse, and install a dialect into a
//!   [`DialectRegistry`].

#![forbid(unsafe_code)]

use cbcl_core::dialect::{Dialect, DialectInstallError, DialectRegistry};
use cbcl_core::sexpr::{Atom, SExpr};
use cbcl_parser::parse_dialect;

use crate::event_types::{AgentDialect, Event, EventTypeError, Tag, KIND_AGENT_DIALECT};
use crate::relay_pool::message::Filter;
use crate::sexpr_codec;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// NIP-32 label namespace used for CBCL dialect discovery.
pub const DIALECT_LABEL_NAMESPACE: &str = "cbcl.dialect";

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors from dialect negotiation operations.
#[derive(Debug, thiserror::Error)]
pub enum NegotiationError {
    /// The event kind is not 31111.
    #[error(transparent)]
    EventType(#[from] EventTypeError),

    /// The event content could not be decoded as an S-expression.
    #[error("codec error: {0}")]
    Codec(#[from] sexpr_codec::CodecError),

    /// The S-expression could not be parsed as a dialect definition.
    #[error("dialect parse error: {0}")]
    DialectParse(String),

    /// The dialect failed installation verification (R1–R3).
    #[error("install error: {0}")]
    Install(DialectInstallError),

    /// The event is missing a required `["dialect", _]` tag.
    #[error("missing dialect tag")]
    MissingDialectTag,

    /// The dialect name in the tag does not match the parsed dialect name.
    #[error("dialect name mismatch: tag says \"{tag}\" but parsed name is \"{parsed}\"")]
    NameMismatch { tag: String, parsed: String },
}

// ---------------------------------------------------------------------------
// DialectBuilder — construct unsigned kind 31111 events
// ---------------------------------------------------------------------------

/// Builder for constructing unsigned kind 31111 dialect definition events.
///
/// Produces an [`Event`] with:
/// - `kind = 31111` (parameterized-replaceable)
/// - `["dialect", name]` tag
/// - `["L", "cbcl.dialect"]` label namespace tag
/// - `["l", name, "cbcl.dialect"]` label tag
/// - Content: the dialect S-expression (either raw or serialized from a `Dialect`)
pub struct DialectBuilder {
    dialect_name: String,
    content: String,
    extra_tags: Vec<Tag>,
}

impl DialectBuilder {
    /// Create a builder from a `Dialect` struct. The content is serialized as a
    /// `(define ...)` S-expression.
    pub fn from_dialect(dialect: &Dialect) -> Self {
        let content = serialize_dialect(dialect);
        Self {
            dialect_name: dialect.name.clone(),
            content,
            extra_tags: Vec::new(),
        }
    }

    /// Create a builder from raw S-expression content. The dialect name is
    /// extracted from the `["dialect", _]` tag you must provide, or set via
    /// the name parameter.
    pub fn from_content(name: &str, content: &str) -> Self {
        Self {
            dialect_name: name.to_string(),
            content: content.to_string(),
            extra_tags: Vec::new(),
        }
    }

    /// Add an extra tag to the event.
    pub fn tag(mut self, tag: Tag) -> Self {
        self.extra_tags.push(tag);
        self
    }

    /// Build the unsigned event.
    ///
    /// The `id`, `pubkey`, `created_at`, and `sig` fields are left as
    /// placeholders for the caller to fill after signing.
    pub fn build(self) -> Event {
        let mut tags: Vec<Tag> = vec![
            Tag::Dialect(self.dialect_name.clone()),
            Tag::LabelNamespace(DIALECT_LABEL_NAMESPACE.to_string()),
            Tag::Label(
                self.dialect_name.clone(),
                DIALECT_LABEL_NAMESPACE.to_string(),
            ),
        ];
        tags.extend(self.extra_tags);

        let raw_tags: Vec<Vec<String>> = tags.iter().map(Tag::to_raw).collect();

        Event {
            id: String::new(),
            pubkey: String::new(),
            created_at: 0,
            kind: KIND_AGENT_DIALECT,
            tags: raw_tags,
            content: self.content,
            sig: String::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Query filters
// ---------------------------------------------------------------------------

/// Build a NIP-01 filter that discovers all CBCL dialect events.
///
/// Filters for kind 31111 with `#L = ["cbcl.dialect"]`.
pub fn dialect_filter() -> Filter {
    Filter {
        kinds: Some(vec![KIND_AGENT_DIALECT]),
        label_namespace_tags: Some(vec![DIALECT_LABEL_NAMESPACE.to_string()]),
        ..Default::default()
    }
}

/// Build a NIP-01 filter for a specific dialect by name.
///
/// Filters for kind 31111 with `#l = [name]` within the `cbcl.dialect` namespace.
pub fn dialect_filter_by_name(name: &str) -> Filter {
    Filter {
        kinds: Some(vec![KIND_AGENT_DIALECT]),
        label_namespace_tags: Some(vec![DIALECT_LABEL_NAMESPACE.to_string()]),
        label_tags: Some(vec![name.to_string()]),
        ..Default::default()
    }
}

/// Build a NIP-01 filter for dialects published by a specific author.
pub fn dialect_filter_by_author(author_pubkey: &str) -> Filter {
    Filter {
        kinds: Some(vec![KIND_AGENT_DIALECT]),
        authors: Some(vec![author_pubkey.to_string()]),
        label_namespace_tags: Some(vec![DIALECT_LABEL_NAMESPACE.to_string()]),
        ..Default::default()
    }
}

// ---------------------------------------------------------------------------
// Parse dialect from event
// ---------------------------------------------------------------------------

/// Parse a `Dialect` from an [`AgentDialect`] event.
///
/// Decodes the event content as an S-expression, then parses it using
/// `cbcl_parser::parse_dialect` (or `parse_meta_define` for `(meta ...)` forms).
/// Validates that the dialect tag matches the parsed name.
pub fn parse_dialect_event(dialect_event: &AgentDialect) -> Result<Dialect, NegotiationError> {
    // Extract the dialect name from the tag
    let tag_name = dialect_event
        .tags
        .iter()
        .find_map(|t| match t {
            Tag::Dialect(name) => Some(name.as_str()),
            _ => None,
        })
        .ok_or(NegotiationError::MissingDialectTag)?;

    // Decode the S-expression content
    let sexpr = sexpr_codec::decode(&dialect_event.event.content)?;

    // Parse the dialect (support both `(define ...)` and `(meta (define ...))` forms)
    let dialect = if is_meta_form(&sexpr) {
        cbcl_parser::parse_meta_define(&sexpr)
    } else {
        parse_dialect(&sexpr)
    }
    .map_err(NegotiationError::DialectParse)?;

    // Validate name consistency
    if dialect.name != tag_name {
        return Err(NegotiationError::NameMismatch {
            tag: tag_name.to_string(),
            parsed: dialect.name,
        });
    }

    Ok(dialect)
}

// ---------------------------------------------------------------------------
// Install dialect from event
// ---------------------------------------------------------------------------

/// Parse and install a dialect from a raw [`Event`] into a [`DialectRegistry`].
///
/// This is the main entry point for dialect negotiation: it wraps the event
/// as an [`AgentDialect`], parses the dialect definition, and installs it
/// into the registry (verifying R1–R3).
pub fn install_dialect_event(
    event: Event,
    registry: &mut DialectRegistry,
) -> Result<Dialect, NegotiationError> {
    let agent_dialect = AgentDialect::from_event(event)?;
    let dialect = parse_dialect_event(&agent_dialect)?;
    registry
        .install(dialect.clone())
        .map_err(NegotiationError::Install)?;
    Ok(dialect)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Check if the S-expression is a `(meta ...)` form.
fn is_meta_form(sexpr: &SExpr) -> bool {
    match sexpr {
        SExpr::List(items) => matches!(items.first(), Some(SExpr::Atom(Atom::Symbol(s))) if s == "meta"),
        _ => false,
    }
}

/// Serialize a `Dialect` into a `(define ...)` S-expression string.
fn serialize_dialect(dialect: &Dialect) -> String {
    let mut items: Vec<SExpr> = Vec::new();

    // (define name (extends...) author ...)
    items.push(SExpr::Atom(Atom::Symbol("define".into())));
    items.push(SExpr::Atom(Atom::Symbol(dialect.name.clone())));

    // extends list
    items.push(SExpr::List(
        dialect
            .extends
            .iter()
            .map(|e| SExpr::Atom(Atom::Symbol(e.clone())))
            .collect(),
    ));

    // author
    if let Some(ref author) = dialect.author {
        items.push(SExpr::Atom(Atom::Symbol(author.clone())));
    } else {
        items.push(SExpr::Atom(Atom::Symbol("@anonymous".into())));
    }

    // performative definitions: (extend name (params...) template)
    for perf in &dialect.performatives {
        items.push(SExpr::List(vec![
            SExpr::Atom(Atom::Symbol("extend".into())),
            SExpr::Atom(Atom::Symbol(perf.name.clone())),
            SExpr::List(perf.params.clone()),
            perf.template.clone(),
        ]));
    }

    // resource requirements
    items.push(SExpr::List(vec![
        SExpr::Atom(Atom::Keyword("resource-requirements".into())),
        SExpr::List(vec![
            SExpr::List(vec![
                SExpr::Atom(Atom::Symbol("max-depth".into())),
                SExpr::Atom(Atom::Num(dialect.resources.max_depth as i64)),
            ]),
            SExpr::List(vec![
                SExpr::Atom(Atom::Symbol("max-expansion-size".into())),
                SExpr::Atom(Atom::Num(dialect.resources.max_expansion_size as i64)),
            ]),
            SExpr::List(vec![
                SExpr::Atom(Atom::Symbol("verification-time".into())),
                SExpr::Atom(Atom::Num(dialect.resources.verification_time_ms as i64)),
            ]),
        ]),
    ]));

    // examples
    if !dialect.examples.is_empty() {
        let mut ex_clause = vec![SExpr::Atom(Atom::Keyword("examples".into()))];
        ex_clause.extend(dialect.examples.clone());
        items.push(SExpr::List(ex_clause));
    }

    // integrity fields
    if let Some(ref hash) = dialect.hash {
        items.push(SExpr::List(vec![
            SExpr::Atom(Atom::Keyword("hash".into())),
            SExpr::Atom(Atom::Str(hash.clone())),
        ]));
    }

    if let Some(ref sig) = dialect.signature {
        let sig_str = String::from_utf8_lossy(sig).into_owned();
        items.push(SExpr::List(vec![
            SExpr::Atom(Atom::Keyword("signature".into())),
            SExpr::Atom(Atom::Symbol(sig_str)),
        ]));
    }

    if let Some(ref protocol) = dialect.protocol {
        items.push(SExpr::List(vec![
            SExpr::Atom(Atom::Keyword("protocol".into())),
            SExpr::Atom(Atom::Str(protocol.clone())),
        ]));
    }

    sexpr_codec::encode(&SExpr::List(items))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use cbcl_core::dialect::{PerformativeDef, ResourceBounds};

    fn make_event(tags: Vec<Vec<String>>, content: &str) -> Event {
        Event {
            id: "a".repeat(64),
            pubkey: "b".repeat(64),
            created_at: 1700000000,
            kind: KIND_AGENT_DIALECT,
            tags,
            content: content.to_string(),
            sig: "c".repeat(128),
        }
    }

    fn sample_dialect() -> Dialect {
        Dialect {
            name: "commerce".into(),
            extends: vec!["cbcl".into()],
            author: Some("@marketplace".into()),
            performatives: vec![PerformativeDef {
                name: "negotiate".into(),
                params: vec![
                    SExpr::Atom(Atom::Symbol("price".into())),
                    SExpr::Atom(Atom::Symbol("item".into())),
                ],
                template: SExpr::List(vec![
                    SExpr::Atom(Atom::Symbol("effect".into())),
                    SExpr::Atom(Atom::Symbol("negotiate-price".into())),
                ]),
            }],
            resources: ResourceBounds {
                max_depth: 16,
                max_expansion_size: 1024,
                verification_time_ms: 50,
            },
            examples: vec![],
            signature: None,
            hash: None,
            protocol: Some("ed25519".into()),
        }
    }

    // ==== DialectBuilder ====

    #[test]
    fn builder_from_dialect_produces_correct_tags() {
        let dialect = sample_dialect();
        let event = DialectBuilder::from_dialect(&dialect).build();

        assert_eq!(event.kind, KIND_AGENT_DIALECT);
        assert_eq!(event.tags.len(), 3);
        assert_eq!(Tag::parse(&event.tags[0]), Tag::Dialect("commerce".into()));
        assert_eq!(
            Tag::parse(&event.tags[1]),
            Tag::LabelNamespace(DIALECT_LABEL_NAMESPACE.into())
        );
        assert_eq!(
            Tag::parse(&event.tags[2]),
            Tag::Label("commerce".into(), DIALECT_LABEL_NAMESPACE.into())
        );
    }

    #[test]
    fn builder_from_content_produces_correct_event() {
        let content = "(define test-dialect (cbcl) @author)";
        let event = DialectBuilder::from_content("test-dialect", content).build();

        assert_eq!(event.kind, KIND_AGENT_DIALECT);
        assert_eq!(event.content, content);
        assert_eq!(Tag::parse(&event.tags[0]), Tag::Dialect("test-dialect".into()));
    }

    #[test]
    fn builder_with_extra_tags() {
        let dialect = sample_dialect();
        let event = DialectBuilder::from_dialect(&dialect)
            .tag(Tag::Hashtag("cbcl".into()))
            .build();

        assert_eq!(event.tags.len(), 4);
        assert_eq!(Tag::parse(&event.tags[3]), Tag::Hashtag("cbcl".into()));
    }

    #[test]
    fn builder_placeholder_fields() {
        let event = DialectBuilder::from_content("x", "()").build();
        assert!(event.id.is_empty());
        assert!(event.pubkey.is_empty());
        assert_eq!(event.created_at, 0);
        assert!(event.sig.is_empty());
    }

    // ==== Serialization round-trip ====

    #[test]
    fn serialize_then_parse_round_trip() {
        let dialect = sample_dialect();
        let content = serialize_dialect(&dialect);
        let sexpr = sexpr_codec::decode(&content).unwrap();
        let parsed = parse_dialect(&sexpr).unwrap();

        assert_eq!(parsed.name, dialect.name);
        assert_eq!(parsed.extends, dialect.extends);
        assert_eq!(parsed.author, dialect.author);
        assert_eq!(parsed.performatives.len(), dialect.performatives.len());
        assert_eq!(parsed.performatives[0].name, "negotiate");
        assert_eq!(parsed.resources, dialect.resources);
        assert_eq!(parsed.protocol, dialect.protocol);
    }

    #[test]
    fn serialize_minimal_dialect() {
        let dialect = Dialect {
            name: "minimal".into(),
            extends: vec![],
            author: None,
            performatives: vec![],
            resources: ResourceBounds {
                max_depth: 8,
                max_expansion_size: 512,
                verification_time_ms: 10,
            },
            examples: vec![],
            signature: None,
            hash: None,
            protocol: None,
        };
        let content = serialize_dialect(&dialect);
        let sexpr = sexpr_codec::decode(&content).unwrap();
        let parsed = parse_dialect(&sexpr).unwrap();
        assert_eq!(parsed.name, "minimal");
        assert_eq!(parsed.author, Some("@anonymous".into()));
    }

    #[test]
    fn serialize_dialect_with_integrity() {
        let dialect = Dialect {
            name: "signed".into(),
            extends: vec!["cbcl".into()],
            author: Some("@authority".into()),
            performatives: vec![],
            resources: ResourceBounds {
                max_depth: 8,
                max_expansion_size: 512,
                verification_time_ms: 10,
            },
            examples: vec![],
            signature: Some(b"sig-bytes".to_vec()),
            hash: Some("sha256:abcd1234".into()),
            protocol: Some("ed25519".into()),
        };
        let content = serialize_dialect(&dialect);
        let sexpr = sexpr_codec::decode(&content).unwrap();
        let parsed = parse_dialect(&sexpr).unwrap();
        assert_eq!(parsed.hash, Some("sha256:abcd1234".into()));
        assert!(parsed.signature.is_some());
        assert_eq!(parsed.protocol, Some("ed25519".into()));
    }

    // ==== Query filters ====

    #[test]
    fn dialect_filter_matches_kind_and_namespace() {
        let f = dialect_filter();
        assert_eq!(f.kinds, Some(vec![KIND_AGENT_DIALECT]));
        assert_eq!(
            f.label_namespace_tags,
            Some(vec![DIALECT_LABEL_NAMESPACE.into()])
        );
        assert!(f.label_tags.is_none());
    }

    #[test]
    fn dialect_filter_by_name_includes_label() {
        let f = dialect_filter_by_name("commerce");
        assert_eq!(f.kinds, Some(vec![KIND_AGENT_DIALECT]));
        assert_eq!(f.label_tags, Some(vec!["commerce".into()]));
    }

    #[test]
    fn dialect_filter_by_author_includes_pubkey() {
        let f = dialect_filter_by_author("abcd1234");
        assert_eq!(f.authors, Some(vec!["abcd1234".into()]));
        assert_eq!(f.kinds, Some(vec![KIND_AGENT_DIALECT]));
    }

    #[test]
    fn dialect_filter_serializes_with_label_tags() {
        let f = dialect_filter_by_name("commerce");
        let json = serde_json::to_value(&f).unwrap();
        assert_eq!(json["#L"], serde_json::json!(["cbcl.dialect"]));
        assert_eq!(json["#l"], serde_json::json!(["commerce"]));
        assert_eq!(json["kinds"], serde_json::json!([31111]));
    }

    // ==== Parse dialect from event ====

    #[test]
    fn parse_dialect_event_define_form() {
        let event = make_event(
            vec![
                vec!["dialect".into(), "commerce".into()],
                vec!["L".into(), DIALECT_LABEL_NAMESPACE.into()],
                vec!["l".into(), "commerce".into(), DIALECT_LABEL_NAMESPACE.into()],
            ],
            "(define commerce (cbcl) @marketplace (extend negotiate (price item) (effect negotiate-price)) (:resource-requirements ((max-depth 16) (max-expansion-size 1024) (verification-time 50))) (:protocol \"ed25519\"))",
        );
        let agent_dialect = AgentDialect::from_event(event).unwrap();
        let dialect = parse_dialect_event(&agent_dialect).unwrap();

        assert_eq!(dialect.name, "commerce");
        assert_eq!(dialect.extends, vec!["cbcl"]);
        assert_eq!(dialect.performatives.len(), 1);
        assert_eq!(dialect.performatives[0].name, "negotiate");
    }

    #[test]
    fn parse_dialect_event_meta_form() {
        let event = make_event(
            vec![vec!["dialect".into(), "commerce".into()]],
            "(meta (define commerce (cbcl) @marketplace))",
        );
        let agent_dialect = AgentDialect::from_event(event).unwrap();
        let dialect = parse_dialect_event(&agent_dialect).unwrap();

        assert_eq!(dialect.name, "commerce");
    }

    #[test]
    fn parse_dialect_event_missing_dialect_tag() {
        let event = make_event(
            vec![vec!["L".into(), DIALECT_LABEL_NAMESPACE.into()]],
            "(define commerce (cbcl) @author)",
        );
        let agent_dialect = AgentDialect::from_event(event).unwrap();
        let err = parse_dialect_event(&agent_dialect).unwrap_err();
        assert!(matches!(err, NegotiationError::MissingDialectTag));
    }

    #[test]
    fn parse_dialect_event_name_mismatch() {
        let event = make_event(
            vec![vec!["dialect".into(), "wrong-name".into()]],
            "(define commerce (cbcl) @author)",
        );
        let agent_dialect = AgentDialect::from_event(event).unwrap();
        let err = parse_dialect_event(&agent_dialect).unwrap_err();
        assert!(matches!(err, NegotiationError::NameMismatch { .. }));
    }

    #[test]
    fn parse_dialect_event_bad_content() {
        let event = make_event(
            vec![vec!["dialect".into(), "test".into()]],
            "",
        );
        let agent_dialect = AgentDialect::from_event(event).unwrap();
        let err = parse_dialect_event(&agent_dialect).unwrap_err();
        assert!(matches!(err, NegotiationError::Codec(_)));
    }

    #[test]
    fn parse_dialect_event_invalid_sexpr() {
        let event = make_event(
            vec![vec!["dialect".into(), "test".into()]],
            "(not-define test)",
        );
        let agent_dialect = AgentDialect::from_event(event).unwrap();
        let err = parse_dialect_event(&agent_dialect).unwrap_err();
        assert!(matches!(err, NegotiationError::DialectParse(_)));
    }

    // ==== Install dialect from event ====

    #[test]
    fn install_dialect_event_success() {
        let event = make_event(
            vec![
                vec!["dialect".into(), "commerce".into()],
                vec!["L".into(), DIALECT_LABEL_NAMESPACE.into()],
                vec!["l".into(), "commerce".into(), DIALECT_LABEL_NAMESPACE.into()],
            ],
            "(define commerce (cbcl) @marketplace (extend negotiate (price item) (effect negotiate-price)) (:resource-requirements ((max-depth 16) (max-expansion-size 1024) (verification-time 50))))",
        );

        let mut registry = DialectRegistry::new();
        assert_eq!(registry.len(), 1);

        let dialect = install_dialect_event(event, &mut registry).unwrap();
        assert_eq!(dialect.name, "commerce");
        assert_eq!(registry.len(), 2);
        assert!(registry.find_by_name("commerce").is_some());
        assert!(registry.find_performative_dialect("negotiate").is_some());
    }

    #[test]
    fn install_dialect_event_wrong_kind() {
        let event = Event {
            id: "a".repeat(64),
            pubkey: "b".repeat(64),
            created_at: 1700000000,
            kind: 21111, // wrong kind
            tags: vec![vec!["dialect".into(), "test".into()]],
            content: "(define test (cbcl) @author)".into(),
            sig: "c".repeat(128),
        };

        let mut registry = DialectRegistry::new();
        let err = install_dialect_event(event, &mut registry).unwrap_err();
        assert!(matches!(err, NegotiationError::EventType(_)));
    }

    #[test]
    fn install_dialect_event_r3_violation() {
        // Dialect that redefines "tell" — should fail R3
        let event = make_event(
            vec![vec!["dialect".into(), "bad-dialect".into()]],
            "(define bad-dialect (cbcl) @author (extend tell () (effect custom-tell)) (:resource-requirements ((max-depth 8) (max-expansion-size 512) (verification-time 10))))",
        );

        let mut registry = DialectRegistry::new();
        let err = install_dialect_event(event, &mut registry).unwrap_err();
        assert!(matches!(err, NegotiationError::Install(_)));
        assert_eq!(registry.len(), 1); // unchanged
    }

    #[test]
    fn install_multiple_dialects() {
        let mut registry = DialectRegistry::new();

        let event1 = make_event(
            vec![vec!["dialect".into(), "planning".into()]],
            "(define planning (cbcl) @planner (extend propose-step (step-id action) (effect propose)) (:resource-requirements ((max-depth 16) (max-expansion-size 1024) (verification-time 50))))",
        );
        install_dialect_event(event1, &mut registry).unwrap();

        let event2 = make_event(
            vec![vec!["dialect".into(), "commerce".into()]],
            "(define commerce (cbcl) @marketplace (extend negotiate (price) (effect negotiate-price)) (:resource-requirements ((max-depth 8) (max-expansion-size 512) (verification-time 10))))",
        );
        install_dialect_event(event2, &mut registry).unwrap();

        assert_eq!(registry.len(), 3);
        assert!(registry.find_by_name("planning").is_some());
        assert!(registry.find_by_name("commerce").is_some());
    }

    // ==== End-to-end: build → parse → install ====

    #[test]
    fn end_to_end_build_then_install() {
        let dialect = sample_dialect();
        let event = DialectBuilder::from_dialect(&dialect).build();

        // Simulate relay by adding required fields
        let event = Event {
            id: "a".repeat(64),
            pubkey: "b".repeat(64),
            created_at: 1700000000,
            sig: "c".repeat(128),
            ..event
        };

        let mut registry = DialectRegistry::new();
        let installed = install_dialect_event(event, &mut registry).unwrap();

        assert_eq!(installed.name, "commerce");
        assert_eq!(installed.performatives.len(), 1);
        assert_eq!(installed.performatives[0].name, "negotiate");
        assert_eq!(registry.len(), 2);
    }

    #[test]
    fn end_to_end_build_minimal_then_install() {
        let dialect = Dialect {
            name: "simple".into(),
            extends: vec!["cbcl".into()],
            author: Some("@test".into()),
            performatives: vec![],
            resources: ResourceBounds {
                max_depth: 8,
                max_expansion_size: 512,
                verification_time_ms: 10,
            },
            examples: vec![],
            signature: None,
            hash: None,
            protocol: None,
        };

        let event = DialectBuilder::from_dialect(&dialect).build();
        let event = Event {
            id: "a".repeat(64),
            pubkey: "b".repeat(64),
            created_at: 1700000000,
            sig: "c".repeat(128),
            ..event
        };

        let mut registry = DialectRegistry::new();
        let installed = install_dialect_event(event, &mut registry).unwrap();
        assert_eq!(installed.name, "simple");
        assert_eq!(registry.len(), 2);
    }
}
