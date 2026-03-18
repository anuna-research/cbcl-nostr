//! Agent profile: publish and query kind 0 (user metadata) per NIP-01.
//!
//! Provides:
//! - [`AgentProfile`] — structured agent identity (name, about, picture).
//! - [`ProfileBuilder`] — fluent builder for kind 0 metadata events.
//! - [`profile_filter`] / [`profile_filter_by_pubkeys`] — NIP-01 subscription
//!   filters for querying agent profiles.
//! - [`parse_profile_event`] — extract an [`AgentProfile`] from a kind 0 event.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};

use crate::event_types::{Event, EventTypeError};
use crate::relay_pool::message::Filter;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Nostr event kind for user metadata (NIP-01).
pub const KIND_METADATA: u64 = 0;

// ---------------------------------------------------------------------------
// AgentProfile
// ---------------------------------------------------------------------------

/// Structured agent identity extracted from a kind 0 event.
///
/// The three core fields (`name`, `about`, `picture`) follow the NIP-01
/// metadata convention. Additional fields from the JSON content are
/// captured in `extra`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentProfile {
    /// Display name for the agent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// Short description / bio.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub about: Option<String>,

    /// URL to a profile picture.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub picture: Option<String>,

    /// Any additional metadata fields beyond name/about/picture.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

impl AgentProfile {
    /// Create an empty profile.
    pub fn new() -> Self {
        Self {
            name: None,
            about: None,
            picture: None,
            extra: serde_json::Map::new(),
        }
    }
}

impl Default for AgentProfile {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors from agent profile operations.
#[derive(Debug, thiserror::Error)]
pub enum ProfileError {
    /// The event kind is not 0.
    #[error(transparent)]
    EventType(#[from] EventTypeError),

    /// The event content is not valid JSON.
    #[error("invalid profile JSON: {0}")]
    InvalidJson(String),
}

// ---------------------------------------------------------------------------
// ProfileBuilder — construct unsigned kind 0 events
// ---------------------------------------------------------------------------

/// Builder for constructing unsigned kind 0 metadata events.
///
/// Produces an [`Event`] with:
/// - `kind = 0` (replaceable metadata)
/// - Content: JSON object with `name`, `about`, `picture`, and any extra fields.
pub struct ProfileBuilder {
    profile: AgentProfile,
}

impl ProfileBuilder {
    /// Create a new builder with the given display name.
    pub fn new(name: &str) -> Self {
        Self {
            profile: AgentProfile {
                name: Some(name.to_string()),
                about: None,
                picture: None,
                extra: serde_json::Map::new(),
            },
        }
    }

    /// Create a builder from an existing [`AgentProfile`].
    pub fn from_profile(profile: AgentProfile) -> Self {
        Self { profile }
    }

    /// Set the about / bio text.
    pub fn about(mut self, about: &str) -> Self {
        self.profile.about = Some(about.to_string());
        self
    }

    /// Set the profile picture URL.
    pub fn picture(mut self, url: &str) -> Self {
        self.profile.picture = Some(url.to_string());
        self
    }

    /// Set an arbitrary extra metadata field.
    pub fn field(mut self, key: &str, value: serde_json::Value) -> Self {
        self.profile.extra.insert(key.to_string(), value);
        self
    }

    /// Build the unsigned event.
    ///
    /// The `id`, `pubkey`, `created_at`, and `sig` fields are left as
    /// placeholders for the caller to fill after signing.
    pub fn build(self) -> Event {
        let content =
            serde_json::to_string(&self.profile).expect("AgentProfile serialization cannot fail");

        Event {
            id: String::new(),
            pubkey: String::new(),
            created_at: 0,
            kind: KIND_METADATA,
            tags: Vec::new(),
            content,
            sig: String::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Query filters
// ---------------------------------------------------------------------------

/// Build a NIP-01 filter that discovers all kind 0 metadata events.
pub fn profile_filter() -> Filter {
    Filter {
        kinds: Some(vec![KIND_METADATA]),
        ..Default::default()
    }
}

/// Build a NIP-01 filter for kind 0 metadata from specific pubkeys.
pub fn profile_filter_by_pubkeys(pubkeys: &[&str]) -> Filter {
    Filter {
        kinds: Some(vec![KIND_METADATA]),
        authors: Some(pubkeys.iter().map(|pk| pk.to_string()).collect()),
        ..Default::default()
    }
}

// ---------------------------------------------------------------------------
// Parse profile from event
// ---------------------------------------------------------------------------

/// Parse an [`AgentProfile`] from a kind 0 [`Event`].
///
/// Validates the event kind and deserializes the JSON content into an
/// [`AgentProfile`]. Unknown fields are captured in [`AgentProfile::extra`].
pub fn parse_profile_event(event: &Event) -> Result<AgentProfile, ProfileError> {
    if event.kind != KIND_METADATA {
        return Err(ProfileError::EventType(EventTypeError::WrongKind {
            expected: KIND_METADATA,
            got: event.kind,
        }));
    }

    let profile: AgentProfile = serde_json::from_str(&event.content)
        .map_err(|e| ProfileError::InvalidJson(e.to_string()))?;

    Ok(profile)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_event(kind: u64, content: &str) -> Event {
        Event {
            id: "a".repeat(64),
            pubkey: "b".repeat(64),
            created_at: 1700000000,
            kind,
            tags: vec![],
            content: content.to_string(),
            sig: "c".repeat(128),
        }
    }

    // ==== AgentProfile ====

    #[test]
    fn profile_new_is_empty() {
        let p = AgentProfile::new();
        assert_eq!(p.name, None);
        assert_eq!(p.about, None);
        assert_eq!(p.picture, None);
        assert!(p.extra.is_empty());
    }

    #[test]
    fn profile_default_is_empty() {
        let p = AgentProfile::default();
        assert_eq!(p, AgentProfile::new());
    }

    #[test]
    fn profile_serde_round_trip() {
        let p = AgentProfile {
            name: Some("agent-007".into()),
            about: Some("A helpful agent".into()),
            picture: Some("https://example.com/pic.png".into()),
            extra: serde_json::Map::new(),
        };
        let json = serde_json::to_string(&p).unwrap();
        let back: AgentProfile = serde_json::from_str(&json).unwrap();
        assert_eq!(p, back);
    }

    #[test]
    fn profile_serde_with_extra_fields() {
        let mut extra = serde_json::Map::new();
        extra.insert("nip05".into(), serde_json::json!("agent@example.com"));
        extra.insert("lud16".into(), serde_json::json!("agent@ln.example.com"));

        let p = AgentProfile {
            name: Some("agent".into()),
            about: None,
            picture: None,
            extra,
        };
        let json = serde_json::to_string(&p).unwrap();
        let back: AgentProfile = serde_json::from_str(&json).unwrap();
        assert_eq!(p, back);

        // Verify extra fields appear at top level in JSON
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["nip05"], "agent@example.com");
        assert_eq!(v["lud16"], "agent@ln.example.com");
    }

    #[test]
    fn profile_serde_skips_none_fields() {
        let p = AgentProfile {
            name: Some("agent".into()),
            about: None,
            picture: None,
            extra: serde_json::Map::new(),
        };
        let json = serde_json::to_string(&p).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(v.get("about").is_none());
        assert!(v.get("picture").is_none());
    }

    #[test]
    fn profile_deserialize_unknown_fields() {
        let json = r#"{"name":"bot","display_name":"Bot 3000","website":"https://bot.ai"}"#;
        let p: AgentProfile = serde_json::from_str(json).unwrap();
        assert_eq!(p.name, Some("bot".into()));
        assert_eq!(p.extra["display_name"], "Bot 3000");
        assert_eq!(p.extra["website"], "https://bot.ai");
    }

    // ==== ProfileBuilder ====

    #[test]
    fn builder_minimal() {
        let event = ProfileBuilder::new("agent-007").build();

        assert_eq!(event.kind, KIND_METADATA);
        assert!(event.tags.is_empty());

        let profile: AgentProfile = serde_json::from_str(&event.content).unwrap();
        assert_eq!(profile.name, Some("agent-007".into()));
        assert_eq!(profile.about, None);
        assert_eq!(profile.picture, None);
    }

    #[test]
    fn builder_full() {
        let event = ProfileBuilder::new("agent-007")
            .about("CBCL commerce agent")
            .picture("https://example.com/agent.png")
            .field("nip05", serde_json::json!("agent@example.com"))
            .build();

        assert_eq!(event.kind, KIND_METADATA);

        let profile: AgentProfile = serde_json::from_str(&event.content).unwrap();
        assert_eq!(profile.name, Some("agent-007".into()));
        assert_eq!(profile.about, Some("CBCL commerce agent".into()));
        assert_eq!(
            profile.picture,
            Some("https://example.com/agent.png".into())
        );
        assert_eq!(profile.extra["nip05"], "agent@example.com");
    }

    #[test]
    fn builder_from_profile() {
        let profile = AgentProfile {
            name: Some("existing".into()),
            about: Some("bio".into()),
            picture: None,
            extra: serde_json::Map::new(),
        };
        let event = ProfileBuilder::from_profile(profile.clone()).build();

        let parsed: AgentProfile = serde_json::from_str(&event.content).unwrap();
        assert_eq!(parsed.name, profile.name);
        assert_eq!(parsed.about, profile.about);
    }

    #[test]
    fn builder_placeholder_fields() {
        let event = ProfileBuilder::new("x").build();
        assert!(event.id.is_empty());
        assert!(event.pubkey.is_empty());
        assert_eq!(event.created_at, 0);
        assert!(event.sig.is_empty());
    }

    // ==== Query filters ====

    #[test]
    fn profile_filter_matches_kind_0() {
        let f = profile_filter();
        assert_eq!(f.kinds, Some(vec![KIND_METADATA]));
        assert!(f.authors.is_none());
    }

    #[test]
    fn profile_filter_by_pubkeys_includes_authors() {
        let f = profile_filter_by_pubkeys(&["abc123", "def456"]);
        assert_eq!(f.kinds, Some(vec![KIND_METADATA]));
        assert_eq!(
            f.authors,
            Some(vec!["abc123".into(), "def456".into()])
        );
    }

    #[test]
    fn profile_filter_serializes_correctly() {
        let f = profile_filter_by_pubkeys(&["abc123"]);
        let json = serde_json::to_value(&f).unwrap();
        assert_eq!(json["kinds"], serde_json::json!([0]));
        assert_eq!(json["authors"], serde_json::json!(["abc123"]));
    }

    // ==== Parse profile from event ====

    #[test]
    fn parse_profile_event_ok() {
        let event = make_event(
            KIND_METADATA,
            r#"{"name":"agent-007","about":"A helpful agent","picture":"https://example.com/pic.png"}"#,
        );
        let profile = parse_profile_event(&event).unwrap();
        assert_eq!(profile.name, Some("agent-007".into()));
        assert_eq!(profile.about, Some("A helpful agent".into()));
        assert_eq!(
            profile.picture,
            Some("https://example.com/pic.png".into())
        );
    }

    #[test]
    fn parse_profile_event_minimal() {
        let event = make_event(KIND_METADATA, r#"{"name":"bot"}"#);
        let profile = parse_profile_event(&event).unwrap();
        assert_eq!(profile.name, Some("bot".into()));
        assert_eq!(profile.about, None);
        assert_eq!(profile.picture, None);
    }

    #[test]
    fn parse_profile_event_empty_object() {
        let event = make_event(KIND_METADATA, "{}");
        let profile = parse_profile_event(&event).unwrap();
        assert_eq!(profile.name, None);
        assert_eq!(profile.about, None);
        assert_eq!(profile.picture, None);
    }

    #[test]
    fn parse_profile_event_with_extra_fields() {
        let event = make_event(
            KIND_METADATA,
            r#"{"name":"agent","nip05":"agent@example.com","lud16":"agent@ln.example.com"}"#,
        );
        let profile = parse_profile_event(&event).unwrap();
        assert_eq!(profile.name, Some("agent".into()));
        assert_eq!(profile.extra["nip05"], "agent@example.com");
        assert_eq!(profile.extra["lud16"], "agent@ln.example.com");
    }

    #[test]
    fn parse_profile_event_wrong_kind() {
        let event = make_event(21111, r#"{"name":"agent"}"#);
        let err = parse_profile_event(&event).unwrap_err();
        assert!(matches!(err, ProfileError::EventType(_)));
    }

    #[test]
    fn parse_profile_event_invalid_json() {
        let event = make_event(KIND_METADATA, "not json");
        let err = parse_profile_event(&event).unwrap_err();
        assert!(matches!(err, ProfileError::InvalidJson(_)));
    }

    #[test]
    fn parse_profile_event_empty_content() {
        let event = make_event(KIND_METADATA, "");
        let err = parse_profile_event(&event).unwrap_err();
        assert!(matches!(err, ProfileError::InvalidJson(_)));
    }

    // ==== End-to-end: build → parse ====

    #[test]
    fn end_to_end_build_then_parse() {
        let event = ProfileBuilder::new("agent-007")
            .about("CBCL commerce agent")
            .picture("https://example.com/agent.png")
            .field("nip05", serde_json::json!("agent@example.com"))
            .build();

        // Simulate relay by adding required fields
        let event = Event {
            id: "a".repeat(64),
            pubkey: "b".repeat(64),
            created_at: 1700000000,
            sig: "c".repeat(128),
            ..event
        };

        let profile = parse_profile_event(&event).unwrap();
        assert_eq!(profile.name, Some("agent-007".into()));
        assert_eq!(profile.about, Some("CBCL commerce agent".into()));
        assert_eq!(
            profile.picture,
            Some("https://example.com/agent.png".into())
        );
        assert_eq!(profile.extra["nip05"], "agent@example.com");
    }

    #[test]
    fn end_to_end_update_profile() {
        // Build initial profile
        let event1 = ProfileBuilder::new("agent-v1").build();
        let event1 = Event {
            id: "a".repeat(64),
            pubkey: "b".repeat(64),
            created_at: 1700000000,
            sig: "c".repeat(128),
            ..event1
        };
        let profile1 = parse_profile_event(&event1).unwrap();
        assert_eq!(profile1.name, Some("agent-v1".into()));

        // Build updated profile (kind 0 is replaceable — latest wins)
        let event2 = ProfileBuilder::new("agent-v2")
            .about("Updated bio")
            .build();
        let event2 = Event {
            id: "d".repeat(64),
            pubkey: "b".repeat(64),
            created_at: 1700000001,
            sig: "e".repeat(128),
            ..event2
        };
        let profile2 = parse_profile_event(&event2).unwrap();
        assert_eq!(profile2.name, Some("agent-v2".into()));
        assert_eq!(profile2.about, Some("Updated bio".into()));
    }
}
