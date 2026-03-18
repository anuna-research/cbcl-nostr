//! Agent discovery via hello/bye broadcast protocol.
//!
//! Agents announce their presence by publishing `hello` events carrying
//! capabilities and agent-type metadata. They depart gracefully with `bye`
//! events. A local [`AgentRegistry`] tracks discovered agents with
//! last-seen timestamps and capability lists.
//!
//! # Protocol
//!
//! - **hello** — broadcast kind 21111 with `["performative","hello"]`,
//!   `["agent-type", <type>]`, and zero or more `["capability", <cap>]` tags.
//!   The content S-expression is `(hello)`.
//! - **bye** — broadcast kind 21111 with `["performative","bye"]`.
//!   The content S-expression is `(bye)`.
//!
//! # Subscription
//!
//! Use [`hello_filter`] to build a NIP-01 filter that matches incoming
//! hello/bye events. Feed matched events to [`AgentRegistry::process_event`]
//! to maintain the directory.

#![forbid(unsafe_code)]

use std::collections::HashMap;

use crate::event_types::{Event, Tag, KIND_AGENT_MESSAGE};
use crate::message_builder::MessageBuilder;
use crate::relay_pool::message::Filter;

// ---------------------------------------------------------------------------
// Tag constants
// ---------------------------------------------------------------------------

/// Tag key for the agent type.
const TAG_AGENT_TYPE: &str = "agent-type";

/// Tag key for a capability entry.
const TAG_CAPABILITY: &str = "capability";

// ---------------------------------------------------------------------------
// Hello builder
// ---------------------------------------------------------------------------

/// Build an unsigned `hello` broadcast event announcing agent presence.
///
/// The event is kind 21111 with:
/// - `["performative", "hello"]`
/// - `["agent-type", <agent_type>]`
/// - `["capability", <cap>]` for each capability
///
/// # Errors
///
/// Returns the underlying [`MessageBuilder`] error (should not happen for
/// valid inputs since `hello` is a broadcast performative).
pub fn build_hello(
    agent_type: &str,
    capabilities: &[&str],
) -> Result<Event, crate::message_builder::BuilderError> {
    let mut builder = MessageBuilder::new("hello");

    builder = builder.tag(Tag::Unknown(vec![
        TAG_AGENT_TYPE.into(),
        agent_type.into(),
    ]));

    for cap in capabilities {
        builder = builder.tag(Tag::Unknown(vec![
            TAG_CAPABILITY.into(),
            (*cap).into(),
        ]));
    }

    builder.build()
}

/// Build an unsigned `bye` broadcast event for graceful departure.
///
/// The event is kind 21111 with `["performative", "bye"]`.
pub fn build_bye() -> Result<Event, crate::message_builder::BuilderError> {
    MessageBuilder::new("bye").build()
}

// ---------------------------------------------------------------------------
// Subscription filter
// ---------------------------------------------------------------------------

/// Build a NIP-01 filter that matches hello and bye agent broadcasts.
///
/// This subscribes to kind 21111 events where the `#performative` tag
/// is one of `["hello", "bye"]`. We use the `#t` filter as a proxy for
/// the performative tag by also adding a `["t", "hello"]` / `["t", "bye"]`
/// hashtag to discovery events, since NIP-01 filters don't natively support
/// arbitrary tag names.
///
/// Alternatively, callers can filter client-side after subscribing to all
/// kind 21111 events. This helper returns a broad filter for kind 21111.
pub fn discovery_filter() -> Filter {
    Filter {
        kinds: Some(vec![KIND_AGENT_MESSAGE]),
        ..Default::default()
    }
}

// ---------------------------------------------------------------------------
// Agent registry
// ---------------------------------------------------------------------------

/// Errors from agent registry operations.
#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    /// The event kind is not a kind 21111 agent message.
    #[error("not an agent message: kind {0}")]
    WrongKind(u64),

    /// No performative tag found on the event.
    #[error("missing performative tag")]
    MissingPerformative,

    /// The performative is not hello or bye.
    #[error("not a discovery event: performative \"{0}\"")]
    NotDiscovery(String),
}

/// A discovered agent's entry in the registry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentEntry {
    /// The agent's public key (hex).
    pub pubkey: String,
    /// The agent type declared in the hello event.
    pub agent_type: String,
    /// Capabilities declared in the hello event.
    pub capabilities: Vec<String>,
    /// Unix timestamp (seconds) of the last hello event seen from this agent.
    pub last_seen: u64,
}

/// In-memory registry of discovered agents.
///
/// Feed hello/bye events via [`process_event`](Self::process_event) to
/// maintain the directory. Agents that send `bye` are removed.
#[derive(Debug, Clone, Default)]
pub struct AgentRegistry {
    agents: HashMap<String, AgentEntry>,
}

impl AgentRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Process a kind 21111 event and update the registry.
    ///
    /// - **hello**: inserts or updates the agent entry with capabilities and
    ///   last-seen timestamp.
    /// - **bye**: removes the agent from the registry.
    ///
    /// Returns the performative that was processed (`"hello"` or `"bye"`).
    pub fn process_event(&mut self, event: &Event) -> Result<String, RegistryError> {
        if event.kind != KIND_AGENT_MESSAGE {
            return Err(RegistryError::WrongKind(event.kind));
        }

        let tags: Vec<Tag> = event.tags.iter().map(|t| Tag::parse(t)).collect();

        let performative = tags
            .iter()
            .find_map(|t| match t {
                Tag::Performative(v) => Some(v.as_str()),
                _ => None,
            })
            .ok_or(RegistryError::MissingPerformative)?;

        match performative {
            "hello" => {
                let agent_type = extract_tag_value(&event.tags, TAG_AGENT_TYPE)
                    .unwrap_or_default();
                let capabilities = extract_all_tag_values(&event.tags, TAG_CAPABILITY);

                self.agents.insert(
                    event.pubkey.clone(),
                    AgentEntry {
                        pubkey: event.pubkey.clone(),
                        agent_type,
                        capabilities,
                        last_seen: event.created_at,
                    },
                );

                Ok("hello".into())
            }
            "bye" => {
                self.agents.remove(&event.pubkey);
                Ok("bye".into())
            }
            other => Err(RegistryError::NotDiscovery(other.into())),
        }
    }

    /// Get an agent entry by public key.
    pub fn get(&self, pubkey: &str) -> Option<&AgentEntry> {
        self.agents.get(pubkey)
    }

    /// Iterate over all known agents.
    pub fn agents(&self) -> impl Iterator<Item = &AgentEntry> {
        self.agents.values()
    }

    /// Number of agents currently in the registry.
    pub fn len(&self) -> usize {
        self.agents.len()
    }

    /// Returns `true` if the registry has no agents.
    pub fn is_empty(&self) -> bool {
        self.agents.is_empty()
    }

    /// Remove agents whose `last_seen` timestamp is older than `cutoff`.
    ///
    /// Returns the number of agents evicted.
    pub fn evict_stale(&mut self, cutoff: u64) -> usize {
        let before = self.agents.len();
        self.agents.retain(|_, entry| entry.last_seen >= cutoff);
        before - self.agents.len()
    }

    /// Remove an agent by public key. Returns the entry if it existed.
    pub fn remove(&mut self, pubkey: &str) -> Option<AgentEntry> {
        self.agents.remove(pubkey)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Extract the first value for a raw tag key.
fn extract_tag_value(tags: &[Vec<String>], key: &str) -> Option<String> {
    tags.iter()
        .find(|t| t.first().map(String::as_str) == Some(key) && t.len() >= 2)
        .map(|t| t[1].clone())
}

/// Extract all values for a raw tag key.
fn extract_all_tag_values(tags: &[Vec<String>], key: &str) -> Vec<String> {
    tags.iter()
        .filter(|t| t.first().map(String::as_str) == Some(key) && t.len() >= 2)
        .map(|t| t[1].clone())
        .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_event(pubkey: &str, created_at: u64, tags: Vec<Vec<String>>, content: &str) -> Event {
        Event {
            id: "a".repeat(64),
            pubkey: pubkey.into(),
            created_at,
            kind: KIND_AGENT_MESSAGE,
            tags,
            content: content.into(),
            sig: "c".repeat(128),
        }
    }

    fn hello_tags(agent_type: &str, caps: &[&str]) -> Vec<Vec<String>> {
        let mut tags = vec![
            vec!["performative".into(), "hello".into()],
            vec!["agent-type".into(), agent_type.into()],
        ];
        for cap in caps {
            tags.push(vec!["capability".into(), (*cap).into()]);
        }
        tags
    }

    fn bye_tags() -> Vec<Vec<String>> {
        vec![vec!["performative".into(), "bye".into()]]
    }

    // === build_hello ===

    #[test]
    fn build_hello_event() {
        let event = build_hello("assistant", &["chat", "search"]).unwrap();
        assert_eq!(event.kind, KIND_AGENT_MESSAGE);
        assert_eq!(event.content, "(hello)");

        let tags: Vec<Tag> = event.tags.iter().map(|t| Tag::parse(t)).collect();
        assert!(matches!(&tags[0], Tag::Performative(v) if v == "hello"));

        // agent-type and capability are Unknown tags
        assert_eq!(event.tags[1], vec!["agent-type", "assistant"]);
        assert_eq!(event.tags[2], vec!["capability", "chat"]);
        assert_eq!(event.tags[3], vec!["capability", "search"]);
    }

    #[test]
    fn build_hello_no_capabilities() {
        let event = build_hello("monitor", &[]).unwrap();
        // performative + agent-type, no capability tags
        assert_eq!(event.tags.len(), 2);
    }

    // === build_bye ===

    #[test]
    fn build_bye_event() {
        let event = build_bye().unwrap();
        assert_eq!(event.kind, KIND_AGENT_MESSAGE);
        assert_eq!(event.content, "(bye)");
        assert_eq!(event.tags.len(), 1);
        assert_eq!(
            Tag::parse(&event.tags[0]),
            Tag::Performative("bye".into())
        );
    }

    // === discovery_filter ===

    #[test]
    fn filter_matches_agent_messages() {
        let f = discovery_filter();
        assert_eq!(f.kinds, Some(vec![KIND_AGENT_MESSAGE]));
    }

    // === AgentRegistry process hello ===

    #[test]
    fn registry_hello_adds_agent() {
        let mut reg = AgentRegistry::new();
        let event = make_event(
            "pubkey_alice",
            1000,
            hello_tags("assistant", &["chat", "search"]),
            "(hello)",
        );

        let result = reg.process_event(&event).unwrap();
        assert_eq!(result, "hello");
        assert_eq!(reg.len(), 1);

        let entry = reg.get("pubkey_alice").unwrap();
        assert_eq!(entry.agent_type, "assistant");
        assert_eq!(entry.capabilities, vec!["chat", "search"]);
        assert_eq!(entry.last_seen, 1000);
    }

    #[test]
    fn registry_hello_updates_existing() {
        let mut reg = AgentRegistry::new();

        let event1 = make_event(
            "pubkey_alice",
            1000,
            hello_tags("assistant", &["chat"]),
            "(hello)",
        );
        reg.process_event(&event1).unwrap();

        let event2 = make_event(
            "pubkey_alice",
            2000,
            hello_tags("assistant", &["chat", "code"]),
            "(hello)",
        );
        reg.process_event(&event2).unwrap();

        assert_eq!(reg.len(), 1);
        let entry = reg.get("pubkey_alice").unwrap();
        assert_eq!(entry.capabilities, vec!["chat", "code"]);
        assert_eq!(entry.last_seen, 2000);
    }

    #[test]
    fn registry_multiple_agents() {
        let mut reg = AgentRegistry::new();

        reg.process_event(&make_event(
            "alice",
            1000,
            hello_tags("assistant", &["chat"]),
            "(hello)",
        ))
        .unwrap();

        reg.process_event(&make_event(
            "bob",
            1001,
            hello_tags("tool", &["compute"]),
            "(hello)",
        ))
        .unwrap();

        assert_eq!(reg.len(), 2);
        assert_eq!(reg.get("alice").unwrap().agent_type, "assistant");
        assert_eq!(reg.get("bob").unwrap().agent_type, "tool");
    }

    // === AgentRegistry process bye ===

    #[test]
    fn registry_bye_removes_agent() {
        let mut reg = AgentRegistry::new();

        reg.process_event(&make_event(
            "alice",
            1000,
            hello_tags("assistant", &["chat"]),
            "(hello)",
        ))
        .unwrap();
        assert_eq!(reg.len(), 1);

        let result = reg
            .process_event(&make_event("alice", 2000, bye_tags(), "(bye)"))
            .unwrap();
        assert_eq!(result, "bye");
        assert_eq!(reg.len(), 0);
        assert!(reg.get("alice").is_none());
    }

    #[test]
    fn registry_bye_unknown_agent_is_noop() {
        let mut reg = AgentRegistry::new();
        let result = reg
            .process_event(&make_event("unknown", 1000, bye_tags(), "(bye)"))
            .unwrap();
        assert_eq!(result, "bye");
        assert!(reg.is_empty());
    }

    // === AgentRegistry errors ===

    #[test]
    fn registry_wrong_kind() {
        let mut reg = AgentRegistry::new();
        let event = Event {
            kind: 1,
            ..make_event("alice", 1000, hello_tags("assistant", &[]), "(hello)")
        };
        let err = reg.process_event(&event).unwrap_err();
        assert!(matches!(err, RegistryError::WrongKind(1)));
    }

    #[test]
    fn registry_missing_performative() {
        let mut reg = AgentRegistry::new();
        let event = make_event("alice", 1000, vec![], "(hello)");
        let err = reg.process_event(&event).unwrap_err();
        assert!(matches!(err, RegistryError::MissingPerformative));
    }

    #[test]
    fn registry_non_discovery_performative() {
        let mut reg = AgentRegistry::new();
        let event = make_event(
            "alice",
            1000,
            vec![vec!["performative".into(), "tell".into()]],
            "(tell)",
        );
        let err = reg.process_event(&event).unwrap_err();
        assert!(matches!(err, RegistryError::NotDiscovery(_)));
    }

    // === evict_stale ===

    #[test]
    fn evict_stale_removes_old_agents() {
        let mut reg = AgentRegistry::new();

        reg.process_event(&make_event(
            "old",
            100,
            hello_tags("assistant", &[]),
            "(hello)",
        ))
        .unwrap();
        reg.process_event(&make_event(
            "new",
            500,
            hello_tags("assistant", &[]),
            "(hello)",
        ))
        .unwrap();

        let evicted = reg.evict_stale(300);
        assert_eq!(evicted, 1);
        assert_eq!(reg.len(), 1);
        assert!(reg.get("old").is_none());
        assert!(reg.get("new").is_some());
    }

    #[test]
    fn evict_stale_none_removed() {
        let mut reg = AgentRegistry::new();
        reg.process_event(&make_event(
            "alice",
            500,
            hello_tags("assistant", &[]),
            "(hello)",
        ))
        .unwrap();
        assert_eq!(reg.evict_stale(100), 0);
        assert_eq!(reg.len(), 1);
    }

    // === remove ===

    #[test]
    fn remove_returns_entry() {
        let mut reg = AgentRegistry::new();
        reg.process_event(&make_event(
            "alice",
            1000,
            hello_tags("assistant", &["chat"]),
            "(hello)",
        ))
        .unwrap();

        let entry = reg.remove("alice").unwrap();
        assert_eq!(entry.agent_type, "assistant");
        assert!(reg.is_empty());
    }

    #[test]
    fn remove_missing_returns_none() {
        let mut reg = AgentRegistry::new();
        assert!(reg.remove("nonexistent").is_none());
    }

    // === agents iterator ===

    #[test]
    fn agents_iterator() {
        let mut reg = AgentRegistry::new();
        reg.process_event(&make_event(
            "alice",
            1000,
            hello_tags("assistant", &["chat"]),
            "(hello)",
        ))
        .unwrap();
        reg.process_event(&make_event(
            "bob",
            1001,
            hello_tags("tool", &["compute"]),
            "(hello)",
        ))
        .unwrap();

        let mut pubkeys: Vec<&str> = reg.agents().map(|a| a.pubkey.as_str()).collect();
        pubkeys.sort();
        assert_eq!(pubkeys, vec!["alice", "bob"]);
    }

    // === hello with no agent-type ===

    #[test]
    fn hello_without_agent_type_defaults_empty() {
        let mut reg = AgentRegistry::new();
        let event = make_event(
            "alice",
            1000,
            vec![vec!["performative".into(), "hello".into()]],
            "(hello)",
        );
        reg.process_event(&event).unwrap();
        let entry = reg.get("alice").unwrap();
        assert_eq!(entry.agent_type, "");
        assert!(entry.capabilities.is_empty());
    }
}
