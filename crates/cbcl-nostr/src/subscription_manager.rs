//! Subscription manager for agent communication patterns.
//!
//! Maps high-level agent communication needs to NIP-01 REQ subscriptions
//! with proper filter patterns and EOSE handling. Manages the lifecycle of
//! five core subscription types:
//!
//! - **Inbox** — kind 21111 messages addressed to our pubkey (`#p` filter).
//! - **Dialect listener** — kind 31111 dialect definitions (`#L` = `cbcl.dialect`).
//! - **Bounty board** — kind 21111 broadcast messages tagged `#t = bounty`.
//! - **Agent discovery** — kind 0 metadata events for known agent pubkeys.
//! - **Dialect registry** — kind 31111 dialects from specific authors.
//!
//! Each subscription tracks its EOSE state, distinguishing the initial
//! historical sync phase from real-time streaming.

#![forbid(unsafe_code)]

use std::collections::HashMap;

use crate::agent_profile::{profile_filter, profile_filter_by_pubkeys};
#[cfg(test)]
use crate::agent_profile::KIND_METADATA;
use crate::dialect_negotiation::{dialect_filter, DIALECT_LABEL_NAMESPACE};
use crate::event_types::{KIND_AGENT_DIALECT, KIND_AGENT_MESSAGE};
use crate::relay_pool::message::{Filter, SubscriptionId};

// ---------------------------------------------------------------------------
// Subscription kind
// ---------------------------------------------------------------------------

/// The purpose of a managed subscription.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SubscriptionKind {
    /// Kind 21111 messages where our pubkey appears in a `#p` tag.
    Inbox,
    /// Kind 31111 dialect definitions in the `cbcl.dialect` namespace.
    DialectListener,
    /// Kind 21111 broadcast messages tagged `#t = bounty`.
    BountyBoard,
    /// Kind 0 metadata for a set of agent pubkeys.
    AgentDiscovery,
    /// Kind 31111 dialects published by specific authors.
    DialectRegistry,
}

impl std::fmt::Display for SubscriptionKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Inbox => write!(f, "inbox"),
            Self::DialectListener => write!(f, "dialect-listener"),
            Self::BountyBoard => write!(f, "bounty-board"),
            Self::AgentDiscovery => write!(f, "agent-discovery"),
            Self::DialectRegistry => write!(f, "dialect-registry"),
        }
    }
}

// ---------------------------------------------------------------------------
// EOSE state
// ---------------------------------------------------------------------------

/// Tracks whether a subscription has received its EOSE marker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncState {
    /// Still receiving stored/historical events from the relay.
    Syncing,
    /// EOSE received — now in real-time streaming mode.
    Live,
}

// ---------------------------------------------------------------------------
// Managed subscription
// ---------------------------------------------------------------------------

/// A subscription managed by the [`SubscriptionManager`].
#[derive(Debug, Clone)]
pub struct ManagedSubscription {
    /// The NIP-01 subscription ID sent to relays.
    pub sub_id: SubscriptionId,
    /// What this subscription is for.
    pub kind: SubscriptionKind,
    /// The filters sent with the REQ.
    pub filters: Vec<Filter>,
    /// Current sync state (syncing vs live).
    pub sync_state: SyncState,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors from subscription manager operations.
#[derive(Debug, thiserror::Error)]
pub enum SubscriptionError {
    /// A subscription of this kind already exists.
    #[error("subscription already active: {0}")]
    AlreadyActive(SubscriptionKind),

    /// No subscription of this kind is active.
    #[error("subscription not active: {0}")]
    NotActive(SubscriptionKind),

    /// The inbox subscription requires a pubkey.
    #[error("missing own pubkey for inbox subscription")]
    MissingPubkey,

    /// Agent discovery requires at least one pubkey.
    #[error("agent discovery requires at least one pubkey")]
    EmptyPubkeys,
}

// ---------------------------------------------------------------------------
// Subscription manager
// ---------------------------------------------------------------------------

/// Manages Nostr REQ subscriptions for agent communication patterns.
///
/// Tracks active subscriptions, their filters, and EOSE sync state. The
/// manager produces `(SubscriptionId, Vec<Filter>)` pairs that callers
/// send to the relay pool — it does not hold a reference to the pool
/// itself, keeping the layers decoupled.
///
/// # Example
///
/// ```
/// use cbcl_nostr::subscription_manager::{SubscriptionManager, SubscriptionKind};
///
/// let mut mgr = SubscriptionManager::new();
///
/// // Open inbox subscription for our pubkey
/// let (sub_id, filters) = mgr.open_inbox("aabbccdd").unwrap();
/// // Caller sends REQ(sub_id, filters) to relay pool
///
/// // Later, when EOSE arrives for this subscription:
/// mgr.mark_live(&sub_id);
/// ```
pub struct SubscriptionManager {
    /// Active subscriptions keyed by their kind.
    subscriptions: HashMap<SubscriptionKind, ManagedSubscription>,
    /// Reverse lookup: subscription ID → kind.
    id_to_kind: HashMap<String, SubscriptionKind>,
}

impl SubscriptionManager {
    /// Create a new, empty subscription manager.
    pub fn new() -> Self {
        Self {
            subscriptions: HashMap::new(),
            id_to_kind: HashMap::new(),
        }
    }

    /// Open an inbox subscription for kind 21111 messages addressed to `pubkey`.
    ///
    /// Returns the subscription ID and filters to send as a REQ to relays.
    pub fn open_inbox(
        &mut self,
        pubkey: &str,
    ) -> Result<(SubscriptionId, Vec<Filter>), SubscriptionError> {
        if pubkey.is_empty() {
            return Err(SubscriptionError::MissingPubkey);
        }
        self.ensure_not_active(SubscriptionKind::Inbox)?;

        let filters = vec![Filter {
            kinds: Some(vec![KIND_AGENT_MESSAGE]),
            p_tags: Some(vec![pubkey.to_string()]),
            ..Default::default()
        }];

        Ok(self.register(SubscriptionKind::Inbox, filters))
    }

    /// Open a dialect listener subscription for all kind 31111 dialect events.
    ///
    /// Uses the `cbcl.dialect` NIP-32 label namespace.
    pub fn open_dialect_listener(
        &mut self,
    ) -> Result<(SubscriptionId, Vec<Filter>), SubscriptionError> {
        self.ensure_not_active(SubscriptionKind::DialectListener)?;

        let filters = vec![dialect_filter()];

        Ok(self.register(SubscriptionKind::DialectListener, filters))
    }

    /// Open a bounty board subscription for broadcast `#t = bounty` messages.
    pub fn open_bounty_board(
        &mut self,
    ) -> Result<(SubscriptionId, Vec<Filter>), SubscriptionError> {
        self.ensure_not_active(SubscriptionKind::BountyBoard)?;

        let filters = vec![Filter {
            kinds: Some(vec![KIND_AGENT_MESSAGE]),
            t_tags: Some(vec!["bounty".to_string()]),
            ..Default::default()
        }];

        Ok(self.register(SubscriptionKind::BountyBoard, filters))
    }

    /// Open an agent discovery subscription for kind 0 metadata events.
    ///
    /// If `pubkeys` is empty, subscribes to all kind 0 events.
    /// If `pubkeys` is non-empty, filters by those specific authors.
    pub fn open_agent_discovery(
        &mut self,
        pubkeys: &[&str],
    ) -> Result<(SubscriptionId, Vec<Filter>), SubscriptionError> {
        self.ensure_not_active(SubscriptionKind::AgentDiscovery)?;

        let filters = if pubkeys.is_empty() {
            vec![profile_filter()]
        } else {
            vec![profile_filter_by_pubkeys(pubkeys)]
        };

        Ok(self.register(SubscriptionKind::AgentDiscovery, filters))
    }

    /// Open a dialect registry subscription for kind 31111 events from
    /// specific authors.
    ///
    /// Requires at least one author pubkey.
    pub fn open_dialect_registry(
        &mut self,
        author_pubkeys: &[&str],
    ) -> Result<(SubscriptionId, Vec<Filter>), SubscriptionError> {
        if author_pubkeys.is_empty() {
            return Err(SubscriptionError::EmptyPubkeys);
        }
        self.ensure_not_active(SubscriptionKind::DialectRegistry)?;

        // Combine all author pubkeys into a single filter.
        let filters = vec![Filter {
            kinds: Some(vec![KIND_AGENT_DIALECT]),
            authors: Some(author_pubkeys.iter().map(|pk| pk.to_string()).collect()),
            label_namespace_tags: Some(vec![DIALECT_LABEL_NAMESPACE.to_string()]),
            ..Default::default()
        }];

        Ok(self.register(SubscriptionKind::DialectRegistry, filters))
    }

    /// Close a subscription by kind.
    ///
    /// Returns the subscription ID so the caller can send CLOSE to relays.
    pub fn close(&mut self, kind: SubscriptionKind) -> Result<SubscriptionId, SubscriptionError> {
        match self.subscriptions.remove(&kind) {
            Some(sub) => {
                self.id_to_kind.remove(&sub.sub_id.0);
                Ok(sub.sub_id)
            }
            None => Err(SubscriptionError::NotActive(kind)),
        }
    }

    /// Close all active subscriptions.
    ///
    /// Returns the subscription IDs so the caller can send CLOSE to relays.
    pub fn close_all(&mut self) -> Vec<SubscriptionId> {
        let ids: Vec<SubscriptionId> = self
            .subscriptions
            .drain()
            .map(|(_, sub)| sub.sub_id)
            .collect();
        self.id_to_kind.clear();
        ids
    }

    /// Mark a subscription as live (EOSE received).
    ///
    /// Returns `true` if the subscription was found and transitioned from
    /// `Syncing` to `Live`. Returns `false` if already live or not found.
    pub fn mark_live(&mut self, sub_id: &SubscriptionId) -> bool {
        if let Some(kind) = self.id_to_kind.get(&sub_id.0) {
            if let Some(sub) = self.subscriptions.get_mut(kind) {
                if sub.sync_state == SyncState::Syncing {
                    sub.sync_state = SyncState::Live;
                    return true;
                }
            }
        }
        false
    }

    /// Look up the kind of subscription for a given subscription ID.
    pub fn kind_of(&self, sub_id: &SubscriptionId) -> Option<SubscriptionKind> {
        self.id_to_kind.get(&sub_id.0).copied()
    }

    /// Get a managed subscription by kind.
    pub fn get(&self, kind: SubscriptionKind) -> Option<&ManagedSubscription> {
        self.subscriptions.get(&kind)
    }

    /// Check whether a subscription of the given kind is active.
    pub fn is_active(&self, kind: SubscriptionKind) -> bool {
        self.subscriptions.contains_key(&kind)
    }

    /// Get the sync state of a subscription by its ID.
    pub fn sync_state(&self, sub_id: &SubscriptionId) -> Option<SyncState> {
        self.id_to_kind
            .get(&sub_id.0)
            .and_then(|kind| self.subscriptions.get(kind))
            .map(|sub| sub.sync_state)
    }

    /// Number of active subscriptions.
    pub fn active_count(&self) -> usize {
        self.subscriptions.len()
    }

    /// Iterator over all active subscriptions.
    pub fn iter(&self) -> impl Iterator<Item = (&SubscriptionKind, &ManagedSubscription)> {
        self.subscriptions.iter()
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    fn ensure_not_active(&self, kind: SubscriptionKind) -> Result<(), SubscriptionError> {
        if self.subscriptions.contains_key(&kind) {
            return Err(SubscriptionError::AlreadyActive(kind));
        }
        Ok(())
    }

    fn register(
        &mut self,
        kind: SubscriptionKind,
        filters: Vec<Filter>,
    ) -> (SubscriptionId, Vec<Filter>) {
        let sub_id = SubscriptionId::generate();
        let managed = ManagedSubscription {
            sub_id: sub_id.clone(),
            kind,
            filters: filters.clone(),
            sync_state: SyncState::Syncing,
        };
        self.id_to_kind.insert(sub_id.0.clone(), kind);
        self.subscriptions.insert(kind, managed);
        (sub_id, filters)
    }
}

impl Default for SubscriptionManager {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for SubscriptionManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SubscriptionManager")
            .field("active", &self.subscriptions.len())
            .field("kinds", &self.subscriptions.keys().collect::<Vec<_>>())
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn pubkey() -> &'static str {
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    }

    fn pubkey2() -> &'static str {
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    }

    // === Inbox ===

    #[test]
    fn open_inbox_produces_correct_filter() {
        let mut mgr = SubscriptionManager::new();
        let (sub_id, filters) = mgr.open_inbox(pubkey()).unwrap();

        assert_eq!(filters.len(), 1);
        assert_eq!(filters[0].kinds, Some(vec![KIND_AGENT_MESSAGE]));
        assert_eq!(filters[0].p_tags, Some(vec![pubkey().to_string()]));
        assert!(mgr.is_active(SubscriptionKind::Inbox));
        assert_eq!(mgr.kind_of(&sub_id), Some(SubscriptionKind::Inbox));
    }

    #[test]
    fn open_inbox_empty_pubkey_fails() {
        let mut mgr = SubscriptionManager::new();
        let err = mgr.open_inbox("").unwrap_err();
        assert!(matches!(err, SubscriptionError::MissingPubkey));
    }

    #[test]
    fn open_inbox_twice_fails() {
        let mut mgr = SubscriptionManager::new();
        mgr.open_inbox(pubkey()).unwrap();
        let err = mgr.open_inbox(pubkey()).unwrap_err();
        assert!(matches!(err, SubscriptionError::AlreadyActive(_)));
    }

    // === Dialect Listener ===

    #[test]
    fn open_dialect_listener_produces_correct_filter() {
        let mut mgr = SubscriptionManager::new();
        let (_sub_id, filters) = mgr.open_dialect_listener().unwrap();

        assert_eq!(filters.len(), 1);
        assert_eq!(filters[0].kinds, Some(vec![KIND_AGENT_DIALECT]));
        assert_eq!(
            filters[0].label_namespace_tags,
            Some(vec![DIALECT_LABEL_NAMESPACE.to_string()])
        );
    }

    // === Bounty Board ===

    #[test]
    fn open_bounty_board_produces_correct_filter() {
        let mut mgr = SubscriptionManager::new();
        let (_sub_id, filters) = mgr.open_bounty_board().unwrap();

        assert_eq!(filters.len(), 1);
        assert_eq!(filters[0].kinds, Some(vec![KIND_AGENT_MESSAGE]));
        assert_eq!(filters[0].t_tags, Some(vec!["bounty".to_string()]));
    }

    // === Agent Discovery ===

    #[test]
    fn open_agent_discovery_all() {
        let mut mgr = SubscriptionManager::new();
        let (_sub_id, filters) = mgr.open_agent_discovery(&[]).unwrap();

        assert_eq!(filters.len(), 1);
        assert_eq!(filters[0].kinds, Some(vec![KIND_METADATA]));
        assert!(filters[0].authors.is_none());
    }

    #[test]
    fn open_agent_discovery_specific_pubkeys() {
        let mut mgr = SubscriptionManager::new();
        let (_sub_id, filters) = mgr.open_agent_discovery(&[pubkey(), pubkey2()]).unwrap();

        assert_eq!(filters.len(), 1);
        assert_eq!(filters[0].kinds, Some(vec![KIND_METADATA]));
        let authors = filters[0].authors.as_ref().unwrap();
        assert_eq!(authors.len(), 2);
        assert!(authors.contains(&pubkey().to_string()));
        assert!(authors.contains(&pubkey2().to_string()));
    }

    // === Dialect Registry ===

    #[test]
    fn open_dialect_registry_produces_correct_filter() {
        let mut mgr = SubscriptionManager::new();
        let (_sub_id, filters) = mgr.open_dialect_registry(&[pubkey()]).unwrap();

        assert_eq!(filters.len(), 1);
        assert_eq!(filters[0].kinds, Some(vec![KIND_AGENT_DIALECT]));
        assert_eq!(filters[0].authors, Some(vec![pubkey().to_string()]));
        assert_eq!(
            filters[0].label_namespace_tags,
            Some(vec![DIALECT_LABEL_NAMESPACE.to_string()])
        );
    }

    #[test]
    fn open_dialect_registry_empty_pubkeys_fails() {
        let mut mgr = SubscriptionManager::new();
        let err = mgr.open_dialect_registry(&[]).unwrap_err();
        assert!(matches!(err, SubscriptionError::EmptyPubkeys));
    }

    // === EOSE / Sync State ===

    #[test]
    fn initial_state_is_syncing() {
        let mut mgr = SubscriptionManager::new();
        let (sub_id, _) = mgr.open_inbox(pubkey()).unwrap();

        assert_eq!(mgr.sync_state(&sub_id), Some(SyncState::Syncing));
    }

    #[test]
    fn mark_live_transitions_state() {
        let mut mgr = SubscriptionManager::new();
        let (sub_id, _) = mgr.open_inbox(pubkey()).unwrap();

        assert!(mgr.mark_live(&sub_id));
        assert_eq!(mgr.sync_state(&sub_id), Some(SyncState::Live));
    }

    #[test]
    fn mark_live_idempotent() {
        let mut mgr = SubscriptionManager::new();
        let (sub_id, _) = mgr.open_inbox(pubkey()).unwrap();

        assert!(mgr.mark_live(&sub_id));
        // Second call returns false — already live.
        assert!(!mgr.mark_live(&sub_id));
        assert_eq!(mgr.sync_state(&sub_id), Some(SyncState::Live));
    }

    #[test]
    fn mark_live_unknown_id() {
        let mut mgr = SubscriptionManager::new();
        let unknown = SubscriptionId::new("unknown");
        assert!(!mgr.mark_live(&unknown));
    }

    // === Close ===

    #[test]
    fn close_removes_subscription() {
        let mut mgr = SubscriptionManager::new();
        let (sub_id, _) = mgr.open_inbox(pubkey()).unwrap();

        let closed_id = mgr.close(SubscriptionKind::Inbox).unwrap();
        assert_eq!(closed_id, sub_id);
        assert!(!mgr.is_active(SubscriptionKind::Inbox));
        assert_eq!(mgr.active_count(), 0);
    }

    #[test]
    fn close_not_active_fails() {
        let mut mgr = SubscriptionManager::new();
        let err = mgr.close(SubscriptionKind::Inbox).unwrap_err();
        assert!(matches!(err, SubscriptionError::NotActive(_)));
    }

    #[test]
    fn close_then_reopen() {
        let mut mgr = SubscriptionManager::new();
        mgr.open_inbox(pubkey()).unwrap();
        mgr.close(SubscriptionKind::Inbox).unwrap();

        // Should be able to reopen after close.
        let result = mgr.open_inbox(pubkey());
        assert!(result.is_ok());
    }

    // === Close All ===

    #[test]
    fn close_all_returns_all_ids() {
        let mut mgr = SubscriptionManager::new();
        let (id1, _) = mgr.open_inbox(pubkey()).unwrap();
        let (id2, _) = mgr.open_bounty_board().unwrap();

        let ids = mgr.close_all();
        assert_eq!(ids.len(), 2);
        assert!(ids.contains(&id1));
        assert!(ids.contains(&id2));
        assert_eq!(mgr.active_count(), 0);
    }

    #[test]
    fn close_all_empty_manager() {
        let mut mgr = SubscriptionManager::new();
        let ids = mgr.close_all();
        assert!(ids.is_empty());
    }

    // === Multiple subscriptions ===

    #[test]
    fn multiple_subscription_kinds_coexist() {
        let mut mgr = SubscriptionManager::new();
        mgr.open_inbox(pubkey()).unwrap();
        mgr.open_dialect_listener().unwrap();
        mgr.open_bounty_board().unwrap();
        mgr.open_agent_discovery(&[]).unwrap();
        mgr.open_dialect_registry(&[pubkey()]).unwrap();

        assert_eq!(mgr.active_count(), 5);
        assert!(mgr.is_active(SubscriptionKind::Inbox));
        assert!(mgr.is_active(SubscriptionKind::DialectListener));
        assert!(mgr.is_active(SubscriptionKind::BountyBoard));
        assert!(mgr.is_active(SubscriptionKind::AgentDiscovery));
        assert!(mgr.is_active(SubscriptionKind::DialectRegistry));
    }

    #[test]
    fn kind_of_returns_none_for_unknown() {
        let mgr = SubscriptionManager::new();
        let unknown = SubscriptionId::new("unknown");
        assert_eq!(mgr.kind_of(&unknown), None);
    }

    #[test]
    fn sync_state_returns_none_for_unknown() {
        let mgr = SubscriptionManager::new();
        let unknown = SubscriptionId::new("unknown");
        assert_eq!(mgr.sync_state(&unknown), None);
    }

    // === Get ===

    #[test]
    fn get_returns_managed_subscription() {
        let mut mgr = SubscriptionManager::new();
        mgr.open_inbox(pubkey()).unwrap();

        let sub = mgr.get(SubscriptionKind::Inbox).unwrap();
        assert_eq!(sub.kind, SubscriptionKind::Inbox);
        assert_eq!(sub.sync_state, SyncState::Syncing);
        assert_eq!(sub.filters.len(), 1);
    }

    #[test]
    fn get_returns_none_when_not_active() {
        let mgr = SubscriptionManager::new();
        assert!(mgr.get(SubscriptionKind::Inbox).is_none());
    }

    // === Iterator ===

    #[test]
    fn iter_yields_all_active() {
        let mut mgr = SubscriptionManager::new();
        mgr.open_inbox(pubkey()).unwrap();
        mgr.open_bounty_board().unwrap();

        let kinds: Vec<SubscriptionKind> = mgr.iter().map(|(k, _)| *k).collect();
        assert_eq!(kinds.len(), 2);
        assert!(kinds.contains(&SubscriptionKind::Inbox));
        assert!(kinds.contains(&SubscriptionKind::BountyBoard));
    }

    // === Display ===

    #[test]
    fn subscription_kind_display() {
        assert_eq!(SubscriptionKind::Inbox.to_string(), "inbox");
        assert_eq!(SubscriptionKind::DialectListener.to_string(), "dialect-listener");
        assert_eq!(SubscriptionKind::BountyBoard.to_string(), "bounty-board");
        assert_eq!(SubscriptionKind::AgentDiscovery.to_string(), "agent-discovery");
        assert_eq!(SubscriptionKind::DialectRegistry.to_string(), "dialect-registry");
    }

    // === Debug ===

    #[test]
    fn debug_format() {
        let mgr = SubscriptionManager::new();
        let debug = format!("{mgr:?}");
        assert!(debug.contains("SubscriptionManager"));
        assert!(debug.contains("active"));
    }

    // === Default ===

    #[test]
    fn default_is_empty() {
        let mgr = SubscriptionManager::default();
        assert_eq!(mgr.active_count(), 0);
    }
}
