//! WebSocket connection pool to Nostr relays.
//!
//! Manages concurrent connections to multiple Nostr relays with automatic
//! reconnection, event publishing, and subscription management per NIP-01.
//!
//! # Example
//!
//! ```no_run
//! use cbcl_nostr::relay_pool::{RelayPool, PoolConfig, Filter, SubscriptionId};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let pool = RelayPool::new(PoolConfig::default());
//!
//! pool.add_relay("wss://relay.example.com").await?;
//! pool.add_relay("wss://relay2.example.com").await?;
//!
//! // Subscribe to agent messages addressed to us
//! let filters = vec![Filter {
//!     kinds: Some(vec![21111]),
//!     p_tags: Some(vec!["our_pubkey_hex".into()]),
//!     ..Default::default()
//! }];
//! let sub_id = pool.subscribe(SubscriptionId::generate(), filters).await?;
//!
//! // Receive events from the unified stream
//! let mut rx = pool.events();
//! while let Some((relay_url, msg)) = rx.recv().await {
//!     println!("From {relay_url}: {msg:?}");
//! }
//! # Ok(())
//! # }
//! ```

pub mod message;
pub mod relay;

pub use message::{ClientMessage, Filter, RelayMessage, SubscriptionId};
pub use relay::{ReconnectPolicy, RelayError, RelayStatus};

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::{mpsc, Mutex};
use url::Url;

use crate::event_types::Event;
use relay::RelayHandle;

// ---------------------------------------------------------------------------
// Pool configuration
// ---------------------------------------------------------------------------

/// Configuration for the relay pool.
#[derive(Debug, Clone)]
pub struct PoolConfig {
    /// Reconnection policy applied to each relay connection.
    pub reconnect_policy: ReconnectPolicy,
    /// Channel capacity for the unified incoming message stream.
    pub incoming_buffer: usize,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            reconnect_policy: ReconnectPolicy::default(),
            incoming_buffer: 1024,
        }
    }
}

// ---------------------------------------------------------------------------
// Pool errors
// ---------------------------------------------------------------------------

/// Errors from relay pool operations.
#[derive(Debug, thiserror::Error)]
pub enum PoolError {
    #[error("invalid relay URL: {0}")]
    InvalidUrl(String),
    #[error("relay already in pool: {0}")]
    DuplicateRelay(String),
    #[error("relay not found: {0}")]
    RelayNotFound(String),
    #[error(transparent)]
    Relay(#[from] RelayError),
}

// ---------------------------------------------------------------------------
// Publish result
// ---------------------------------------------------------------------------

/// Result of publishing an event to a single relay.
#[derive(Debug, Clone)]
pub struct PublishResult {
    /// The relay URL that was sent to.
    pub relay_url: Url,
    /// Whether the send succeeded (enqueued to the relay's outgoing channel).
    pub success: bool,
    /// Error message if the send failed.
    pub error: Option<String>,
}

// ---------------------------------------------------------------------------
// Relay pool
// ---------------------------------------------------------------------------

/// A pool of WebSocket connections to Nostr relays.
///
/// Provides a unified interface for publishing events and managing
/// subscriptions across multiple relays. Each relay connection runs
/// as an independent tokio task with automatic reconnection.
pub struct RelayPool {
    config: PoolConfig,
    relays: Arc<Mutex<HashMap<Url, RelayHandle>>>,
    incoming_tx: mpsc::Sender<(Url, RelayMessage)>,
    incoming_rx: Arc<Mutex<Option<mpsc::Receiver<(Url, RelayMessage)>>>>,
}

impl RelayPool {
    /// Create a new relay pool with the given configuration.
    pub fn new(config: PoolConfig) -> Self {
        let (incoming_tx, incoming_rx) =
            mpsc::channel::<(Url, RelayMessage)>(config.incoming_buffer);
        Self {
            config,
            relays: Arc::new(Mutex::new(HashMap::new())),
            incoming_tx,
            incoming_rx: Arc::new(Mutex::new(Some(incoming_rx))),
        }
    }

    /// Add a relay to the pool and begin connecting.
    ///
    /// The URL must use the `wss://` or `ws://` scheme.
    pub async fn add_relay(&self, url: &str) -> Result<(), PoolError> {
        let parsed = Url::parse(url).map_err(|e| PoolError::InvalidUrl(e.to_string()))?;

        match parsed.scheme() {
            "wss" | "ws" => {}
            scheme => {
                return Err(PoolError::InvalidUrl(format!(
                    "unsupported scheme: {scheme}"
                )));
            }
        }

        let mut relays = self.relays.lock().await;
        if relays.contains_key(&parsed) {
            return Err(PoolError::DuplicateRelay(url.to_string()));
        }

        let handle = relay::spawn_relay(
            parsed.clone(),
            self.config.reconnect_policy.clone(),
            self.incoming_tx.clone(),
        );
        relays.insert(parsed, handle);
        Ok(())
    }

    /// Remove a relay from the pool, shutting down its connection.
    pub async fn remove_relay(&self, url: &str) -> Result<(), PoolError> {
        let parsed = Url::parse(url).map_err(|e| PoolError::InvalidUrl(e.to_string()))?;
        let mut relays = self.relays.lock().await;
        match relays.remove(&parsed) {
            Some(handle) => {
                handle.shutdown().await;
                Ok(())
            }
            None => Err(PoolError::RelayNotFound(url.to_string())),
        }
    }

    /// Publish an event to all connected relays.
    ///
    /// Returns a [`PublishResult`] for each relay indicating whether the
    /// message was successfully enqueued. The actual relay acknowledgement
    /// (OK/rejected) arrives asynchronously via the event stream.
    pub async fn publish(&self, event: Event) -> Vec<PublishResult> {
        let relays = self.relays.lock().await;
        let mut results = Vec::with_capacity(relays.len());

        for (url, handle) in relays.iter() {
            let msg = ClientMessage::Event(event.clone());
            let result = match handle.send(msg).await {
                Ok(()) => PublishResult {
                    relay_url: url.clone(),
                    success: true,
                    error: None,
                },
                Err(e) => PublishResult {
                    relay_url: url.clone(),
                    success: false,
                    error: Some(e.to_string()),
                },
            };
            results.push(result);
        }

        results
    }

    /// Open a subscription on all connected relays.
    ///
    /// Sends a `REQ` message with the given filters to every relay in the pool.
    pub async fn subscribe(
        &self,
        sub_id: SubscriptionId,
        filters: Vec<Filter>,
    ) -> Result<SubscriptionId, PoolError> {
        let relays = self.relays.lock().await;
        let msg = ClientMessage::Req(sub_id.clone(), filters);

        for handle in relays.values() {
            // Best-effort: if a relay is temporarily down, the subscription
            // will be established when it reconnects (callers should re-subscribe
            // on reconnection events if needed).
            let _ = handle.send(msg.clone()).await;
        }

        Ok(sub_id)
    }

    /// Close a subscription on all relays.
    pub async fn unsubscribe(&self, sub_id: &SubscriptionId) -> Result<(), PoolError> {
        let relays = self.relays.lock().await;
        let msg = ClientMessage::Close(sub_id.clone());

        for handle in relays.values() {
            let _ = handle.send(msg.clone()).await;
        }

        Ok(())
    }

    /// Take the unified event receiver.
    ///
    /// This can only be called once; subsequent calls return a receiver that
    /// will never yield messages. Use this to drive your event processing loop.
    pub fn events(&self) -> mpsc::Receiver<(Url, RelayMessage)> {
        // Try to take the receiver. If already taken, return a dummy channel.
        let mut guard = self.incoming_rx.blocking_lock();
        match guard.take() {
            Some(rx) => rx,
            None => {
                let (_tx, rx) = mpsc::channel(1);
                rx
            }
        }
    }

    /// Async version of [`events`](Self::events).
    pub async fn events_async(&self) -> mpsc::Receiver<(Url, RelayMessage)> {
        let mut guard = self.incoming_rx.lock().await;
        match guard.take() {
            Some(rx) => rx,
            None => {
                let (_tx, rx) = mpsc::channel(1);
                rx
            }
        }
    }

    /// Get the current status of a specific relay.
    pub async fn relay_status(&self, url: &str) -> Option<RelayStatus> {
        let parsed = Url::parse(url).ok()?;
        let relays = self.relays.lock().await;
        relays.get(&parsed).map(|h| h.status())
    }

    /// Get a snapshot of all relay URLs and their current statuses.
    pub async fn relay_statuses(&self) -> Vec<(Url, RelayStatus)> {
        let relays = self.relays.lock().await;
        relays
            .iter()
            .map(|(url, handle)| (url.clone(), handle.status()))
            .collect()
    }

    /// Number of relays in the pool (regardless of connection state).
    pub async fn relay_count(&self) -> usize {
        self.relays.lock().await.len()
    }

    /// Gracefully shut down all relay connections.
    pub async fn shutdown(self) {
        let mut relays = self.relays.lock().await;
        for (_, handle) in relays.drain() {
            handle.shutdown().await;
        }
    }
}

impl std::fmt::Debug for RelayPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RelayPool")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn pool_add_relay_validates_url() {
        let pool = RelayPool::new(PoolConfig::default());
        assert!(pool.add_relay("not a url").await.is_err());
    }

    #[tokio::test]
    async fn pool_add_relay_rejects_http() {
        let pool = RelayPool::new(PoolConfig::default());
        let err = pool.add_relay("http://example.com").await.unwrap_err();
        assert!(matches!(err, PoolError::InvalidUrl(_)));
    }

    #[tokio::test]
    async fn pool_remove_nonexistent_relay() {
        let pool = RelayPool::new(PoolConfig::default());
        let err = pool
            .remove_relay("wss://nonexistent.example.com")
            .await
            .unwrap_err();
        assert!(matches!(err, PoolError::RelayNotFound(_)));
    }

    #[tokio::test]
    async fn pool_empty_publish() {
        let pool = RelayPool::new(PoolConfig::default());
        let event = Event {
            id: "a".repeat(64),
            pubkey: "b".repeat(64),
            created_at: 1700000000,
            kind: 21111,
            tags: vec![],
            content: "(tell)".into(),
            sig: "c".repeat(128),
        };
        let results = pool.publish(event).await;
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn pool_relay_count() {
        let pool = RelayPool::new(PoolConfig::default());
        assert_eq!(pool.relay_count().await, 0);
    }

    #[tokio::test]
    async fn pool_relay_status_unknown_url() {
        let pool = RelayPool::new(PoolConfig::default());
        assert!(pool.relay_status("wss://unknown.example.com").await.is_none());
    }

    #[tokio::test]
    async fn pool_subscribe_empty_pool() {
        let pool = RelayPool::new(PoolConfig::default());
        let sub_id = SubscriptionId::new("test-sub");
        let filters = vec![Filter {
            kinds: Some(vec![21111]),
            ..Default::default()
        }];
        // Should succeed even with no relays (no-op).
        let result = pool.subscribe(sub_id.clone(), filters).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().0, "test-sub");
    }

    #[tokio::test]
    async fn pool_unsubscribe_empty_pool() {
        let pool = RelayPool::new(PoolConfig::default());
        let sub_id = SubscriptionId::new("test-sub");
        assert!(pool.unsubscribe(&sub_id).await.is_ok());
    }
}
