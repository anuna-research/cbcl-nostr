//! Single relay WebSocket connection with automatic reconnection.

use std::sync::Arc;

use futures_util::{SinkExt, StreamExt};
use tokio::sync::{mpsc, watch};
use tokio_tungstenite::tungstenite;
use url::Url;

use super::message::{ClientMessage, RelayMessage};

// ---------------------------------------------------------------------------
// Connection state
// ---------------------------------------------------------------------------

/// Current state of a relay connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayStatus {
    /// Not yet connected or disconnected intentionally.
    Disconnected,
    /// Attempting to establish a WebSocket connection.
    Connecting,
    /// WebSocket connection is open and healthy.
    Connected,
    /// Connection was terminated; will attempt to reconnect.
    Reconnecting,
    /// Permanently shut down; will not reconnect.
    Terminated,
}

impl std::fmt::Display for RelayStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Disconnected => write!(f, "disconnected"),
            Self::Connecting => write!(f, "connecting"),
            Self::Connected => write!(f, "connected"),
            Self::Reconnecting => write!(f, "reconnecting"),
            Self::Terminated => write!(f, "terminated"),
        }
    }
}

// ---------------------------------------------------------------------------
// Reconnect policy
// ---------------------------------------------------------------------------

/// Configuration for exponential backoff reconnection.
#[derive(Debug, Clone)]
pub struct ReconnectPolicy {
    /// Initial delay before the first reconnection attempt.
    pub initial_delay: std::time::Duration,
    /// Maximum delay between reconnection attempts.
    pub max_delay: std::time::Duration,
    /// Multiplier applied to the delay after each failed attempt.
    pub multiplier: f64,
    /// Maximum number of consecutive reconnection attempts before giving up.
    /// `None` means unlimited.
    pub max_retries: Option<u32>,
}

impl Default for ReconnectPolicy {
    fn default() -> Self {
        Self {
            initial_delay: std::time::Duration::from_secs(1),
            max_delay: std::time::Duration::from_secs(60),
            multiplier: 2.0,
            max_retries: None,
        }
    }
}

impl ReconnectPolicy {
    /// Compute the delay for the nth retry (0-indexed).
    fn delay_for(&self, attempt: u32) -> std::time::Duration {
        let secs = self.initial_delay.as_secs_f64() * self.multiplier.powi(attempt as i32);
        let capped = secs.min(self.max_delay.as_secs_f64());
        std::time::Duration::from_secs_f64(capped)
    }
}

// ---------------------------------------------------------------------------
// Relay handle (public)
// ---------------------------------------------------------------------------

/// A handle to a running relay connection task.
///
/// Dropping the handle will not stop the background task; call
/// [`RelayHandle::shutdown`] for a graceful close.
#[derive(Debug)]
pub struct RelayHandle {
    /// The relay URL.
    pub url: Url,
    /// Send client messages to the relay.
    pub(crate) outgoing_tx: mpsc::Sender<ClientMessage>,
    /// Watch the connection status.
    pub(crate) status_rx: watch::Receiver<RelayStatus>,
    /// Signal the relay task to shut down.
    pub(crate) shutdown_tx: mpsc::Sender<()>,
}

impl RelayHandle {
    /// Current connection status.
    pub fn status(&self) -> RelayStatus {
        *self.status_rx.borrow()
    }

    /// Send a message to this relay.
    pub async fn send(&self, msg: ClientMessage) -> Result<(), RelayError> {
        self.outgoing_tx
            .send(msg)
            .await
            .map_err(|_| RelayError::SendFailed)
    }

    /// Request a graceful shutdown.
    pub async fn shutdown(&self) {
        let _ = self.shutdown_tx.send(()).await;
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors that can occur during relay operations.
#[derive(Debug, thiserror::Error)]
pub enum RelayError {
    #[error("invalid relay URL: {0}")]
    InvalidUrl(String),
    #[error("WebSocket error: {0}")]
    WebSocket(String),
    #[error("send failed: relay task is gone")]
    SendFailed,
    #[error("connection failed after {0} attempts")]
    MaxRetriesExceeded(u32),
}

// ---------------------------------------------------------------------------
// Relay task
// ---------------------------------------------------------------------------

/// Spawn a background task that maintains a WebSocket connection to a single
/// relay. Returns a [`RelayHandle`] for interacting with the connection and
/// the receiver half of the channel that delivers incoming relay messages.
pub fn spawn_relay(
    url: Url,
    policy: ReconnectPolicy,
    incoming_tx: mpsc::Sender<(Url, RelayMessage)>,
) -> RelayHandle {
    let (outgoing_tx, outgoing_rx) = mpsc::channel::<ClientMessage>(256);
    let (status_tx, status_rx) = watch::channel(RelayStatus::Disconnected);
    let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>(1);

    let url_clone = url.clone();
    tokio::spawn(relay_task(
        url_clone,
        policy,
        outgoing_rx,
        incoming_tx,
        status_tx,
        shutdown_rx,
    ));

    RelayHandle {
        url,
        outgoing_tx,
        status_rx,
        shutdown_tx,
    }
}

/// The main event loop for a single relay connection.
async fn relay_task(
    url: Url,
    policy: ReconnectPolicy,
    mut outgoing_rx: mpsc::Receiver<ClientMessage>,
    incoming_tx: mpsc::Sender<(Url, RelayMessage)>,
    status_tx: watch::Sender<RelayStatus>,
    mut shutdown_rx: mpsc::Receiver<()>,
) {
    let url = Arc::new(url);
    let mut attempt: u32 = 0;

    'outer: loop {
        // Check retry limit.
        if let Some(max) = policy.max_retries {
            if attempt > max {
                let _ = status_tx.send(RelayStatus::Terminated);
                break;
            }
        }

        if attempt > 0 {
            let _ = status_tx.send(RelayStatus::Reconnecting);
            let delay = policy.delay_for(attempt - 1);
            tokio::select! {
                _ = tokio::time::sleep(delay) => {}
                _ = shutdown_rx.recv() => {
                    let _ = status_tx.send(RelayStatus::Terminated);
                    break;
                }
            }
        }

        let _ = status_tx.send(RelayStatus::Connecting);

        // Attempt connection.
        let ws_stream = match tokio_tungstenite::connect_async(url.as_str()).await {
            Ok((stream, _response)) => stream,
            Err(e) => {
                tracing::warn!(relay = %url, error = %e, attempt, "connection failed");
                attempt += 1;
                continue;
            }
        };

        let _ = status_tx.send(RelayStatus::Connected);
        attempt = 0; // Reset on successful connection.
        tracing::info!(relay = %url, "connected");

        let (mut ws_sink, mut ws_stream_rx) = ws_stream.split();

        // Process messages until the connection drops or we're told to shut down.
        loop {
            tokio::select! {
                // Outgoing client message to send to the relay.
                maybe_msg = outgoing_rx.recv() => {
                    match maybe_msg {
                        Some(msg) => {
                            let text = msg.to_json();
                            if let Err(e) = ws_sink.send(tungstenite::Message::Text(text.into())).await {
                                tracing::warn!(relay = %url, error = %e, "send error, reconnecting");
                                attempt += 1;
                                continue 'outer;
                            }
                        }
                        None => {
                            // All senders dropped — shut down.
                            let _ = status_tx.send(RelayStatus::Terminated);
                            let _ = ws_sink.close().await;
                            break 'outer;
                        }
                    }
                }

                // Incoming message from the relay.
                maybe_ws = ws_stream_rx.next() => {
                    match maybe_ws {
                        Some(Ok(tungstenite::Message::Text(text))) => {
                            match RelayMessage::from_json(&text) {
                                Ok(relay_msg) => {
                                    if incoming_tx.send(((*url).clone(), relay_msg)).await.is_err() {
                                        // Pool receiver dropped.
                                        let _ = status_tx.send(RelayStatus::Terminated);
                                        let _ = ws_sink.close().await;
                                        break 'outer;
                                    }
                                }
                                Err(e) => {
                                    tracing::debug!(relay = %url, error = %e, "unparseable relay message");
                                }
                            }
                        }
                        Some(Ok(tungstenite::Message::Close(_))) | None => {
                            tracing::info!(relay = %url, "connection closed, reconnecting");
                            attempt += 1;
                            continue 'outer;
                        }
                        Some(Ok(tungstenite::Message::Ping(data))) => {
                            let _ = ws_sink.send(tungstenite::Message::Pong(data)).await;
                        }
                        Some(Ok(_)) => {
                            // Binary, Pong, Frame — ignore.
                        }
                        Some(Err(e)) => {
                            tracing::warn!(relay = %url, error = %e, "WebSocket error, reconnecting");
                            attempt += 1;
                            continue 'outer;
                        }
                    }
                }

                // Shutdown signal.
                _ = shutdown_rx.recv() => {
                    let _ = status_tx.send(RelayStatus::Terminated);
                    let _ = ws_sink.close().await;
                    break 'outer;
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reconnect_policy_delay_exponential() {
        let policy = ReconnectPolicy {
            initial_delay: std::time::Duration::from_secs(1),
            max_delay: std::time::Duration::from_secs(60),
            multiplier: 2.0,
            max_retries: None,
        };
        assert_eq!(policy.delay_for(0), std::time::Duration::from_secs(1));
        assert_eq!(policy.delay_for(1), std::time::Duration::from_secs(2));
        assert_eq!(policy.delay_for(2), std::time::Duration::from_secs(4));
        assert_eq!(policy.delay_for(3), std::time::Duration::from_secs(8));
    }

    #[test]
    fn reconnect_policy_delay_capped() {
        let policy = ReconnectPolicy {
            initial_delay: std::time::Duration::from_secs(1),
            max_delay: std::time::Duration::from_secs(10),
            multiplier: 2.0,
            max_retries: None,
        };
        // 2^10 = 1024, should be capped at 10.
        assert_eq!(policy.delay_for(10), std::time::Duration::from_secs(10));
    }

    #[test]
    fn relay_status_display() {
        assert_eq!(RelayStatus::Connected.to_string(), "connected");
        assert_eq!(RelayStatus::Reconnecting.to_string(), "reconnecting");
        assert_eq!(RelayStatus::Terminated.to_string(), "terminated");
    }
}
