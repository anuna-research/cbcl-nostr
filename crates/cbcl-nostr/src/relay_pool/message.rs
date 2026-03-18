//! NIP-01 protocol messages exchanged between clients and relays.

use serde::{Deserialize, Serialize};

use crate::event_types::Event;

// ---------------------------------------------------------------------------
// Subscription ID
// ---------------------------------------------------------------------------

/// Opaque identifier for a relay subscription (NIP-01 `<subscription_id>`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SubscriptionId(pub String);

impl SubscriptionId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// Generate a random subscription ID.
    pub fn generate() -> Self {
        let mut buf = [0u8; 8];
        ::getrandom::getrandom(&mut buf).expect("getrandom failed");
        let nonce = u64::from_le_bytes(buf);
        Self(format!("sub_{nonce:x}"))
    }
}

impl std::fmt::Display for SubscriptionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

// ---------------------------------------------------------------------------
// NIP-01 subscription filter
// ---------------------------------------------------------------------------

/// A NIP-01 subscription filter.
///
/// All fields are optional; only non-`None` fields are serialized into the
/// JSON filter object sent to the relay.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Filter {
    /// Match events with these IDs (hex).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ids: Option<Vec<String>>,

    /// Match events by these authors (hex pubkeys).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authors: Option<Vec<String>>,

    /// Match these event kinds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kinds: Option<Vec<u64>>,

    /// Match events referencing these event IDs (`#e` tag).
    #[serde(rename = "#e", skip_serializing_if = "Option::is_none")]
    pub e_tags: Option<Vec<String>>,

    /// Match events referencing these pubkeys (`#p` tag).
    #[serde(rename = "#p", skip_serializing_if = "Option::is_none")]
    pub p_tags: Option<Vec<String>>,

    /// Match events referencing these hashtags (`#t` tag).
    #[serde(rename = "#t", skip_serializing_if = "Option::is_none")]
    pub t_tags: Option<Vec<String>>,

    /// Match events with these label namespaces (`#L` tag, NIP-32).
    #[serde(rename = "#L", skip_serializing_if = "Option::is_none")]
    pub label_namespace_tags: Option<Vec<String>>,

    /// Match events with these label values (`#l` tag, NIP-32).
    #[serde(rename = "#l", skip_serializing_if = "Option::is_none")]
    pub label_tags: Option<Vec<String>>,

    /// Events must be newer than this Unix timestamp.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub since: Option<u64>,

    /// Events must be older than this Unix timestamp.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub until: Option<u64>,

    /// Maximum number of events to return.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u64>,
}

// ---------------------------------------------------------------------------
// Client → Relay messages
// ---------------------------------------------------------------------------

/// A message sent from the client to a relay (NIP-01).
#[derive(Debug, Clone)]
pub enum ClientMessage {
    /// `["EVENT", <event>]` — publish an event.
    Event(Event),
    /// `["REQ", <sub_id>, <filter>, ...]` — open a subscription.
    Req(SubscriptionId, Vec<Filter>),
    /// `["CLOSE", <sub_id>]` — close a subscription.
    Close(SubscriptionId),
}

impl ClientMessage {
    /// Serialize to the NIP-01 JSON array format.
    pub fn to_json(&self) -> String {
        match self {
            ClientMessage::Event(event) => {
                let event_json = serde_json::to_value(event).unwrap();
                serde_json::to_string(&serde_json::json!(["EVENT", event_json])).unwrap()
            }
            ClientMessage::Req(sub_id, filters) => {
                let mut arr = vec![
                    serde_json::Value::String("REQ".into()),
                    serde_json::Value::String(sub_id.0.clone()),
                ];
                for f in filters {
                    arr.push(serde_json::to_value(f).unwrap());
                }
                serde_json::to_string(&arr).unwrap()
            }
            ClientMessage::Close(sub_id) => {
                serde_json::to_string(&serde_json::json!(["CLOSE", sub_id.0])).unwrap()
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Relay → Client messages
// ---------------------------------------------------------------------------

/// A message received from a relay (NIP-01).
#[derive(Debug, Clone)]
pub enum RelayMessage {
    /// `["EVENT", <sub_id>, <event>]` — an event matching a subscription.
    Event(SubscriptionId, Event),
    /// `["OK", <event_id>, <accepted>, <message>]` — publish acknowledgement.
    Ok {
        event_id: String,
        accepted: bool,
        message: String,
    },
    /// `["EOSE", <sub_id>]` — end of stored events for a subscription.
    Eose(SubscriptionId),
    /// `["CLOSED", <sub_id>, <message>]` — relay closed a subscription.
    Closed {
        subscription_id: SubscriptionId,
        message: String,
    },
    /// `["NOTICE", <message>]` — human-readable relay notice.
    Notice(String),
}

impl RelayMessage {
    /// Parse a NIP-01 JSON array from a relay into a `RelayMessage`.
    pub fn from_json(json: &str) -> Result<Self, MessageError> {
        let arr: Vec<serde_json::Value> =
            serde_json::from_str(json).map_err(|e| MessageError::InvalidJson(e.to_string()))?;

        let label = arr
            .first()
            .and_then(|v| v.as_str())
            .ok_or_else(|| MessageError::MissingLabel)?;

        match label {
            "EVENT" => {
                let sub_id = arr
                    .get(1)
                    .and_then(|v| v.as_str())
                    .ok_or(MessageError::MissingField("subscription_id"))?;
                let event: Event = serde_json::from_value(
                    arr.get(2)
                        .cloned()
                        .ok_or(MessageError::MissingField("event"))?,
                )
                .map_err(|e| MessageError::InvalidEvent(e.to_string()))?;
                Ok(RelayMessage::Event(SubscriptionId::new(sub_id), event))
            }
            "OK" => {
                let event_id = arr
                    .get(1)
                    .and_then(|v| v.as_str())
                    .ok_or(MessageError::MissingField("event_id"))?
                    .to_string();
                let accepted = arr
                    .get(2)
                    .and_then(|v| v.as_bool())
                    .ok_or(MessageError::MissingField("accepted"))?;
                let message = arr
                    .get(3)
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                Ok(RelayMessage::Ok {
                    event_id,
                    accepted,
                    message,
                })
            }
            "EOSE" => {
                let sub_id = arr
                    .get(1)
                    .and_then(|v| v.as_str())
                    .ok_or(MessageError::MissingField("subscription_id"))?;
                Ok(RelayMessage::Eose(SubscriptionId::new(sub_id)))
            }
            "CLOSED" => {
                let sub_id = arr
                    .get(1)
                    .and_then(|v| v.as_str())
                    .ok_or(MessageError::MissingField("subscription_id"))?;
                let message = arr
                    .get(2)
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                Ok(RelayMessage::Closed {
                    subscription_id: SubscriptionId::new(sub_id),
                    message,
                })
            }
            "NOTICE" => {
                let message = arr
                    .get(1)
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                Ok(RelayMessage::Notice(message))
            }
            other => Err(MessageError::UnknownLabel(other.to_string())),
        }
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors from parsing relay messages.
#[derive(Debug, thiserror::Error)]
pub enum MessageError {
    #[error("invalid JSON: {0}")]
    InvalidJson(String),
    #[error("missing message label")]
    MissingLabel,
    #[error("missing field: {0}")]
    MissingField(&'static str),
    #[error("invalid event: {0}")]
    InvalidEvent(String),
    #[error("unknown message label: {0}")]
    UnknownLabel(String),
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_event() -> Event {
        Event {
            id: "a".repeat(64),
            pubkey: "b".repeat(64),
            created_at: 1700000000,
            kind: 21111,
            tags: vec![vec!["p".into(), "c".repeat(64)]],
            content: "(tell @agent \"hello\")".into(),
            sig: "d".repeat(128),
        }
    }

    // === SubscriptionId ===

    #[test]
    fn subscription_id_display() {
        let id = SubscriptionId::new("my-sub");
        assert_eq!(id.to_string(), "my-sub");
    }

    #[test]
    fn subscription_id_generate_is_unique() {
        let a = SubscriptionId::generate();
        let b = SubscriptionId::generate();
        assert_ne!(a, b);
    }

    // === Filter ===

    #[test]
    fn filter_default_serializes_empty() {
        let f = Filter::default();
        let json = serde_json::to_string(&f).unwrap();
        assert_eq!(json, "{}");
    }

    #[test]
    fn filter_with_fields_serializes_correctly() {
        let f = Filter {
            kinds: Some(vec![21111]),
            p_tags: Some(vec!["abc".into()]),
            limit: Some(10),
            ..Default::default()
        };
        let v: serde_json::Value = serde_json::to_value(&f).unwrap();
        assert_eq!(v["kinds"], serde_json::json!([21111]));
        assert_eq!(v["#p"], serde_json::json!(["abc"]));
        assert_eq!(v["limit"], serde_json::json!(10));
        assert!(v.get("ids").is_none());
    }

    // === ClientMessage ===

    #[test]
    fn client_event_to_json() {
        let msg = ClientMessage::Event(sample_event());
        let json = msg.to_json();
        let arr: Vec<serde_json::Value> = serde_json::from_str(&json).unwrap();
        assert_eq!(arr[0], "EVENT");
        assert_eq!(arr[1]["kind"], 21111);
    }

    #[test]
    fn client_req_to_json() {
        let filters = vec![Filter {
            kinds: Some(vec![21111]),
            ..Default::default()
        }];
        let msg = ClientMessage::Req(SubscriptionId::new("sub1"), filters);
        let json = msg.to_json();
        let arr: Vec<serde_json::Value> = serde_json::from_str(&json).unwrap();
        assert_eq!(arr[0], "REQ");
        assert_eq!(arr[1], "sub1");
        assert_eq!(arr[2]["kinds"], serde_json::json!([21111]));
    }

    #[test]
    fn client_close_to_json() {
        let msg = ClientMessage::Close(SubscriptionId::new("sub1"));
        let json = msg.to_json();
        assert_eq!(json, r#"["CLOSE","sub1"]"#);
    }

    // === RelayMessage ===

    #[test]
    fn parse_relay_event() {
        let event = sample_event();
        let json = format!(
            r#"["EVENT","sub1",{}]"#,
            serde_json::to_string(&event).unwrap()
        );
        let msg = RelayMessage::from_json(&json).unwrap();
        match msg {
            RelayMessage::Event(sub_id, e) => {
                assert_eq!(sub_id.0, "sub1");
                assert_eq!(e.kind, 21111);
            }
            other => panic!("expected Event, got {other:?}"),
        }
    }

    #[test]
    fn parse_relay_ok_accepted() {
        let json = r#"["OK","abc123",true,""]"#;
        let msg = RelayMessage::from_json(json).unwrap();
        match msg {
            RelayMessage::Ok {
                event_id,
                accepted,
                message,
            } => {
                assert_eq!(event_id, "abc123");
                assert!(accepted);
                assert_eq!(message, "");
            }
            other => panic!("expected Ok, got {other:?}"),
        }
    }

    #[test]
    fn parse_relay_ok_rejected() {
        let json = r#"["OK","abc123",false,"error: rate limited"]"#;
        let msg = RelayMessage::from_json(json).unwrap();
        match msg {
            RelayMessage::Ok {
                accepted, message, ..
            } => {
                assert!(!accepted);
                assert_eq!(message, "error: rate limited");
            }
            other => panic!("expected Ok, got {other:?}"),
        }
    }

    #[test]
    fn parse_relay_eose() {
        let json = r#"["EOSE","sub1"]"#;
        let msg = RelayMessage::from_json(json).unwrap();
        match msg {
            RelayMessage::Eose(sub_id) => assert_eq!(sub_id.0, "sub1"),
            other => panic!("expected Eose, got {other:?}"),
        }
    }

    #[test]
    fn parse_relay_closed() {
        let json = r#"["CLOSED","sub1","error: subscription not found"]"#;
        let msg = RelayMessage::from_json(json).unwrap();
        match msg {
            RelayMessage::Closed {
                subscription_id,
                message,
            } => {
                assert_eq!(subscription_id.0, "sub1");
                assert_eq!(message, "error: subscription not found");
            }
            other => panic!("expected Closed, got {other:?}"),
        }
    }

    #[test]
    fn parse_relay_notice() {
        let json = r#"["NOTICE","rate limited"]"#;
        let msg = RelayMessage::from_json(json).unwrap();
        match msg {
            RelayMessage::Notice(msg) => assert_eq!(msg, "rate limited"),
            other => panic!("expected Notice, got {other:?}"),
        }
    }

    #[test]
    fn parse_invalid_json() {
        let err = RelayMessage::from_json("not json").unwrap_err();
        assert!(matches!(err, MessageError::InvalidJson(_)));
    }

    #[test]
    fn parse_missing_label() {
        let err = RelayMessage::from_json("[123]").unwrap_err();
        assert!(matches!(err, MessageError::MissingLabel));
    }

    #[test]
    fn parse_unknown_label() {
        let err = RelayMessage::from_json(r#"["UNKNOWN"]"#).unwrap_err();
        assert!(matches!(err, MessageError::UnknownLabel(_)));
    }
}
