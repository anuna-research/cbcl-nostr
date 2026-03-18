//! NIP-57 Lightning Zap integration for CBCL agent payments.
//!
//! Provides:
//! - Kind constants for zap request (9734) and zap receipt (9735) events.
//! - [`ZapRequestBuilder`] — constructs kind 9734 zap requests targeting
//!   task-completion (`ok`) events.
//! - [`ZapReceipt`] — parses kind 9735 zap receipts to confirm payment.
//! - [`reconcile`] — compares zap receipt amount against a commerce invoice
//!   amount for payment reconciliation.

#![forbid(unsafe_code)]

use crate::event_types::{Event, Tag};

// ---------------------------------------------------------------------------
// Event kinds (NIP-57)
// ---------------------------------------------------------------------------

/// Nostr event kind for a zap request (NIP-57).
pub const KIND_ZAP_REQUEST: u64 = 9734;

/// Nostr event kind for a zap receipt (NIP-57).
pub const KIND_ZAP_RECEIPT: u64 = 9735;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors from zap request construction or receipt parsing.
#[derive(Debug, thiserror::Error)]
pub enum ZapError {
    /// The zap request is missing a required field.
    #[error("missing required field: {0}")]
    MissingField(&'static str),

    /// The event kind does not match the expected zap kind.
    #[error("wrong kind: expected {expected}, got {got}")]
    WrongKind { expected: u64, got: u64 },

    /// The amount could not be parsed as a valid millisatoshi value.
    #[error("invalid amount: {0}")]
    InvalidAmount(String),

    /// The embedded zap request in a receipt is malformed.
    #[error("malformed embedded zap request: {0}")]
    MalformedRequest(String),

    /// JSON deserialization failed.
    #[error("json error: {0}")]
    Json(String),
}

// ---------------------------------------------------------------------------
// ZapRequestBuilder
// ---------------------------------------------------------------------------

/// Builder for constructing unsigned kind 9734 zap request events.
///
/// Per NIP-57, a zap request contains:
/// - `["p", <recipient-pubkey>]` — the Lightning recipient.
/// - `["e", <event-id>]` — the event being zapped (typically an `ok` event).
/// - `["amount", <millisats>]` — requested payment amount in millisatoshis.
/// - `["relays", <relay-url>, ...]` — relays where the receipt should appear.
/// - `["lnurl", <lnurl>]` — (optional) the LNURL pay endpoint.
///
/// The content field may carry an optional message.
pub struct ZapRequestBuilder {
    recipient: Option<String>,
    event_id: Option<String>,
    amount_msats: Option<u64>,
    relays: Vec<String>,
    lnurl: Option<String>,
    content: String,
}

impl ZapRequestBuilder {
    /// Create a new zap request builder.
    pub fn new() -> Self {
        Self {
            recipient: None,
            event_id: None,
            amount_msats: None,
            relays: Vec::new(),
            lnurl: None,
            content: String::new(),
        }
    }

    /// Set the recipient public key (hex).
    pub fn recipient(mut self, pubkey: &str) -> Self {
        self.recipient = Some(pubkey.to_string());
        self
    }

    /// Set the event ID being zapped (typically a task-completion `ok` event).
    pub fn event_id(mut self, event_id: &str) -> Self {
        self.event_id = Some(event_id.to_string());
        self
    }

    /// Set the payment amount in millisatoshis.
    pub fn amount_msats(mut self, msats: u64) -> Self {
        self.amount_msats = Some(msats);
        self
    }

    /// Add a relay URL where the zap receipt should be published.
    pub fn relay(mut self, relay_url: &str) -> Self {
        self.relays.push(relay_url.to_string());
        self
    }

    /// Add multiple relay URLs.
    pub fn relays(mut self, relay_urls: &[&str]) -> Self {
        self.relays.extend(relay_urls.iter().map(|s| s.to_string()));
        self
    }

    /// Set the LNURL pay endpoint.
    pub fn lnurl(mut self, lnurl: &str) -> Self {
        self.lnurl = Some(lnurl.to_string());
        self
    }

    /// Set an optional content message.
    pub fn content(mut self, content: &str) -> Self {
        self.content = content.to_string();
        self
    }

    /// Build the unsigned kind 9734 zap request event.
    pub fn build(self) -> Result<Event, ZapError> {
        let recipient = self
            .recipient
            .ok_or(ZapError::MissingField("recipient (p tag)"))?;
        let amount_msats = self
            .amount_msats
            .ok_or(ZapError::MissingField("amount"))?;

        let mut tags: Vec<Vec<String>> = Vec::new();

        // p tag — recipient
        tags.push(vec!["p".into(), recipient]);

        // e tag — referenced event (optional per NIP-57 but we require it
        // for task-completion targeting)
        if let Some(ref eid) = self.event_id {
            tags.push(vec!["e".into(), eid.clone()]);
        }

        // amount tag
        tags.push(vec!["amount".into(), amount_msats.to_string()]);

        // relays tag
        if !self.relays.is_empty() {
            let mut relay_tag = vec!["relays".into()];
            relay_tag.extend(self.relays);
            tags.push(relay_tag);
        }

        // lnurl tag
        if let Some(ref lnurl) = self.lnurl {
            tags.push(vec!["lnurl".into(), lnurl.clone()]);
        }

        Ok(Event {
            id: String::new(),
            pubkey: String::new(),
            created_at: 0,
            kind: KIND_ZAP_REQUEST,
            tags,
            content: self.content,
            sig: String::new(),
        })
    }
}

impl Default for ZapRequestBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// ZapReceipt — parsed kind 9735
// ---------------------------------------------------------------------------

/// A parsed kind 9735 zap receipt event.
///
/// Contains the extracted fields needed for payment confirmation and
/// reconciliation with commerce invoices.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZapReceipt {
    /// The underlying NIP-01 event (kind 9735).
    pub event: Event,
    /// Recipient public key from the `p` tag.
    pub recipient: String,
    /// Referenced event ID from the `e` tag (if present).
    pub event_id: Option<String>,
    /// Payment amount in millisatoshis from the embedded zap request's
    /// `amount` tag (the canonical source per NIP-57).
    pub amount_msats: u64,
    /// The bolt11 invoice string from the `bolt11` tag.
    pub bolt11: Option<String>,
    /// The serialized zap request (kind 9734) from the `description` tag.
    pub zap_request_json: String,
}

impl ZapReceipt {
    /// Parse a kind 9735 event into a [`ZapReceipt`].
    ///
    /// Extracts the `p`, `e`, `bolt11`, and `description` tags. The
    /// `description` tag must contain a valid serialized kind 9734 event
    /// whose `amount` tag provides the canonical payment amount.
    pub fn from_event(event: Event) -> Result<Self, ZapError> {
        if event.kind != KIND_ZAP_RECEIPT {
            return Err(ZapError::WrongKind {
                expected: KIND_ZAP_RECEIPT,
                got: event.kind,
            });
        }

        let tags: Vec<Tag> = event.tags.iter().map(|t| Tag::parse(t)).collect();

        // Extract p tag
        let recipient = tags
            .iter()
            .find_map(|t| match t {
                Tag::PubKey(pk) => Some(pk.clone()),
                _ => None,
            })
            .ok_or(ZapError::MissingField("p tag (recipient)"))?;

        // Extract e tag (optional)
        let event_id = tags.iter().find_map(|t| match t {
            Tag::Event(eid) => Some(eid.clone()),
            _ => None,
        });

        // Extract bolt11 tag
        let bolt11 = event.tags.iter().find_map(|raw| {
            if raw.first().map(String::as_str) == Some("bolt11") && raw.len() >= 2 {
                Some(raw[1].clone())
            } else {
                None
            }
        });

        // Extract description tag (serialized zap request)
        let zap_request_json = event
            .tags
            .iter()
            .find_map(|raw| {
                if raw.first().map(String::as_str) == Some("description") && raw.len() >= 2 {
                    Some(raw[1].clone())
                } else {
                    None
                }
            })
            .ok_or(ZapError::MissingField("description tag (zap request)"))?;

        // Parse embedded zap request to extract the canonical amount
        let zap_request: Event = serde_json::from_str(&zap_request_json)
            .map_err(|e| ZapError::Json(e.to_string()))?;

        if zap_request.kind != KIND_ZAP_REQUEST {
            return Err(ZapError::MalformedRequest(format!(
                "embedded event has kind {}, expected {}",
                zap_request.kind, KIND_ZAP_REQUEST
            )));
        }

        let amount_msats = zap_request
            .tags
            .iter()
            .find_map(|raw| {
                if raw.first().map(String::as_str) == Some("amount") && raw.len() >= 2 {
                    raw[1].parse::<u64>().ok()
                } else {
                    None
                }
            })
            .ok_or(ZapError::MissingField(
                "amount tag in embedded zap request",
            ))?;

        Ok(Self {
            event,
            recipient,
            event_id,
            amount_msats,
            bolt11,
            zap_request_json,
        })
    }
}

// ---------------------------------------------------------------------------
// Reconciliation
// ---------------------------------------------------------------------------

/// Result of reconciling a zap receipt against a commerce invoice amount.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReconciliationResult {
    /// The zap amount exactly matches the invoice amount.
    ExactMatch,
    /// The zap amount exceeds the invoice amount by the given number of
    /// millisatoshis (overpayment).
    Overpaid { excess_msats: u64 },
    /// The zap amount is less than the invoice amount by the given number
    /// of millisatoshis (underpayment).
    Underpaid { shortfall_msats: u64 },
}

/// Reconcile a zap receipt's payment amount against a commerce invoice.
///
/// The `invoice_amount_msats` is the expected payment amount from the
/// commerce `invoice` performative, converted to millisatoshis. The zap
/// receipt's `amount_msats` is compared against it.
///
/// # Examples
///
/// ```
/// use cbcl_nostr::zap_integration::{ReconciliationResult, reconcile};
///
/// assert_eq!(reconcile(50_000, 50_000), ReconciliationResult::ExactMatch);
/// assert_eq!(
///     reconcile(60_000, 50_000),
///     ReconciliationResult::Overpaid { excess_msats: 10_000 }
/// );
/// assert_eq!(
///     reconcile(40_000, 50_000),
///     ReconciliationResult::Underpaid { shortfall_msats: 10_000 }
/// );
/// ```
pub fn reconcile(zap_amount_msats: u64, invoice_amount_msats: u64) -> ReconciliationResult {
    match zap_amount_msats.cmp(&invoice_amount_msats) {
        std::cmp::Ordering::Equal => ReconciliationResult::ExactMatch,
        std::cmp::Ordering::Greater => ReconciliationResult::Overpaid {
            excess_msats: zap_amount_msats - invoice_amount_msats,
        },
        std::cmp::Ordering::Less => ReconciliationResult::Underpaid {
            shortfall_msats: invoice_amount_msats - zap_amount_msats,
        },
    }
}

/// Convert a satoshi amount to millisatoshis.
pub fn sats_to_msats(sats: u64) -> u64 {
    sats * 1000
}

/// Convert a millisatoshi amount to satoshis (truncating).
pub fn msats_to_sats(msats: u64) -> u64 {
    msats / 1000
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // Helper: build a minimal zap request event (kind 9734) for embedding
    fn make_zap_request_event(
        recipient: &str,
        event_id: Option<&str>,
        amount_msats: u64,
    ) -> Event {
        let mut tags = vec![
            vec!["p".into(), recipient.into()],
            vec!["amount".into(), amount_msats.to_string()],
        ];
        if let Some(eid) = event_id {
            tags.push(vec!["e".into(), eid.into()]);
        }
        tags.push(vec![
            "relays".into(),
            "wss://relay.example.com".into(),
        ]);

        Event {
            id: "a".repeat(64),
            pubkey: "b".repeat(64),
            created_at: 1700000000,
            kind: KIND_ZAP_REQUEST,
            tags,
            content: String::new(),
            sig: "c".repeat(128),
        }
    }

    // Helper: build a kind 9735 receipt wrapping a zap request
    fn make_zap_receipt(
        recipient: &str,
        event_id: Option<&str>,
        amount_msats: u64,
        bolt11: Option<&str>,
    ) -> Event {
        let zap_req = make_zap_request_event(recipient, event_id, amount_msats);
        let zap_req_json = serde_json::to_string(&zap_req).unwrap();

        let mut tags = vec![
            vec!["p".into(), recipient.into()],
            vec!["description".into(), zap_req_json],
        ];
        if let Some(eid) = event_id {
            tags.push(vec!["e".into(), eid.into()]);
        }
        if let Some(b11) = bolt11 {
            tags.push(vec!["bolt11".into(), b11.into()]);
        }

        Event {
            id: "d".repeat(64),
            pubkey: "e".repeat(64), // lightning node pubkey
            created_at: 1700000001,
            kind: KIND_ZAP_RECEIPT,
            tags,
            content: String::new(),
            sig: "f".repeat(128),
        }
    }

    // ====================================================================
    // ZapRequestBuilder
    // ====================================================================

    #[test]
    fn build_zap_request_basic() {
        let event = ZapRequestBuilder::new()
            .recipient("abc123")
            .event_id("def456")
            .amount_msats(50_000)
            .relay("wss://relay.example.com")
            .build()
            .unwrap();

        assert_eq!(event.kind, KIND_ZAP_REQUEST);
        assert_eq!(event.tags.len(), 4); // p, e, amount, relays

        let tags: Vec<Tag> = event.tags.iter().map(|t| Tag::parse(t)).collect();
        assert!(tags.contains(&Tag::PubKey("abc123".into())));
        assert!(tags.contains(&Tag::Event("def456".into())));
        assert!(tags.contains(&Tag::Amount("50000".into())));
    }

    #[test]
    fn build_zap_request_multiple_relays() {
        let event = ZapRequestBuilder::new()
            .recipient("abc123")
            .amount_msats(1000)
            .relays(&["wss://r1.example.com", "wss://r2.example.com"])
            .build()
            .unwrap();

        let relay_tag = event
            .tags
            .iter()
            .find(|t| t.first().map(String::as_str) == Some("relays"))
            .unwrap();
        assert_eq!(relay_tag.len(), 3); // "relays", url1, url2
    }

    #[test]
    fn build_zap_request_with_lnurl() {
        let event = ZapRequestBuilder::new()
            .recipient("abc123")
            .amount_msats(1000)
            .lnurl("lnurl1dp68gurn8ghj7...")
            .build()
            .unwrap();

        let lnurl_tag = event
            .tags
            .iter()
            .find(|t| t.first().map(String::as_str) == Some("lnurl"))
            .unwrap();
        assert_eq!(lnurl_tag[1], "lnurl1dp68gurn8ghj7...");
    }

    #[test]
    fn build_zap_request_with_content() {
        let event = ZapRequestBuilder::new()
            .recipient("abc123")
            .amount_msats(1000)
            .content("Great work on the task!")
            .build()
            .unwrap();

        assert_eq!(event.content, "Great work on the task!");
    }

    #[test]
    fn build_zap_request_missing_recipient() {
        let err = ZapRequestBuilder::new()
            .amount_msats(1000)
            .build()
            .unwrap_err();
        assert!(matches!(err, ZapError::MissingField(_)));
    }

    #[test]
    fn build_zap_request_missing_amount() {
        let err = ZapRequestBuilder::new()
            .recipient("abc123")
            .build()
            .unwrap_err();
        assert!(matches!(err, ZapError::MissingField(_)));
    }

    #[test]
    fn build_zap_request_without_event_id() {
        let event = ZapRequestBuilder::new()
            .recipient("abc123")
            .amount_msats(1000)
            .build()
            .unwrap();

        // No e tag present
        let has_e = event
            .tags
            .iter()
            .any(|t| t.first().map(String::as_str) == Some("e"));
        assert!(!has_e);
    }

    #[test]
    fn build_zap_request_unsigned_placeholders() {
        let event = ZapRequestBuilder::new()
            .recipient("abc123")
            .amount_msats(1000)
            .build()
            .unwrap();

        assert!(event.id.is_empty());
        assert!(event.pubkey.is_empty());
        assert_eq!(event.created_at, 0);
        assert!(event.sig.is_empty());
    }

    // ====================================================================
    // ZapReceipt parsing
    // ====================================================================

    #[test]
    fn parse_zap_receipt_basic() {
        let event = make_zap_receipt("abc123", Some("def456"), 50_000, Some("lnbc500..."));
        let receipt = ZapReceipt::from_event(event).unwrap();

        assert_eq!(receipt.recipient, "abc123");
        assert_eq!(receipt.event_id, Some("def456".into()));
        assert_eq!(receipt.amount_msats, 50_000);
        assert_eq!(receipt.bolt11, Some("lnbc500...".into()));
    }

    #[test]
    fn parse_zap_receipt_no_event_id() {
        let event = make_zap_receipt("abc123", None, 25_000, None);
        let receipt = ZapReceipt::from_event(event).unwrap();

        assert_eq!(receipt.recipient, "abc123");
        assert_eq!(receipt.event_id, None);
        assert_eq!(receipt.amount_msats, 25_000);
        assert_eq!(receipt.bolt11, None);
    }

    #[test]
    fn parse_zap_receipt_wrong_kind() {
        let mut event = make_zap_receipt("abc123", None, 1000, None);
        event.kind = 9734; // wrong kind
        let err = ZapReceipt::from_event(event).unwrap_err();
        assert!(matches!(err, ZapError::WrongKind { .. }));
    }

    #[test]
    fn parse_zap_receipt_missing_p_tag() {
        let mut event = make_zap_receipt("abc123", None, 1000, None);
        event.tags.retain(|t| t.first().map(String::as_str) != Some("p"));
        let err = ZapReceipt::from_event(event).unwrap_err();
        assert!(matches!(err, ZapError::MissingField(_)));
    }

    #[test]
    fn parse_zap_receipt_missing_description() {
        let mut event = make_zap_receipt("abc123", None, 1000, None);
        event
            .tags
            .retain(|t| t.first().map(String::as_str) != Some("description"));
        let err = ZapReceipt::from_event(event).unwrap_err();
        assert!(matches!(err, ZapError::MissingField(_)));
    }

    #[test]
    fn parse_zap_receipt_invalid_description_json() {
        let mut event = make_zap_receipt("abc123", None, 1000, None);
        // Replace description with invalid JSON
        for tag in &mut event.tags {
            if tag.first().map(String::as_str) == Some("description") {
                tag[1] = "not-valid-json".into();
            }
        }
        let err = ZapReceipt::from_event(event).unwrap_err();
        assert!(matches!(err, ZapError::Json(_)));
    }

    #[test]
    fn parse_zap_receipt_wrong_embedded_kind() {
        let mut event = make_zap_receipt("abc123", None, 1000, None);
        // Replace description with a valid event but wrong kind
        let bad_req = Event {
            id: "a".repeat(64),
            pubkey: "b".repeat(64),
            created_at: 1700000000,
            kind: 1, // wrong kind
            tags: vec![vec!["amount".into(), "1000".into()]],
            content: String::new(),
            sig: "c".repeat(128),
        };
        let bad_json = serde_json::to_string(&bad_req).unwrap();
        for tag in &mut event.tags {
            if tag.first().map(String::as_str) == Some("description") {
                tag[1] = bad_json.clone();
            }
        }
        let err = ZapReceipt::from_event(event).unwrap_err();
        assert!(matches!(err, ZapError::MalformedRequest(_)));
    }

    #[test]
    fn parse_zap_receipt_missing_amount_in_request() {
        let mut event = make_zap_receipt("abc123", None, 1000, None);
        // Replace description with a request missing amount
        let bad_req = Event {
            id: "a".repeat(64),
            pubkey: "b".repeat(64),
            created_at: 1700000000,
            kind: KIND_ZAP_REQUEST,
            tags: vec![vec!["p".into(), "abc123".into()]], // no amount
            content: String::new(),
            sig: "c".repeat(128),
        };
        let bad_json = serde_json::to_string(&bad_req).unwrap();
        for tag in &mut event.tags {
            if tag.first().map(String::as_str) == Some("description") {
                tag[1] = bad_json.clone();
            }
        }
        let err = ZapReceipt::from_event(event).unwrap_err();
        assert!(matches!(err, ZapError::MissingField(_)));
    }

    // ====================================================================
    // Reconciliation
    // ====================================================================

    #[test]
    fn reconcile_exact_match() {
        assert_eq!(reconcile(50_000, 50_000), ReconciliationResult::ExactMatch);
    }

    #[test]
    fn reconcile_overpaid() {
        assert_eq!(
            reconcile(60_000, 50_000),
            ReconciliationResult::Overpaid {
                excess_msats: 10_000
            }
        );
    }

    #[test]
    fn reconcile_underpaid() {
        assert_eq!(
            reconcile(40_000, 50_000),
            ReconciliationResult::Underpaid {
                shortfall_msats: 10_000
            }
        );
    }

    #[test]
    fn reconcile_zero_amounts() {
        assert_eq!(reconcile(0, 0), ReconciliationResult::ExactMatch);
    }

    #[test]
    fn reconcile_zap_receipt_against_invoice() {
        // Simulate: invoice says 50 sats, zap receipt confirms 50 sats
        let invoice_sats = 50;
        let invoice_msats = sats_to_msats(invoice_sats);

        let event = make_zap_receipt("seller", Some("task-ok-event"), invoice_msats, None);
        let receipt = ZapReceipt::from_event(event).unwrap();

        let result = reconcile(receipt.amount_msats, invoice_msats);
        assert_eq!(result, ReconciliationResult::ExactMatch);
    }

    #[test]
    fn reconcile_underpaid_receipt() {
        let invoice_msats = sats_to_msats(100);
        let paid_msats = sats_to_msats(80);

        let event = make_zap_receipt("seller", Some("task-ok-event"), paid_msats, None);
        let receipt = ZapReceipt::from_event(event).unwrap();

        let result = reconcile(receipt.amount_msats, invoice_msats);
        assert_eq!(
            result,
            ReconciliationResult::Underpaid {
                shortfall_msats: sats_to_msats(20)
            }
        );
    }

    // ====================================================================
    // Unit conversion
    // ====================================================================

    #[test]
    fn sats_msats_conversion() {
        assert_eq!(sats_to_msats(1), 1000);
        assert_eq!(sats_to_msats(50), 50_000);
        assert_eq!(msats_to_sats(50_000), 50);
        assert_eq!(msats_to_sats(1500), 1); // truncates
        assert_eq!(msats_to_sats(999), 0); // truncates
    }

    // ====================================================================
    // End-to-end: build request → embed in receipt → parse → reconcile
    // ====================================================================

    #[test]
    fn end_to_end_zap_flow() {
        // 1. Build a zap request targeting an "ok" event
        let zap_req_event = ZapRequestBuilder::new()
            .recipient("seller_pk")
            .event_id("ok_event_id")
            .amount_msats(sats_to_msats(100))
            .relay("wss://relay.example.com")
            .content("Payment for completed task")
            .build()
            .unwrap();

        assert_eq!(zap_req_event.kind, KIND_ZAP_REQUEST);

        // 2. Simulate: fill in signing fields (as if signed)
        let mut signed_req = zap_req_event;
        signed_req.id = "a".repeat(64);
        signed_req.pubkey = "buyer_pk".repeat(4);
        signed_req.created_at = 1700000000;
        signed_req.sig = "s".repeat(128);

        // 3. Simulate: lightning node creates receipt
        let req_json = serde_json::to_string(&signed_req).unwrap();
        let receipt_event = Event {
            id: "r".repeat(64),
            pubkey: "lightning_node".repeat(5).chars().take(64).collect(),
            created_at: 1700000001,
            kind: KIND_ZAP_RECEIPT,
            tags: vec![
                vec!["p".into(), "seller_pk".into()],
                vec!["e".into(), "ok_event_id".into()],
                vec!["description".into(), req_json],
                vec!["bolt11".into(), "lnbc1000n1...".into()],
            ],
            content: String::new(),
            sig: "z".repeat(128),
        };

        // 4. Parse the receipt
        let receipt = ZapReceipt::from_event(receipt_event).unwrap();
        assert_eq!(receipt.recipient, "seller_pk");
        assert_eq!(receipt.event_id, Some("ok_event_id".into()));
        assert_eq!(receipt.amount_msats, 100_000);
        assert_eq!(receipt.bolt11, Some("lnbc1000n1...".into()));

        // 5. Reconcile against the commerce invoice
        let invoice_msats = sats_to_msats(100);
        let result = reconcile(receipt.amount_msats, invoice_msats);
        assert_eq!(result, ReconciliationResult::ExactMatch);
    }
}
