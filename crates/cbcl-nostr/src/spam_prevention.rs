//! Spam prevention: rate limiting, NIP-13 proof-of-work, pubkey allowlists,
//! and zap-gating for CBCL-over-Nostr.
//!
//! Provides four defense layers:
//!
//! - **Rate limiter** — token-bucket rate limiting of outgoing messages,
//!   configurable per relay policy.
//! - **NIP-13 proof-of-work** — compute and verify leading-zero-bit
//!   commitments on event IDs.
//! - **Pubkey allowlist** — filter incoming events against a set of
//!   trusted public keys.
//! - **Zap gate** — require payment history (prior zap receipts) before
//!   accepting broadcast messages from a pubkey.

#![forbid(unsafe_code)]

use std::collections::{HashMap, HashSet};
use std::time::Duration;

#[cfg(not(feature = "wasm"))]
use std::time::Instant;
#[cfg(feature = "wasm")]
use web_time::Instant;

use sha2::{Digest, Sha256};

use crate::event_types::Event;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors returned by spam-prevention checks.
#[derive(Debug, thiserror::Error)]
pub enum SpamError {
    /// Outgoing message was rejected by the rate limiter.
    #[error("rate limited: {0}")]
    RateLimited(String),

    /// Event does not meet the required proof-of-work difficulty.
    #[error("insufficient proof-of-work: need {required} bits, got {actual}")]
    InsufficientPow { required: u8, actual: u8 },

    /// Event author is not on the pubkey allowlist.
    #[error("pubkey not allowed: {0}")]
    PubkeyNotAllowed(String),

    /// Event author has no qualifying zap history.
    #[error("zap gate: pubkey {0} has no qualifying payment history")]
    ZapGateRejected(String),

    /// Hex decoding failed during PoW verification.
    #[error("invalid hex in event id: {0}")]
    InvalidHex(String),
}

// ===========================================================================
// 1. Rate Limiter (token bucket)
// ===========================================================================

/// Configuration for per-relay rate limiting.
#[derive(Debug, Clone)]
pub struct RateLimitPolicy {
    /// Maximum number of tokens (burst capacity).
    pub capacity: u32,
    /// Tokens added per second (sustained rate).
    pub refill_rate: f64,
}

impl Default for RateLimitPolicy {
    fn default() -> Self {
        Self {
            capacity: 10,
            refill_rate: 1.0,
        }
    }
}

/// Token-bucket rate limiter tracking per-relay quotas.
#[derive(Debug)]
pub struct RateLimiter {
    default_policy: RateLimitPolicy,
    buckets: HashMap<String, TokenBucket>,
}

#[derive(Debug)]
struct TokenBucket {
    tokens: f64,
    capacity: u32,
    refill_rate: f64,
    last_refill: Instant,
}

impl TokenBucket {
    fn new(policy: &RateLimitPolicy) -> Self {
        Self {
            tokens: policy.capacity as f64,
            capacity: policy.capacity,
            refill_rate: policy.refill_rate,
            last_refill: Instant::now(),
        }
    }

    fn try_consume(&mut self) -> bool {
        self.refill();
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.refill_rate).min(self.capacity as f64);
        self.last_refill = now;
    }

    fn time_until_available(&mut self) -> Duration {
        self.refill();
        if self.tokens >= 1.0 {
            Duration::ZERO
        } else {
            let deficit = 1.0 - self.tokens;
            Duration::from_secs_f64(deficit / self.refill_rate)
        }
    }
}

impl RateLimiter {
    /// Create a rate limiter with the given default policy.
    pub fn new(default_policy: RateLimitPolicy) -> Self {
        Self {
            default_policy,
            buckets: HashMap::new(),
        }
    }

    /// Set a custom policy for a specific relay URL.
    pub fn set_relay_policy(&mut self, relay_url: &str, policy: RateLimitPolicy) {
        let bucket = TokenBucket::new(&policy);
        self.buckets.insert(relay_url.to_string(), bucket);
    }

    /// Try to send a message to `relay_url`. Returns `Ok(())` if allowed,
    /// or `Err(SpamError::RateLimited)` with the wait duration if throttled.
    pub fn check(&mut self, relay_url: &str) -> Result<(), SpamError> {
        let bucket = self
            .buckets
            .entry(relay_url.to_string())
            .or_insert_with(|| TokenBucket::new(&self.default_policy));

        if bucket.try_consume() {
            Ok(())
        } else {
            let wait = bucket.time_until_available();
            Err(SpamError::RateLimited(format!(
                "relay {relay_url}: retry after {:.1}s",
                wait.as_secs_f64()
            )))
        }
    }

    /// Returns the estimated wait time before the next message can be sent
    /// to `relay_url`, or `Duration::ZERO` if a token is available now.
    pub fn time_until_ready(&mut self, relay_url: &str) -> Duration {
        let bucket = self
            .buckets
            .entry(relay_url.to_string())
            .or_insert_with(|| TokenBucket::new(&self.default_policy));
        bucket.time_until_available()
    }

    /// Reset the bucket for a relay (e.g. after reconnect).
    pub fn reset(&mut self, relay_url: &str) {
        self.buckets.remove(relay_url);
    }
}

// ===========================================================================
// 2. NIP-13 Proof-of-Work
// ===========================================================================

/// Count the number of leading zero bits in a hex-encoded event ID.
pub fn count_leading_zero_bits(hex_id: &str) -> Result<u8, SpamError> {
    let bytes = hex::decode(hex_id).map_err(|e| SpamError::InvalidHex(e.to_string()))?;
    let mut count: u8 = 0;
    for byte in &bytes {
        if *byte == 0 {
            count += 8;
        } else {
            count += byte.leading_zeros() as u8;
            break;
        }
    }
    Ok(count)
}

/// Verify that an event meets the required PoW difficulty (leading zero bits).
///
/// Per NIP-13, the event must have a `["nonce", "<nonce>", "<target>"]` tag
/// and the event ID must have at least `required_bits` leading zero bits.
pub fn verify_pow(event: &Event, required_bits: u8) -> Result<(), SpamError> {
    let actual = count_leading_zero_bits(&event.id)?;
    if actual >= required_bits {
        Ok(())
    } else {
        Err(SpamError::InsufficientPow {
            required: required_bits,
            actual,
        })
    }
}

/// Mine proof-of-work on an event by mutating the nonce tag until the
/// event ID has at least `target_bits` leading zero bits.
///
/// The event's `id` field is recomputed on each attempt. Returns the
/// number of iterations performed.
///
/// # Panics
///
/// Panics if `target_bits` > 64 (impractical to mine).
pub fn mine_pow(event: &mut Event, target_bits: u8) -> u64 {
    assert!(target_bits <= 64, "target_bits must be <= 64");

    // Find or create the nonce tag
    let nonce_idx = event
        .tags
        .iter()
        .position(|t| t.first().map(|s| s.as_str()) == Some("nonce"));

    let target_str = target_bits.to_string();

    match nonce_idx {
        Some(idx) => {
            // Ensure tag has 3 elements: ["nonce", "<val>", "<target>"]
            while event.tags[idx].len() < 3 {
                event.tags[idx].push(String::new());
            }
            event.tags[idx][2] = target_str.clone();
        }
        None => {
            event
                .tags
                .push(vec!["nonce".into(), "0".into(), target_str.clone()]);
        }
    }

    let nonce_idx = event
        .tags
        .iter()
        .position(|t| t.first().map(|s| s.as_str()) == Some("nonce"))
        .unwrap();

    let mut iterations: u64 = 0;

    loop {
        event.tags[nonce_idx][1] = iterations.to_string();
        let id = compute_event_id_raw(event);
        let bits = count_leading_zero_bits_bytes(&id);
        if bits >= target_bits {
            event.id = hex::encode(id);
            return iterations;
        }
        iterations += 1;
    }
}

/// Compute event ID as raw bytes (avoids hex encode/decode per iteration).
fn compute_event_id_raw(event: &Event) -> [u8; 32] {
    let serialized = format!(
        "[0,\"{}\",{},{},{},\"{}\"]",
        event.pubkey,
        event.created_at,
        event.kind,
        serde_json::to_string(&event.tags).unwrap(),
        event.content.replace('\\', "\\\\").replace('"', "\\\""),
    );
    let mut hasher = Sha256::new();
    hasher.update(serialized.as_bytes());
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Count leading zero bits directly on a byte array.
fn count_leading_zero_bits_bytes(bytes: &[u8]) -> u8 {
    let mut count: u8 = 0;
    for byte in bytes {
        if *byte == 0 {
            count += 8;
        } else {
            count += byte.leading_zeros() as u8;
            break;
        }
    }
    count
}

// ===========================================================================
// 3. Pubkey Allowlist
// ===========================================================================

/// Filter incoming events against a set of trusted public keys.
///
/// When the allowlist is non-empty, only events from listed pubkeys are
/// accepted. An empty allowlist accepts all events (open mode).
#[derive(Debug, Clone)]
pub struct PubkeyAllowlist {
    allowed: HashSet<String>,
}

impl PubkeyAllowlist {
    /// Create a new empty allowlist (open mode — all pubkeys accepted).
    pub fn new() -> Self {
        Self {
            allowed: HashSet::new(),
        }
    }

    /// Create an allowlist from an iterator of hex-encoded pubkeys.
    pub fn from_pubkeys(pubkeys: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            allowed: pubkeys.into_iter().map(Into::into).collect(),
        }
    }

    /// Add a hex-encoded pubkey to the allowlist.
    pub fn add(&mut self, pubkey: impl Into<String>) {
        self.allowed.insert(pubkey.into());
    }

    /// Remove a pubkey from the allowlist.
    pub fn remove(&mut self, pubkey: &str) -> bool {
        self.allowed.remove(pubkey)
    }

    /// Returns `true` if the allowlist is in open mode (empty).
    pub fn is_open(&self) -> bool {
        self.allowed.is_empty()
    }

    /// Returns the number of pubkeys in the allowlist.
    pub fn len(&self) -> usize {
        self.allowed.len()
    }

    /// Returns `true` if the allowlist has no entries (open mode).
    pub fn is_empty(&self) -> bool {
        self.allowed.is_empty()
    }

    /// Check whether an event's author is on the allowlist.
    ///
    /// Returns `Ok(())` if the allowlist is empty (open mode) or the
    /// event's pubkey is in the set. Returns `Err` otherwise.
    pub fn check(&self, event: &Event) -> Result<(), SpamError> {
        if self.allowed.is_empty() || self.allowed.contains(&event.pubkey) {
            Ok(())
        } else {
            Err(SpamError::PubkeyNotAllowed(event.pubkey.clone()))
        }
    }
}

impl Default for PubkeyAllowlist {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// 4. Zap Gate
// ===========================================================================

/// Zap-gating: require that a pubkey has payment history before accepting
/// broadcast messages from it.
///
/// Tracks cumulative zap amounts (in millisatoshis) per pubkey and
/// enforces a configurable minimum threshold.
#[derive(Debug, Clone)]
pub struct ZapGate {
    /// Minimum cumulative zap amount (millisatoshis) required.
    threshold_msats: u64,
    /// Recorded cumulative zap amounts per pubkey.
    ledger: HashMap<String, u64>,
}

impl ZapGate {
    /// Create a new zap gate with the given minimum threshold in millisatoshis.
    pub fn new(threshold_msats: u64) -> Self {
        Self {
            threshold_msats,
            ledger: HashMap::new(),
        }
    }

    /// Record a zap payment from `pubkey` of `amount_msats` millisatoshis.
    pub fn record_zap(&mut self, pubkey: &str, amount_msats: u64) {
        let entry = self.ledger.entry(pubkey.to_string()).or_insert(0);
        *entry = entry.saturating_add(amount_msats);
    }

    /// Get the cumulative zap total for a pubkey.
    pub fn zap_total(&self, pubkey: &str) -> u64 {
        self.ledger.get(pubkey).copied().unwrap_or(0)
    }

    /// Get the configured threshold in millisatoshis.
    pub fn threshold(&self) -> u64 {
        self.threshold_msats
    }

    /// Check whether `pubkey` has met the zap threshold.
    ///
    /// Returns `Ok(())` if the cumulative zap amount meets or exceeds the
    /// threshold. Returns `Err(SpamError::ZapGateRejected)` otherwise.
    pub fn check(&self, pubkey: &str) -> Result<(), SpamError> {
        let total = self.zap_total(pubkey);
        if total >= self.threshold_msats {
            Ok(())
        } else {
            Err(SpamError::ZapGateRejected(pubkey.to_string()))
        }
    }

    /// Check an event's author against the zap gate.
    pub fn check_event(&self, event: &Event) -> Result<(), SpamError> {
        self.check(&event.pubkey)
    }

    /// Remove a pubkey's payment record.
    pub fn clear(&mut self, pubkey: &str) {
        self.ledger.remove(pubkey);
    }

    /// Reset all payment records.
    pub fn clear_all(&mut self) {
        self.ledger.clear();
    }
}

// ===========================================================================
// Composite spam filter
// ===========================================================================

/// A composite inbound spam filter combining allowlist, PoW, and zap-gate
/// checks.
///
/// Checks are run in order: allowlist → PoW → zap-gate. The first failure
/// short-circuits.
#[derive(Debug)]
pub struct SpamFilter {
    /// Pubkey allowlist (empty = open).
    pub allowlist: PubkeyAllowlist,
    /// Required PoW difficulty in leading zero bits (0 = disabled).
    pub required_pow_bits: u8,
    /// Zap gate (None = disabled).
    pub zap_gate: Option<ZapGate>,
}

impl SpamFilter {
    /// Create a new spam filter with all checks disabled.
    pub fn new() -> Self {
        Self {
            allowlist: PubkeyAllowlist::new(),
            required_pow_bits: 0,
            zap_gate: None,
        }
    }

    /// Run all enabled checks on an incoming event.
    ///
    /// Returns `Ok(())` if the event passes all checks, or the first
    /// `SpamError` encountered.
    pub fn check_inbound(&self, event: &Event) -> Result<(), SpamError> {
        // 1. Allowlist
        self.allowlist.check(event)?;

        // 2. PoW
        if self.required_pow_bits > 0 {
            verify_pow(event, self.required_pow_bits)?;
        }

        // 3. Zap gate
        if let Some(ref gate) = self.zap_gate {
            gate.check_event(event)?;
        }

        Ok(())
    }
}

impl Default for SpamFilter {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_event(pubkey: &str, id: &str) -> Event {
        Event {
            id: id.to_string(),
            pubkey: pubkey.to_string(),
            created_at: 1700000000,
            kind: 21111,
            tags: vec![],
            content: "(tell @bob \"hi\")".to_string(),
            sig: "c".repeat(128),
        }
    }

    // ------------------------------------------------------------------
    // Rate limiter
    // ------------------------------------------------------------------

    #[test]
    fn rate_limiter_allows_within_capacity() {
        let mut rl = RateLimiter::new(RateLimitPolicy {
            capacity: 3,
            refill_rate: 1.0,
        });
        assert!(rl.check("wss://relay.example.com").is_ok());
        assert!(rl.check("wss://relay.example.com").is_ok());
        assert!(rl.check("wss://relay.example.com").is_ok());
    }

    #[test]
    fn rate_limiter_rejects_over_capacity() {
        let mut rl = RateLimiter::new(RateLimitPolicy {
            capacity: 2,
            refill_rate: 0.0001, // very slow refill
        });
        assert!(rl.check("wss://r.example.com").is_ok());
        assert!(rl.check("wss://r.example.com").is_ok());
        let err = rl.check("wss://r.example.com").unwrap_err();
        assert!(matches!(err, SpamError::RateLimited(_)));
    }

    #[test]
    fn rate_limiter_independent_relays() {
        let mut rl = RateLimiter::new(RateLimitPolicy {
            capacity: 1,
            refill_rate: 0.0001,
        });
        assert!(rl.check("wss://a.example.com").is_ok());
        assert!(rl.check("wss://b.example.com").is_ok());
        // a is now exhausted
        assert!(rl.check("wss://a.example.com").is_err());
    }

    #[test]
    fn rate_limiter_custom_relay_policy() {
        let mut rl = RateLimiter::new(RateLimitPolicy {
            capacity: 1,
            refill_rate: 0.0001,
        });
        rl.set_relay_policy(
            "wss://fast.example.com",
            RateLimitPolicy {
                capacity: 100,
                refill_rate: 10.0,
            },
        );
        // fast relay has large capacity
        for _ in 0..50 {
            assert!(rl.check("wss://fast.example.com").is_ok());
        }
    }

    #[test]
    fn rate_limiter_reset() {
        let mut rl = RateLimiter::new(RateLimitPolicy {
            capacity: 1,
            refill_rate: 0.0001,
        });
        assert!(rl.check("wss://r.example.com").is_ok());
        assert!(rl.check("wss://r.example.com").is_err());
        rl.reset("wss://r.example.com");
        assert!(rl.check("wss://r.example.com").is_ok());
    }

    #[test]
    fn rate_limiter_time_until_ready() {
        let mut rl = RateLimiter::new(RateLimitPolicy {
            capacity: 1,
            refill_rate: 1.0,
        });
        assert_eq!(rl.time_until_ready("wss://r.example.com"), Duration::ZERO);
        assert!(rl.check("wss://r.example.com").is_ok());
        let wait = rl.time_until_ready("wss://r.example.com");
        assert!(wait > Duration::ZERO);
    }

    // ------------------------------------------------------------------
    // NIP-13 PoW
    // ------------------------------------------------------------------

    #[test]
    fn count_leading_zeros_all_zero() {
        let id = format!("0000{}", "ff".repeat(30));
        assert_eq!(count_leading_zero_bits(&id).unwrap(), 16);
    }

    #[test]
    fn count_leading_zeros_none() {
        let id = "ff".repeat(32);
        assert_eq!(count_leading_zero_bits(&id).unwrap(), 0);
    }

    #[test]
    fn count_leading_zeros_partial() {
        // 0x0f = 0000_1111 => 4 leading zero bits
        let id = format!("0f{}", "aa".repeat(31));
        assert_eq!(count_leading_zero_bits(&id).unwrap(), 4);
    }

    #[test]
    fn count_leading_zeros_mixed() {
        // 0x00 0x01 => 8 + 7 = 15 leading zero bits
        let id = format!("0001{}", "bb".repeat(30));
        assert_eq!(count_leading_zero_bits(&id).unwrap(), 15);
    }

    #[test]
    fn verify_pow_sufficient() {
        let event = make_event("b".repeat(64).as_str(), &format!("0000{}", "aa".repeat(30)));
        assert!(verify_pow(&event, 16).is_ok());
        assert!(verify_pow(&event, 15).is_ok());
    }

    #[test]
    fn verify_pow_insufficient() {
        let event = make_event("b".repeat(64).as_str(), &format!("0f{}", "aa".repeat(31)));
        let err = verify_pow(&event, 8).unwrap_err();
        assert!(matches!(
            err,
            SpamError::InsufficientPow {
                required: 8,
                actual: 4
            }
        ));
    }

    #[test]
    fn mine_pow_produces_valid_result() {
        let mut event = Event {
            id: String::new(),
            pubkey: "b".repeat(64),
            created_at: 1700000000,
            kind: 21111,
            tags: vec![],
            content: "(hello)".to_string(),
            sig: String::new(),
        };
        let target = 8;
        let _iters = mine_pow(&mut event, target);
        assert!(verify_pow(&event, target).is_ok());
        // Verify nonce tag is present
        let nonce_tag = event
            .tags
            .iter()
            .find(|t| t.first().map(|s| s.as_str()) == Some("nonce"));
        assert!(nonce_tag.is_some());
        let tag = nonce_tag.unwrap();
        assert_eq!(tag[2], target.to_string());
    }

    #[test]
    fn mine_pow_zero_bits_trivial() {
        let mut event = Event {
            id: String::new(),
            pubkey: "b".repeat(64),
            created_at: 1700000000,
            kind: 21111,
            tags: vec![],
            content: "(hello)".to_string(),
            sig: String::new(),
        };
        let iters = mine_pow(&mut event, 0);
        assert_eq!(iters, 0); // first attempt always works for 0 bits
        assert!(verify_pow(&event, 0).is_ok());
    }

    // ------------------------------------------------------------------
    // Pubkey allowlist
    // ------------------------------------------------------------------

    #[test]
    fn allowlist_open_mode_accepts_all() {
        let al = PubkeyAllowlist::new();
        assert!(al.is_open());
        let event = make_event(&"a".repeat(64), &"0".repeat(64));
        assert!(al.check(&event).is_ok());
    }

    #[test]
    fn allowlist_accepts_listed_pubkey() {
        let pk = "a".repeat(64);
        let al = PubkeyAllowlist::from_pubkeys(vec![pk.clone()]);
        assert!(!al.is_open());
        assert_eq!(al.len(), 1);
        let event = make_event(&pk, &"0".repeat(64));
        assert!(al.check(&event).is_ok());
    }

    #[test]
    fn allowlist_rejects_unlisted_pubkey() {
        let al = PubkeyAllowlist::from_pubkeys(vec!["a".repeat(64)]);
        let event = make_event(&"b".repeat(64), &"0".repeat(64));
        let err = al.check(&event).unwrap_err();
        assert!(matches!(err, SpamError::PubkeyNotAllowed(_)));
    }

    #[test]
    fn allowlist_add_remove() {
        let mut al = PubkeyAllowlist::new();
        let pk = "a".repeat(64);
        al.add(pk.clone());
        assert_eq!(al.len(), 1);
        assert!(al.remove(&pk));
        assert!(al.is_open());
    }

    // ------------------------------------------------------------------
    // Zap gate
    // ------------------------------------------------------------------

    #[test]
    fn zap_gate_rejects_without_history() {
        let gate = ZapGate::new(1000);
        let err = gate.check("unknown_pk").unwrap_err();
        assert!(matches!(err, SpamError::ZapGateRejected(_)));
    }

    #[test]
    fn zap_gate_accepts_after_payment() {
        let mut gate = ZapGate::new(1000);
        gate.record_zap("pk1", 500);
        assert!(gate.check("pk1").is_err()); // still below threshold
        gate.record_zap("pk1", 500);
        assert!(gate.check("pk1").is_ok()); // exactly at threshold
    }

    #[test]
    fn zap_gate_cumulative() {
        let mut gate = ZapGate::new(100);
        gate.record_zap("pk1", 30);
        gate.record_zap("pk1", 30);
        gate.record_zap("pk1", 40);
        assert_eq!(gate.zap_total("pk1"), 100);
        assert!(gate.check("pk1").is_ok());
    }

    #[test]
    fn zap_gate_check_event() {
        let mut gate = ZapGate::new(100);
        let pk = "a".repeat(64);
        gate.record_zap(&pk, 200);
        let event = make_event(&pk, &"0".repeat(64));
        assert!(gate.check_event(&event).is_ok());
    }

    #[test]
    fn zap_gate_clear() {
        let mut gate = ZapGate::new(100);
        gate.record_zap("pk1", 200);
        gate.clear("pk1");
        assert!(gate.check("pk1").is_err());
    }

    #[test]
    fn zap_gate_clear_all() {
        let mut gate = ZapGate::new(100);
        gate.record_zap("pk1", 200);
        gate.record_zap("pk2", 300);
        gate.clear_all();
        assert!(gate.check("pk1").is_err());
        assert!(gate.check("pk2").is_err());
    }

    #[test]
    fn zap_gate_threshold() {
        let gate = ZapGate::new(42);
        assert_eq!(gate.threshold(), 42);
    }

    #[test]
    fn zap_gate_saturating_add() {
        let mut gate = ZapGate::new(1);
        gate.record_zap("pk1", u64::MAX);
        gate.record_zap("pk1", 1);
        assert_eq!(gate.zap_total("pk1"), u64::MAX);
    }

    // ------------------------------------------------------------------
    // Composite spam filter
    // ------------------------------------------------------------------

    #[test]
    fn spam_filter_all_disabled_accepts() {
        let filter = SpamFilter::new();
        let event = make_event(&"a".repeat(64), &"ff".repeat(32));
        assert!(filter.check_inbound(&event).is_ok());
    }

    #[test]
    fn spam_filter_allowlist_rejects() {
        let mut filter = SpamFilter::new();
        filter.allowlist.add("a".repeat(64));
        let event = make_event(&"b".repeat(64), &"ff".repeat(32));
        let err = filter.check_inbound(&event).unwrap_err();
        assert!(matches!(err, SpamError::PubkeyNotAllowed(_)));
    }

    #[test]
    fn spam_filter_pow_rejects() {
        let mut filter = SpamFilter::new();
        filter.required_pow_bits = 16;
        let event = make_event(&"a".repeat(64), &"ff".repeat(32));
        let err = filter.check_inbound(&event).unwrap_err();
        assert!(matches!(err, SpamError::InsufficientPow { .. }));
    }

    #[test]
    fn spam_filter_zap_gate_rejects() {
        let mut filter = SpamFilter::new();
        filter.zap_gate = Some(ZapGate::new(1000));
        let event = make_event(&"a".repeat(64), &"00".repeat(32));
        let err = filter.check_inbound(&event).unwrap_err();
        assert!(matches!(err, SpamError::ZapGateRejected(_)));
    }

    #[test]
    fn spam_filter_all_pass() {
        let pk = "a".repeat(64);
        let mut filter = SpamFilter::new();
        filter.allowlist.add(pk.clone());
        filter.required_pow_bits = 8;
        let mut gate = ZapGate::new(100);
        gate.record_zap(&pk, 200);
        filter.zap_gate = Some(gate);

        // Event with sufficient PoW
        let event = make_event(&pk, &format!("00{}", "aa".repeat(31)));
        assert!(filter.check_inbound(&event).is_ok());
    }

    #[test]
    fn spam_filter_short_circuits_on_allowlist() {
        let mut filter = SpamFilter::new();
        filter.allowlist.add("a".repeat(64));
        filter.required_pow_bits = 32; // extremely high, but won't be reached
        filter.zap_gate = Some(ZapGate::new(u64::MAX));

        // Rejected pubkey — never reaches PoW or zap check
        let event = make_event(&"b".repeat(64), &"00".repeat(32));
        let err = filter.check_inbound(&event).unwrap_err();
        assert!(matches!(err, SpamError::PubkeyNotAllowed(_)));
    }
}
