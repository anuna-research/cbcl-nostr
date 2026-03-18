//! NIP-59 Gift Wrap for confidential agent communication.
//!
//! Wraps CBCL messages (kind 21111 agent messages, kind 31111 dialect
//! definitions) in a two-layer encryption envelope:
//!
//! 1. **Rumor** — the inner event, unsigned, containing the actual CBCL
//!    S-expression content.
//! 2. **Seal (kind 13)** — the rumor serialized to JSON and encrypted with
//!    NIP-44 between the real sender and recipient. Signed by the sender.
//! 3. **Gift Wrap (kind 1059)** — the seal serialized to JSON and encrypted
//!    with NIP-44 between a random ephemeral key and the recipient. Signed
//!    by the ephemeral key. Timestamp is randomized to prevent correlation.
//!
//! The receiver unwraps the gift wrap using their secret key, decrypts the
//! seal, verifies the sender's signature, decrypts the rumor, and passes
//! it to the inbox handler for CBCL parsing.

#![forbid(unsafe_code)]

use secp256k1::{Keypair, Secp256k1, XOnlyPublicKey};

use crate::event_signing::{
    conversation_key, nip44_decrypt, nip44_encrypt, sign_event, verify_event, Nip44Error,
    SigningError,
};
use crate::event_types::Event;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Nostr event kind for a sealed event (NIP-59).
pub const KIND_SEAL: u64 = 13;

/// Nostr event kind for a gift-wrapped event (NIP-59).
pub const KIND_GIFT_WRAP: u64 = 1059;

/// Maximum random offset (in seconds) applied to gift wrap timestamps.
/// NIP-59 recommends randomizing ±2 days.
const TIMESTAMP_JITTER_SECS: u64 = 2 * 24 * 60 * 60;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors from gift wrap and unwrap operations.
#[derive(Debug, thiserror::Error)]
pub enum GiftWrapError {
    /// Event signing or verification failed.
    #[error("signing error: {0}")]
    Signing(#[from] SigningError),

    /// NIP-44 encryption or decryption failed.
    #[error("nip44 error: {0}")]
    Nip44(#[from] Nip44Error),

    /// JSON serialization/deserialization failed.
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    /// The outer event kind is not the expected gift wrap or seal kind.
    #[error("wrong kind: expected {expected}, got {got}")]
    WrongKind { expected: u64, got: u64 },

    /// Hex encoding/decoding failed.
    #[error("hex error: {0}")]
    Hex(#[from] hex::FromHexError),

    /// secp256k1 key operation failed.
    #[error("secp256k1 error: {0}")]
    Secp256k1(#[from] secp256k1::Error),
}

// ---------------------------------------------------------------------------
// Gift wrap creation
// ---------------------------------------------------------------------------

/// Create a NIP-59 gift-wrapped event.
///
/// Takes an inner event (the rumor, which should be unsigned), encrypts it
/// in a two-layer envelope, and returns the outer gift wrap event ready for
/// publishing.
///
/// # Arguments
///
/// * `rumor` — The inner event to wrap. Its `id`, `sig`, `pubkey`, and
///   `created_at` fields will be set/cleared as needed. The rumor is NOT
///   signed (per NIP-59).
/// * `sender_secret_key_hex` — 32-byte hex secret key of the real sender.
/// * `recipient_pubkey_hex` — 32-byte hex x-only public key of the recipient.
/// * `now` — Current unix timestamp in seconds.
pub fn gift_wrap(
    mut rumor: Event,
    sender_secret_key_hex: &str,
    recipient_pubkey_hex: &str,
    now: u64,
) -> Result<Event, GiftWrapError> {
    // Derive sender pubkey
    let secp = Secp256k1::new();
    let sk_bytes = hex::decode(sender_secret_key_hex)?;
    let sk = secp256k1::SecretKey::from_slice(&sk_bytes)?;
    let keypair = Keypair::from_secret_key(&secp, &sk);
    let (sender_xonly, _) = XOnlyPublicKey::from_keypair(&keypair);
    let sender_pubkey_hex = hex::encode(sender_xonly.serialize());

    // Step 1: Prepare the rumor (unsigned inner event)
    rumor.pubkey = sender_pubkey_hex;
    rumor.created_at = now;
    // Compute ID for the rumor so receivers can reference it, but leave sig empty
    rumor.id = crate::event_signing::compute_event_id(&rumor);
    rumor.sig = String::new();

    let rumor_json = serde_json::to_string(&rumor)?;

    // Step 2: Create the seal (kind 13)
    let sender_recipient_ck = conversation_key(sender_secret_key_hex, recipient_pubkey_hex)?;
    let encrypted_rumor = nip44_encrypt(&sender_recipient_ck, &rumor_json)?;

    let mut seal = Event {
        id: String::new(),
        pubkey: String::new(),
        created_at: 0,
        kind: KIND_SEAL,
        tags: vec![],
        content: encrypted_rumor,
        sig: String::new(),
    };
    sign_event(&mut seal, sender_secret_key_hex, now)?;

    // Step 3: Create the gift wrap (kind 1059) with ephemeral key
    let ephemeral_sk = generate_ephemeral_key();
    let ephemeral_sk_hex = hex::encode(&ephemeral_sk);

    let ephemeral_recipient_ck = conversation_key(&ephemeral_sk_hex, recipient_pubkey_hex)?;
    let seal_json = serde_json::to_string(&seal)?;
    let encrypted_seal = nip44_encrypt(&ephemeral_recipient_ck, &seal_json)?;

    // Randomize the timestamp to prevent timing correlation
    let jittered_ts = randomize_timestamp(now);

    let mut wrap = Event {
        id: String::new(),
        pubkey: String::new(),
        created_at: 0,
        kind: KIND_GIFT_WRAP,
        tags: vec![vec!["p".into(), recipient_pubkey_hex.to_string()]],
        content: encrypted_seal,
        sig: String::new(),
    };
    sign_event(&mut wrap, &ephemeral_sk_hex, jittered_ts)?;

    Ok(wrap)
}

// ---------------------------------------------------------------------------
// Gift wrap unwrapping
// ---------------------------------------------------------------------------

/// Result of unwrapping a gift-wrapped event.
#[derive(Debug, Clone)]
pub struct UnwrappedEvent {
    /// The decrypted inner event (rumor). Note: the rumor is unsigned per
    /// NIP-59 — its `sig` field will be empty.
    pub rumor: Event,
    /// The public key of the real sender (from the verified seal).
    pub sender_pubkey: String,
}

/// Unwrap a NIP-59 gift-wrapped event.
///
/// Decrypts the two-layer envelope and returns the inner rumor along with
/// the verified sender public key.
///
/// # Arguments
///
/// * `wrapped` — The gift wrap event (kind 1059).
/// * `recipient_secret_key_hex` — 32-byte hex secret key of the recipient.
pub fn unwrap_gift(
    wrapped: &Event,
    recipient_secret_key_hex: &str,
) -> Result<UnwrappedEvent, GiftWrapError> {
    // Validate outer kind
    if wrapped.kind != KIND_GIFT_WRAP {
        return Err(GiftWrapError::WrongKind {
            expected: KIND_GIFT_WRAP,
            got: wrapped.kind,
        });
    }

    // Step 1: Decrypt the seal using recipient's key + ephemeral pubkey
    let ephemeral_pubkey = &wrapped.pubkey;
    let ck_outer = conversation_key(recipient_secret_key_hex, ephemeral_pubkey)?;
    let seal_json = nip44_decrypt(&ck_outer, &wrapped.content)?;
    let seal: Event = serde_json::from_str(&seal_json)?;

    // Validate seal kind
    if seal.kind != KIND_SEAL {
        return Err(GiftWrapError::WrongKind {
            expected: KIND_SEAL,
            got: seal.kind,
        });
    }

    // Verify the seal's signature (proves the sender's identity)
    verify_event(&seal)?;

    let sender_pubkey = seal.pubkey.clone();

    // Step 2: Decrypt the rumor using recipient's key + sender's pubkey
    let ck_inner = conversation_key(recipient_secret_key_hex, &sender_pubkey)?;
    let rumor_json = nip44_decrypt(&ck_inner, &seal.content)?;
    let rumor: Event = serde_json::from_str(&rumor_json)?;

    Ok(UnwrappedEvent {
        rumor,
        sender_pubkey,
    })
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Generate a random 32-byte ephemeral secret key.
fn generate_ephemeral_key() -> [u8; 32] {
    use rand::RngCore;
    let secp = Secp256k1::new();
    loop {
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        // Ensure it's a valid secp256k1 secret key
        if secp256k1::SecretKey::from_slice(&bytes).is_ok() {
            // Verify we can derive a valid keypair
            let sk = secp256k1::SecretKey::from_slice(&bytes).unwrap();
            let _ = Keypair::from_secret_key(&secp, &sk);
            return bytes;
        }
    }
}

/// Apply random jitter to a timestamp (±TIMESTAMP_JITTER_SECS).
fn randomize_timestamp(now: u64) -> u64 {
    use rand::Rng;
    let jitter: i64 = rand::thread_rng().gen_range(
        -(TIMESTAMP_JITTER_SECS as i64)..=(TIMESTAMP_JITTER_SECS as i64),
    );
    (now as i64 + jitter).max(0) as u64
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event_types::{KIND_AGENT_DIALECT, KIND_AGENT_MESSAGE};

    /// Generate a fresh keypair, returning (secret_key_hex, pubkey_hex).
    fn gen_keypair() -> (String, String) {
        let secp = Secp256k1::new();
        let (sk, _pk) = secp.generate_keypair(&mut rand::thread_rng());
        let keypair = Keypair::from_secret_key(&secp, &sk);
        let (xonly, _) = XOnlyPublicKey::from_keypair(&keypair);
        (
            hex::encode(sk.secret_bytes()),
            hex::encode(xonly.serialize()),
        )
    }

    fn make_rumor(kind: u64, content: &str, tags: Vec<Vec<String>>) -> Event {
        Event {
            id: String::new(),
            pubkey: String::new(),
            created_at: 0,
            kind,
            tags,
            content: content.to_string(),
            sig: String::new(),
        }
    }

    // ====================================================================
    // Basic round-trip
    // ====================================================================

    #[test]
    fn gift_wrap_round_trip_agent_message() {
        let (sender_sk, _sender_pk) = gen_keypair();
        let (recipient_sk, recipient_pk) = gen_keypair();
        let now = 1700000000u64;

        let rumor = make_rumor(
            KIND_AGENT_MESSAGE,
            r#"(tell @bob "hello")"#,
            vec![
                vec!["p".into(), recipient_pk.clone()],
                vec!["performative".into(), "tell".into()],
            ],
        );

        let wrapped = gift_wrap(rumor, &sender_sk, &recipient_pk, now).unwrap();

        // Outer event should be kind 1059
        assert_eq!(wrapped.kind, KIND_GIFT_WRAP);
        // Should have a p tag for the recipient
        assert!(wrapped.tags.iter().any(|t| t.len() >= 2
            && t[0] == "p"
            && t[1] == recipient_pk));

        // Unwrap
        let result = unwrap_gift(&wrapped, &recipient_sk).unwrap();
        assert_eq!(result.rumor.content, r#"(tell @bob "hello")"#);
        assert_eq!(result.rumor.kind, KIND_AGENT_MESSAGE);
        assert!(!result.sender_pubkey.is_empty());
        // Rumor should be unsigned
        assert!(result.rumor.sig.is_empty());
    }

    #[test]
    fn gift_wrap_round_trip_agent_dialect() {
        let (sender_sk, _sender_pk) = gen_keypair();
        let (recipient_sk, recipient_pk) = gen_keypair();
        let now = 1700000000u64;

        let rumor = make_rumor(
            KIND_AGENT_DIALECT,
            "(meta (define commerce :extends cbcl-base))",
            vec![
                vec!["dialect".into(), "commerce".into()],
                vec!["L".into(), "cbcl.dialect".into()],
                vec!["l".into(), "commerce".into(), "cbcl.dialect".into()],
            ],
        );

        let wrapped = gift_wrap(rumor, &sender_sk, &recipient_pk, now).unwrap();
        let result = unwrap_gift(&wrapped, &recipient_sk).unwrap();

        assert_eq!(result.rumor.kind, KIND_AGENT_DIALECT);
        assert_eq!(
            result.rumor.content,
            "(meta (define commerce :extends cbcl-base))"
        );
    }

    // ====================================================================
    // Sender identity
    // ====================================================================

    #[test]
    fn unwrap_reveals_correct_sender() {
        let (sender_sk, sender_pk) = gen_keypair();
        let (recipient_sk, recipient_pk) = gen_keypair();

        let rumor = make_rumor(KIND_AGENT_MESSAGE, "(hello)", vec![]);
        let wrapped = gift_wrap(rumor, &sender_sk, &recipient_pk, 1700000000).unwrap();
        let result = unwrap_gift(&wrapped, &recipient_sk).unwrap();

        assert_eq!(result.sender_pubkey, sender_pk);
    }

    // ====================================================================
    // Ephemeral key hides sender
    // ====================================================================

    #[test]
    fn outer_pubkey_is_ephemeral_not_sender() {
        let (sender_sk, sender_pk) = gen_keypair();
        let (_recipient_sk, recipient_pk) = gen_keypair();

        let rumor = make_rumor(KIND_AGENT_MESSAGE, "(hello)", vec![]);
        let wrapped = gift_wrap(rumor, &sender_sk, &recipient_pk, 1700000000).unwrap();

        // The outer pubkey should NOT be the sender's pubkey
        assert_ne!(wrapped.pubkey, sender_pk);
    }

    // ====================================================================
    // Wrong recipient cannot unwrap
    // ====================================================================

    #[test]
    fn wrong_recipient_cannot_unwrap() {
        let (sender_sk, _sender_pk) = gen_keypair();
        let (_recipient_sk, recipient_pk) = gen_keypair();
        let (wrong_sk, _wrong_pk) = gen_keypair();

        let rumor = make_rumor(KIND_AGENT_MESSAGE, "(hello)", vec![]);
        let wrapped = gift_wrap(rumor, &sender_sk, &recipient_pk, 1700000000).unwrap();

        // A third party should not be able to unwrap
        assert!(unwrap_gift(&wrapped, &wrong_sk).is_err());
    }

    // ====================================================================
    // Wrong kind rejected
    // ====================================================================

    #[test]
    fn unwrap_rejects_non_gift_wrap_kind() {
        let event = Event {
            id: "a".repeat(64),
            pubkey: "b".repeat(64),
            created_at: 1700000000,
            kind: KIND_AGENT_MESSAGE,
            tags: vec![],
            content: String::new(),
            sig: "c".repeat(128),
        };
        let (recipient_sk, _) = gen_keypair();
        let err = unwrap_gift(&event, &recipient_sk).unwrap_err();
        assert!(matches!(
            err,
            GiftWrapError::WrongKind {
                expected: KIND_GIFT_WRAP,
                ..
            }
        ));
    }

    // ====================================================================
    // Timestamp jitter
    // ====================================================================

    #[test]
    fn gift_wrap_timestamp_is_jittered() {
        let (sender_sk, _sender_pk) = gen_keypair();
        let (_recipient_sk, recipient_pk) = gen_keypair();
        let now = 1700000000u64;

        // Create multiple wraps and check that timestamps vary
        let mut timestamps = Vec::new();
        for _ in 0..10 {
            let rumor = make_rumor(KIND_AGENT_MESSAGE, "(hello)", vec![]);
            let wrapped = gift_wrap(rumor, &sender_sk, &recipient_pk, now).unwrap();
            timestamps.push(wrapped.created_at);
        }

        // At least some timestamps should differ from `now`
        let differs = timestamps.iter().any(|&ts| ts != now);
        assert!(differs, "expected jittered timestamps but all equal {now}");
    }

    // ====================================================================
    // Tampered gift wrap
    // ====================================================================

    #[test]
    fn tampered_content_fails_unwrap() {
        let (sender_sk, _sender_pk) = gen_keypair();
        let (recipient_sk, recipient_pk) = gen_keypair();

        let rumor = make_rumor(KIND_AGENT_MESSAGE, "(hello)", vec![]);
        let mut wrapped = gift_wrap(rumor, &sender_sk, &recipient_pk, 1700000000).unwrap();

        // Tamper with the encrypted content
        wrapped.content = "definitely-not-valid-base64-payload!!".into();
        assert!(unwrap_gift(&wrapped, &recipient_sk).is_err());
    }

    // ====================================================================
    // Inner event tags preserved
    // ====================================================================

    #[test]
    fn inner_tags_preserved_through_wrap() {
        let (sender_sk, _sender_pk) = gen_keypair();
        let (recipient_sk, recipient_pk) = gen_keypair();

        let rumor = make_rumor(
            KIND_AGENT_MESSAGE,
            r#"(tell @bob "hi")"#,
            vec![
                vec!["p".into(), recipient_pk.clone()],
                vec!["performative".into(), "tell".into()],
                vec!["thread".into(), "conv-42".into()],
                vec!["dialect".into(), "commerce".into()],
            ],
        );

        let wrapped = gift_wrap(rumor, &sender_sk, &recipient_pk, 1700000000).unwrap();
        let result = unwrap_gift(&wrapped, &recipient_sk).unwrap();

        // All original tags should be present in the rumor
        assert_eq!(result.rumor.tags.len(), 4);
        assert_eq!(result.rumor.tags[0], vec!["p", &recipient_pk]);
        assert_eq!(result.rumor.tags[1], vec!["performative", "tell"]);
        assert_eq!(result.rumor.tags[2], vec!["thread", "conv-42"]);
        assert_eq!(result.rumor.tags[3], vec!["dialect", "commerce"]);
    }

    // ====================================================================
    // Rumor has ID but no signature
    // ====================================================================

    #[test]
    fn rumor_has_id_but_empty_sig() {
        let (sender_sk, _sender_pk) = gen_keypair();
        let (recipient_sk, recipient_pk) = gen_keypair();

        let rumor = make_rumor(KIND_AGENT_MESSAGE, "(hello)", vec![]);
        let wrapped = gift_wrap(rumor, &sender_sk, &recipient_pk, 1700000000).unwrap();
        let result = unwrap_gift(&wrapped, &recipient_sk).unwrap();

        assert!(!result.rumor.id.is_empty(), "rumor should have an ID");
        assert_eq!(result.rumor.id.len(), 64, "rumor ID should be 32-byte hex");
        assert!(result.rumor.sig.is_empty(), "rumor should be unsigned");
    }

    // ====================================================================
    // Multiple wraps produce different ciphertexts
    // ====================================================================

    #[test]
    fn same_message_produces_different_wraps() {
        let (sender_sk, _sender_pk) = gen_keypair();
        let (_recipient_sk, recipient_pk) = gen_keypair();

        let rumor1 = make_rumor(KIND_AGENT_MESSAGE, "(hello)", vec![]);
        let rumor2 = make_rumor(KIND_AGENT_MESSAGE, "(hello)", vec![]);

        let wrap1 = gift_wrap(rumor1, &sender_sk, &recipient_pk, 1700000000).unwrap();
        let wrap2 = gift_wrap(rumor2, &sender_sk, &recipient_pk, 1700000000).unwrap();

        // Different ephemeral keys → different ciphertexts
        assert_ne!(wrap1.content, wrap2.content);
        // Different ephemeral pubkeys
        assert_ne!(wrap1.pubkey, wrap2.pubkey);
    }

    // ====================================================================
    // Verify outer event signature
    // ====================================================================

    #[test]
    fn outer_event_has_valid_signature() {
        let (sender_sk, _sender_pk) = gen_keypair();
        let (_recipient_sk, recipient_pk) = gen_keypair();

        let rumor = make_rumor(KIND_AGENT_MESSAGE, "(hello)", vec![]);
        let wrapped = gift_wrap(rumor, &sender_sk, &recipient_pk, 1700000000).unwrap();

        // The outer event itself should have a valid signature (from ephemeral key)
        verify_event(&wrapped).unwrap();
    }
}
