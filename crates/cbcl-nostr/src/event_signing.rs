//! Nostr event signing, verification, and NIP-44 encryption primitives.
//!
//! Provides:
//! - Event ID computation per NIP-01 (SHA-256 of canonical serialization).
//! - Schnorr signing and verification using secp256k1.
//! - NIP-44 v2 encrypt/decrypt for private agent-to-agent messages.

#![forbid(unsafe_code)]

use hmac::{Hmac, Mac};
use secp256k1::{Keypair, PublicKey, Secp256k1, SecretKey, XOnlyPublicKey};
use sha2::{Digest, Sha256};

use crate::event_types::Event;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors from event signing and verification.
#[derive(Debug, thiserror::Error)]
pub enum SigningError {
    /// Hex decoding failed.
    #[error("hex error: {0}")]
    Hex(#[from] hex::FromHexError),

    /// secp256k1 operation failed.
    #[error("secp256k1 error: {0}")]
    Secp256k1(#[from] secp256k1::Error),

    /// Event ID does not match computed hash.
    #[error("event id mismatch: expected {expected}, got {got}")]
    IdMismatch { expected: String, got: String },
}

/// Errors from NIP-44 encryption/decryption.
#[derive(Debug, thiserror::Error)]
pub enum Nip44Error {
    /// Hex decoding failed.
    #[error("hex error: {0}")]
    Hex(#[from] hex::FromHexError),

    /// secp256k1 operation failed.
    #[error("secp256k1 error: {0}")]
    Secp256k1(#[from] secp256k1::Error),

    /// Base64 decoding failed.
    #[error("base64 error: {0}")]
    Base64(#[from] base64::DecodeError),

    /// Invalid payload structure.
    #[error("invalid payload: {0}")]
    InvalidPayload(String),

    /// AEAD encryption/decryption failed.
    #[error("aead error")]
    Aead,

    /// HMAC verification failed.
    #[error("hmac verification failed")]
    HmacMismatch,
}

// ---------------------------------------------------------------------------
// Event ID computation
// ---------------------------------------------------------------------------

/// Compute the NIP-01 event ID: SHA-256 of `[0, pubkey, created_at, kind, tags, content]`.
///
/// Returns the 32-byte hash as a lowercase hex string.
pub fn compute_event_id(event: &Event) -> String {
    let serialized = serde_json::json!([
        0,
        event.pubkey,
        event.created_at,
        event.kind,
        event.tags,
        event.content,
    ]);
    let bytes = serialized.to_string().into_bytes();
    let hash = Sha256::digest(&bytes);
    hex::encode(hash)
}

// ---------------------------------------------------------------------------
// Signing
// ---------------------------------------------------------------------------

/// Sign an event in place, filling in `pubkey`, `created_at`, `id`, and `sig`.
///
/// The `secret_key_hex` must be a 32-byte lowercase hex-encoded secret key.
/// `created_at` is set to the provided timestamp (pass `now()` from the caller).
pub fn sign_event(
    event: &mut Event,
    secret_key_hex: &str,
    created_at: u64,
) -> Result<(), SigningError> {
    let secp = Secp256k1::new();
    let sk_bytes = hex::decode(secret_key_hex)?;
    let sk = SecretKey::from_slice(&sk_bytes)?;
    let keypair = Keypair::from_secret_key(&secp, &sk);
    let (xonly, _parity) = XOnlyPublicKey::from_keypair(&keypair);

    event.pubkey = hex::encode(xonly.serialize());
    event.created_at = created_at;
    event.id = compute_event_id(event);

    let id_bytes = hex::decode(&event.id)?;
    let sig = secp.sign_schnorr(&id_bytes, &keypair);
    event.sig = hex::encode(sig.as_ref());

    Ok(())
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

/// Verify an event's ID and Schnorr signature.
///
/// Checks that:
/// 1. The `id` field matches the SHA-256 of the canonical serialization.
/// 2. The `sig` field is a valid Schnorr signature over `id` by `pubkey`.
pub fn verify_event(event: &Event) -> Result<(), SigningError> {
    // Verify ID
    let computed_id = compute_event_id(event);
    if computed_id != event.id {
        return Err(SigningError::IdMismatch {
            expected: computed_id,
            got: event.id.clone(),
        });
    }

    // Verify signature
    let secp = Secp256k1::verification_only();
    let pk_bytes = hex::decode(&event.pubkey)?;
    let xonly = XOnlyPublicKey::from_slice(&pk_bytes)?;
    let id_bytes = hex::decode(&event.id)?;
    let sig_bytes = hex::decode(&event.sig)?;
    let sig = secp256k1::schnorr::Signature::from_slice(&sig_bytes)?;

    secp.verify_schnorr(&sig, &id_bytes, &xonly)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// NIP-44 v2 primitives
// ---------------------------------------------------------------------------

/// NIP-44 protocol version byte.
const NIP44_VERSION: u8 = 2;

/// Salt used for HKDF extract when deriving the conversation key.
const NIP44_SALT: &[u8] = b"nip44-v2";

/// Compute a NIP-44 conversation key from a secret key and a recipient's public key.
///
/// Performs ECDH and then HKDF-extract with `NIP44_SALT`.
pub fn conversation_key(
    secret_key_hex: &str,
    pubkey_hex: &str,
) -> Result<[u8; 32], Nip44Error> {
    let sk_bytes = hex::decode(secret_key_hex)?;
    let sk = SecretKey::from_slice(&sk_bytes)?;

    // Reconstruct full 33-byte compressed public key (02 prefix for even parity)
    let mut pk_full = [0u8; 33];
    pk_full[0] = 0x02;
    let pk_bytes = hex::decode(pubkey_hex)?;
    pk_full[1..].copy_from_slice(&pk_bytes);
    let pk = PublicKey::from_slice(&pk_full)?;

    // ECDH: shared point x-coordinate
    let shared = secp256k1::ecdh::shared_secret_point(&pk, &sk);
    // shared_secret_point returns 64 bytes (x || y), we want the first 32 (x)
    let shared_x = &shared[..32];

    // HKDF extract
    let hk = hkdf::Hkdf::<Sha256>::new(Some(NIP44_SALT), shared_x);
    let mut ck = [0u8; 32];
    hk.expand(b"", &mut ck)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    Ok(ck)
}

/// Derive message keys (chacha_key, chacha_nonce, hmac_key) from a conversation
/// key and a 32-byte nonce via HKDF-expand.
fn message_keys(conversation_key: &[u8; 32], nonce: &[u8; 32]) -> ([u8; 32], [u8; 12], [u8; 32]) {
    let hk = hkdf::Hkdf::<Sha256>::new(Some(nonce), conversation_key);
    let mut okm = [0u8; 76]; // 32 + 12 + 32
    hk.expand(b"nip44-v2", &mut okm)
        .expect("76 bytes is valid for HKDF-SHA256");
    let mut chacha_key = [0u8; 32];
    let mut chacha_nonce = [0u8; 12];
    let mut hmac_key = [0u8; 32];
    chacha_key.copy_from_slice(&okm[..32]);
    chacha_nonce.copy_from_slice(&okm[32..44]);
    hmac_key.copy_from_slice(&okm[44..76]);
    (chacha_key, chacha_nonce, hmac_key)
}

/// Pad plaintext according to NIP-44 v2 padding rules.
///
/// Format: 2-byte big-endian length prefix + plaintext + zero padding to next power-of-2 boundary.
fn pad_plaintext(plaintext: &[u8]) -> Vec<u8> {
    let len = plaintext.len();
    assert!(len > 0 && len <= 65535, "plaintext length out of range");

    // Calculate padded length: next power of 2, minimum 32
    let padded_len = if len <= 32 {
        32
    } else {
        len.next_power_of_two()
    };

    let mut padded = Vec::with_capacity(2 + padded_len);
    padded.push((len >> 8) as u8);
    padded.push((len & 0xff) as u8);
    padded.extend_from_slice(plaintext);
    padded.resize(2 + padded_len, 0);
    padded
}

/// Unpad a NIP-44 v2 padded plaintext.
fn unpad_plaintext(padded: &[u8]) -> Result<Vec<u8>, Nip44Error> {
    if padded.len() < 2 {
        return Err(Nip44Error::InvalidPayload("padded data too short".into()));
    }
    let len = ((padded[0] as usize) << 8) | (padded[1] as usize);
    if len == 0 || 2 + len > padded.len() {
        return Err(Nip44Error::InvalidPayload(format!(
            "invalid plaintext length {len} for padded size {}",
            padded.len()
        )));
    }
    Ok(padded[2..2 + len].to_vec())
}

/// Encrypt a plaintext string using NIP-44 v2.
///
/// Returns a base64-encoded payload: `version(1) || nonce(32) || ciphertext(variable) || hmac(32)`.
pub fn nip44_encrypt(
    conversation_key: &[u8; 32],
    plaintext: &str,
) -> Result<String, Nip44Error> {
    use chacha20poly1305::aead::KeyInit;
    use chacha20poly1305::{ChaCha20Poly1305, aead::Aead};

    let mut nonce_bytes = [0u8; 32];
    getrandom(&mut nonce_bytes);

    let padded = pad_plaintext(plaintext.as_bytes());
    let (chacha_key, chacha_nonce, hmac_key) = message_keys(conversation_key, &nonce_bytes);

    // Encrypt with ChaCha20-Poly1305 (using the 12-byte nonce from HKDF)
    let cipher = ChaCha20Poly1305::new((&chacha_key).into());
    let ciphertext = cipher
        .encrypt((&chacha_nonce).into(), padded.as_ref())
        .map_err(|_| Nip44Error::Aead)?;

    // Build payload: version || nonce || ciphertext
    let mut payload = Vec::with_capacity(1 + 32 + ciphertext.len() + 32);
    payload.push(NIP44_VERSION);
    payload.extend_from_slice(&nonce_bytes);
    payload.extend_from_slice(&ciphertext);

    // HMAC-SHA256 over the payload so far
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&hmac_key)
        .expect("HMAC accepts any key size");
    mac.update(&payload);
    let hmac_result = mac.finalize().into_bytes();
    payload.extend_from_slice(&hmac_result);

    use base64::Engine;
    Ok(base64::engine::general_purpose::STANDARD.encode(&payload))
}

/// Decrypt a NIP-44 v2 base64-encoded payload.
///
/// Returns the plaintext string.
pub fn nip44_decrypt(
    conversation_key: &[u8; 32],
    payload_b64: &str,
) -> Result<String, Nip44Error> {
    use base64::Engine;
    use chacha20poly1305::aead::KeyInit;
    use chacha20poly1305::{ChaCha20Poly1305, aead::Aead};

    let payload = base64::engine::general_purpose::STANDARD.decode(payload_b64)?;

    // Minimum: 1 (version) + 32 (nonce) + 16 (min ciphertext with poly1305 tag) + 32 (hmac) = 81
    if payload.len() < 81 {
        return Err(Nip44Error::InvalidPayload("payload too short".into()));
    }

    if payload[0] != NIP44_VERSION {
        return Err(Nip44Error::InvalidPayload(format!(
            "unsupported version: {}",
            payload[0]
        )));
    }

    let nonce_bytes: [u8; 32] = payload[1..33]
        .try_into()
        .expect("slice is exactly 32 bytes");
    let hmac_start = payload.len() - 32;
    let ciphertext = &payload[33..hmac_start];
    let received_hmac = &payload[hmac_start..];

    let (chacha_key, chacha_nonce, hmac_key) = message_keys(conversation_key, &nonce_bytes);

    // Verify HMAC over version || nonce || ciphertext
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&hmac_key)
        .expect("HMAC accepts any key size");
    mac.update(&payload[..hmac_start]);
    mac.verify_slice(received_hmac)
        .map_err(|_| Nip44Error::HmacMismatch)?;

    // Decrypt
    let cipher = ChaCha20Poly1305::new((&chacha_key).into());
    let padded = cipher
        .decrypt((&chacha_nonce).into(), ciphertext)
        .map_err(|_| Nip44Error::Aead)?;

    let plaintext = unpad_plaintext(&padded)?;
    String::from_utf8(plaintext)
        .map_err(|_| Nip44Error::InvalidPayload("plaintext is not valid UTF-8".into()))
}

/// Fill a buffer with random bytes using the system RNG.
fn getrandom(buf: &mut [u8]) {
    use rand::RngCore;
    rand::thread_rng().fill_bytes(buf);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Generate a fresh keypair, returning (secret_key_hex, pubkey_hex).
    fn gen_keypair() -> (String, String) {
        let secp = Secp256k1::new();
        let (sk, _pk) = secp.generate_keypair(&mut rand::thread_rng());
        let keypair = Keypair::from_secret_key(&secp, &sk);
        let (xonly, _) = XOnlyPublicKey::from_keypair(&keypair);
        (hex::encode(sk.secret_bytes()), hex::encode(xonly.serialize()))
    }

    fn unsigned_event(content: &str) -> Event {
        Event {
            id: String::new(),
            pubkey: String::new(),
            created_at: 0,
            kind: 21111,
            tags: vec![
                vec!["p".into(), "ab".repeat(32)],
                vec!["performative".into(), "tell".into()],
            ],
            content: content.to_string(),
            sig: String::new(),
        }
    }

    // ====================================================================
    // Event ID
    // ====================================================================

    #[test]
    fn compute_event_id_deterministic() {
        let event = Event {
            id: String::new(),
            pubkey: "aa".repeat(32),
            created_at: 1700000000,
            kind: 21111,
            tags: vec![vec!["p".into(), "bb".repeat(32)]],
            content: "(tell @bob \"hello\")".into(),
            sig: String::new(),
        };
        let id1 = compute_event_id(&event);
        let id2 = compute_event_id(&event);
        assert_eq!(id1, id2);
        assert_eq!(id1.len(), 64); // 32 bytes hex
    }

    #[test]
    fn compute_event_id_changes_with_content() {
        let mut event = Event {
            id: String::new(),
            pubkey: "aa".repeat(32),
            created_at: 1700000000,
            kind: 21111,
            tags: vec![],
            content: "hello".into(),
            sig: String::new(),
        };
        let id1 = compute_event_id(&event);
        event.content = "world".into();
        let id2 = compute_event_id(&event);
        assert_ne!(id1, id2);
    }

    // ====================================================================
    // Sign + Verify round-trip
    // ====================================================================

    #[test]
    fn sign_and_verify_round_trip() {
        let (sk, _pk) = gen_keypair();
        let mut event = unsigned_event("(tell @bob \"hi\")");
        sign_event(&mut event, &sk, 1700000000).unwrap();

        assert!(!event.id.is_empty());
        assert!(!event.pubkey.is_empty());
        assert!(!event.sig.is_empty());
        assert_eq!(event.created_at, 1700000000);

        verify_event(&event).unwrap();
    }

    #[test]
    fn verify_rejects_tampered_content() {
        let (sk, _pk) = gen_keypair();
        let mut event = unsigned_event("(tell @bob \"hi\")");
        sign_event(&mut event, &sk, 1700000000).unwrap();

        event.content = "(tell @bob \"tampered\")".into();
        assert!(verify_event(&event).is_err());
    }

    #[test]
    fn verify_rejects_tampered_sig() {
        let (sk, _pk) = gen_keypair();
        let mut event = unsigned_event("(tell @bob \"hi\")");
        sign_event(&mut event, &sk, 1700000000).unwrap();

        // Flip a byte in the signature
        let mut sig_bytes = hex::decode(&event.sig).unwrap();
        sig_bytes[0] ^= 0xff;
        event.sig = hex::encode(sig_bytes);
        assert!(verify_event(&event).is_err());
    }

    #[test]
    fn verify_rejects_wrong_pubkey() {
        let (sk, _pk) = gen_keypair();
        let mut event = unsigned_event("(tell @bob \"hi\")");
        sign_event(&mut event, &sk, 1700000000).unwrap();

        // Use a different pubkey
        let (_, other_pk) = gen_keypair();
        event.pubkey = other_pk;
        // Recompute ID with wrong pubkey
        event.id = compute_event_id(&event);
        assert!(verify_event(&event).is_err());
    }

    #[test]
    fn verify_rejects_mismatched_id() {
        let (sk, _pk) = gen_keypair();
        let mut event = unsigned_event("(tell @bob \"hi\")");
        sign_event(&mut event, &sk, 1700000000).unwrap();

        event.id = "ff".repeat(32);
        assert!(matches!(
            verify_event(&event),
            Err(SigningError::IdMismatch { .. })
        ));
    }

    #[test]
    fn sign_sets_pubkey_from_secret_key() {
        let (sk, expected_pk) = gen_keypair();
        let mut event = unsigned_event("(tell @bob \"hi\")");
        sign_event(&mut event, &sk, 1700000000).unwrap();
        assert_eq!(event.pubkey, expected_pk);
    }

    #[test]
    fn sign_invalid_secret_key_hex() {
        let mut event = unsigned_event("(tell @bob \"hi\")");
        assert!(sign_event(&mut event, "not-hex", 1700000000).is_err());
    }

    #[test]
    fn sign_different_timestamps_different_ids() {
        let (sk, _pk) = gen_keypair();
        let mut e1 = unsigned_event("(tell @bob \"hi\")");
        let mut e2 = unsigned_event("(tell @bob \"hi\")");
        sign_event(&mut e1, &sk, 1700000000).unwrap();
        sign_event(&mut e2, &sk, 1700000001).unwrap();
        assert_ne!(e1.id, e2.id);
    }

    // ====================================================================
    // NIP-44 conversation key
    // ====================================================================

    #[test]
    fn conversation_key_deterministic() {
        let (sk1, _pk1) = gen_keypair();
        let (_sk2, pk2) = gen_keypair();
        let ck1 = conversation_key(&sk1, &pk2).unwrap();
        let ck2 = conversation_key(&sk1, &pk2).unwrap();
        assert_eq!(ck1, ck2);
    }

    #[test]
    fn conversation_key_symmetric() {
        let (sk1, pk1) = gen_keypair();
        let (sk2, pk2) = gen_keypair();
        let ck_ab = conversation_key(&sk1, &pk2).unwrap();
        let ck_ba = conversation_key(&sk2, &pk1).unwrap();
        assert_eq!(ck_ab, ck_ba);
    }

    // ====================================================================
    // NIP-44 encrypt/decrypt
    // ====================================================================

    #[test]
    fn nip44_round_trip() {
        let (sk1, _pk1) = gen_keypair();
        let (_sk2, pk2) = gen_keypair();
        let ck = conversation_key(&sk1, &pk2).unwrap();

        let plaintext = "hello, agent!";
        let encrypted = nip44_encrypt(&ck, plaintext).unwrap();
        let decrypted = nip44_decrypt(&ck, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn nip44_round_trip_long_message() {
        let (sk1, _pk1) = gen_keypair();
        let (_sk2, pk2) = gen_keypair();
        let ck = conversation_key(&sk1, &pk2).unwrap();

        let plaintext = "x".repeat(1000);
        let encrypted = nip44_encrypt(&ck, &plaintext).unwrap();
        let decrypted = nip44_decrypt(&ck, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn nip44_wrong_key_fails() {
        let (sk1, _pk1) = gen_keypair();
        let (_sk2, pk2) = gen_keypair();
        let ck = conversation_key(&sk1, &pk2).unwrap();

        let encrypted = nip44_encrypt(&ck, "secret").unwrap();

        // Use a different conversation key
        let (sk3, _pk3) = gen_keypair();
        let wrong_ck = conversation_key(&sk3, &pk2).unwrap();
        assert!(nip44_decrypt(&wrong_ck, &encrypted).is_err());
    }

    #[test]
    fn nip44_tampered_ciphertext_fails() {
        let (sk1, _pk1) = gen_keypair();
        let (_sk2, pk2) = gen_keypair();
        let ck = conversation_key(&sk1, &pk2).unwrap();

        let encrypted = nip44_encrypt(&ck, "secret").unwrap();

        use base64::Engine;
        let mut payload = base64::engine::general_purpose::STANDARD
            .decode(&encrypted)
            .unwrap();
        // Tamper with ciphertext (byte after version + nonce)
        if payload.len() > 40 {
            payload[40] ^= 0xff;
        }
        let tampered = base64::engine::general_purpose::STANDARD.encode(&payload);
        assert!(nip44_decrypt(&ck, &tampered).is_err());
    }

    #[test]
    fn nip44_decrypt_invalid_version() {
        let (sk1, _pk1) = gen_keypair();
        let (_sk2, pk2) = gen_keypair();
        let ck = conversation_key(&sk1, &pk2).unwrap();

        let encrypted = nip44_encrypt(&ck, "test").unwrap();

        use base64::Engine;
        let mut payload = base64::engine::general_purpose::STANDARD
            .decode(&encrypted)
            .unwrap();
        payload[0] = 99; // invalid version
        let bad = base64::engine::general_purpose::STANDARD.encode(&payload);
        let err = nip44_decrypt(&ck, &bad).unwrap_err();
        assert!(matches!(err, Nip44Error::InvalidPayload(_)));
    }

    #[test]
    fn nip44_decrypt_too_short() {
        let ck = [0u8; 32];
        use base64::Engine;
        let short = base64::engine::general_purpose::STANDARD.encode(&[0u8; 10]);
        assert!(matches!(
            nip44_decrypt(&ck, &short),
            Err(Nip44Error::InvalidPayload(_))
        ));
    }

    // ====================================================================
    // Padding
    // ====================================================================

    #[test]
    fn pad_unpad_round_trip() {
        for len in [1, 5, 31, 32, 33, 64, 100, 255, 1000] {
            let data: Vec<u8> = (0..len).map(|i| (i % 256) as u8).collect();
            let padded = pad_plaintext(&data);
            let unpadded = unpad_plaintext(&padded).unwrap();
            assert_eq!(data, unpadded, "round-trip failed for len {len}");
        }
    }

    #[test]
    fn pad_minimum_32() {
        let padded = pad_plaintext(b"x");
        assert_eq!(padded.len(), 2 + 32); // 2-byte prefix + 32 padded
    }

    #[test]
    fn pad_power_of_two() {
        let padded = pad_plaintext(&vec![0u8; 33]);
        assert_eq!(padded.len(), 2 + 64); // next power of 2 above 33 is 64
    }
}
