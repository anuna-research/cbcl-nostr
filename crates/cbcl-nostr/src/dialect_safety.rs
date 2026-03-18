//! Dialect safety verification: R1–R4 constraint checks before installation.
//!
//! Provides:
//! - [`verify_r1`] — no recursion in performative templates.
//! - [`verify_r2`] — resource bounds within valid ranges.
//! - [`verify_r3`] — core performatives not redefined.
//! - [`verify_r4`] — provenance via Nostr event pubkey/signature.
//! - [`verify_all`] — run all four checks, collecting violations.
//! - [`install_dialect_event_verified`] — parse, verify R1–R4, and install.

#![forbid(unsafe_code)]

use cbcl_core::dialect::{Dialect, DialectRegistry};
use cbcl_core::r4::{R4Result, Signer};

use crate::dialect_negotiation::{self, NegotiationError};
use crate::event_signing;
use crate::event_types::{AgentDialect, Event, Tag};

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// A single safety constraint violation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SafetyViolation {
    /// R1: one or more performatives contain self-references (recursion).
    R1 { recursive: Vec<String> },
    /// R2: resource bounds outside valid ranges.
    R2,
    /// R3: one or more core performatives are redefined.
    R3 { redefined: Vec<String> },
    /// R4: provenance check failed — invalid event signature.
    R4 { reason: String },
}

impl core::fmt::Display for SafetyViolation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SafetyViolation::R1 { recursive } => {
                write!(f, "R1 violation: recursive performatives: {}", recursive.join(", "))
            }
            SafetyViolation::R2 => write!(f, "R2 violation: resource bounds out of range"),
            SafetyViolation::R3 { redefined } => {
                write!(
                    f,
                    "R3 violation: core performatives redefined: {}",
                    redefined.join(", ")
                )
            }
            SafetyViolation::R4 { reason } => {
                write!(f, "R4 violation: provenance check failed: {reason}")
            }
        }
    }
}

/// Result of running all safety checks on a dialect.
#[derive(Debug, Clone)]
pub struct SafetyReport {
    /// The dialect name that was checked.
    pub dialect_name: String,
    /// Any violations found (empty means all checks passed).
    pub violations: Vec<SafetyViolation>,
    /// R4 provenance result (Valid, Unsigned, or Invalid).
    pub r4_result: R4Result,
    /// The pubkey of the event author (hex-encoded).
    pub author_pubkey: String,
}

impl SafetyReport {
    /// Returns `true` if all safety constraints are satisfied.
    pub fn is_safe(&self) -> bool {
        self.violations.is_empty()
    }
}

/// Errors from verified dialect installation.
#[derive(Debug, thiserror::Error)]
pub enum VerifiedInstallError {
    /// Negotiation-level error (wrong kind, codec, parse, etc.).
    #[error(transparent)]
    Negotiation(#[from] NegotiationError),

    /// The event's Nostr signature is invalid.
    #[error("event signature verification failed: {0}")]
    EventSignature(#[from] event_signing::SigningError),

    /// One or more safety constraints were violated.
    #[error("safety violations: {}", format_violations(.0))]
    Safety(Vec<SafetyViolation>),
}

fn format_violations(violations: &[SafetyViolation]) -> String {
    violations
        .iter()
        .map(|v| v.to_string())
        .collect::<Vec<_>>()
        .join("; ")
}

// ---------------------------------------------------------------------------
// R1: No recursion
// ---------------------------------------------------------------------------

/// Verify R1: no performative template contains a self-reference.
///
/// Returns `None` if the constraint is satisfied, or `Some(violation)` with
/// the names of recursive performatives.
pub fn verify_r1(dialect: &Dialect) -> Option<SafetyViolation> {
    let violations = cbcl_core::r1::r1_violations(dialect);
    if violations.is_empty() {
        None
    } else {
        Some(SafetyViolation::R1 {
            recursive: violations,
        })
    }
}

// ---------------------------------------------------------------------------
// R2: Resource bounds valid
// ---------------------------------------------------------------------------

/// Verify R2: resource bounds are within valid ranges.
///
/// Valid ranges (per cbcl-core):
/// - `max_depth`: 1–64
/// - `max_expansion_size`: 1–8192
/// - `verification_time_ms`: 1–1000
pub fn verify_r2(dialect: &Dialect) -> Option<SafetyViolation> {
    if cbcl_core::r2::verify_r2(dialect) {
        None
    } else {
        Some(SafetyViolation::R2)
    }
}

// ---------------------------------------------------------------------------
// R3: Core performatives preserved
// ---------------------------------------------------------------------------

/// Verify R3: no core performative (tell, ask, reply, ok, error, cancel,
/// hello, bye) is redefined by this dialect.
///
/// Returns `None` if the constraint is satisfied, or `Some(violation)` with
/// the names of redefined core performatives.
pub fn verify_r3(dialect: &Dialect) -> Option<SafetyViolation> {
    let violations = cbcl_core::r3::r3_violations(dialect);
    if violations.is_empty() {
        None
    } else {
        Some(SafetyViolation::R3 {
            redefined: violations,
        })
    }
}

// ---------------------------------------------------------------------------
// R4: Provenance via Nostr pubkey signature
// ---------------------------------------------------------------------------

/// A [`Signer`] implementation that verifies dialect signatures using the
/// Nostr event author's public key (Schnorr/secp256k1).
///
/// For R4 in the Nostr context, provenance is established by verifying
/// the Nostr event's signature (which covers the entire event including
/// the dialect content). The dialect-level signature field is optional;
/// if present, it is verified against the event author's pubkey.
struct NostrEventSigner {
    pubkey_bytes: [u8; 32],
}

impl NostrEventSigner {
    fn from_pubkey_hex(pubkey_hex: &str) -> Result<Self, event_signing::SigningError> {
        let bytes = hex::decode(pubkey_hex)?;
        if bytes.len() != 32 {
            return Err(secp256k1::Error::InvalidPublicKey.into());
        }
        let mut pubkey_bytes = [0u8; 32];
        pubkey_bytes.copy_from_slice(&bytes);
        Ok(Self { pubkey_bytes })
    }
}

impl Signer for NostrEventSigner {
    fn sign(&self, _data: &[u8]) -> Vec<u8> {
        // Signing is not supported via this read-only verifier.
        // This path is unused during verification.
        Vec::new()
    }

    fn verify(&self, data: &[u8], sig: &[u8]) -> bool {
        if sig.len() != 64 {
            return false;
        }
        let secp = secp256k1::Secp256k1::verification_only();
        let Ok(xonly) = secp256k1::XOnlyPublicKey::from_slice(&self.pubkey_bytes) else {
            return false;
        };
        let Ok(schnorr_sig) = secp256k1::schnorr::Signature::from_slice(sig) else {
            return false;
        };
        // The data is the canonical dialect body; verify Schnorr signature
        secp.verify_schnorr(&schnorr_sig, data, &xonly).is_ok()
    }
}

/// Verify R4: provenance via the Nostr event's pubkey and signature.
///
/// This performs two checks:
/// 1. **Event-level provenance**: the Nostr event signature is valid
///    (covers the entire event including dialect content).
/// 2. **Dialect-level signature** (optional): if the dialect has a
///    `signature` field, verify it against the event author's pubkey
///    using cbcl-core's `check_r4`.
///
/// Returns `None` if provenance is established, or `Some(R4 violation)`.
/// Also returns the `R4Result` from the dialect-level check.
pub fn verify_r4(
    event: &Event,
    dialect: &Dialect,
) -> (Option<SafetyViolation>, R4Result) {
    // Step 1: Verify the Nostr event signature (event-level provenance).
    if let Err(e) = event_signing::verify_event(event) {
        return (
            Some(SafetyViolation::R4 {
                reason: format!("event signature invalid: {e}"),
            }),
            R4Result::Invalid,
        );
    }

    // Step 2: Check dialect-level signature via cbcl-core R4.
    let signer = match NostrEventSigner::from_pubkey_hex(&event.pubkey) {
        Ok(s) => s,
        Err(e) => {
            return (
                Some(SafetyViolation::R4 {
                    reason: format!("invalid author pubkey: {e}"),
                }),
                R4Result::Invalid,
            );
        }
    };

    let r4_result = cbcl_core::r4::check_r4(dialect, &signer);
    match r4_result {
        R4Result::Valid | R4Result::Unsigned => (None, r4_result),
        R4Result::Invalid => (
            Some(SafetyViolation::R4 {
                reason: "dialect signature verification failed".into(),
            }),
            r4_result,
        ),
    }
}

// ---------------------------------------------------------------------------
// Combined verification
// ---------------------------------------------------------------------------

/// Run all safety checks (R1–R4) on a dialect parsed from a Nostr event.
///
/// Returns a [`SafetyReport`] with any violations found.
pub fn verify_all(event: &Event, dialect: &Dialect) -> SafetyReport {
    let mut violations = Vec::new();

    if let Some(v) = verify_r1(dialect) {
        violations.push(v);
    }
    if let Some(v) = verify_r2(dialect) {
        violations.push(v);
    }
    if let Some(v) = verify_r3(dialect) {
        violations.push(v);
    }

    let (r4_violation, r4_result) = verify_r4(event, dialect);
    if let Some(v) = r4_violation {
        violations.push(v);
    }

    // Extract author pubkey from event
    let author_pubkey = event.pubkey.clone();

    // Extract dialect name from event tags
    let dialect_name = event
        .tags
        .iter()
        .find_map(|raw| match Tag::parse(raw) {
            Tag::Dialect(name) => Some(name),
            _ => None,
        })
        .unwrap_or_else(|| dialect.name.clone());

    SafetyReport {
        dialect_name,
        violations,
        r4_result,
        author_pubkey,
    }
}

// ---------------------------------------------------------------------------
// Verified installation
// ---------------------------------------------------------------------------

/// Parse, verify R1–R4, and install a dialect from a signed Nostr event.
///
/// Unlike [`dialect_negotiation::install_dialect_event`], this function:
/// 1. Verifies the Nostr event signature (R4 event-level provenance).
/// 2. Parses the dialect definition.
/// 3. Runs all safety checks (R1–R4) including dialect-level signature.
/// 4. Only installs if all checks pass.
///
/// Returns the installed dialect and its safety report on success.
pub fn install_dialect_event_verified(
    event: Event,
    registry: &mut DialectRegistry,
) -> Result<(Dialect, SafetyReport), VerifiedInstallError> {
    // Step 1: Verify event signature first (fail fast on tampered events).
    event_signing::verify_event(&event)?;

    // Step 2: Parse the dialect from the event.
    let agent_dialect =
        AgentDialect::from_event(event.clone()).map_err(NegotiationError::from)?;
    let dialect = dialect_negotiation::parse_dialect_event(&agent_dialect)?;

    // Step 3: Run all safety checks.
    let report = verify_all(&event, &dialect);
    if !report.is_safe() {
        return Err(VerifiedInstallError::Safety(report.violations));
    }

    // Step 4: Install into registry (R1–R3 are re-checked by cbcl-core).
    registry
        .install(dialect.clone())
        .map_err(|e| NegotiationError::Install(e))?;

    Ok((dialect, report))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use cbcl_core::dialect::{PerformativeDef, ResourceBounds};
    use cbcl_core::sexpr::{Atom, SExpr};
    use crate::event_types::KIND_AGENT_DIALECT;

    fn make_dialect_event(tags: Vec<Vec<String>>, content: &str) -> Event {
        Event {
            id: "a".repeat(64),
            pubkey: "b".repeat(64),
            created_at: 1700000000,
            kind: KIND_AGENT_DIALECT,
            tags,
            content: content.to_string(),
            sig: "c".repeat(128),
        }
    }

    fn valid_dialect() -> Dialect {
        Dialect {
            name: "commerce".into(),
            extends: vec!["cbcl".into()],
            author: Some("@marketplace".into()),
            performatives: vec![PerformativeDef {
                name: "negotiate".into(),
                params: vec![
                    SExpr::Atom(Atom::Symbol("price".into())),
                    SExpr::Atom(Atom::Symbol("item".into())),
                ],
                template: SExpr::List(vec![
                    SExpr::Atom(Atom::Symbol("effect".into())),
                    SExpr::Atom(Atom::Symbol("negotiate-price".into())),
                ]),
            }],
            resources: ResourceBounds {
                max_depth: 16,
                max_expansion_size: 1024,
                verification_time_ms: 50,
            },
            examples: vec![],
            signature: None,
            hash: None,
            protocol: None,
        }
    }

    // ==== R1: No recursion ====

    #[test]
    fn r1_passes_for_non_recursive_dialect() {
        let dialect = valid_dialect();
        assert!(verify_r1(&dialect).is_none());
    }

    #[test]
    fn r1_fails_for_recursive_performative() {
        let dialect = Dialect {
            name: "recursive".into(),
            extends: vec!["cbcl".into()],
            author: Some("@author".into()),
            performatives: vec![PerformativeDef {
                name: "loop-it".into(),
                params: vec![],
                template: SExpr::List(vec![
                    SExpr::Atom(Atom::Symbol("loop-it".into())),
                ]),
            }],
            resources: ResourceBounds {
                max_depth: 8,
                max_expansion_size: 512,
                verification_time_ms: 10,
            },
            examples: vec![],
            signature: None,
            hash: None,
            protocol: None,
        };

        let violation = verify_r1(&dialect);
        assert!(violation.is_some());
        match violation.unwrap() {
            SafetyViolation::R1 { recursive } => {
                assert!(recursive.contains(&"loop-it".to_string()));
            }
            other => panic!("expected R1 violation, got {other}"),
        }
    }

    #[test]
    fn r1_passes_for_base_dialect() {
        let base = cbcl_core::dialect::base_dialect();
        assert!(verify_r1(&base).is_none());
    }

    // ==== R2: Resource bounds ====

    #[test]
    fn r2_passes_for_valid_bounds() {
        let dialect = valid_dialect();
        assert!(verify_r2(&dialect).is_none());
    }

    #[test]
    fn r2_fails_for_zero_depth() {
        let mut dialect = valid_dialect();
        dialect.resources.max_depth = 0;
        assert_eq!(verify_r2(&dialect), Some(SafetyViolation::R2));
    }

    #[test]
    fn r2_fails_for_excessive_depth() {
        let mut dialect = valid_dialect();
        dialect.resources.max_depth = 65;
        assert_eq!(verify_r2(&dialect), Some(SafetyViolation::R2));
    }

    #[test]
    fn r2_fails_for_zero_expansion() {
        let mut dialect = valid_dialect();
        dialect.resources.max_expansion_size = 0;
        assert_eq!(verify_r2(&dialect), Some(SafetyViolation::R2));
    }

    #[test]
    fn r2_fails_for_excessive_expansion() {
        let mut dialect = valid_dialect();
        dialect.resources.max_expansion_size = 8193;
        assert_eq!(verify_r2(&dialect), Some(SafetyViolation::R2));
    }

    #[test]
    fn r2_fails_for_zero_verification_time() {
        let mut dialect = valid_dialect();
        dialect.resources.verification_time_ms = 0;
        assert_eq!(verify_r2(&dialect), Some(SafetyViolation::R2));
    }

    #[test]
    fn r2_fails_for_excessive_verification_time() {
        let mut dialect = valid_dialect();
        dialect.resources.verification_time_ms = 1001;
        assert_eq!(verify_r2(&dialect), Some(SafetyViolation::R2));
    }

    #[test]
    fn r2_boundary_values_pass() {
        // Test boundary values
        let mut dialect = valid_dialect();
        dialect.resources.max_depth = 1;
        dialect.resources.max_expansion_size = 1;
        dialect.resources.verification_time_ms = 1;
        assert!(verify_r2(&dialect).is_none());

        dialect.resources.max_depth = 64;
        dialect.resources.max_expansion_size = 8192;
        dialect.resources.verification_time_ms = 1000;
        assert!(verify_r2(&dialect).is_none());
    }

    // ==== R3: Core performatives preserved ====

    #[test]
    fn r3_passes_for_non_core_performatives() {
        let dialect = valid_dialect();
        assert!(verify_r3(&dialect).is_none());
    }

    #[test]
    fn r3_fails_for_redefined_tell() {
        let dialect = Dialect {
            name: "bad-dialect".into(),
            extends: vec!["cbcl".into()],
            author: Some("@author".into()),
            performatives: vec![PerformativeDef {
                name: "tell".into(),
                params: vec![],
                template: SExpr::List(vec![
                    SExpr::Atom(Atom::Symbol("effect".into())),
                    SExpr::Atom(Atom::Symbol("custom-tell".into())),
                ]),
            }],
            resources: ResourceBounds {
                max_depth: 8,
                max_expansion_size: 512,
                verification_time_ms: 10,
            },
            examples: vec![],
            signature: None,
            hash: None,
            protocol: None,
        };

        let violation = verify_r3(&dialect);
        assert!(violation.is_some());
        match violation.unwrap() {
            SafetyViolation::R3 { redefined } => {
                assert!(redefined.contains(&"tell".to_string()));
            }
            other => panic!("expected R3 violation, got {other}"),
        }
    }

    #[test]
    fn r3_fails_for_multiple_core_redefinitions() {
        let dialect = Dialect {
            name: "very-bad".into(),
            extends: vec!["cbcl".into()],
            author: Some("@author".into()),
            performatives: vec![
                PerformativeDef {
                    name: "tell".into(),
                    params: vec![],
                    template: SExpr::Atom(Atom::Symbol("x".into())),
                },
                PerformativeDef {
                    name: "ask".into(),
                    params: vec![],
                    template: SExpr::Atom(Atom::Symbol("y".into())),
                },
            ],
            resources: ResourceBounds {
                max_depth: 8,
                max_expansion_size: 512,
                verification_time_ms: 10,
            },
            examples: vec![],
            signature: None,
            hash: None,
            protocol: None,
        };

        let violation = verify_r3(&dialect);
        assert!(violation.is_some());
        match violation.unwrap() {
            SafetyViolation::R3 { redefined } => {
                assert!(redefined.contains(&"tell".to_string()));
                assert!(redefined.contains(&"ask".to_string()));
            }
            other => panic!("expected R3 violation, got {other}"),
        }
    }

    #[test]
    fn r3_passes_for_base_dialect() {
        let base = cbcl_core::dialect::base_dialect();
        assert!(verify_r3(&base).is_none());
    }

    // ==== R4: Provenance ====

    #[test]
    fn r4_fails_for_invalid_event_signature() {
        let event = make_dialect_event(
            vec![vec!["dialect".into(), "commerce".into()]],
            "(define commerce (cbcl) @marketplace)",
        );
        let dialect = valid_dialect();

        let (violation, r4_result) = verify_r4(&event, &dialect);
        assert!(violation.is_some());
        assert_eq!(r4_result, R4Result::Invalid);
        match violation.unwrap() {
            SafetyViolation::R4 { reason } => {
                assert!(reason.contains("event signature invalid"));
            }
            other => panic!("expected R4 violation, got {other}"),
        }
    }

    #[test]
    fn r4_passes_for_valid_signed_event_unsigned_dialect() {
        // Create a properly signed event
        let (sk, _pk) = gen_keypair();
        let mut event = Event {
            id: String::new(),
            pubkey: String::new(),
            created_at: 0,
            kind: KIND_AGENT_DIALECT,
            tags: vec![vec!["dialect".into(), "commerce".into()]],
            content: "(define commerce (cbcl) @marketplace)".into(),
            sig: String::new(),
        };
        event_signing::sign_event(&mut event, &sk, 1700000000).unwrap();

        let dialect = valid_dialect(); // no signature field

        let (violation, r4_result) = verify_r4(&event, &dialect);
        assert!(violation.is_none());
        assert_eq!(r4_result, R4Result::Unsigned);
    }

    // ==== Combined verification ====

    #[test]
    fn verify_all_passes_for_valid_signed_event() {
        let (sk, _pk) = gen_keypair();
        let dialect = valid_dialect();
        let content = crate::dialect_negotiation::DialectBuilder::from_dialect(&dialect)
            .build()
            .content;

        let mut event = Event {
            id: String::new(),
            pubkey: String::new(),
            created_at: 0,
            kind: KIND_AGENT_DIALECT,
            tags: vec![vec!["dialect".into(), "commerce".into()]],
            content,
            sig: String::new(),
        };
        event_signing::sign_event(&mut event, &sk, 1700000000).unwrap();

        let report = verify_all(&event, &dialect);
        assert!(report.is_safe());
        assert_eq!(report.dialect_name, "commerce");
        assert!(!report.author_pubkey.is_empty());
    }

    #[test]
    fn verify_all_collects_multiple_violations() {
        // Dialect with R1, R2, and R3 violations
        let dialect = Dialect {
            name: "triple-bad".into(),
            extends: vec!["cbcl".into()],
            author: Some("@author".into()),
            performatives: vec![
                // R3: redefines core "tell"
                PerformativeDef {
                    name: "tell".into(),
                    params: vec![],
                    template: SExpr::List(vec![
                        SExpr::Atom(Atom::Symbol("effect".into())),
                        SExpr::Atom(Atom::Symbol("x".into())),
                    ]),
                },
                // R1: recursive
                PerformativeDef {
                    name: "recurse".into(),
                    params: vec![],
                    template: SExpr::List(vec![
                        SExpr::Atom(Atom::Symbol("recurse".into())),
                    ]),
                },
            ],
            resources: ResourceBounds {
                max_depth: 0,          // R2 violation
                max_expansion_size: 0, // R2 violation
                verification_time_ms: 0, // R2 violation
            },
            examples: vec![],
            signature: None,
            hash: None,
            protocol: None,
        };

        let event = make_dialect_event(
            vec![vec!["dialect".into(), "triple-bad".into()]],
            "",
        );

        let report = verify_all(&event, &dialect);
        assert!(!report.is_safe());

        // Should have R1, R2, R3, and R4 (invalid event sig) violations
        let has_r1 = report.violations.iter().any(|v| matches!(v, SafetyViolation::R1 { .. }));
        let has_r2 = report.violations.iter().any(|v| matches!(v, SafetyViolation::R2));
        let has_r3 = report.violations.iter().any(|v| matches!(v, SafetyViolation::R3 { .. }));
        let has_r4 = report.violations.iter().any(|v| matches!(v, SafetyViolation::R4 { .. }));

        assert!(has_r1, "expected R1 violation");
        assert!(has_r2, "expected R2 violation");
        assert!(has_r3, "expected R3 violation");
        assert!(has_r4, "expected R4 violation");
    }

    #[test]
    fn verify_all_only_r4_for_valid_dialect_bad_sig() {
        let dialect = valid_dialect();
        let event = make_dialect_event(
            vec![vec!["dialect".into(), "commerce".into()]],
            "(define commerce (cbcl) @marketplace)",
        );

        let report = verify_all(&event, &dialect);
        assert!(!report.is_safe());
        assert_eq!(report.violations.len(), 1);
        assert!(matches!(&report.violations[0], SafetyViolation::R4 { .. }));
    }

    // ==== Verified installation ====

    #[test]
    fn install_verified_succeeds_with_signed_event() {
        let (sk, _pk) = gen_keypair();
        let dialect = valid_dialect();
        let builder_event = crate::dialect_negotiation::DialectBuilder::from_dialect(&dialect)
            .build();

        let mut event = Event {
            id: String::new(),
            pubkey: String::new(),
            created_at: 0,
            sig: String::new(),
            ..builder_event
        };
        event_signing::sign_event(&mut event, &sk, 1700000000).unwrap();

        let mut registry = DialectRegistry::new();
        let (installed, report) = install_dialect_event_verified(event, &mut registry).unwrap();

        assert_eq!(installed.name, "commerce");
        assert!(report.is_safe());
        assert_eq!(registry.len(), 2);
    }

    #[test]
    fn install_verified_rejects_unsigned_event() {
        let event = make_dialect_event(
            vec![
                vec!["dialect".into(), "commerce".into()],
                vec!["L".into(), "cbcl.dialect".into()],
                vec!["l".into(), "commerce".into(), "cbcl.dialect".into()],
            ],
            "(define commerce (cbcl) @marketplace (extend negotiate (price item) (effect negotiate-price)) (:resource-requirements ((max-depth 16) (max-expansion-size 1024) (verification-time 50))))",
        );

        let mut registry = DialectRegistry::new();
        let err = install_dialect_event_verified(event, &mut registry).unwrap_err();
        assert!(matches!(err, VerifiedInstallError::EventSignature(_)));
        assert_eq!(registry.len(), 1); // unchanged
    }

    #[test]
    fn install_verified_rejects_r3_violation() {
        let (sk, _pk) = gen_keypair();

        let mut event = Event {
            id: String::new(),
            pubkey: String::new(),
            created_at: 0,
            kind: KIND_AGENT_DIALECT,
            tags: vec![
                vec!["dialect".into(), "bad-dialect".into()],
                vec!["L".into(), "cbcl.dialect".into()],
                vec!["l".into(), "bad-dialect".into(), "cbcl.dialect".into()],
            ],
            content: "(define bad-dialect (cbcl) @author (extend tell () (effect custom-tell)) (:resource-requirements ((max-depth 8) (max-expansion-size 512) (verification-time 10))))".into(),
            sig: String::new(),
        };
        event_signing::sign_event(&mut event, &sk, 1700000000).unwrap();

        let mut registry = DialectRegistry::new();
        let err = install_dialect_event_verified(event, &mut registry).unwrap_err();
        assert!(matches!(err, VerifiedInstallError::Safety(_)));
        assert_eq!(registry.len(), 1); // unchanged
    }

    // ==== SafetyViolation Display ====

    #[test]
    fn violation_display_r1() {
        let v = SafetyViolation::R1 {
            recursive: vec!["foo".into(), "bar".into()],
        };
        let s = v.to_string();
        assert!(s.contains("R1"));
        assert!(s.contains("foo"));
        assert!(s.contains("bar"));
    }

    #[test]
    fn violation_display_r2() {
        let v = SafetyViolation::R2;
        assert!(v.to_string().contains("R2"));
    }

    #[test]
    fn violation_display_r3() {
        let v = SafetyViolation::R3 {
            redefined: vec!["tell".into()],
        };
        let s = v.to_string();
        assert!(s.contains("R3"));
        assert!(s.contains("tell"));
    }

    #[test]
    fn violation_display_r4() {
        let v = SafetyViolation::R4 {
            reason: "bad sig".into(),
        };
        let s = v.to_string();
        assert!(s.contains("R4"));
        assert!(s.contains("bad sig"));
    }

    // ==== SafetyReport ====

    #[test]
    fn safety_report_is_safe_when_empty() {
        let report = SafetyReport {
            dialect_name: "test".into(),
            violations: vec![],
            r4_result: R4Result::Unsigned,
            author_pubkey: "aa".repeat(32),
        };
        assert!(report.is_safe());
    }

    #[test]
    fn safety_report_not_safe_with_violations() {
        let report = SafetyReport {
            dialect_name: "test".into(),
            violations: vec![SafetyViolation::R2],
            r4_result: R4Result::Unsigned,
            author_pubkey: "aa".repeat(32),
        };
        assert!(!report.is_safe());
    }

    // ==== NostrEventSigner ====

    #[test]
    fn nostr_signer_rejects_invalid_pubkey() {
        let result = NostrEventSigner::from_pubkey_hex("not-hex");
        assert!(result.is_err());
    }

    #[test]
    fn nostr_signer_rejects_wrong_length_pubkey() {
        let result = NostrEventSigner::from_pubkey_hex("aabbcc");
        assert!(result.is_err());
    }

    #[test]
    fn nostr_signer_verify_rejects_wrong_sig_length() {
        let signer = NostrEventSigner::from_pubkey_hex(&"aa".repeat(32)).unwrap();
        assert!(!signer.verify(b"data", b"short"));
    }

    // ==== Helper ====

    fn gen_keypair() -> (String, String) {
        let secp = secp256k1::Secp256k1::new();
        let (sk, _pk) = secp.generate_keypair(&mut rand::thread_rng());
        let keypair = secp256k1::Keypair::from_secret_key(&secp, &sk);
        let (xonly, _) = secp256k1::XOnlyPublicKey::from_keypair(&keypair);
        (
            hex::encode(sk.secret_bytes()),
            hex::encode(xonly.serialize()),
        )
    }
}
