//! Payment safety guards per NIP-XX security considerations.
//!
//! Provides:
//! - [`TrustThresholds`] — configurable thresholds for publisher trustworthiness.
//! - [`PublisherVerdict`] — result of verifying a task publisher's payment history.
//! - [`verify_publisher`] — check a publisher's reputation summary against trust
//!   thresholds before starting work.
//! - [`AmountTracker`] — validates amount tag consistency across negotiation events.
//! - [`PaymentOrderingGuard`] — detects and warns about payment-before-work patterns.

#![forbid(unsafe_code)]

use crate::commerce_dialect::NegotiationState;
use crate::event_types::Tag;
use crate::reputation_query::ReputationSummary;

// ---------------------------------------------------------------------------
// Trust thresholds
// ---------------------------------------------------------------------------

/// Configurable thresholds for evaluating task publisher trustworthiness.
///
/// An agent should verify the publisher's on-relay reputation against these
/// thresholds before claiming or starting work on a task.  All fields have
/// sensible defaults via [`TrustThresholds::default`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustThresholds {
    /// Minimum number of completed payments (zap receipts) the publisher
    /// must have made.  Publishers with fewer receipts are considered
    /// unverified.  Default: 1.
    pub min_completed_payments: u64,

    /// Minimum completion rate (0–100) the publisher must have.  A publisher
    /// with a completion rate below this is considered risky.  Default: 50.
    pub min_completion_rate_pct: u8,

    /// Minimum total earnings in millisatoshis the publisher must have paid
    /// out historically.  This guards against new accounts with a single
    /// tiny payment.  Default: 0 (no minimum).
    pub min_total_paid_msats: u64,

    /// Maximum acceptable age (in seconds) since the publisher's last
    /// payment activity.  If their last zap receipt is older than this,
    /// they are flagged as stale.  Set to `0` to disable staleness checks.
    /// Default: 0 (disabled).
    pub max_inactivity_secs: u64,
}

impl Default for TrustThresholds {
    fn default() -> Self {
        Self {
            min_completed_payments: 1,
            min_completion_rate_pct: 50,
            min_total_paid_msats: 0,
            max_inactivity_secs: 0,
        }
    }
}

impl TrustThresholds {
    /// Create thresholds that trust any publisher (all minimums zeroed).
    pub fn permissive() -> Self {
        Self {
            min_completed_payments: 0,
            min_completion_rate_pct: 0,
            min_total_paid_msats: 0,
            max_inactivity_secs: 0,
        }
    }

    /// Create strict thresholds suitable for high-value tasks.
    pub fn strict() -> Self {
        Self {
            min_completed_payments: 5,
            min_completion_rate_pct: 80,
            min_total_paid_msats: 100_000,
            max_inactivity_secs: 30 * 24 * 3600, // 30 days
        }
    }
}

// ---------------------------------------------------------------------------
// Publisher verdict
// ---------------------------------------------------------------------------

/// Reasons why a publisher failed trust verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustViolation {
    /// Publisher has fewer completed payments than the threshold.
    InsufficientPaymentHistory {
        required: u64,
        actual: u64,
    },
    /// Publisher's completion rate is below the threshold.
    LowCompletionRate {
        required_pct: u8,
        actual_pct: u8,
    },
    /// Publisher's total historical payouts are below the threshold.
    InsufficientTotalPaid {
        required_msats: u64,
        actual_msats: u64,
    },
    /// Publisher's last payment activity is too old.
    StaleActivity {
        max_age_secs: u64,
        last_activity: u64,
        now: u64,
    },
}

/// Result of verifying a task publisher's payment history.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublisherVerdict {
    /// The publisher's public key (hex).
    pub pubkey: String,
    /// Trust violations found (empty if trusted).
    pub violations: Vec<TrustViolation>,
}

impl PublisherVerdict {
    /// Returns `true` if the publisher passed all trust checks.
    pub fn is_trusted(&self) -> bool {
        self.violations.is_empty()
    }
}

/// Verify a task publisher's reputation summary against trust thresholds.
///
/// The `now` parameter is the current Unix timestamp in seconds, used for
/// staleness checks.  Pass `0` to skip staleness checks regardless of the
/// threshold configuration.
///
/// # Example
///
/// ```
/// use cbcl_nostr::payment_safety::{TrustThresholds, verify_publisher};
/// use cbcl_nostr::reputation_query::ReputationSummary;
///
/// let summary = ReputationSummary {
///     pubkey: "publisher_pk".into(),
///     total_earnings_msats: 200_000,
///     completed_tasks: 5,
///     assigned_tasks: 6,
///     completion_rate_pct: 83,
///     domain_expertise: vec![],
///     last_activity: 1700000000,
/// };
///
/// let verdict = verify_publisher(&summary, &TrustThresholds::default(), 1700000100);
/// assert!(verdict.is_trusted());
/// ```
pub fn verify_publisher(
    summary: &ReputationSummary,
    thresholds: &TrustThresholds,
    now: u64,
) -> PublisherVerdict {
    let mut violations = Vec::new();

    if summary.completed_tasks < thresholds.min_completed_payments {
        violations.push(TrustViolation::InsufficientPaymentHistory {
            required: thresholds.min_completed_payments,
            actual: summary.completed_tasks,
        });
    }

    if summary.completion_rate_pct < thresholds.min_completion_rate_pct {
        violations.push(TrustViolation::LowCompletionRate {
            required_pct: thresholds.min_completion_rate_pct,
            actual_pct: summary.completion_rate_pct,
        });
    }

    if summary.total_earnings_msats < thresholds.min_total_paid_msats {
        violations.push(TrustViolation::InsufficientTotalPaid {
            required_msats: thresholds.min_total_paid_msats,
            actual_msats: summary.total_earnings_msats,
        });
    }

    if thresholds.max_inactivity_secs > 0 && now > 0 && summary.last_activity > 0 {
        let age = now.saturating_sub(summary.last_activity);
        if age > thresholds.max_inactivity_secs {
            violations.push(TrustViolation::StaleActivity {
                max_age_secs: thresholds.max_inactivity_secs,
                last_activity: summary.last_activity,
                now,
            });
        }
    }

    PublisherVerdict {
        pubkey: summary.pubkey.clone(),
        violations,
    }
}

// ---------------------------------------------------------------------------
// Amount consistency tracker
// ---------------------------------------------------------------------------

/// Errors from amount consistency checks.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AmountError {
    /// An amount tag could not be parsed as a valid u64 millisatoshi value.
    #[error("invalid amount tag value: \"{0}\"")]
    InvalidAmount(String),

    /// The amount changed between negotiation events when it should not have.
    #[error(
        "amount mismatch: agreed {agreed_msats} msats but event carries {event_msats} msats"
    )]
    AmountMismatch {
        agreed_msats: u64,
        event_msats: u64,
    },
}

/// Tracks the agreed-upon amount across a negotiation and validates that
/// subsequent events (invoice, paid) carry consistent amount tags.
///
/// # Usage
///
/// ```
/// use cbcl_nostr::payment_safety::AmountTracker;
/// use cbcl_nostr::event_types::Tag;
///
/// let mut tracker = AmountTracker::new();
///
/// // Record the amount from the accepted quote
/// tracker.set_agreed_amount(50_000);
///
/// // Validate that the invoice carries the same amount
/// let invoice_tags = vec![Tag::Amount("50000".into())];
/// assert!(tracker.validate_amount_tags(&invoice_tags).is_ok());
/// ```
pub struct AmountTracker {
    agreed_amount_msats: Option<u64>,
}

impl AmountTracker {
    /// Create a new tracker with no agreed amount yet.
    pub fn new() -> Self {
        Self {
            agreed_amount_msats: None,
        }
    }

    /// Set the agreed-upon amount (from quote acceptance or task amount tag).
    pub fn set_agreed_amount(&mut self, msats: u64) {
        self.agreed_amount_msats = Some(msats);
    }

    /// Get the currently agreed amount, if any.
    pub fn agreed_amount(&self) -> Option<u64> {
        self.agreed_amount_msats
    }

    /// Extract and parse the amount from a set of tags.
    ///
    /// Returns `Ok(Some(msats))` if an amount tag is present and valid,
    /// `Ok(None)` if no amount tag is present, or `Err` if the amount
    /// tag value is not a valid u64.
    pub fn extract_amount(tags: &[Tag]) -> Result<Option<u64>, AmountError> {
        for tag in tags {
            if let Tag::Amount(ref val) = tag {
                let msats = val
                    .parse::<u64>()
                    .map_err(|_| AmountError::InvalidAmount(val.clone()))?;
                return Ok(Some(msats));
            }
        }
        Ok(None)
    }

    /// Validate that the amount tags on an event are consistent with the
    /// previously agreed amount.
    ///
    /// If no agreed amount has been set, this is a no-op (returns `Ok`).
    /// If the event has no amount tag, this also returns `Ok` (amount tags
    /// are optional on some event types).
    pub fn validate_amount_tags(&self, tags: &[Tag]) -> Result<(), AmountError> {
        let agreed = match self.agreed_amount_msats {
            Some(a) => a,
            None => return Ok(()),
        };

        let event_amount = Self::extract_amount(tags)?;
        if let Some(event_msats) = event_amount {
            if event_msats != agreed {
                return Err(AmountError::AmountMismatch {
                    agreed_msats: agreed,
                    event_msats,
                });
            }
        }

        Ok(())
    }
}

impl Default for AmountTracker {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Payment ordering guard
// ---------------------------------------------------------------------------

/// Warnings about suspicious payment ordering patterns.
///
/// Per NIP-XX security considerations, agents should be wary of publishers
/// who request payment before work is completed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PaymentOrderingWarning {
    /// A `paid` performative was observed before the negotiation reached
    /// the `Invoiced` state (payment before invoice).
    PaidBeforeInvoice {
        current_state: NegotiationState,
    },

    /// An `invoice` performative was observed before the negotiation reached
    /// a post-acceptance state (invoice before work agreement).
    InvoiceBeforeAcceptance {
        current_state: NegotiationState,
    },

    /// A zap receipt arrived before work was confirmed as complete.
    /// This could indicate a prepayment scam where the publisher
    /// claims payment was already sent to pressure the worker.
    PrematurePaymentClaim {
        current_state: NegotiationState,
    },
}

/// Guards against payment-before-work patterns in commerce negotiations.
///
/// Tracks the current negotiation state and flags suspicious ordering
/// of payment-related events.
///
/// # Example
///
/// ```
/// use cbcl_nostr::payment_safety::PaymentOrderingGuard;
/// use cbcl_nostr::commerce_dialect::NegotiationState;
///
/// let mut guard = PaymentOrderingGuard::new();
///
/// // Normal flow: no warnings
/// assert!(guard.check_transition("quote").is_empty());
/// assert!(guard.check_transition("accept-quote").is_empty());
/// assert!(guard.check_transition("invoice").is_empty());
/// assert!(guard.check_transition("paid").is_empty());
/// ```
pub struct PaymentOrderingGuard {
    state: NegotiationState,
}

impl PaymentOrderingGuard {
    /// Create a new guard starting from the `Open` state.
    pub fn new() -> Self {
        Self {
            state: NegotiationState::Open,
        }
    }

    /// Create a guard starting from a specific negotiation state.
    pub fn from_state(state: NegotiationState) -> Self {
        Self { state }
    }

    /// The current negotiation state.
    pub fn state(&self) -> NegotiationState {
        self.state
    }

    /// Check a commerce performative for payment ordering violations and
    /// advance the state if valid.
    ///
    /// Returns a list of warnings (empty if everything is normal).
    /// The state is advanced regardless of warnings, since the caller
    /// may choose to proceed despite warnings.
    pub fn check_transition(&mut self, performative: &str) -> Vec<PaymentOrderingWarning> {
        let mut warnings = Vec::new();

        // Check for suspicious patterns BEFORE advancing state
        match performative {
            "invoice" => {
                match self.state {
                    NegotiationState::Open
                    | NegotiationState::Quoted
                    | NegotiationState::Countered => {
                        warnings.push(PaymentOrderingWarning::InvoiceBeforeAcceptance {
                            current_state: self.state,
                        });
                    }
                    _ => {}
                }
            }
            "paid" => {
                match self.state {
                    NegotiationState::Open
                    | NegotiationState::Quoted
                    | NegotiationState::Accepted
                    | NegotiationState::Countered
                    | NegotiationState::Working
                    | NegotiationState::Completed => {
                        warnings.push(PaymentOrderingWarning::PaidBeforeInvoice {
                            current_state: self.state,
                        });
                    }
                    _ => {}
                }
            }
            _ => {}
        }

        // Advance state if possible (ignore transition errors — the
        // commerce_dialect state machine will catch those separately)
        if let Ok(next) = self.state.apply(performative) {
            self.state = next;
        }

        warnings
    }

    /// Check whether a zap receipt arriving at the current state is
    /// premature (i.e. work is not yet confirmed complete).
    ///
    /// A zap receipt is expected only after `Invoiced` or `Paid` states.
    /// Receiving one earlier is suspicious.
    pub fn check_zap_receipt(&self) -> Option<PaymentOrderingWarning> {
        match self.state {
            NegotiationState::Invoiced | NegotiationState::Paid => None,
            _ => Some(PaymentOrderingWarning::PrematurePaymentClaim {
                current_state: self.state,
            }),
        }
    }
}

impl Default for PaymentOrderingGuard {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reputation_query::DomainExpertise;

    // ====================================================================
    // TrustThresholds
    // ====================================================================

    #[test]
    fn default_thresholds() {
        let t = TrustThresholds::default();
        assert_eq!(t.min_completed_payments, 1);
        assert_eq!(t.min_completion_rate_pct, 50);
        assert_eq!(t.min_total_paid_msats, 0);
        assert_eq!(t.max_inactivity_secs, 0);
    }

    #[test]
    fn permissive_thresholds() {
        let t = TrustThresholds::permissive();
        assert_eq!(t.min_completed_payments, 0);
        assert_eq!(t.min_completion_rate_pct, 0);
        assert_eq!(t.min_total_paid_msats, 0);
        assert_eq!(t.max_inactivity_secs, 0);
    }

    #[test]
    fn strict_thresholds() {
        let t = TrustThresholds::strict();
        assert_eq!(t.min_completed_payments, 5);
        assert_eq!(t.min_completion_rate_pct, 80);
        assert_eq!(t.min_total_paid_msats, 100_000);
        assert!(t.max_inactivity_secs > 0);
    }

    // ====================================================================
    // Helper: build a ReputationSummary
    // ====================================================================

    fn make_summary(
        completed: u64,
        assigned: u64,
        total_msats: u64,
        rate_pct: u8,
        last_activity: u64,
    ) -> ReputationSummary {
        ReputationSummary {
            pubkey: "publisher_pk".into(),
            total_earnings_msats: total_msats,
            completed_tasks: completed,
            assigned_tasks: assigned,
            completion_rate_pct: rate_pct,
            domain_expertise: vec![],
            last_activity,
        }
    }

    // ====================================================================
    // verify_publisher — trusted
    // ====================================================================

    #[test]
    fn publisher_trusted_default_thresholds() {
        let summary = make_summary(3, 3, 150_000, 100, 1700000000);
        let verdict = verify_publisher(&summary, &TrustThresholds::default(), 1700000100);
        assert!(verdict.is_trusted());
        assert!(verdict.violations.is_empty());
    }

    #[test]
    fn publisher_trusted_permissive() {
        let summary = make_summary(0, 0, 0, 100, 0);
        let verdict = verify_publisher(&summary, &TrustThresholds::permissive(), 0);
        assert!(verdict.is_trusted());
    }

    #[test]
    fn publisher_trusted_strict() {
        let summary = make_summary(10, 12, 500_000, 83, 1700000000);
        let verdict = verify_publisher(&summary, &TrustThresholds::strict(), 1700000100);
        assert!(verdict.is_trusted());
    }

    // ====================================================================
    // verify_publisher — violations
    // ====================================================================

    #[test]
    fn publisher_insufficient_history() {
        let summary = make_summary(0, 0, 0, 100, 0);
        let verdict = verify_publisher(&summary, &TrustThresholds::default(), 0);
        assert!(!verdict.is_trusted());
        assert!(matches!(
            verdict.violations[0],
            TrustViolation::InsufficientPaymentHistory {
                required: 1,
                actual: 0
            }
        ));
    }

    #[test]
    fn publisher_low_completion_rate() {
        let summary = make_summary(2, 10, 50_000, 20, 1700000000);
        let verdict = verify_publisher(&summary, &TrustThresholds::default(), 1700000100);
        assert!(!verdict.is_trusted());
        assert!(verdict.violations.iter().any(|v| matches!(
            v,
            TrustViolation::LowCompletionRate {
                required_pct: 50,
                actual_pct: 20,
            }
        )));
    }

    #[test]
    fn publisher_insufficient_total_paid() {
        let thresholds = TrustThresholds {
            min_total_paid_msats: 100_000,
            ..TrustThresholds::default()
        };
        let summary = make_summary(2, 2, 50_000, 100, 1700000000);
        let verdict = verify_publisher(&summary, &thresholds, 1700000100);
        assert!(!verdict.is_trusted());
        assert!(verdict.violations.iter().any(|v| matches!(
            v,
            TrustViolation::InsufficientTotalPaid {
                required_msats: 100_000,
                actual_msats: 50_000,
            }
        )));
    }

    #[test]
    fn publisher_stale_activity() {
        let thresholds = TrustThresholds {
            max_inactivity_secs: 3600, // 1 hour
            ..TrustThresholds::default()
        };
        let summary = make_summary(5, 5, 200_000, 100, 1700000000);
        let now = 1700000000 + 7200; // 2 hours later
        let verdict = verify_publisher(&summary, &thresholds, now);
        assert!(!verdict.is_trusted());
        assert!(verdict
            .violations
            .iter()
            .any(|v| matches!(v, TrustViolation::StaleActivity { .. })));
    }

    #[test]
    fn staleness_disabled_when_max_zero() {
        let thresholds = TrustThresholds {
            max_inactivity_secs: 0,
            ..TrustThresholds::default()
        };
        let summary = make_summary(1, 1, 1000, 100, 1); // very old
        let verdict = verify_publisher(&summary, &thresholds, 1700000000);
        // Should not flag staleness since max_inactivity_secs is 0
        assert!(!verdict
            .violations
            .iter()
            .any(|v| matches!(v, TrustViolation::StaleActivity { .. })));
    }

    #[test]
    fn staleness_disabled_when_now_zero() {
        let thresholds = TrustThresholds {
            max_inactivity_secs: 3600,
            ..TrustThresholds::default()
        };
        let summary = make_summary(1, 1, 1000, 100, 1);
        let verdict = verify_publisher(&summary, &thresholds, 0);
        assert!(!verdict
            .violations
            .iter()
            .any(|v| matches!(v, TrustViolation::StaleActivity { .. })));
    }

    #[test]
    fn multiple_violations() {
        let summary = make_summary(0, 5, 0, 0, 0);
        let thresholds = TrustThresholds::strict();
        let verdict = verify_publisher(&summary, &thresholds, 1700000000);
        assert!(!verdict.is_trusted());
        // Should have at least insufficient history, low rate, and insufficient total
        assert!(verdict.violations.len() >= 3);
    }

    // ====================================================================
    // AmountTracker — extract_amount
    // ====================================================================

    #[test]
    fn extract_amount_present() {
        let tags = vec![
            Tag::Performative("invoice".into()),
            Tag::Amount("50000".into()),
        ];
        assert_eq!(AmountTracker::extract_amount(&tags).unwrap(), Some(50_000));
    }

    #[test]
    fn extract_amount_absent() {
        let tags = vec![Tag::Performative("tell".into())];
        assert_eq!(AmountTracker::extract_amount(&tags).unwrap(), None);
    }

    #[test]
    fn extract_amount_invalid() {
        let tags = vec![Tag::Amount("not_a_number".into())];
        assert!(AmountTracker::extract_amount(&tags).is_err());
    }

    // ====================================================================
    // AmountTracker — consistency validation
    // ====================================================================

    #[test]
    fn amount_consistent() {
        let mut tracker = AmountTracker::new();
        tracker.set_agreed_amount(50_000);

        let tags = vec![Tag::Amount("50000".into())];
        assert!(tracker.validate_amount_tags(&tags).is_ok());
    }

    #[test]
    fn amount_mismatch() {
        let mut tracker = AmountTracker::new();
        tracker.set_agreed_amount(50_000);

        let tags = vec![Tag::Amount("75000".into())];
        let err = tracker.validate_amount_tags(&tags).unwrap_err();
        assert!(matches!(
            err,
            AmountError::AmountMismatch {
                agreed_msats: 50_000,
                event_msats: 75_000,
            }
        ));
    }

    #[test]
    fn amount_no_agreed_skips_check() {
        let tracker = AmountTracker::new();
        let tags = vec![Tag::Amount("99999".into())];
        assert!(tracker.validate_amount_tags(&tags).is_ok());
    }

    #[test]
    fn amount_no_tag_on_event_ok() {
        let mut tracker = AmountTracker::new();
        tracker.set_agreed_amount(50_000);
        let tags = vec![Tag::Performative("ok".into())];
        assert!(tracker.validate_amount_tags(&tags).is_ok());
    }

    #[test]
    fn amount_tracker_agreed_amount_getter() {
        let mut tracker = AmountTracker::new();
        assert_eq!(tracker.agreed_amount(), None);
        tracker.set_agreed_amount(42_000);
        assert_eq!(tracker.agreed_amount(), Some(42_000));
    }

    // ====================================================================
    // PaymentOrderingGuard — normal flow
    // ====================================================================

    #[test]
    fn normal_commerce_flow_no_warnings() {
        let mut guard = PaymentOrderingGuard::new();
        assert!(guard.check_transition("quote").is_empty());
        assert!(guard.check_transition("accept-quote").is_empty());
        assert!(guard.check_transition("invoice").is_empty());
        assert!(guard.check_transition("paid").is_empty());
        assert_eq!(guard.state(), NegotiationState::Paid);
    }

    #[test]
    fn counter_then_accept_flow_no_warnings() {
        let mut guard = PaymentOrderingGuard::new();
        assert!(guard.check_transition("quote").is_empty());
        assert!(guard.check_transition("counter").is_empty());
        assert!(guard.check_transition("quote").is_empty());
        assert!(guard.check_transition("accept-quote").is_empty());
        assert!(guard.check_transition("invoice").is_empty());
        assert!(guard.check_transition("paid").is_empty());
    }

    // ====================================================================
    // PaymentOrderingGuard — invoice before acceptance
    // ====================================================================

    #[test]
    fn invoice_before_acceptance_warned() {
        let mut guard = PaymentOrderingGuard::new();
        let warnings = guard.check_transition("invoice");
        assert_eq!(warnings.len(), 1);
        assert!(matches!(
            warnings[0],
            PaymentOrderingWarning::InvoiceBeforeAcceptance {
                current_state: NegotiationState::Open,
            }
        ));
    }

    #[test]
    fn invoice_during_quoting_warned() {
        let mut guard = PaymentOrderingGuard::new();
        guard.check_transition("quote");
        let warnings = guard.check_transition("invoice");
        assert_eq!(warnings.len(), 1);
        assert!(matches!(
            warnings[0],
            PaymentOrderingWarning::InvoiceBeforeAcceptance {
                current_state: NegotiationState::Quoted,
            }
        ));
    }

    #[test]
    fn invoice_during_countered_warned() {
        let mut guard = PaymentOrderingGuard::new();
        guard.check_transition("quote");
        guard.check_transition("counter");
        let warnings = guard.check_transition("invoice");
        assert_eq!(warnings.len(), 1);
        assert!(matches!(
            warnings[0],
            PaymentOrderingWarning::InvoiceBeforeAcceptance {
                current_state: NegotiationState::Countered,
            }
        ));
    }

    // ====================================================================
    // PaymentOrderingGuard — paid before invoice
    // ====================================================================

    #[test]
    fn paid_before_invoice_warned() {
        let mut guard = PaymentOrderingGuard::new();
        let warnings = guard.check_transition("paid");
        assert_eq!(warnings.len(), 1);
        assert!(matches!(
            warnings[0],
            PaymentOrderingWarning::PaidBeforeInvoice {
                current_state: NegotiationState::Open,
            }
        ));
    }

    #[test]
    fn paid_in_accepted_state_warned() {
        let mut guard = PaymentOrderingGuard::new();
        guard.check_transition("quote");
        guard.check_transition("accept-quote");
        let warnings = guard.check_transition("paid");
        assert_eq!(warnings.len(), 1);
        assert!(matches!(
            warnings[0],
            PaymentOrderingWarning::PaidBeforeInvoice {
                current_state: NegotiationState::Accepted,
            }
        ));
    }

    // ====================================================================
    // PaymentOrderingGuard — zap receipt checks
    // ====================================================================

    #[test]
    fn zap_receipt_after_invoice_ok() {
        let mut guard = PaymentOrderingGuard::new();
        guard.check_transition("quote");
        guard.check_transition("accept-quote");
        guard.check_transition("invoice");
        assert!(guard.check_zap_receipt().is_none());
    }

    #[test]
    fn zap_receipt_after_paid_ok() {
        let mut guard = PaymentOrderingGuard::new();
        guard.check_transition("quote");
        guard.check_transition("accept-quote");
        guard.check_transition("invoice");
        guard.check_transition("paid");
        assert!(guard.check_zap_receipt().is_none());
    }

    #[test]
    fn zap_receipt_during_open_premature() {
        let guard = PaymentOrderingGuard::new();
        let warning = guard.check_zap_receipt().unwrap();
        assert!(matches!(
            warning,
            PaymentOrderingWarning::PrematurePaymentClaim {
                current_state: NegotiationState::Open,
            }
        ));
    }

    #[test]
    fn zap_receipt_during_accepted_premature() {
        let mut guard = PaymentOrderingGuard::new();
        guard.check_transition("quote");
        guard.check_transition("accept-quote");
        let warning = guard.check_zap_receipt().unwrap();
        assert!(matches!(
            warning,
            PaymentOrderingWarning::PrematurePaymentClaim {
                current_state: NegotiationState::Accepted,
            }
        ));
    }

    #[test]
    fn zap_receipt_during_working_premature() {
        let guard = PaymentOrderingGuard::from_state(NegotiationState::Working);
        let warning = guard.check_zap_receipt().unwrap();
        assert!(matches!(
            warning,
            PaymentOrderingWarning::PrematurePaymentClaim {
                current_state: NegotiationState::Working,
            }
        ));
    }

    // ====================================================================
    // PaymentOrderingGuard — from_state
    // ====================================================================

    #[test]
    fn guard_from_state() {
        let guard = PaymentOrderingGuard::from_state(NegotiationState::Invoiced);
        assert_eq!(guard.state(), NegotiationState::Invoiced);
        assert!(guard.check_zap_receipt().is_none());
    }

    // ====================================================================
    // End-to-end: publisher verification + amount tracking + ordering guard
    // ====================================================================

    #[test]
    fn end_to_end_safe_task_flow() {
        // 1. Check publisher reputation
        let summary = make_summary(5, 6, 250_000, 83, 1700000000);
        let verdict = verify_publisher(&summary, &TrustThresholds::default(), 1700000100);
        assert!(verdict.is_trusted());

        // 2. Track amount consistency through negotiation
        let mut amount_tracker = AmountTracker::new();
        // Task lists 50k msats
        amount_tracker.set_agreed_amount(50_000);

        // 3. Payment ordering guard through normal flow
        let mut guard = PaymentOrderingGuard::new();
        assert!(guard.check_transition("quote").is_empty());
        assert!(guard.check_transition("accept-quote").is_empty());

        // 4. Invoice carries correct amount
        let invoice_tags = vec![
            Tag::Performative("invoice".into()),
            Tag::Amount("50000".into()),
        ];
        assert!(amount_tracker.validate_amount_tags(&invoice_tags).is_ok());
        assert!(guard.check_transition("invoice").is_empty());

        // 5. Zap receipt is expected at this point
        assert!(guard.check_zap_receipt().is_none());

        // 6. Payment confirmed
        assert!(guard.check_transition("paid").is_empty());
        assert_eq!(guard.state(), NegotiationState::Paid);
    }

    #[test]
    fn end_to_end_suspicious_flow() {
        // Untrusted publisher
        let summary = make_summary(0, 0, 0, 100, 0);
        let verdict = verify_publisher(&summary, &TrustThresholds::default(), 1700000000);
        assert!(!verdict.is_trusted());

        // Amount tampered
        let mut amount_tracker = AmountTracker::new();
        amount_tracker.set_agreed_amount(50_000);
        let bad_tags = vec![Tag::Amount("100000".into())];
        assert!(amount_tracker.validate_amount_tags(&bad_tags).is_err());

        // Invoice before acceptance
        let mut guard = PaymentOrderingGuard::new();
        let warnings = guard.check_transition("invoice");
        assert!(!warnings.is_empty());
    }

    // ====================================================================
    // Domain expertise in verdict context
    // ====================================================================

    #[test]
    fn publisher_with_domain_expertise_trusted() {
        let summary = ReputationSummary {
            pubkey: "expert_pub".into(),
            total_earnings_msats: 500_000,
            completed_tasks: 20,
            assigned_tasks: 22,
            completion_rate_pct: 90,
            domain_expertise: vec![
                DomainExpertise {
                    dialect: "commerce".into(),
                    task_count: 15,
                    total_msats: 400_000,
                },
                DomainExpertise {
                    dialect: "logistics".into(),
                    task_count: 5,
                    total_msats: 100_000,
                },
            ],
            last_activity: 1700000000,
        };
        let verdict = verify_publisher(&summary, &TrustThresholds::strict(), 1700000100);
        assert!(verdict.is_trusted());
    }
}
