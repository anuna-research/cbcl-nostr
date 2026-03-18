//! Reputation query: aggregate on-relay zap receipts into agent reputation.
//!
//! Provides:
//! - [`ReputationAggregator`] — collects kind 9735 zap receipts for a pubkey
//!   and computes total earnings, completion rate, and domain expertise.
//! - [`ReputationSummary`] — snapshot of an agent's reputation for task
//!   assignment decisions.
//! - [`zap_receipt_filter`] — NIP-01 subscription filter for fetching zap
//!   receipts targeting a specific pubkey.

#![forbid(unsafe_code)]

use std::collections::HashMap;

use crate::event_types::{Event, Tag};
use crate::relay_pool::message::Filter;
use crate::zap_integration::{ZapReceipt, ZapError, KIND_ZAP_RECEIPT};

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors from reputation query operations.
#[derive(Debug, thiserror::Error)]
pub enum ReputationError {
    /// A zap receipt could not be parsed.
    #[error("zap receipt parse error: {0}")]
    ZapParse(#[from] ZapError),
}

// ---------------------------------------------------------------------------
// Domain expertise
// ---------------------------------------------------------------------------

/// Accumulated expertise in a single dialect domain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainExpertise {
    /// The dialect identifier (e.g. "commerce", "logistics").
    pub dialect: String,
    /// Number of zap receipts associated with this dialect.
    pub task_count: u64,
    /// Total earnings in millisatoshis for this dialect.
    pub total_msats: u64,
}

// ---------------------------------------------------------------------------
// ReputationSummary
// ---------------------------------------------------------------------------

/// Snapshot of an agent's on-relay reputation derived from zap receipts.
///
/// This summary is designed for task assignment decisions: higher earnings
/// and completion rates signal a more reliable agent, while domain expertise
/// helps match agents to tasks in specific dialect domains.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReputationSummary {
    /// The agent's public key (hex).
    pub pubkey: String,
    /// Total earnings across all zap receipts, in millisatoshis.
    pub total_earnings_msats: u64,
    /// Total number of zap receipts (completed payments).
    pub completed_tasks: u64,
    /// Number of tasks assigned (from assign events) but without a
    /// corresponding zap receipt — i.e. unconfirmed completions.
    pub assigned_tasks: u64,
    /// Completion rate as a percentage (0–100). If no tasks are assigned,
    /// this is 100 (no evidence of non-completion).
    pub completion_rate_pct: u8,
    /// Per-dialect expertise breakdown, sorted by task count descending.
    pub domain_expertise: Vec<DomainExpertise>,
    /// Timestamp of the most recent zap receipt (0 if none).
    pub last_activity: u64,
}

// ---------------------------------------------------------------------------
// Subscription filter
// ---------------------------------------------------------------------------

/// Build a NIP-01 subscription filter for kind 9735 zap receipts targeting
/// the given pubkey as recipient.
///
/// The filter uses the `#p` tag to match receipts where the agent is the
/// payment recipient.
pub fn zap_receipt_filter(pubkey: &str) -> Filter {
    Filter {
        ids: None,
        authors: None,
        kinds: Some(vec![KIND_ZAP_RECEIPT]),
        e_tags: None,
        p_tags: Some(vec![pubkey.to_string()]),
        t_tags: None,
        label_namespace_tags: None,
        label_tags: None,
        since: None,
        until: None,
        limit: None,
    }
}

/// Build a subscription filter for kind 9735 zap receipts targeting
/// the given pubkey, with a time bound.
pub fn zap_receipt_filter_since(pubkey: &str, since: u64) -> Filter {
    let mut f = zap_receipt_filter(pubkey);
    f.since = Some(since);
    f
}

// ---------------------------------------------------------------------------
// ReputationAggregator
// ---------------------------------------------------------------------------

/// Collects zap receipts and assign events to build a [`ReputationSummary`].
///
/// # Usage
///
/// ```
/// use cbcl_nostr::reputation_query::ReputationAggregator;
///
/// let mut agg = ReputationAggregator::new("abcdef1234");
/// // Feed zap receipt events as they arrive from relay subscriptions:
/// // agg.add_zap_receipt(event)?;
/// // agg.record_assignment();
/// let summary = agg.summarize();
/// ```
pub struct ReputationAggregator {
    pubkey: String,
    /// Deduplicated receipts by event ID.
    receipts: HashMap<String, ZapReceipt>,
    /// Dialect tags extracted from zap request content or associated events.
    receipt_dialects: HashMap<String, Vec<String>>,
    /// Number of task assignments observed for this agent.
    assigned_count: u64,
}

impl ReputationAggregator {
    /// Create a new aggregator for the given agent pubkey.
    pub fn new(pubkey: &str) -> Self {
        Self {
            pubkey: pubkey.to_string(),
            receipts: HashMap::new(),
            receipt_dialects: HashMap::new(),
            assigned_count: 0,
        }
    }

    /// Add a kind 9735 zap receipt event.
    ///
    /// The event is parsed via [`ZapReceipt::from_event`] and deduplicated
    /// by event ID. Only receipts where the `p` tag matches this aggregator's
    /// pubkey are counted.
    ///
    /// Optionally, dialect tags associated with this receipt can be provided
    /// via [`add_zap_receipt_with_dialects`].
    pub fn add_zap_receipt(&mut self, event: Event) -> Result<bool, ReputationError> {
        self.add_zap_receipt_with_dialects(event, &[])
    }

    /// Add a zap receipt with associated dialect tags.
    ///
    /// Dialect tags are typically extracted from the task event that was
    /// zapped (e.g. `["dialect", "commerce"]` on the original task).
    pub fn add_zap_receipt_with_dialects(
        &mut self,
        event: Event,
        dialects: &[String],
    ) -> Result<bool, ReputationError> {
        let event_id = event.id.clone();
        let receipt = ZapReceipt::from_event(event)?;

        // Only count receipts where this agent is the recipient
        if receipt.recipient != self.pubkey {
            return Ok(false);
        }

        // Deduplicate by event ID
        if self.receipts.contains_key(&event_id) {
            return Ok(false);
        }

        // Try to extract dialect tags from the embedded zap request content
        let mut all_dialects: Vec<String> = dialects.to_vec();
        if all_dialects.is_empty() {
            // Check the zap request's tags for dialect info
            if let Ok(zap_req) = serde_json::from_str::<Event>(&receipt.zap_request_json) {
                for raw_tag in &zap_req.tags {
                    if let Tag::Dialect(d) = Tag::parse(raw_tag) {
                        all_dialects.push(d);
                    }
                }
            }
        }

        if !all_dialects.is_empty() {
            self.receipt_dialects
                .insert(event_id.clone(), all_dialects);
        }

        self.receipts.insert(event_id, receipt);
        Ok(true)
    }

    /// Record that a task was assigned to this agent.
    ///
    /// This is used to compute the completion rate: assigned tasks without
    /// a corresponding zap receipt count as incomplete.
    pub fn record_assignment(&mut self) {
        self.assigned_count += 1;
    }

    /// Record multiple task assignments.
    pub fn record_assignments(&mut self, count: u64) {
        self.assigned_count += count;
    }

    /// Number of deduplicated zap receipts collected so far.
    pub fn receipt_count(&self) -> usize {
        self.receipts.len()
    }

    /// Produce a reputation summary from the collected data.
    pub fn summarize(&self) -> ReputationSummary {
        let completed = self.receipts.len() as u64;

        // Total earnings
        let total_earnings_msats: u64 = self.receipts.values().map(|r| r.amount_msats).sum();

        // Last activity
        let last_activity = self
            .receipts
            .values()
            .map(|r| r.event.created_at)
            .max()
            .unwrap_or(0);

        // Completion rate: completed / max(assigned, completed)
        // If assigned_count is 0, we use completed as the denominator
        // (agent has no evidence of non-completion).
        let total_tasks = self.assigned_count.max(completed);
        let completion_rate_pct = if total_tasks == 0 {
            100u8
        } else {
            ((completed * 100) / total_tasks).min(100) as u8
        };

        // Domain expertise aggregation
        let mut domain_map: HashMap<String, (u64, u64)> = HashMap::new();
        for (event_id, receipt) in &self.receipts {
            if let Some(dialects) = self.receipt_dialects.get(event_id) {
                for dialect in dialects {
                    let entry = domain_map.entry(dialect.clone()).or_insert((0, 0));
                    entry.0 += 1;
                    entry.1 += receipt.amount_msats;
                }
            }
        }

        let mut domain_expertise: Vec<DomainExpertise> = domain_map
            .into_iter()
            .map(|(dialect, (task_count, total_msats))| DomainExpertise {
                dialect,
                task_count,
                total_msats,
            })
            .collect();
        domain_expertise.sort_by(|a, b| b.task_count.cmp(&a.task_count));

        ReputationSummary {
            pubkey: self.pubkey.clone(),
            total_earnings_msats,
            completed_tasks: completed,
            assigned_tasks: self.assigned_count,
            completion_rate_pct,
            domain_expertise,
            last_activity,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zap_integration::KIND_ZAP_REQUEST;

    const AGENT_PK: &str = "agent_pubkey_hex";

    // Helper: build a minimal zap request event for embedding in receipts
    fn make_zap_request(
        recipient: &str,
        amount_msats: u64,
        dialect_tags: &[&str],
    ) -> Event {
        let mut tags = vec![
            vec!["p".into(), recipient.into()],
            vec!["amount".into(), amount_msats.to_string()],
            vec!["relays".into(), "wss://relay.example.com".into()],
        ];
        for d in dialect_tags {
            tags.push(vec!["dialect".into(), (*d).into()]);
        }
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

    // Helper: build a kind 9735 receipt
    fn make_receipt(
        id: &str,
        recipient: &str,
        amount_msats: u64,
        created_at: u64,
        dialect_tags: &[&str],
    ) -> Event {
        let zap_req = make_zap_request(recipient, amount_msats, dialect_tags);
        let zap_req_json = serde_json::to_string(&zap_req).unwrap();

        Event {
            id: id.into(),
            pubkey: "lightning_node".repeat(5).chars().take(64).collect(),
            created_at,
            kind: KIND_ZAP_RECEIPT,
            tags: vec![
                vec!["p".into(), recipient.into()],
                vec!["description".into(), zap_req_json],
            ],
            content: String::new(),
            sig: "f".repeat(128),
        }
    }

    // ====================================================================
    // Subscription filters
    // ====================================================================

    #[test]
    fn filter_targets_pubkey() {
        let f = zap_receipt_filter("abc123");
        assert_eq!(f.kinds, Some(vec![KIND_ZAP_RECEIPT]));
        assert_eq!(f.p_tags, Some(vec!["abc123".into()]));
        assert!(f.since.is_none());
    }

    #[test]
    fn filter_with_since() {
        let f = zap_receipt_filter_since("abc123", 1700000000);
        assert_eq!(f.kinds, Some(vec![KIND_ZAP_RECEIPT]));
        assert_eq!(f.p_tags, Some(vec!["abc123".into()]));
        assert_eq!(f.since, Some(1700000000));
    }

    // ====================================================================
    // Empty aggregator
    // ====================================================================

    #[test]
    fn empty_aggregator_summary() {
        let agg = ReputationAggregator::new(AGENT_PK);
        let summary = agg.summarize();

        assert_eq!(summary.pubkey, AGENT_PK);
        assert_eq!(summary.total_earnings_msats, 0);
        assert_eq!(summary.completed_tasks, 0);
        assert_eq!(summary.assigned_tasks, 0);
        assert_eq!(summary.completion_rate_pct, 100); // no evidence of failure
        assert!(summary.domain_expertise.is_empty());
        assert_eq!(summary.last_activity, 0);
    }

    // ====================================================================
    // Single receipt
    // ====================================================================

    #[test]
    fn single_receipt_aggregation() {
        let mut agg = ReputationAggregator::new(AGENT_PK);
        let event = make_receipt("evt1", AGENT_PK, 50_000, 1700000001, &[]);
        assert!(agg.add_zap_receipt(event).unwrap());

        let summary = agg.summarize();
        assert_eq!(summary.total_earnings_msats, 50_000);
        assert_eq!(summary.completed_tasks, 1);
        assert_eq!(summary.completion_rate_pct, 100);
        assert_eq!(summary.last_activity, 1700000001);
    }

    // ====================================================================
    // Multiple receipts with dialects
    // ====================================================================

    #[test]
    fn multiple_receipts_with_dialects() {
        let mut agg = ReputationAggregator::new(AGENT_PK);

        // Two commerce tasks, one logistics task
        let e1 = make_receipt("evt1", AGENT_PK, 50_000, 1700000001, &["commerce"]);
        let e2 = make_receipt("evt2", AGENT_PK, 75_000, 1700000002, &["commerce"]);
        let e3 = make_receipt("evt3", AGENT_PK, 30_000, 1700000003, &["logistics"]);

        agg.add_zap_receipt(e1).unwrap();
        agg.add_zap_receipt(e2).unwrap();
        agg.add_zap_receipt(e3).unwrap();

        let summary = agg.summarize();
        assert_eq!(summary.total_earnings_msats, 155_000);
        assert_eq!(summary.completed_tasks, 3);
        assert_eq!(summary.last_activity, 1700000003);

        // Domain expertise sorted by task count descending
        assert_eq!(summary.domain_expertise.len(), 2);
        assert_eq!(summary.domain_expertise[0].dialect, "commerce");
        assert_eq!(summary.domain_expertise[0].task_count, 2);
        assert_eq!(summary.domain_expertise[0].total_msats, 125_000);
        assert_eq!(summary.domain_expertise[1].dialect, "logistics");
        assert_eq!(summary.domain_expertise[1].task_count, 1);
        assert_eq!(summary.domain_expertise[1].total_msats, 30_000);
    }

    // ====================================================================
    // Deduplication
    // ====================================================================

    #[test]
    fn duplicate_receipts_ignored() {
        let mut agg = ReputationAggregator::new(AGENT_PK);
        let e1 = make_receipt("evt1", AGENT_PK, 50_000, 1700000001, &[]);
        let e1_dup = make_receipt("evt1", AGENT_PK, 50_000, 1700000001, &[]);

        assert!(agg.add_zap_receipt(e1).unwrap());
        assert!(!agg.add_zap_receipt(e1_dup).unwrap()); // duplicate

        assert_eq!(agg.receipt_count(), 1);
        assert_eq!(agg.summarize().total_earnings_msats, 50_000);
    }

    // ====================================================================
    // Wrong recipient filtered out
    // ====================================================================

    #[test]
    fn wrong_recipient_ignored() {
        let mut agg = ReputationAggregator::new(AGENT_PK);
        let event = make_receipt("evt1", "other_agent", 50_000, 1700000001, &[]);
        assert!(!agg.add_zap_receipt(event).unwrap());
        assert_eq!(agg.receipt_count(), 0);
    }

    // ====================================================================
    // Completion rate
    // ====================================================================

    #[test]
    fn completion_rate_all_completed() {
        let mut agg = ReputationAggregator::new(AGENT_PK);
        agg.record_assignments(3);

        let e1 = make_receipt("evt1", AGENT_PK, 10_000, 1700000001, &[]);
        let e2 = make_receipt("evt2", AGENT_PK, 20_000, 1700000002, &[]);
        let e3 = make_receipt("evt3", AGENT_PK, 30_000, 1700000003, &[]);
        agg.add_zap_receipt(e1).unwrap();
        agg.add_zap_receipt(e2).unwrap();
        agg.add_zap_receipt(e3).unwrap();

        let summary = agg.summarize();
        assert_eq!(summary.assigned_tasks, 3);
        assert_eq!(summary.completed_tasks, 3);
        assert_eq!(summary.completion_rate_pct, 100);
    }

    #[test]
    fn completion_rate_partial() {
        let mut agg = ReputationAggregator::new(AGENT_PK);
        agg.record_assignments(4); // 4 assigned

        // Only 2 completed
        let e1 = make_receipt("evt1", AGENT_PK, 10_000, 1700000001, &[]);
        let e2 = make_receipt("evt2", AGENT_PK, 20_000, 1700000002, &[]);
        agg.add_zap_receipt(e1).unwrap();
        agg.add_zap_receipt(e2).unwrap();

        let summary = agg.summarize();
        assert_eq!(summary.assigned_tasks, 4);
        assert_eq!(summary.completed_tasks, 2);
        assert_eq!(summary.completion_rate_pct, 50);
    }

    #[test]
    fn completion_rate_no_assignments_tracked() {
        // If we only have receipts and no assignment tracking,
        // completion rate is 100% (no evidence of failure).
        let mut agg = ReputationAggregator::new(AGENT_PK);
        let e1 = make_receipt("evt1", AGENT_PK, 10_000, 1700000001, &[]);
        agg.add_zap_receipt(e1).unwrap();

        let summary = agg.summarize();
        assert_eq!(summary.assigned_tasks, 0);
        assert_eq!(summary.completed_tasks, 1);
        assert_eq!(summary.completion_rate_pct, 100);
    }

    // ====================================================================
    // Explicit dialect tags via add_zap_receipt_with_dialects
    // ====================================================================

    #[test]
    fn explicit_dialect_tags() {
        let mut agg = ReputationAggregator::new(AGENT_PK);
        let event = make_receipt("evt1", AGENT_PK, 50_000, 1700000001, &[]);

        // Provide dialect tags explicitly (e.g. from the task event)
        agg.add_zap_receipt_with_dialects(
            event,
            &["analytics".to_string(), "commerce".to_string()],
        )
        .unwrap();

        let summary = agg.summarize();
        assert_eq!(summary.domain_expertise.len(), 2);

        let dialects: Vec<&str> = summary
            .domain_expertise
            .iter()
            .map(|d| d.dialect.as_str())
            .collect();
        assert!(dialects.contains(&"analytics"));
        assert!(dialects.contains(&"commerce"));
    }

    // ====================================================================
    // Dialect tags extracted from embedded zap request
    // ====================================================================

    #[test]
    fn dialect_from_embedded_zap_request() {
        let mut agg = ReputationAggregator::new(AGENT_PK);

        // The make_receipt helper embeds dialect tags in the zap request
        let event = make_receipt("evt1", AGENT_PK, 50_000, 1700000001, &["commerce"]);
        agg.add_zap_receipt(event).unwrap();

        let summary = agg.summarize();
        assert_eq!(summary.domain_expertise.len(), 1);
        assert_eq!(summary.domain_expertise[0].dialect, "commerce");
    }

    // ====================================================================
    // Invalid event handling
    // ====================================================================

    #[test]
    fn invalid_event_returns_error() {
        let mut agg = ReputationAggregator::new(AGENT_PK);
        let bad_event = Event {
            id: "bad".into(),
            pubkey: "x".into(),
            created_at: 0,
            kind: 1, // wrong kind
            tags: vec![],
            content: String::new(),
            sig: String::new(),
        };

        let result = agg.add_zap_receipt(bad_event);
        assert!(result.is_err());
    }

    // ====================================================================
    // Large aggregation
    // ====================================================================

    #[test]
    fn large_aggregation() {
        let mut agg = ReputationAggregator::new(AGENT_PK);
        agg.record_assignments(100);

        for i in 0..80 {
            let dialect = if i % 3 == 0 {
                "commerce"
            } else if i % 3 == 1 {
                "logistics"
            } else {
                "analytics"
            };
            let event = make_receipt(
                &format!("evt{i}"),
                AGENT_PK,
                10_000 + (i as u64 * 100),
                1700000000 + i as u64,
                &[dialect],
            );
            agg.add_zap_receipt(event).unwrap();
        }

        let summary = agg.summarize();
        assert_eq!(summary.completed_tasks, 80);
        assert_eq!(summary.assigned_tasks, 100);
        assert_eq!(summary.completion_rate_pct, 80);
        assert_eq!(summary.domain_expertise.len(), 3);
        assert_eq!(summary.last_activity, 1700000079);

        // Verify total earnings: sum of 10_000 + i*100 for i in 0..80
        let expected: u64 = (0..80).map(|i| 10_000 + i * 100).sum();
        assert_eq!(summary.total_earnings_msats, expected);
    }
}
