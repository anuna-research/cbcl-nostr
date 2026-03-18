//! Open task market: publish, claim, assign, and withdraw tasks.
//!
//! Agents publish open tasks as broadcast events (no `p` tag) that any agent
//! can discover and claim.  Fixed-price tasks carry an `["amount", <millisats>]`
//! tag.  The publisher controls how concurrent claims are resolved via a
//! [`ClaimPolicy`]: first-reply-wins (auto-assign) or publisher-chooses.
//!
//! # Protocol
//!
//! - **task** — broadcast kind 21111.  No `p` tag.  Content:
//!   `(task :description "..." [:amount <n>])`.  Tags include `["performative","task"]`,
//!   optional `["amount", <millisats>]`, and `["claim-policy", <policy>]`.
//! - **claim** — directed kind 21111 to publisher.  Content:
//!   `(claim :task-ref "<event-id>")`.  References the task via `["e", <id>]`.
//! - **assign** — directed kind 21111 to assignee.  Content:
//!   `(assign :task-ref "<event-id>")`.  Sent by publisher to confirm assignment.
//! - **withdraw** — broadcast kind 21111.  Content:
//!   `(withdraw :task-ref "<event-id>")`.  Publisher cancels an open task.
//!
//! # Claim resolution
//!
//! Under `FirstReplyWins`, the first valid claim automatically transitions the
//! task to `Assigned`.  Under `PublisherChooses`, claims accumulate and the
//! publisher explicitly assigns via an `assign` event.

#![forbid(unsafe_code)]

use std::collections::HashMap;

use cbcl_core::sexpr::{Atom, SExpr};

use crate::event_types::{Event, Tag, KIND_AGENT_MESSAGE};
use crate::message_builder::{BuilderError, MessageBuilder};
use crate::sexpr_codec;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// The four task-market performatives.
pub const TASK_MARKET_PERFORMATIVES: &[&str] = &["task", "claim", "assign", "withdraw"];

/// Returns `true` if `name` is a task-market performative.
pub fn is_task_market_performative(name: &str) -> bool {
    TASK_MARKET_PERFORMATIVES.contains(&name)
}

/// Tag key for the claim policy.
const TAG_CLAIM_POLICY: &str = "claim-policy";

// ---------------------------------------------------------------------------
// Claim policy
// ---------------------------------------------------------------------------

/// How concurrent claims on an open task are resolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ClaimPolicy {
    /// The first valid claim automatically assigns the task.
    FirstReplyWins,
    /// Claims accumulate; the publisher explicitly assigns.
    PublisherChooses,
}

impl ClaimPolicy {
    /// Serialize to the string used in tags.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::FirstReplyWins => "first-reply-wins",
            Self::PublisherChooses => "publisher-chooses",
        }
    }

    /// Parse from a tag value string.
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "first-reply-wins" => Some(Self::FirstReplyWins),
            "publisher-chooses" => Some(Self::PublisherChooses),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Task state machine
// ---------------------------------------------------------------------------

/// Lifecycle state of an open task.
///
/// ```text
/// Open → Claimed → Assigned (terminal)
/// Open → Assigned (first-reply-wins, single claim)
/// Open → Withdrawn (terminal)
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TaskState {
    /// Published and accepting claims.
    Open,
    /// One or more claims received (publisher-chooses mode).
    Claimed,
    /// Assigned to a claimant (terminal).
    Assigned,
    /// Publisher withdrew the task (terminal).
    Withdrawn,
}

/// Errors from invalid task state transitions.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TransitionError {
    /// The action is not valid from the current state.
    #[error("invalid transition: cannot apply \"{action}\" in state {state:?}")]
    InvalidTransition { state: TaskState, action: String },
}

impl TaskState {
    /// Returns `true` if this is a terminal state.
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Assigned | Self::Withdrawn)
    }

    /// Apply a claim. Under `FirstReplyWins` the task moves directly to
    /// `Assigned`; under `PublisherChooses` it moves to `Claimed`.
    pub fn apply_claim(self, policy: ClaimPolicy) -> Result<Self, TransitionError> {
        match self {
            Self::Open => match policy {
                ClaimPolicy::FirstReplyWins => Ok(Self::Assigned),
                ClaimPolicy::PublisherChooses => Ok(Self::Claimed),
            },
            Self::Claimed => match policy {
                // Additional claims in publisher-chooses mode stay Claimed
                ClaimPolicy::PublisherChooses => Ok(Self::Claimed),
                _ => Err(TransitionError::InvalidTransition {
                    state: self,
                    action: "claim".into(),
                }),
            },
            _ => Err(TransitionError::InvalidTransition {
                state: self,
                action: "claim".into(),
            }),
        }
    }

    /// Apply an assign action (only valid from `Claimed`).
    pub fn apply_assign(self) -> Result<Self, TransitionError> {
        match self {
            Self::Claimed => Ok(Self::Assigned),
            _ => Err(TransitionError::InvalidTransition {
                state: self,
                action: "assign".into(),
            }),
        }
    }

    /// Apply a withdraw action (only valid from `Open` or `Claimed`).
    pub fn apply_withdraw(self) -> Result<Self, TransitionError> {
        match self {
            Self::Open | Self::Claimed => Ok(Self::Withdrawn),
            _ => Err(TransitionError::InvalidTransition {
                state: self,
                action: "withdraw".into(),
            }),
        }
    }
}

// ---------------------------------------------------------------------------
// Event builders
// ---------------------------------------------------------------------------

/// Build an unsigned broadcast `task` event.
///
/// The event is kind 21111 with no `p` tag (broadcast).  Tags:
/// - `["performative", "task"]`
/// - `["claim-policy", <policy>]`
/// - `["amount", <millisats>]` (if `amount` is `Some`)
pub fn build_task(
    description: &str,
    amount: Option<u64>,
    policy: ClaimPolicy,
) -> Event {
    let mut body = vec![
        SExpr::Atom(Atom::Keyword("description".into())),
        SExpr::Atom(Atom::Str(description.into())),
    ];
    if let Some(amt) = amount {
        body.push(SExpr::Atom(Atom::Keyword("amount".into())));
        body.push(SExpr::Atom(Atom::Num(amt as i64)));
    }

    let mut items = Vec::with_capacity(1 + body.len());
    items.push(SExpr::Atom(Atom::Symbol("task".into())));
    items.extend(body);
    let content = sexpr_codec::encode(&SExpr::List(items));

    let mut tags: Vec<Vec<String>> = vec![
        vec!["performative".into(), "task".into()],
        vec![TAG_CLAIM_POLICY.into(), policy.as_str().into()],
    ];
    if let Some(amt) = amount {
        tags.push(vec!["amount".into(), amt.to_string()]);
    }

    Event {
        id: String::new(),
        pubkey: String::new(),
        created_at: 0,
        kind: KIND_AGENT_MESSAGE,
        tags,
        content,
        sig: String::new(),
    }
}

/// Build an unsigned directed `claim` event sent to the task publisher.
///
/// Tags include `["e", <task_event_id>]` to reference the task.
pub fn build_claim(
    publisher_pubkey: &str,
    task_event_id: &str,
) -> Result<Event, BuilderError> {
    MessageBuilder::new("claim")
        .recipient(publisher_pubkey)
        .body(vec![
            SExpr::Atom(Atom::Keyword("task-ref".into())),
            SExpr::Atom(Atom::Str(task_event_id.into())),
        ])
        .tag(Tag::Event(task_event_id.into()))
        .build()
}

/// Build an unsigned directed `assign` event sent to the chosen claimant.
///
/// Tags include `["e", <task_event_id>]` to reference the task.
pub fn build_assign(
    assignee_pubkey: &str,
    task_event_id: &str,
) -> Result<Event, BuilderError> {
    MessageBuilder::new("assign")
        .recipient(assignee_pubkey)
        .body(vec![
            SExpr::Atom(Atom::Keyword("task-ref".into())),
            SExpr::Atom(Atom::Str(task_event_id.into())),
        ])
        .tag(Tag::Event(task_event_id.into()))
        .build()
}

/// Build an unsigned broadcast `withdraw` event cancelling an open task.
///
/// Tags include `["e", <task_event_id>]` to reference the task.
pub fn build_withdraw(task_event_id: &str) -> Event {
    let content = sexpr_codec::encode(&SExpr::List(vec![
        SExpr::Atom(Atom::Symbol("withdraw".into())),
        SExpr::Atom(Atom::Keyword("task-ref".into())),
        SExpr::Atom(Atom::Str(task_event_id.into())),
    ]));

    Event {
        id: String::new(),
        pubkey: String::new(),
        created_at: 0,
        kind: KIND_AGENT_MESSAGE,
        tags: vec![
            vec!["performative".into(), "withdraw".into()],
            vec!["e".into(), task_event_id.into()],
        ],
        content,
        sig: String::new(),
    }
}

// ---------------------------------------------------------------------------
// Task registry
// ---------------------------------------------------------------------------

/// Errors from task registry operations.
#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    /// The event kind is not a kind 21111 agent message.
    #[error("not an agent message: kind {0}")]
    WrongKind(u64),

    /// No performative tag found on the event.
    #[error("missing performative tag")]
    MissingPerformative,

    /// The performative is not a task-market verb.
    #[error("not a task-market event: performative \"{0}\"")]
    NotTaskMarket(String),

    /// The referenced task was not found in the registry.
    #[error("task not found: \"{0}\"")]
    TaskNotFound(String),

    /// A state transition was invalid.
    #[error(transparent)]
    Transition(#[from] TransitionError),

    /// The claim event is missing an `e` tag referencing the task.
    #[error("claim/assign/withdraw missing task reference (e tag)")]
    MissingTaskRef,

    /// The actor is not authorized for this action.
    #[error("unauthorized: only the publisher can {0}")]
    Unauthorized(String),
}

/// A claim on an open task.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimEntry {
    /// Public key of the claimant.
    pub claimant: String,
    /// Event ID of the claim event.
    pub claim_event_id: String,
    /// Unix timestamp of the claim.
    pub created_at: u64,
}

/// An open task in the registry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskEntry {
    /// Event ID of the task publication.
    pub task_event_id: String,
    /// Public key of the publisher.
    pub publisher: String,
    /// Task description from the content.
    pub description: String,
    /// Fixed price in millisats (if specified).
    pub amount: Option<u64>,
    /// How concurrent claims are resolved.
    pub claim_policy: ClaimPolicy,
    /// Current lifecycle state.
    pub state: TaskState,
    /// Accumulated claims.
    pub claims: Vec<ClaimEntry>,
    /// Public key of the assigned agent (once assigned).
    pub assignee: Option<String>,
    /// Unix timestamp of the task publication.
    pub created_at: u64,
}

/// In-memory registry of open tasks.
///
/// Feed task/claim/assign/withdraw events via [`process_event`](Self::process_event)
/// to maintain the directory.
#[derive(Debug, Clone, Default)]
pub struct TaskRegistry {
    tasks: HashMap<String, TaskEntry>,
}

impl TaskRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Process a kind 21111 event and update the registry.
    ///
    /// Returns the performative that was processed.
    pub fn process_event(&mut self, event: &Event) -> Result<String, RegistryError> {
        if event.kind != KIND_AGENT_MESSAGE {
            return Err(RegistryError::WrongKind(event.kind));
        }

        let performative = extract_performative(&event.tags)?;

        match performative {
            "task" => self.process_task(event),
            "claim" => self.process_claim(event),
            "assign" => self.process_assign(event),
            "withdraw" => self.process_withdraw(event),
            other => Err(RegistryError::NotTaskMarket(other.into())),
        }
    }

    /// Get a task entry by event ID.
    pub fn get(&self, task_event_id: &str) -> Option<&TaskEntry> {
        self.tasks.get(task_event_id)
    }

    /// Iterate over all tasks.
    pub fn tasks(&self) -> impl Iterator<Item = &TaskEntry> {
        self.tasks.values()
    }

    /// Iterate over tasks that are still open (accepting claims).
    pub fn open_tasks(&self) -> impl Iterator<Item = &TaskEntry> {
        self.tasks.values().filter(|t| t.state == TaskState::Open)
    }

    /// Number of tasks in the registry.
    pub fn len(&self) -> usize {
        self.tasks.len()
    }

    /// Returns `true` if the registry has no tasks.
    pub fn is_empty(&self) -> bool {
        self.tasks.is_empty()
    }

    // -- internal processing --

    fn process_task(&mut self, event: &Event) -> Result<String, RegistryError> {
        let description = extract_description_from_content(&event.content);
        let amount = extract_tag_value(&event.tags, "amount")
            .and_then(|v| v.parse::<u64>().ok());
        let policy = extract_tag_value(&event.tags, TAG_CLAIM_POLICY)
            .and_then(|v| ClaimPolicy::from_str(&v))
            .unwrap_or(ClaimPolicy::FirstReplyWins);

        self.tasks.insert(
            event.id.clone(),
            TaskEntry {
                task_event_id: event.id.clone(),
                publisher: event.pubkey.clone(),
                description,
                amount,
                claim_policy: policy,
                state: TaskState::Open,
                claims: Vec::new(),
                assignee: None,
                created_at: event.created_at,
            },
        );

        Ok("task".into())
    }

    fn process_claim(&mut self, event: &Event) -> Result<String, RegistryError> {
        let task_id = extract_event_ref(&event.tags)
            .ok_or(RegistryError::MissingTaskRef)?;

        let task = self
            .tasks
            .get_mut(&task_id)
            .ok_or_else(|| RegistryError::TaskNotFound(task_id.clone()))?;

        let new_state = task.state.apply_claim(task.claim_policy)?;

        task.claims.push(ClaimEntry {
            claimant: event.pubkey.clone(),
            claim_event_id: event.id.clone(),
            created_at: event.created_at,
        });

        task.state = new_state;

        // Under FirstReplyWins, auto-assign the first claimant
        if task.claim_policy == ClaimPolicy::FirstReplyWins
            && task.state == TaskState::Assigned
        {
            task.assignee = Some(event.pubkey.clone());
        }

        Ok("claim".into())
    }

    fn process_assign(&mut self, event: &Event) -> Result<String, RegistryError> {
        let task_id = extract_event_ref(&event.tags)
            .ok_or(RegistryError::MissingTaskRef)?;

        let task = self
            .tasks
            .get_mut(&task_id)
            .ok_or_else(|| RegistryError::TaskNotFound(task_id.clone()))?;

        // Only the publisher can assign
        if event.pubkey != task.publisher {
            return Err(RegistryError::Unauthorized("assign".into()));
        }

        let new_state = task.state.apply_assign()?;
        task.state = new_state;

        // The assignee is the recipient (p tag) of the assign event
        let assignee = event
            .tags
            .iter()
            .find(|t| t.first().map(String::as_str) == Some("p") && t.len() >= 2)
            .map(|t| t[1].clone());
        task.assignee = assignee;

        Ok("assign".into())
    }

    fn process_withdraw(&mut self, event: &Event) -> Result<String, RegistryError> {
        let task_id = extract_event_ref(&event.tags)
            .ok_or(RegistryError::MissingTaskRef)?;

        let task = self
            .tasks
            .get_mut(&task_id)
            .ok_or_else(|| RegistryError::TaskNotFound(task_id.clone()))?;

        // Only the publisher can withdraw
        if event.pubkey != task.publisher {
            return Err(RegistryError::Unauthorized("withdraw".into()));
        }

        let new_state = task.state.apply_withdraw()?;
        task.state = new_state;

        Ok("withdraw".into())
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Extract the performative tag value from raw tags.
fn extract_performative<'a>(tags: &'a [Vec<String>]) -> Result<&'a str, RegistryError> {
    tags.iter()
        .find(|t| t.first().map(String::as_str) == Some("performative") && t.len() >= 2)
        .map(|t| t[1].as_str())
        .ok_or(RegistryError::MissingPerformative)
}

/// Extract the first `e` tag value (event reference).
fn extract_event_ref(tags: &[Vec<String>]) -> Option<String> {
    tags.iter()
        .find(|t| t.first().map(String::as_str) == Some("e") && t.len() >= 2)
        .map(|t| t[1].clone())
}

/// Extract the first value for a raw tag key.
fn extract_tag_value(tags: &[Vec<String>], key: &str) -> Option<String> {
    tags.iter()
        .find(|t| t.first().map(String::as_str) == Some(key) && t.len() >= 2)
        .map(|t| t[1].clone())
}

/// Extract the description from the task S-expression content.
///
/// Parses `(task :description "..." ...)` and returns the description string.
fn extract_description_from_content(content: &str) -> String {
    let Ok(sexpr) = sexpr_codec::decode(content) else {
        return String::new();
    };
    let SExpr::List(items) = sexpr else {
        return String::new();
    };
    // Look for :description keyword followed by a string
    let mut iter = items.iter().skip(1); // skip "task" symbol
    while let Some(item) = iter.next() {
        if matches!(item, SExpr::Atom(Atom::Keyword(k)) if k == "description") {
            if let Some(SExpr::Atom(Atom::Str(s))) = iter.next() {
                return s.clone();
            }
        }
    }
    String::new()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_event(
        id: &str,
        pubkey: &str,
        created_at: u64,
        tags: Vec<Vec<String>>,
        content: &str,
    ) -> Event {
        Event {
            id: id.into(),
            pubkey: pubkey.into(),
            created_at,
            kind: KIND_AGENT_MESSAGE,
            tags,
            content: content.into(),
            sig: "c".repeat(128),
        }
    }

    fn task_tags(policy: ClaimPolicy, amount: Option<u64>) -> Vec<Vec<String>> {
        let mut tags = vec![
            vec!["performative".into(), "task".into()],
            vec![TAG_CLAIM_POLICY.into(), policy.as_str().into()],
        ];
        if let Some(amt) = amount {
            tags.push(vec!["amount".into(), amt.to_string()]);
        }
        tags
    }

    fn claim_tags(task_event_id: &str, publisher_pk: &str) -> Vec<Vec<String>> {
        vec![
            vec!["p".into(), publisher_pk.into()],
            vec!["performative".into(), "claim".into()],
            vec!["e".into(), task_event_id.into()],
        ]
    }

    fn assign_tags(task_event_id: &str, assignee_pk: &str) -> Vec<Vec<String>> {
        vec![
            vec!["p".into(), assignee_pk.into()],
            vec!["performative".into(), "assign".into()],
            vec!["e".into(), task_event_id.into()],
        ]
    }

    fn withdraw_tags(task_event_id: &str) -> Vec<Vec<String>> {
        vec![
            vec!["performative".into(), "withdraw".into()],
            vec!["e".into(), task_event_id.into()],
        ]
    }

    // ====================================================================
    // Performative check
    // ====================================================================

    #[test]
    fn task_market_performatives_recognized() {
        for &p in TASK_MARKET_PERFORMATIVES {
            assert!(is_task_market_performative(p), "{p} should be task-market");
        }
    }

    #[test]
    fn core_performatives_not_task_market() {
        assert!(!is_task_market_performative("tell"));
        assert!(!is_task_market_performative("hello"));
        assert!(!is_task_market_performative("quote"));
    }

    // ====================================================================
    // ClaimPolicy
    // ====================================================================

    #[test]
    fn claim_policy_round_trip() {
        for policy in [ClaimPolicy::FirstReplyWins, ClaimPolicy::PublisherChooses] {
            let s = policy.as_str();
            assert_eq!(ClaimPolicy::from_str(s), Some(policy));
        }
    }

    #[test]
    fn claim_policy_unknown_returns_none() {
        assert_eq!(ClaimPolicy::from_str("unknown"), None);
    }

    // ====================================================================
    // TaskState — valid transitions
    // ====================================================================

    #[test]
    fn open_claim_first_reply_wins() {
        let state = TaskState::Open
            .apply_claim(ClaimPolicy::FirstReplyWins)
            .unwrap();
        assert_eq!(state, TaskState::Assigned);
    }

    #[test]
    fn open_claim_publisher_chooses() {
        let state = TaskState::Open
            .apply_claim(ClaimPolicy::PublisherChooses)
            .unwrap();
        assert_eq!(state, TaskState::Claimed);
    }

    #[test]
    fn claimed_additional_claim_publisher_chooses() {
        let state = TaskState::Claimed
            .apply_claim(ClaimPolicy::PublisherChooses)
            .unwrap();
        assert_eq!(state, TaskState::Claimed);
    }

    #[test]
    fn claimed_to_assigned() {
        let state = TaskState::Claimed.apply_assign().unwrap();
        assert_eq!(state, TaskState::Assigned);
    }

    #[test]
    fn open_to_withdrawn() {
        let state = TaskState::Open.apply_withdraw().unwrap();
        assert_eq!(state, TaskState::Withdrawn);
    }

    #[test]
    fn claimed_to_withdrawn() {
        let state = TaskState::Claimed.apply_withdraw().unwrap();
        assert_eq!(state, TaskState::Withdrawn);
    }

    // ====================================================================
    // TaskState — invalid transitions
    // ====================================================================

    #[test]
    fn assigned_cannot_claim() {
        let err = TaskState::Assigned
            .apply_claim(ClaimPolicy::FirstReplyWins)
            .unwrap_err();
        assert!(matches!(err, TransitionError::InvalidTransition { .. }));
    }

    #[test]
    fn withdrawn_cannot_claim() {
        let err = TaskState::Withdrawn
            .apply_claim(ClaimPolicy::PublisherChooses)
            .unwrap_err();
        assert!(matches!(err, TransitionError::InvalidTransition { .. }));
    }

    #[test]
    fn open_cannot_assign() {
        let err = TaskState::Open.apply_assign().unwrap_err();
        assert!(matches!(err, TransitionError::InvalidTransition { .. }));
    }

    #[test]
    fn assigned_cannot_withdraw() {
        let err = TaskState::Assigned.apply_withdraw().unwrap_err();
        assert!(matches!(err, TransitionError::InvalidTransition { .. }));
    }

    #[test]
    fn withdrawn_cannot_withdraw() {
        let err = TaskState::Withdrawn.apply_withdraw().unwrap_err();
        assert!(matches!(err, TransitionError::InvalidTransition { .. }));
    }

    // ====================================================================
    // TaskState — terminal
    // ====================================================================

    #[test]
    fn terminal_states() {
        assert!(!TaskState::Open.is_terminal());
        assert!(!TaskState::Claimed.is_terminal());
        assert!(TaskState::Assigned.is_terminal());
        assert!(TaskState::Withdrawn.is_terminal());
    }

    // ====================================================================
    // Event builders
    // ====================================================================

    #[test]
    fn build_task_event() {
        let event = build_task("Fix the bug", None, ClaimPolicy::FirstReplyWins);
        assert_eq!(event.kind, KIND_AGENT_MESSAGE);
        assert_eq!(
            event.content,
            r#"(task :description "Fix the bug")"#
        );
        // No p tag (broadcast)
        assert!(!event.tags.iter().any(|t| t.first().map(String::as_str) == Some("p")));
        // Has performative tag
        assert_eq!(event.tags[0], vec!["performative", "task"]);
        // Has claim-policy tag
        assert_eq!(event.tags[1], vec!["claim-policy", "first-reply-wins"]);
        // No amount tag
        assert!(!event.tags.iter().any(|t| t.first().map(String::as_str) == Some("amount")));
    }

    #[test]
    fn build_task_with_amount() {
        let event = build_task("Deploy service", Some(50000), ClaimPolicy::PublisherChooses);
        assert_eq!(
            event.content,
            r#"(task :description "Deploy service" :amount 50000)"#
        );
        assert_eq!(event.tags[2], vec!["amount", "50000"]);
    }

    #[test]
    fn build_task_no_p_tag() {
        let event = build_task("Test", None, ClaimPolicy::FirstReplyWins);
        for tag in &event.tags {
            assert_ne!(tag.first().map(String::as_str), Some("p"));
        }
    }

    #[test]
    fn build_claim_event() {
        let event = build_claim("publisher_pk", "task_event_123").unwrap();
        assert_eq!(event.kind, KIND_AGENT_MESSAGE);
        assert_eq!(
            event.content,
            r#"(claim :task-ref "task_event_123")"#
        );
        let tags: Vec<Tag> = event.tags.iter().map(|t| Tag::parse(t)).collect();
        assert!(tags.contains(&Tag::PubKey("publisher_pk".into())));
        assert!(tags.contains(&Tag::Performative("claim".into())));
        assert!(tags.contains(&Tag::Event("task_event_123".into())));
    }

    #[test]
    fn build_assign_event() {
        let event = build_assign("assignee_pk", "task_event_123").unwrap();
        assert_eq!(event.kind, KIND_AGENT_MESSAGE);
        assert_eq!(
            event.content,
            r#"(assign :task-ref "task_event_123")"#
        );
        let tags: Vec<Tag> = event.tags.iter().map(|t| Tag::parse(t)).collect();
        assert!(tags.contains(&Tag::PubKey("assignee_pk".into())));
        assert!(tags.contains(&Tag::Performative("assign".into())));
        assert!(tags.contains(&Tag::Event("task_event_123".into())));
    }

    #[test]
    fn build_withdraw_event() {
        let event = build_withdraw("task_event_123");
        assert_eq!(event.kind, KIND_AGENT_MESSAGE);
        assert_eq!(
            event.content,
            r#"(withdraw :task-ref "task_event_123")"#
        );
        // No p tag (broadcast)
        assert!(!event.tags.iter().any(|t| t.first().map(String::as_str) == Some("p")));
        assert_eq!(event.tags[0], vec!["performative", "withdraw"]);
        assert_eq!(event.tags[1], vec!["e", "task_event_123"]);
    }

    // ====================================================================
    // Registry — task publishing
    // ====================================================================

    #[test]
    fn registry_task_adds_entry() {
        let mut reg = TaskRegistry::new();
        let event = make_event(
            "task_001",
            "publisher",
            1000,
            task_tags(ClaimPolicy::FirstReplyWins, None),
            r#"(task :description "Fix the bug")"#,
        );

        let result = reg.process_event(&event).unwrap();
        assert_eq!(result, "task");
        assert_eq!(reg.len(), 1);

        let entry = reg.get("task_001").unwrap();
        assert_eq!(entry.publisher, "publisher");
        assert_eq!(entry.description, "Fix the bug");
        assert_eq!(entry.amount, None);
        assert_eq!(entry.claim_policy, ClaimPolicy::FirstReplyWins);
        assert_eq!(entry.state, TaskState::Open);
        assert!(entry.claims.is_empty());
        assert_eq!(entry.assignee, None);
    }

    #[test]
    fn registry_task_with_amount() {
        let mut reg = TaskRegistry::new();
        let event = make_event(
            "task_002",
            "publisher",
            1000,
            task_tags(ClaimPolicy::PublisherChooses, Some(50000)),
            r#"(task :description "Deploy" :amount 50000)"#,
        );
        reg.process_event(&event).unwrap();

        let entry = reg.get("task_002").unwrap();
        assert_eq!(entry.amount, Some(50000));
        assert_eq!(entry.claim_policy, ClaimPolicy::PublisherChooses);
    }

    // ====================================================================
    // Registry — first-reply-wins
    // ====================================================================

    #[test]
    fn first_reply_wins_auto_assigns() {
        let mut reg = TaskRegistry::new();

        // Publish task
        reg.process_event(&make_event(
            "task_001",
            "publisher",
            1000,
            task_tags(ClaimPolicy::FirstReplyWins, None),
            r#"(task :description "Fix bug")"#,
        ))
        .unwrap();

        // First claim
        let result = reg
            .process_event(&make_event(
                "claim_001",
                "claimer_alice",
                2000,
                claim_tags("task_001", "publisher"),
                r#"(claim :task-ref "task_001")"#,
            ))
            .unwrap();
        assert_eq!(result, "claim");

        let entry = reg.get("task_001").unwrap();
        assert_eq!(entry.state, TaskState::Assigned);
        assert_eq!(entry.assignee, Some("claimer_alice".into()));
        assert_eq!(entry.claims.len(), 1);
    }

    #[test]
    fn first_reply_wins_rejects_second_claim() {
        let mut reg = TaskRegistry::new();

        reg.process_event(&make_event(
            "task_001",
            "publisher",
            1000,
            task_tags(ClaimPolicy::FirstReplyWins, None),
            r#"(task :description "Fix bug")"#,
        ))
        .unwrap();

        // First claim succeeds
        reg.process_event(&make_event(
            "claim_001",
            "alice",
            2000,
            claim_tags("task_001", "publisher"),
            r#"(claim :task-ref "task_001")"#,
        ))
        .unwrap();

        // Second claim fails (task already assigned)
        let err = reg
            .process_event(&make_event(
                "claim_002",
                "bob",
                2001,
                claim_tags("task_001", "publisher"),
                r#"(claim :task-ref "task_001")"#,
            ))
            .unwrap_err();
        assert!(matches!(err, RegistryError::Transition(_)));
    }

    // ====================================================================
    // Registry — publisher-chooses
    // ====================================================================

    #[test]
    fn publisher_chooses_accumulates_claims() {
        let mut reg = TaskRegistry::new();

        reg.process_event(&make_event(
            "task_001",
            "publisher",
            1000,
            task_tags(ClaimPolicy::PublisherChooses, Some(5000)),
            r#"(task :description "Build feature" :amount 5000)"#,
        ))
        .unwrap();

        // Multiple claims
        reg.process_event(&make_event(
            "claim_001",
            "alice",
            2000,
            claim_tags("task_001", "publisher"),
            r#"(claim :task-ref "task_001")"#,
        ))
        .unwrap();

        reg.process_event(&make_event(
            "claim_002",
            "bob",
            2001,
            claim_tags("task_001", "publisher"),
            r#"(claim :task-ref "task_001")"#,
        ))
        .unwrap();

        let entry = reg.get("task_001").unwrap();
        assert_eq!(entry.state, TaskState::Claimed);
        assert_eq!(entry.claims.len(), 2);
        assert_eq!(entry.claims[0].claimant, "alice");
        assert_eq!(entry.claims[1].claimant, "bob");
        assert_eq!(entry.assignee, None);
    }

    #[test]
    fn publisher_chooses_then_assigns() {
        let mut reg = TaskRegistry::new();

        reg.process_event(&make_event(
            "task_001",
            "publisher",
            1000,
            task_tags(ClaimPolicy::PublisherChooses, None),
            r#"(task :description "Review code")"#,
        ))
        .unwrap();

        reg.process_event(&make_event(
            "claim_001",
            "alice",
            2000,
            claim_tags("task_001", "publisher"),
            r#"(claim :task-ref "task_001")"#,
        ))
        .unwrap();

        // Publisher assigns alice
        let result = reg
            .process_event(&make_event(
                "assign_001",
                "publisher",
                3000,
                assign_tags("task_001", "alice"),
                r#"(assign :task-ref "task_001")"#,
            ))
            .unwrap();
        assert_eq!(result, "assign");

        let entry = reg.get("task_001").unwrap();
        assert_eq!(entry.state, TaskState::Assigned);
        assert_eq!(entry.assignee, Some("alice".into()));
    }

    // ====================================================================
    // Registry — withdraw
    // ====================================================================

    #[test]
    fn withdraw_open_task() {
        let mut reg = TaskRegistry::new();

        reg.process_event(&make_event(
            "task_001",
            "publisher",
            1000,
            task_tags(ClaimPolicy::FirstReplyWins, None),
            r#"(task :description "Old task")"#,
        ))
        .unwrap();

        let result = reg
            .process_event(&make_event(
                "withdraw_001",
                "publisher",
                2000,
                withdraw_tags("task_001"),
                r#"(withdraw :task-ref "task_001")"#,
            ))
            .unwrap();
        assert_eq!(result, "withdraw");

        let entry = reg.get("task_001").unwrap();
        assert_eq!(entry.state, TaskState::Withdrawn);
    }

    #[test]
    fn withdraw_claimed_task() {
        let mut reg = TaskRegistry::new();

        reg.process_event(&make_event(
            "task_001",
            "publisher",
            1000,
            task_tags(ClaimPolicy::PublisherChooses, None),
            r#"(task :description "Cancel me")"#,
        ))
        .unwrap();

        reg.process_event(&make_event(
            "claim_001",
            "alice",
            2000,
            claim_tags("task_001", "publisher"),
            r#"(claim :task-ref "task_001")"#,
        ))
        .unwrap();

        reg.process_event(&make_event(
            "withdraw_001",
            "publisher",
            3000,
            withdraw_tags("task_001"),
            r#"(withdraw :task-ref "task_001")"#,
        ))
        .unwrap();

        assert_eq!(reg.get("task_001").unwrap().state, TaskState::Withdrawn);
    }

    #[test]
    fn cannot_withdraw_assigned_task() {
        let mut reg = TaskRegistry::new();

        reg.process_event(&make_event(
            "task_001",
            "publisher",
            1000,
            task_tags(ClaimPolicy::FirstReplyWins, None),
            r#"(task :description "Done")"#,
        ))
        .unwrap();

        reg.process_event(&make_event(
            "claim_001",
            "alice",
            2000,
            claim_tags("task_001", "publisher"),
            r#"(claim :task-ref "task_001")"#,
        ))
        .unwrap();

        let err = reg
            .process_event(&make_event(
                "withdraw_001",
                "publisher",
                3000,
                withdraw_tags("task_001"),
                r#"(withdraw :task-ref "task_001")"#,
            ))
            .unwrap_err();
        assert!(matches!(err, RegistryError::Transition(_)));
    }

    // ====================================================================
    // Registry — authorization
    // ====================================================================

    #[test]
    fn non_publisher_cannot_assign() {
        let mut reg = TaskRegistry::new();

        reg.process_event(&make_event(
            "task_001",
            "publisher",
            1000,
            task_tags(ClaimPolicy::PublisherChooses, None),
            r#"(task :description "Guarded")"#,
        ))
        .unwrap();

        reg.process_event(&make_event(
            "claim_001",
            "alice",
            2000,
            claim_tags("task_001", "publisher"),
            r#"(claim :task-ref "task_001")"#,
        ))
        .unwrap();

        // Bob tries to assign (not the publisher)
        let err = reg
            .process_event(&make_event(
                "assign_001",
                "bob",
                3000,
                assign_tags("task_001", "alice"),
                r#"(assign :task-ref "task_001")"#,
            ))
            .unwrap_err();
        assert!(matches!(err, RegistryError::Unauthorized(_)));
    }

    #[test]
    fn non_publisher_cannot_withdraw() {
        let mut reg = TaskRegistry::new();

        reg.process_event(&make_event(
            "task_001",
            "publisher",
            1000,
            task_tags(ClaimPolicy::FirstReplyWins, None),
            r#"(task :description "Protected")"#,
        ))
        .unwrap();

        let err = reg
            .process_event(&make_event(
                "withdraw_001",
                "attacker",
                2000,
                withdraw_tags("task_001"),
                r#"(withdraw :task-ref "task_001")"#,
            ))
            .unwrap_err();
        assert!(matches!(err, RegistryError::Unauthorized(_)));
    }

    // ====================================================================
    // Registry — errors
    // ====================================================================

    #[test]
    fn registry_wrong_kind() {
        let mut reg = TaskRegistry::new();
        let event = Event {
            kind: 1,
            ..make_event("x", "y", 0, vec![], "")
        };
        let err = reg.process_event(&event).unwrap_err();
        assert!(matches!(err, RegistryError::WrongKind(1)));
    }

    #[test]
    fn registry_missing_performative() {
        let mut reg = TaskRegistry::new();
        let event = make_event("x", "y", 0, vec![], "(task)");
        let err = reg.process_event(&event).unwrap_err();
        assert!(matches!(err, RegistryError::MissingPerformative));
    }

    #[test]
    fn registry_not_task_market() {
        let mut reg = TaskRegistry::new();
        let event = make_event(
            "x",
            "y",
            0,
            vec![vec!["performative".into(), "tell".into()]],
            "(tell)",
        );
        let err = reg.process_event(&event).unwrap_err();
        assert!(matches!(err, RegistryError::NotTaskMarket(_)));
    }

    #[test]
    fn claim_missing_task_ref() {
        let mut reg = TaskRegistry::new();
        let event = make_event(
            "x",
            "y",
            0,
            vec![vec!["performative".into(), "claim".into()]],
            r#"(claim :task-ref "missing")"#,
        );
        let err = reg.process_event(&event).unwrap_err();
        assert!(matches!(err, RegistryError::MissingTaskRef));
    }

    #[test]
    fn claim_task_not_found() {
        let mut reg = TaskRegistry::new();
        let event = make_event(
            "claim_x",
            "claimer",
            0,
            vec![
                vec!["performative".into(), "claim".into()],
                vec!["e".into(), "nonexistent_task".into()],
            ],
            r#"(claim :task-ref "nonexistent_task")"#,
        );
        let err = reg.process_event(&event).unwrap_err();
        assert!(matches!(err, RegistryError::TaskNotFound(_)));
    }

    // ====================================================================
    // Registry — open_tasks iterator
    // ====================================================================

    #[test]
    fn open_tasks_iterator() {
        let mut reg = TaskRegistry::new();

        reg.process_event(&make_event(
            "task_001",
            "pub1",
            1000,
            task_tags(ClaimPolicy::FirstReplyWins, None),
            r#"(task :description "Open")"#,
        ))
        .unwrap();

        reg.process_event(&make_event(
            "task_002",
            "pub2",
            1001,
            task_tags(ClaimPolicy::FirstReplyWins, None),
            r#"(task :description "Also open")"#,
        ))
        .unwrap();

        // Claim task_001 (auto-assigns under first-reply-wins)
        reg.process_event(&make_event(
            "claim_001",
            "alice",
            2000,
            claim_tags("task_001", "pub1"),
            r#"(claim :task-ref "task_001")"#,
        ))
        .unwrap();

        let open: Vec<&str> = reg
            .open_tasks()
            .map(|t| t.task_event_id.as_str())
            .collect();
        assert_eq!(open, vec!["task_002"]);
    }

    // ====================================================================
    // Full lifecycle — publisher-chooses
    // ====================================================================

    #[test]
    fn full_lifecycle_publisher_chooses() {
        let mut reg = TaskRegistry::new();

        // 1. Publisher creates task
        reg.process_event(&make_event(
            "task_001",
            "publisher",
            1000,
            task_tags(ClaimPolicy::PublisherChooses, Some(10000)),
            r#"(task :description "Build API" :amount 10000)"#,
        ))
        .unwrap();
        assert_eq!(reg.get("task_001").unwrap().state, TaskState::Open);

        // 2. Alice claims
        reg.process_event(&make_event(
            "claim_001",
            "alice",
            2000,
            claim_tags("task_001", "publisher"),
            r#"(claim :task-ref "task_001")"#,
        ))
        .unwrap();
        assert_eq!(reg.get("task_001").unwrap().state, TaskState::Claimed);

        // 3. Bob claims
        reg.process_event(&make_event(
            "claim_002",
            "bob",
            2001,
            claim_tags("task_001", "publisher"),
            r#"(claim :task-ref "task_001")"#,
        ))
        .unwrap();
        assert_eq!(reg.get("task_001").unwrap().claims.len(), 2);

        // 4. Publisher assigns bob
        reg.process_event(&make_event(
            "assign_001",
            "publisher",
            3000,
            assign_tags("task_001", "bob"),
            r#"(assign :task-ref "task_001")"#,
        ))
        .unwrap();

        let entry = reg.get("task_001").unwrap();
        assert_eq!(entry.state, TaskState::Assigned);
        assert_eq!(entry.assignee, Some("bob".into()));
        assert!(entry.state.is_terminal());
    }

    // ====================================================================
    // Full lifecycle — first-reply-wins
    // ====================================================================

    #[test]
    fn full_lifecycle_first_reply_wins() {
        let mut reg = TaskRegistry::new();

        // 1. Publish
        reg.process_event(&make_event(
            "task_001",
            "publisher",
            1000,
            task_tags(ClaimPolicy::FirstReplyWins, Some(5000)),
            r#"(task :description "Quick fix" :amount 5000)"#,
        ))
        .unwrap();

        // 2. First claim auto-assigns
        reg.process_event(&make_event(
            "claim_001",
            "alice",
            2000,
            claim_tags("task_001", "publisher"),
            r#"(claim :task-ref "task_001")"#,
        ))
        .unwrap();

        let entry = reg.get("task_001").unwrap();
        assert_eq!(entry.state, TaskState::Assigned);
        assert_eq!(entry.assignee, Some("alice".into()));
        assert!(entry.state.is_terminal());
    }

    // ====================================================================
    // Description extraction
    // ====================================================================

    #[test]
    fn extract_description() {
        let desc = extract_description_from_content(r#"(task :description "Fix the bug")"#);
        assert_eq!(desc, "Fix the bug");
    }

    #[test]
    fn extract_description_with_amount() {
        let desc = extract_description_from_content(
            r#"(task :description "Deploy" :amount 50000)"#,
        );
        assert_eq!(desc, "Deploy");
    }

    #[test]
    fn extract_description_missing() {
        let desc = extract_description_from_content("(task)");
        assert_eq!(desc, "");
    }

    #[test]
    fn extract_description_malformed() {
        let desc = extract_description_from_content("not-valid");
        assert_eq!(desc, "");
    }
}
