//! Thread management for multi-turn agent conversations.
//!
//! Generates thread IDs, tracks conversation state (open / completed /
//! cancelled), and links reply chains via `e` tags.  Supports both directed
//! (tell / ask / reply) and broadcast (hello / bye) patterns.

#![forbid(unsafe_code)]

use std::collections::HashMap;

use crate::event_types::Tag;
use crate::inbox_handler::{InboundMessage, PerformativeKind};
use crate::message_builder::MessageBuilder;

// ---------------------------------------------------------------------------
// Thread ID
// ---------------------------------------------------------------------------

/// A conversation thread identifier.
///
/// Thread IDs are 16-byte random hex strings (32 hex chars), generated via
/// [`ThreadId::generate`].  They are transmitted in `["thread", <id>]` tags
/// on kind 21111 events.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ThreadId(String);

impl ThreadId {
    /// Create a [`ThreadId`] from an existing string value.
    ///
    /// No validation is performed — the caller is responsible for supplying
    /// a well-formed identifier (typically 32 hex chars).
    pub fn from_string(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    /// Generate a new random thread ID (16 random bytes → 32 hex chars).
    pub fn generate() -> Self {
        let mut buf = [0u8; 16];
        getrandom(&mut buf);
        Self(hex::encode(buf))
    }

    /// Return the thread ID as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ThreadId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Fill `buf` with random bytes.
fn getrandom(buf: &mut [u8]) {
    ::getrandom::getrandom(buf).expect("getrandom failed");
}

// ---------------------------------------------------------------------------
// Thread state
// ---------------------------------------------------------------------------

/// The lifecycle state of a conversation thread.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ThreadState {
    /// The conversation is active — messages may still be exchanged.
    Open,
    /// The conversation ended normally (e.g. final `ok` or `reply`).
    Completed,
    /// The conversation was explicitly cancelled (e.g. `cancel` or `bye`).
    Cancelled,
}

impl ThreadState {
    /// Returns `true` if the thread is still active.
    pub fn is_open(&self) -> bool {
        matches!(self, Self::Open)
    }

    /// Returns `true` if the thread has reached a terminal state.
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Completed | Self::Cancelled)
    }
}

// ---------------------------------------------------------------------------
// Conversation thread
// ---------------------------------------------------------------------------

/// A single conversation thread, tracking participants, state, and the
/// ordered chain of event IDs that form the reply history.
#[derive(Debug, Clone)]
pub struct ConversationThread {
    /// Unique thread identifier.
    id: ThreadId,
    /// Current lifecycle state.
    state: ThreadState,
    /// The pubkey that initiated the thread.
    initiator: String,
    /// Ordered list of event IDs in this thread (oldest first).
    event_chain: Vec<String>,
    /// Set of participant pubkeys observed on this thread.
    participants: Vec<String>,
    /// Unix timestamp (seconds) of the most recent message.
    last_activity: u64,
}

impl ConversationThread {
    /// The thread's unique identifier.
    pub fn id(&self) -> &ThreadId {
        &self.id
    }

    /// The current lifecycle state.
    pub fn state(&self) -> ThreadState {
        self.state
    }

    /// The pubkey that initiated this thread.
    pub fn initiator(&self) -> &str {
        &self.initiator
    }

    /// Ordered event IDs forming the reply chain (oldest first).
    pub fn event_chain(&self) -> &[String] {
        &self.event_chain
    }

    /// The most recent event ID in the chain, if any.
    pub fn last_event_id(&self) -> Option<&str> {
        self.event_chain.last().map(String::as_str)
    }

    /// All participant pubkeys observed on this thread.
    pub fn participants(&self) -> &[String] {
        &self.participants
    }

    /// Unix timestamp of the last activity.
    pub fn last_activity(&self) -> u64 {
        self.last_activity
    }

    /// Number of messages in the chain.
    pub fn message_count(&self) -> usize {
        self.event_chain.len()
    }
}

// ---------------------------------------------------------------------------
// Thread manager
// ---------------------------------------------------------------------------

/// Manages conversation threads — creation, state transitions, and lookup.
///
/// The manager is the primary entry point for application code that needs to
/// track multi-turn conversations.  It indexes threads by [`ThreadId`] and
/// provides helpers for common patterns like opening a new thread, recording
/// an inbound message, and completing or cancelling a thread.
#[derive(Debug)]
pub struct ThreadManager {
    threads: HashMap<String, ConversationThread>,
}

impl ThreadManager {
    /// Create an empty thread manager.
    pub fn new() -> Self {
        Self {
            threads: HashMap::new(),
        }
    }

    /// Open a new thread initiated by `initiator_pubkey`.
    ///
    /// Returns the generated [`ThreadId`].
    pub fn open_thread(&mut self, initiator_pubkey: &str) -> ThreadId {
        let id = ThreadId::generate();
        self.open_thread_with_id(id.clone(), initiator_pubkey);
        id
    }

    /// Open a new thread with a specific ID.
    ///
    /// Useful when the remote peer already assigned a thread ID and we need
    /// to adopt it.  If a thread with this ID already exists, this is a no-op.
    pub fn open_thread_with_id(&mut self, id: ThreadId, initiator_pubkey: &str) {
        self.threads.entry(id.as_str().to_string()).or_insert_with(|| {
            ConversationThread {
                id,
                state: ThreadState::Open,
                initiator: initiator_pubkey.to_string(),
                event_chain: Vec::new(),
                participants: vec![initiator_pubkey.to_string()],
                last_activity: 0,
            }
        });
    }

    /// Look up a thread by its ID.
    pub fn get(&self, id: &str) -> Option<&ConversationThread> {
        self.threads.get(id)
    }

    /// Look up a thread mutably by its ID.
    pub fn get_mut(&mut self, id: &str) -> Option<&mut ConversationThread> {
        self.threads.get_mut(id)
    }

    /// Return an iterator over all threads.
    pub fn threads(&self) -> impl Iterator<Item = &ConversationThread> {
        self.threads.values()
    }

    /// Return all threads in a given state.
    pub fn threads_by_state(&self, state: ThreadState) -> Vec<&ConversationThread> {
        self.threads.values().filter(|t| t.state == state).collect()
    }

    /// Record an event on a thread.
    ///
    /// If the thread does not exist, it is auto-created as [`ThreadState::Open`]
    /// with the sender as the initiator.  The event ID is appended to the reply
    /// chain and the sender is added to the participant set.
    ///
    /// Returns `false` if the thread exists but is in a terminal state (the
    /// event is still recorded but callers may want to warn).
    pub fn record_event(
        &mut self,
        thread_id: &str,
        event_id: &str,
        sender_pubkey: &str,
        created_at: u64,
    ) -> bool {
        let thread = self
            .threads
            .entry(thread_id.to_string())
            .or_insert_with(|| ConversationThread {
                id: ThreadId::from_string(thread_id),
                state: ThreadState::Open,
                initiator: sender_pubkey.to_string(),
                event_chain: Vec::new(),
                participants: vec![sender_pubkey.to_string()],
                last_activity: 0,
            });

        // Append event to chain (skip duplicates).
        if !thread.event_chain.iter().any(|e| e == event_id) {
            thread.event_chain.push(event_id.to_string());
        }

        // Add participant if new.
        if !thread.participants.iter().any(|p| p == sender_pubkey) {
            thread.participants.push(sender_pubkey.to_string());
        }

        // Update activity timestamp (only advance forward).
        if created_at > thread.last_activity {
            thread.last_activity = created_at;
        }

        thread.state.is_open()
    }

    /// Record a validated inbound message on its thread (if it has one).
    ///
    /// Extracts the thread ID, event ID, and sender from the message.
    /// Also applies automatic state transitions based on the performative:
    ///
    /// - `cancel` / `bye` → [`ThreadState::Cancelled`]
    ///
    /// Returns `Some(thread_id)` if the message carried a thread tag, `None`
    /// otherwise.
    pub fn record_inbound(&mut self, msg: &InboundMessage) -> Option<String> {
        let thread_id = msg.thread()?;
        let event_id = &msg.message.event.id;
        let sender = msg.sender();
        let created_at = msg.message.event.created_at;

        self.record_event(thread_id, event_id, sender, created_at);

        // Auto-transition based on performative.
        match msg.kind() {
            PerformativeKind::Cancel | PerformativeKind::Bye => {
                self.set_state(thread_id, ThreadState::Cancelled);
            }
            _ => {}
        }

        Some(thread_id.to_string())
    }

    /// Manually transition a thread to a new state.
    ///
    /// Returns `true` if the thread was found and updated.
    pub fn set_state(&mut self, thread_id: &str, state: ThreadState) -> bool {
        if let Some(thread) = self.threads.get_mut(thread_id) {
            thread.state = state;
            true
        } else {
            false
        }
    }

    /// Mark a thread as completed.
    pub fn complete(&mut self, thread_id: &str) -> bool {
        self.set_state(thread_id, ThreadState::Completed)
    }

    /// Mark a thread as cancelled.
    pub fn cancel(&mut self, thread_id: &str) -> bool {
        self.set_state(thread_id, ThreadState::Cancelled)
    }

    /// Remove a thread entirely. Returns the removed thread if it existed.
    pub fn remove(&mut self, thread_id: &str) -> Option<ConversationThread> {
        self.threads.remove(thread_id)
    }

    /// Number of tracked threads.
    pub fn len(&self) -> usize {
        self.threads.len()
    }

    /// Returns `true` if no threads are being tracked.
    pub fn is_empty(&self) -> bool {
        self.threads.is_empty()
    }
}

impl Default for ThreadManager {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Builder helpers — convenience for threading replies
// ---------------------------------------------------------------------------

/// Prepare a [`MessageBuilder`] that continues an existing thread.
///
/// Sets the `thread` tag and, if the thread has prior events, adds an `e` tag
/// referencing the most recent event ID in the chain (reply-to linking).
pub fn continue_thread(
    thread: &ConversationThread,
    performative: &str,
) -> MessageBuilder {
    let mut builder = MessageBuilder::new(performative)
        .thread(thread.id().as_str());

    if let Some(last_eid) = thread.last_event_id() {
        builder = builder.tag(Tag::Event(last_eid.to_string()));
    }

    builder
}

/// Prepare a [`MessageBuilder`] that starts a new thread.
///
/// Generates a fresh [`ThreadId`] and returns both the ID and the builder.
pub fn start_thread(performative: &str) -> (ThreadId, MessageBuilder) {
    let id = ThreadId::generate();
    let builder = MessageBuilder::new(performative).thread(id.as_str());
    (id, builder)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event_types::{AgentMessage, Event, KIND_AGENT_MESSAGE, Tag};
    use crate::inbox_handler::InboundMessage;
    use cbcl_core::sexpr::{Atom, SExpr};

    // ====================================================================
    // ThreadId
    // ====================================================================

    #[test]
    fn thread_id_generate_is_32_hex_chars() {
        let id = ThreadId::generate();
        assert_eq!(id.as_str().len(), 32);
        assert!(id.as_str().chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn thread_id_generate_unique() {
        let a = ThreadId::generate();
        let b = ThreadId::generate();
        assert_ne!(a, b);
    }

    #[test]
    fn thread_id_from_string() {
        let id = ThreadId::from_string("conv-42");
        assert_eq!(id.as_str(), "conv-42");
    }

    #[test]
    fn thread_id_display() {
        let id = ThreadId::from_string("abc123");
        assert_eq!(format!("{id}"), "abc123");
    }

    // ====================================================================
    // ThreadState
    // ====================================================================

    #[test]
    fn thread_state_open_is_open() {
        assert!(ThreadState::Open.is_open());
        assert!(!ThreadState::Completed.is_open());
        assert!(!ThreadState::Cancelled.is_open());
    }

    #[test]
    fn thread_state_terminal() {
        assert!(!ThreadState::Open.is_terminal());
        assert!(ThreadState::Completed.is_terminal());
        assert!(ThreadState::Cancelled.is_terminal());
    }

    // ====================================================================
    // ThreadManager — open / get
    // ====================================================================

    #[test]
    fn open_and_get_thread() {
        let mut mgr = ThreadManager::new();
        let id = mgr.open_thread("alice");
        let thread = mgr.get(id.as_str()).unwrap();
        assert_eq!(thread.state(), ThreadState::Open);
        assert_eq!(thread.initiator(), "alice");
        assert_eq!(thread.participants(), &["alice"]);
        assert_eq!(thread.message_count(), 0);
    }

    #[test]
    fn open_thread_with_id_no_overwrite() {
        let mut mgr = ThreadManager::new();
        let id = ThreadId::from_string("my-thread");
        mgr.open_thread_with_id(id.clone(), "alice");
        // Second call with different initiator should be a no-op.
        mgr.open_thread_with_id(ThreadId::from_string("my-thread"), "bob");
        let thread = mgr.get("my-thread").unwrap();
        assert_eq!(thread.initiator(), "alice");
    }

    #[test]
    fn get_nonexistent_returns_none() {
        let mgr = ThreadManager::new();
        assert!(mgr.get("no-such-thread").is_none());
    }

    // ====================================================================
    // ThreadManager — record_event
    // ====================================================================

    #[test]
    fn record_event_creates_thread() {
        let mut mgr = ThreadManager::new();
        let open = mgr.record_event("t1", "evt-1", "alice", 1000);
        assert!(open);
        let thread = mgr.get("t1").unwrap();
        assert_eq!(thread.state(), ThreadState::Open);
        assert_eq!(thread.event_chain(), &["evt-1"]);
        assert_eq!(thread.last_activity(), 1000);
    }

    #[test]
    fn record_event_appends_to_chain() {
        let mut mgr = ThreadManager::new();
        mgr.record_event("t1", "evt-1", "alice", 1000);
        mgr.record_event("t1", "evt-2", "bob", 2000);
        let thread = mgr.get("t1").unwrap();
        assert_eq!(thread.event_chain(), &["evt-1", "evt-2"]);
        assert_eq!(thread.participants(), &["alice", "bob"]);
        assert_eq!(thread.last_activity(), 2000);
    }

    #[test]
    fn record_event_deduplicates() {
        let mut mgr = ThreadManager::new();
        mgr.record_event("t1", "evt-1", "alice", 1000);
        mgr.record_event("t1", "evt-1", "alice", 1000);
        let thread = mgr.get("t1").unwrap();
        assert_eq!(thread.message_count(), 1);
    }

    #[test]
    fn record_event_on_terminal_thread_returns_false() {
        let mut mgr = ThreadManager::new();
        mgr.record_event("t1", "evt-1", "alice", 1000);
        mgr.complete("t1");
        let open = mgr.record_event("t1", "evt-2", "bob", 2000);
        assert!(!open);
        // Event is still recorded.
        assert_eq!(mgr.get("t1").unwrap().message_count(), 2);
    }

    // ====================================================================
    // ThreadManager — state transitions
    // ====================================================================

    #[test]
    fn complete_thread() {
        let mut mgr = ThreadManager::new();
        mgr.open_thread_with_id(ThreadId::from_string("t1"), "alice");
        assert!(mgr.complete("t1"));
        assert_eq!(mgr.get("t1").unwrap().state(), ThreadState::Completed);
    }

    #[test]
    fn cancel_thread() {
        let mut mgr = ThreadManager::new();
        mgr.open_thread_with_id(ThreadId::from_string("t1"), "alice");
        assert!(mgr.cancel("t1"));
        assert_eq!(mgr.get("t1").unwrap().state(), ThreadState::Cancelled);
    }

    #[test]
    fn set_state_nonexistent_returns_false() {
        let mut mgr = ThreadManager::new();
        assert!(!mgr.complete("nope"));
    }

    // ====================================================================
    // ThreadManager — query helpers
    // ====================================================================

    #[test]
    fn threads_by_state() {
        let mut mgr = ThreadManager::new();
        mgr.open_thread_with_id(ThreadId::from_string("t1"), "alice");
        mgr.open_thread_with_id(ThreadId::from_string("t2"), "bob");
        mgr.open_thread_with_id(ThreadId::from_string("t3"), "carol");
        mgr.complete("t2");
        let open = mgr.threads_by_state(ThreadState::Open);
        assert_eq!(open.len(), 2);
        let done = mgr.threads_by_state(ThreadState::Completed);
        assert_eq!(done.len(), 1);
        assert_eq!(done[0].id().as_str(), "t2");
    }

    #[test]
    fn remove_thread() {
        let mut mgr = ThreadManager::new();
        mgr.open_thread_with_id(ThreadId::from_string("t1"), "alice");
        let removed = mgr.remove("t1");
        assert!(removed.is_some());
        assert!(mgr.get("t1").is_none());
        assert!(mgr.is_empty());
    }

    #[test]
    fn len_and_is_empty() {
        let mut mgr = ThreadManager::new();
        assert!(mgr.is_empty());
        assert_eq!(mgr.len(), 0);
        mgr.open_thread_with_id(ThreadId::from_string("t1"), "alice");
        assert!(!mgr.is_empty());
        assert_eq!(mgr.len(), 1);
    }

    // ====================================================================
    // record_inbound — auto state transitions
    // ====================================================================

    fn make_inbound(
        performative: &str,
        thread_id: Option<&str>,
        event_id: &str,
        sender: &str,
    ) -> InboundMessage {
        let mut tags_raw: Vec<Vec<String>> = vec![
            vec!["performative".into(), performative.into()],
        ];
        if let Some(tid) = thread_id {
            tags_raw.push(vec!["thread".into(), tid.into()]);
        }
        let event = Event {
            id: event_id.to_string(),
            pubkey: sender.to_string(),
            created_at: 1_700_000_000,
            kind: KIND_AGENT_MESSAGE,
            tags: tags_raw.clone(),
            content: format!("({performative})"),
            sig: "c".repeat(128),
        };
        let tags: Vec<Tag> = tags_raw.iter().map(|t| Tag::parse(t)).collect();
        let message = AgentMessage {
            event,
            tags,
        };
        InboundMessage {
            message,
            performative: performative.to_string(),
            content: SExpr::List(vec![SExpr::Atom(Atom::Symbol(performative.into()))]),
            relay_url: None,
        }
    }

    #[test]
    fn record_inbound_with_thread() {
        let mut mgr = ThreadManager::new();
        let msg = make_inbound("tell", Some("t1"), "evt-1", "alice");
        let result = mgr.record_inbound(&msg);
        assert_eq!(result, Some("t1".to_string()));
        let thread = mgr.get("t1").unwrap();
        assert_eq!(thread.state(), ThreadState::Open);
        assert_eq!(thread.event_chain(), &["evt-1"]);
    }

    #[test]
    fn record_inbound_without_thread() {
        let mut mgr = ThreadManager::new();
        let msg = make_inbound("hello", None, "evt-1", "alice");
        let result = mgr.record_inbound(&msg);
        assert_eq!(result, None);
    }

    #[test]
    fn record_inbound_cancel_transitions_to_cancelled() {
        let mut mgr = ThreadManager::new();
        let tell = make_inbound("tell", Some("t1"), "evt-1", "alice");
        mgr.record_inbound(&tell);
        let cancel = make_inbound("cancel", Some("t1"), "evt-2", "bob");
        mgr.record_inbound(&cancel);
        assert_eq!(mgr.get("t1").unwrap().state(), ThreadState::Cancelled);
    }

    #[test]
    fn record_inbound_bye_transitions_to_cancelled() {
        let mut mgr = ThreadManager::new();
        let tell = make_inbound("tell", Some("t1"), "evt-1", "alice");
        mgr.record_inbound(&tell);
        let bye = make_inbound("bye", Some("t1"), "evt-2", "alice");
        mgr.record_inbound(&bye);
        assert_eq!(mgr.get("t1").unwrap().state(), ThreadState::Cancelled);
    }

    #[test]
    fn record_inbound_tell_stays_open() {
        let mut mgr = ThreadManager::new();
        let tell = make_inbound("tell", Some("t1"), "evt-1", "alice");
        mgr.record_inbound(&tell);
        assert_eq!(mgr.get("t1").unwrap().state(), ThreadState::Open);
    }

    // ====================================================================
    // Builder helpers
    // ====================================================================

    #[test]
    fn continue_thread_adds_e_tag() {
        let mut mgr = ThreadManager::new();
        mgr.open_thread_with_id(ThreadId::from_string("t1"), "alice");
        mgr.record_event("t1", "evt-1", "alice", 1000);

        let thread = mgr.get("t1").unwrap();
        let event = continue_thread(thread, "reply")
            .recipient("alice")
            .build()
            .unwrap();

        // Should have thread tag and e tag.
        let tags: Vec<Tag> = event.tags.iter().map(|t| Tag::parse(t)).collect();
        assert!(tags.contains(&Tag::Thread("t1".into())));
        assert!(tags.contains(&Tag::Event("evt-1".into())));
    }

    #[test]
    fn continue_thread_no_prior_events() {
        let mut mgr = ThreadManager::new();
        mgr.open_thread_with_id(ThreadId::from_string("t1"), "alice");

        let thread = mgr.get("t1").unwrap();
        let event = continue_thread(thread, "tell")
            .recipient("bob")
            .build()
            .unwrap();

        let tags: Vec<Tag> = event.tags.iter().map(|t| Tag::parse(t)).collect();
        assert!(tags.contains(&Tag::Thread("t1".into())));
        // No e tag when there are no prior events.
        assert!(!tags.iter().any(|t| matches!(t, Tag::Event(_))));
    }

    #[test]
    fn start_thread_returns_id_and_builder() {
        let (id, builder) = start_thread("ask");
        let event = builder.recipient("bob").build().unwrap();
        let tags: Vec<Tag> = event.tags.iter().map(|t| Tag::parse(t)).collect();
        assert!(tags.contains(&Tag::Thread(id.as_str().to_string())));
        assert!(tags.contains(&Tag::Performative("ask".into())));
    }

    // ====================================================================
    // ConversationThread accessors
    // ====================================================================

    #[test]
    fn thread_last_event_id() {
        let mut mgr = ThreadManager::new();
        mgr.open_thread_with_id(ThreadId::from_string("t1"), "alice");
        assert_eq!(mgr.get("t1").unwrap().last_event_id(), None);
        mgr.record_event("t1", "evt-1", "alice", 1000);
        assert_eq!(mgr.get("t1").unwrap().last_event_id(), Some("evt-1"));
        mgr.record_event("t1", "evt-2", "bob", 2000);
        assert_eq!(mgr.get("t1").unwrap().last_event_id(), Some("evt-2"));
    }

    // ====================================================================
    // Default trait
    // ====================================================================

    #[test]
    fn thread_manager_default() {
        let mgr = ThreadManager::default();
        assert!(mgr.is_empty());
    }
}
