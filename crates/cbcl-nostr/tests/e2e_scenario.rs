//! End-to-end scenario: full NIP-XX happy path in a single test.
//!
//! Two agents discover each other, negotiate a commerce dialect, publish an
//! open task with bounty, claim it, negotiate price, complete work, invoice,
//! and pay via Lightning zap.
//!
//! This test runs entirely in-process — no real relay required.  Events are
//! signed with real secp256k1 keys and verified, but "publishing" is simulated
//! by passing events directly between agent-local state machines.
//!
//! Run with:
//!
//! ```sh
//! cargo test --test e2e_scenario
//! ```

use cbcl_core::dialect::DialectRegistry;
use cbcl_core::sexpr::{Atom, SExpr};
use cbcl_nostr::agent_discovery::{self, AgentRegistry};
use cbcl_nostr::commerce_dialect::{
    commerce_dialect_event, unwrap_commerce, CommerceMessageBuilder, NegotiationState,
};
use cbcl_nostr::conversation_threads::{self, ThreadManager, ThreadState};
use cbcl_nostr::dialect_negotiation::install_dialect_event;
use cbcl_nostr::event_signing::{sign_event, verify_event};
use cbcl_nostr::event_types::{Event, Tag};
use cbcl_nostr::inbox_handler::{InboxHandler, PerformativeKind};
use cbcl_nostr::message_builder::MessageBuilder;
use cbcl_nostr::open_task_market::{self, ClaimPolicy, TaskRegistry, TaskState};
use cbcl_nostr::payment_safety::{
    verify_publisher, AmountTracker, PaymentOrderingGuard, TrustThresholds,
};
use cbcl_nostr::reputation_query::ReputationAggregator;
use cbcl_nostr::sexpr_codec;
use cbcl_nostr::zap_integration::{
    reconcile, sats_to_msats, ReconciliationResult, ZapReceipt, ZapRequestBuilder,
    KIND_ZAP_RECEIPT, KIND_ZAP_REQUEST,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Generate a fresh keypair → (secret_key_hex, pubkey_hex).
fn gen_keypair() -> (String, String) {
    cbcl_nostr::event_signing::generate_keypair()
}

/// Monotonically increasing timestamp for event ordering.
fn timestamp(offset: u64) -> u64 {
    1_700_000_000 + offset
}

/// Sign an event with the given secret key and timestamp offset.
fn sign(event: &mut Event, sk: &str, ts_offset: u64) {
    sign_event(event, sk, timestamp(ts_offset)).unwrap();
}

/// Build a zap receipt event (kind 9735) wrapping an embedded zap request.
fn make_zap_receipt(
    recipient: &str,
    event_id: &str,
    amount_msats: u64,
    ln_node_pubkey: &str,
    ts: u64,
) -> Event {
    // Build the embedded zap request (kind 9734)
    let zap_req = Event {
        id: "a".repeat(64),
        pubkey: "b".repeat(64),
        created_at: ts,
        kind: KIND_ZAP_REQUEST,
        tags: vec![
            vec!["p".into(), recipient.into()],
            vec!["e".into(), event_id.into()],
            vec!["amount".into(), amount_msats.to_string()],
            vec!["relays".into(), "wss://relay.example.com".into()],
        ],
        content: String::new(),
        sig: "c".repeat(128),
    };
    let zap_req_json = serde_json::to_string(&zap_req).unwrap();

    Event {
        id: format!("receipt_{}", event_id.chars().take(50).collect::<String>()),
        pubkey: ln_node_pubkey.into(),
        created_at: ts + 1,
        kind: KIND_ZAP_RECEIPT,
        tags: vec![
            vec!["p".into(), recipient.into()],
            vec!["e".into(), event_id.into()],
            vec!["description".into(), zap_req_json],
            vec!["bolt11".into(), "lnbc500n1...".into()],
        ],
        content: String::new(),
        sig: "f".repeat(128),
    }
}

// =========================================================================
// THE E2E SCENARIO
// =========================================================================

#[test]
fn full_nip_xx_happy_path() {
    // =====================================================================
    // Phase 0: Setup — generate identities
    // =====================================================================
    let (sk_alice, pk_alice) = gen_keypair(); // Alice: task publisher / buyer
    let (sk_bob, pk_bob) = gen_keypair(); // Bob: worker / seller
    let ln_node_pubkey = "e".repeat(64); // simulated lightning node

    // =====================================================================
    // Phase 1: Agent discovery — hello broadcasts
    // =====================================================================
    let mut agent_reg = AgentRegistry::new();

    // Alice announces as a "coordinator" agent
    let mut hello_alice =
        agent_discovery::build_hello("coordinator", &["commerce", "planning"]).unwrap();
    sign(&mut hello_alice, &sk_alice, 0);
    verify_event(&hello_alice).unwrap();
    agent_reg.process_event(&hello_alice).unwrap();

    // Bob announces as a "worker" agent
    let mut hello_bob =
        agent_discovery::build_hello("worker", &["commerce", "rust-dev"]).unwrap();
    sign(&mut hello_bob, &sk_bob, 1);
    verify_event(&hello_bob).unwrap();
    agent_reg.process_event(&hello_bob).unwrap();

    // Both agents are now discoverable
    assert_eq!(agent_reg.len(), 2);
    let alice_entry = agent_reg.get(&pk_alice).unwrap();
    assert_eq!(alice_entry.agent_type, "coordinator");
    assert!(alice_entry.capabilities.contains(&"commerce".to_string()));

    let bob_entry = agent_reg.get(&pk_bob).unwrap();
    assert_eq!(bob_entry.agent_type, "worker");
    assert!(bob_entry.capabilities.contains(&"rust-dev".to_string()));

    // =====================================================================
    // Phase 2: Dialect negotiation — publish & install commerce dialect
    // =====================================================================
    let mut dialect_event = commerce_dialect_event();
    sign(&mut dialect_event, &sk_alice, 2);
    verify_event(&dialect_event).unwrap();

    // Both agents install the commerce dialect
    let mut alice_registry = DialectRegistry::new();
    let installed_a =
        install_dialect_event(dialect_event.clone(), &mut alice_registry).unwrap();
    assert_eq!(installed_a.name, "commerce");
    assert_eq!(installed_a.performatives.len(), 6);

    let mut bob_registry = DialectRegistry::new();
    let installed_b = install_dialect_event(dialect_event, &mut bob_registry).unwrap();
    assert_eq!(installed_b.name, "commerce");

    // Verify commerce performatives are findable
    assert!(alice_registry.find_performative_dialect("quote").is_some());
    assert!(bob_registry.find_performative_dialect("invoice").is_some());

    // =====================================================================
    // Phase 3: Open task market — Alice publishes a task with bounty
    // =====================================================================
    let bounty_msats = sats_to_msats(500); // 500 sats = 500_000 msats
    let mut task_event =
        open_task_market::build_task("Implement CBCL parser in Rust", Some(bounty_msats), ClaimPolicy::FirstReplyWins);
    sign(&mut task_event, &sk_alice, 3);
    verify_event(&task_event).unwrap();
    let task_event_id = task_event.id.clone();

    // Verify the task content is well-formed
    let task_sexpr = sexpr_codec::decode(&task_event.content).unwrap();
    match &task_sexpr {
        SExpr::List(items) => {
            assert!(matches!(&items[0], SExpr::Atom(Atom::Symbol(s)) if s == "task"));
        }
        _ => panic!("expected task to be a list"),
    }

    // Both agents process the task event into their registries
    let mut alice_task_reg = TaskRegistry::new();
    alice_task_reg.process_event(&task_event).unwrap();
    let mut bob_task_reg = TaskRegistry::new();
    bob_task_reg.process_event(&task_event).unwrap();

    // Task is open in both registries
    assert_eq!(
        bob_task_reg.get(&task_event_id).unwrap().state,
        TaskState::Open
    );
    assert_eq!(
        bob_task_reg.get(&task_event_id).unwrap().amount,
        Some(bounty_msats)
    );

    // =====================================================================
    // Phase 3b: Payment safety — Bob checks Alice's reputation before claiming
    // =====================================================================

    // Simulate Alice having some prior payment history (one prior zap receipt)
    let mut alice_rep = ReputationAggregator::new(&pk_alice);
    let prior_receipt = make_zap_receipt(
        &pk_alice,
        &"prior_task".repeat(5).chars().take(64).collect::<String>(),
        sats_to_msats(100),
        &ln_node_pubkey,
        timestamp(0),
    );
    alice_rep.add_zap_receipt(prior_receipt).unwrap();
    alice_rep.record_assignment(); // 1 assigned, 1 completed

    let alice_summary = alice_rep.summarize();
    assert_eq!(alice_summary.completed_tasks, 1);
    assert_eq!(alice_summary.total_earnings_msats, sats_to_msats(100));

    // Bob verifies Alice with permissive thresholds
    let thresholds = TrustThresholds::default(); // min 1 completed payment
    let verdict = verify_publisher(&alice_summary, &thresholds, timestamp(3));
    assert!(
        verdict.is_trusted(),
        "Alice should be trusted: {:?}",
        verdict.violations
    );

    // =====================================================================
    // Phase 4: Bob claims the task
    // =====================================================================
    let mut claim_event =
        open_task_market::build_claim(&pk_alice, &task_event_id).unwrap();
    sign(&mut claim_event, &sk_bob, 4);
    verify_event(&claim_event).unwrap();

    // Process claim in Alice's registry (FirstReplyWins → auto-assign)
    alice_task_reg.process_event(&claim_event).unwrap();
    let task = alice_task_reg.get(&task_event_id).unwrap();
    assert_eq!(task.state, TaskState::Assigned);
    assert_eq!(task.assignee, Some(pk_bob.clone()));

    // =====================================================================
    // Phase 5: Price negotiation via commerce dialect
    //
    // Conversation thread:
    //   Bob  → Alice: quote (500 sats)
    //   Alice → Bob:  counter (400 sats)
    //   Bob  → Alice: quote (450 sats) — revised
    //   Alice → Bob:  accept-quote
    // =====================================================================
    let (thread_id, _) = conversation_threads::start_thread("tell");
    let handler_alice = InboxHandler::new(alice_registry);
    let _handler_bob = InboxHandler::new(bob_registry);
    let mut thread_mgr = ThreadManager::new();
    let mut negotiation_state = NegotiationState::Open;
    let mut ordering_guard = PaymentOrderingGuard::new();
    let mut amount_tracker = AmountTracker::new();

    // --- Bob sends quote: 500 sats ---
    let mut quote_event = CommerceMessageBuilder::new("quote")
        .recipient(&pk_alice)
        .body(vec![
            SExpr::Atom(Atom::Keyword("item".into())),
            SExpr::Atom(Atom::Str("CBCL parser implementation".into())),
            SExpr::Atom(Atom::Keyword("price".into())),
            SExpr::Atom(Atom::Num(500)),
            SExpr::Atom(Atom::Keyword("currency".into())),
            SExpr::Atom(Atom::Str("sats".into())),
        ])
        .thread(thread_id.as_str())
        .tag(Tag::Amount(bounty_msats.to_string()))
        .build()
        .unwrap();
    sign(&mut quote_event, &sk_bob, 5);
    verify_event(&quote_event).unwrap();

    // Alice verifies the commerce content
    let quote_tags: Vec<Tag> = quote_event.tags.iter().map(|t| Tag::parse(t)).collect();
    assert!(quote_tags.contains(&Tag::Dialect("commerce".into())));
    let quote_sexpr = sexpr_codec::decode(&quote_event.content).unwrap();
    let quote_inner = unwrap_commerce(&quote_sexpr).unwrap();
    match quote_inner {
        SExpr::List(items) => {
            assert!(matches!(&items[0], SExpr::Atom(Atom::Symbol(s)) if s == "quote"));
        }
        _ => panic!("expected list"),
    }

    // Advance state machine
    negotiation_state = negotiation_state.apply("quote").unwrap();
    assert_eq!(negotiation_state, NegotiationState::Quoted);
    let warnings = ordering_guard.check_transition("quote");
    assert!(warnings.is_empty());

    // --- Alice counters: 400 sats ---
    let counter_msats = sats_to_msats(400);
    let mut counter_event = CommerceMessageBuilder::new("counter")
        .recipient(&pk_bob)
        .body(vec![
            SExpr::Atom(Atom::Keyword("quote-ref".into())),
            SExpr::Atom(Atom::Str(quote_event.id.clone())),
            SExpr::Atom(Atom::Keyword("price".into())),
            SExpr::Atom(Atom::Num(400)),
            SExpr::Atom(Atom::Keyword("currency".into())),
            SExpr::Atom(Atom::Str("sats".into())),
        ])
        .thread(thread_id.as_str())
        .tag(Tag::Amount(counter_msats.to_string()))
        .build()
        .unwrap();
    sign(&mut counter_event, &sk_alice, 6);
    verify_event(&counter_event).unwrap();

    // Bob verifies counter content
    let counter_sexpr = sexpr_codec::decode(&counter_event.content).unwrap();
    let counter_inner = unwrap_commerce(&counter_sexpr).unwrap();
    match counter_inner {
        SExpr::List(items) => {
            assert!(matches!(&items[0], SExpr::Atom(Atom::Symbol(s)) if s == "counter"));
        }
        _ => panic!("expected list"),
    }

    negotiation_state = negotiation_state.apply("counter").unwrap();
    assert_eq!(negotiation_state, NegotiationState::Countered);
    let warnings = ordering_guard.check_transition("counter");
    assert!(warnings.is_empty());

    // --- Bob sends revised quote: 450 sats ---
    let agreed_msats = sats_to_msats(450);
    let mut quote2_event = CommerceMessageBuilder::new("quote")
        .recipient(&pk_alice)
        .body(vec![
            SExpr::Atom(Atom::Keyword("item".into())),
            SExpr::Atom(Atom::Str("CBCL parser implementation".into())),
            SExpr::Atom(Atom::Keyword("price".into())),
            SExpr::Atom(Atom::Num(450)),
            SExpr::Atom(Atom::Keyword("currency".into())),
            SExpr::Atom(Atom::Str("sats".into())),
        ])
        .thread(thread_id.as_str())
        .tag(Tag::Amount(agreed_msats.to_string()))
        .build()
        .unwrap();
    sign(&mut quote2_event, &sk_bob, 7);
    verify_event(&quote2_event).unwrap();

    negotiation_state = negotiation_state.apply("quote").unwrap();
    assert_eq!(negotiation_state, NegotiationState::Quoted);
    // Second quote also passes through ordering guard
    let warnings = ordering_guard.check_transition("quote");
    assert!(warnings.is_empty());

    // --- Alice accepts the revised quote ---
    let mut accept_event = CommerceMessageBuilder::new("accept-quote")
        .recipient(&pk_bob)
        .body(vec![
            SExpr::Atom(Atom::Keyword("quote-ref".into())),
            SExpr::Atom(Atom::Str(quote2_event.id.clone())),
        ])
        .thread(thread_id.as_str())
        .tag(Tag::Amount(agreed_msats.to_string()))
        .build()
        .unwrap();
    sign(&mut accept_event, &sk_alice, 8);
    verify_event(&accept_event).unwrap();

    negotiation_state = negotiation_state.apply("accept-quote").unwrap();
    assert_eq!(negotiation_state, NegotiationState::Accepted);
    let warnings = ordering_guard.check_transition("accept-quote");
    assert!(warnings.is_empty());

    // Set the agreed amount for tracking
    amount_tracker.set_agreed_amount(agreed_msats);
    assert_eq!(amount_tracker.agreed_amount(), Some(agreed_msats));

    // =====================================================================
    // Phase 6: Work execution
    // =====================================================================
    negotiation_state = negotiation_state.begin_work().unwrap();
    assert_eq!(negotiation_state, NegotiationState::Working);

    // Bob sends a "tell" to Alice announcing work is in progress
    let mut working_event = MessageBuilder::new("tell")
        .recipient(&pk_alice)
        .body(vec![SExpr::Atom(Atom::Str(
            "Work in progress on CBCL parser".into(),
        ))])
        .thread(thread_id.as_str())
        .build()
        .unwrap();
    sign(&mut working_event, &sk_bob, 9);
    verify_event(&working_event).unwrap();
    let working_inbound = handler_alice
        .process(working_event, None)
        .unwrap();
    thread_mgr.record_inbound(&working_inbound);

    // Bob completes work
    negotiation_state = negotiation_state.complete_work().unwrap();
    assert_eq!(negotiation_state, NegotiationState::Completed);

    // Bob sends "ok" to signal completion
    let mut ok_event = MessageBuilder::new("ok")
        .recipient(&pk_alice)
        .thread(thread_id.as_str())
        .build()
        .unwrap();
    sign(&mut ok_event, &sk_bob, 10);
    verify_event(&ok_event).unwrap();
    let ok_event_id = ok_event.id.clone();

    let ok_inbound = handler_alice.process(ok_event, None).unwrap();
    assert_eq!(ok_inbound.performative, "ok");
    assert_eq!(ok_inbound.kind(), PerformativeKind::Ok);
    thread_mgr.record_inbound(&ok_inbound);

    // =====================================================================
    // Phase 7: Invoice
    // =====================================================================
    let mut invoice_event = CommerceMessageBuilder::new("invoice")
        .recipient(&pk_bob)
        .body(vec![
            SExpr::Atom(Atom::Keyword("invoice-ref".into())),
            SExpr::Atom(Atom::Str("inv-001".into())),
            SExpr::Atom(Atom::Keyword("amount".into())),
            SExpr::Atom(Atom::Num(450)),
            SExpr::Atom(Atom::Keyword("currency".into())),
            SExpr::Atom(Atom::Str("sats".into())),
        ])
        .thread(thread_id.as_str())
        .tag(Tag::Amount(agreed_msats.to_string()))
        .build()
        .unwrap();
    sign(&mut invoice_event, &sk_alice, 11);
    verify_event(&invoice_event).unwrap();

    // Verify invoice content
    let invoice_sexpr = sexpr_codec::decode(&invoice_event.content).unwrap();
    let invoice_inner = unwrap_commerce(&invoice_sexpr).unwrap();
    match invoice_inner {
        SExpr::List(items) => {
            assert!(matches!(&items[0], SExpr::Atom(Atom::Symbol(s)) if s == "invoice"));
        }
        _ => panic!("expected list"),
    }

    negotiation_state = negotiation_state.apply("invoice").unwrap();
    assert_eq!(negotiation_state, NegotiationState::Invoiced);

    // Verify amount tag consistency
    let invoice_tags: Vec<Tag> = invoice_event
        .tags
        .iter()
        .map(|t| Tag::parse(t))
        .collect();
    let extracted = AmountTracker::extract_amount(&invoice_tags).unwrap();
    assert_eq!(extracted, Some(agreed_msats));
    amount_tracker.validate_amount_tags(&invoice_tags).unwrap();

    // Payment ordering guard: invoice after acceptance is fine
    let warnings = ordering_guard.check_transition("invoice");
    assert!(warnings.is_empty());

    // =====================================================================
    // Phase 8: Payment via Lightning zap
    // =====================================================================

    // Bob builds a zap request targeting the "ok" event
    let zap_request = ZapRequestBuilder::new()
        .recipient(&pk_alice)
        .event_id(&ok_event_id)
        .amount_msats(agreed_msats)
        .relay("wss://relay.example.com")
        .content("Payment for CBCL parser implementation")
        .build()
        .unwrap();
    assert_eq!(zap_request.kind, KIND_ZAP_REQUEST);

    // Simulate: sign the zap request (fill placeholder fields)
    let mut signed_zap_req = zap_request;
    signed_zap_req.id = "z".repeat(64);
    signed_zap_req.pubkey = pk_bob.clone();
    signed_zap_req.created_at = timestamp(12);
    signed_zap_req.sig = "s".repeat(128);

    // Simulate: Lightning node creates a zap receipt (kind 9735)
    let receipt_event = make_zap_receipt(
        &pk_alice,
        &ok_event_id,
        agreed_msats,
        &ln_node_pubkey,
        timestamp(12),
    );

    // Parse the zap receipt
    let zap_receipt = ZapReceipt::from_event(receipt_event.clone()).unwrap();
    assert_eq!(zap_receipt.recipient, pk_alice);
    assert_eq!(zap_receipt.event_id, Some(ok_event_id.clone()));
    assert_eq!(zap_receipt.amount_msats, agreed_msats);
    assert_eq!(zap_receipt.bolt11, Some("lnbc500n1...".into()));

    // Reconcile payment against invoice
    let reconciliation = reconcile(zap_receipt.amount_msats, agreed_msats);
    assert_eq!(reconciliation, ReconciliationResult::ExactMatch);

    // Alice confirms payment via "paid" message
    let mut paid_event = CommerceMessageBuilder::new("paid")
        .recipient(&pk_bob)
        .body(vec![
            SExpr::Atom(Atom::Keyword("invoice-ref".into())),
            SExpr::Atom(Atom::Str("inv-001".into())),
            SExpr::Atom(Atom::Keyword("tx-ref".into())),
            SExpr::Atom(Atom::Str(zap_receipt.event.id.clone())),
        ])
        .thread(thread_id.as_str())
        .tag(Tag::Amount(agreed_msats.to_string()))
        .build()
        .unwrap();
    sign(&mut paid_event, &sk_alice, 13);
    verify_event(&paid_event).unwrap();

    // Verify paid content
    let paid_sexpr = sexpr_codec::decode(&paid_event.content).unwrap();
    let paid_inner = unwrap_commerce(&paid_sexpr).unwrap();
    match paid_inner {
        SExpr::List(items) => {
            assert!(matches!(&items[0], SExpr::Atom(Atom::Symbol(s)) if s == "paid"));
        }
        _ => panic!("expected list"),
    }

    negotiation_state = negotiation_state.apply("paid").unwrap();
    assert_eq!(negotiation_state, NegotiationState::Paid);
    assert!(negotiation_state.is_terminal());

    // =====================================================================
    // Phase 9: Finalize — update reputation, close thread
    // =====================================================================

    // Update Alice's reputation with the new payment
    alice_rep.add_zap_receipt(receipt_event).unwrap();
    alice_rep.record_assignment(); // now 2 assigned, 2 completed
    let final_summary = alice_rep.summarize();
    assert_eq!(final_summary.completed_tasks, 2);
    assert_eq!(
        final_summary.total_earnings_msats,
        sats_to_msats(100) + agreed_msats
    );
    assert_eq!(final_summary.completion_rate_pct, 100);

    // Close the conversation thread
    thread_mgr.complete(thread_id.as_str());
    let thread = thread_mgr.get(thread_id.as_str()).unwrap();
    assert_eq!(thread.state(), ThreadState::Completed);
    assert!(thread.state().is_terminal());
    assert!(thread.message_count() >= 2); // working (tell) + ok went through inbox handler

    // =====================================================================
    // Phase 10: Verify invariants across the entire flow
    // =====================================================================

    // 1. All events had valid signatures
    //    (verify_event was called on every event above)

    // 2. The negotiation state machine reached terminal Paid state
    assert_eq!(negotiation_state, NegotiationState::Paid);

    // 3. The task was assigned to Bob
    let final_task = alice_task_reg.get(&task_event_id).unwrap();
    assert_eq!(final_task.state, TaskState::Assigned);
    assert_eq!(final_task.assignee, Some(pk_bob.clone()));

    // 4. Payment was reconciled exactly
    assert_eq!(
        reconcile(agreed_msats, agreed_msats),
        ReconciliationResult::ExactMatch
    );

    // 5. Thread has Bob (who sent tell and ok through the thread)
    assert!(thread.participants().contains(&pk_bob));

    // 6. Agent registry still has both agents
    assert_eq!(agent_reg.len(), 2);

    // 7. Payment ordering guard sees no issues on the completed transaction
    let zap_check = ordering_guard.check_zap_receipt();
    assert!(zap_check.is_none(), "no ordering warnings expected");

    // 8. Amount tracker is consistent throughout
    assert_eq!(amount_tracker.agreed_amount(), Some(agreed_msats));
}

// =========================================================================
// Variant: task with counter-offer rejected, then new task
// =========================================================================

#[test]
fn negotiation_rejection_then_new_deal() {
    let (sk_alice, pk_alice) = gen_keypair();
    let (sk_bob, pk_bob) = gen_keypair();

    // Quick discovery
    let mut agent_reg = AgentRegistry::new();
    let mut h1 = agent_discovery::build_hello("buyer", &["commerce"]).unwrap();
    sign(&mut h1, &sk_alice, 0);
    agent_reg.process_event(&h1).unwrap();
    let mut h2 = agent_discovery::build_hello("seller", &["commerce"]).unwrap();
    sign(&mut h2, &sk_bob, 1);
    agent_reg.process_event(&h2).unwrap();

    // Install commerce dialect
    let mut dialect_event = commerce_dialect_event();
    sign(&mut dialect_event, &sk_alice, 2);
    let mut registry = DialectRegistry::new();
    install_dialect_event(dialect_event, &mut registry).unwrap();
    let _handler = InboxHandler::new(registry);

    // Start negotiation — Bob quotes 1000 sats
    let mut state = NegotiationState::Open;

    let mut quote_event = CommerceMessageBuilder::new("quote")
        .recipient(&pk_alice)
        .body(vec![
            SExpr::Atom(Atom::Keyword("item".into())),
            SExpr::Atom(Atom::Str("premium service".into())),
            SExpr::Atom(Atom::Keyword("price".into())),
            SExpr::Atom(Atom::Num(1000)),
        ])
        .build()
        .unwrap();
    sign(&mut quote_event, &sk_bob, 3);
    verify_event(&quote_event).unwrap();
    let q_sexpr = sexpr_codec::decode(&quote_event.content).unwrap();
    assert!(unwrap_commerce(&q_sexpr).is_some());
    state = state.apply("quote").unwrap();

    // Alice rejects
    let mut reject_event = CommerceMessageBuilder::new("reject-quote")
        .recipient(&pk_bob)
        .body(vec![
            SExpr::Atom(Atom::Keyword("quote-ref".into())),
            SExpr::Atom(Atom::Str(quote_event.id.clone())),
            SExpr::Atom(Atom::Keyword("reason".into())),
            SExpr::Atom(Atom::Str("too expensive".into())),
        ])
        .build()
        .unwrap();
    sign(&mut reject_event, &sk_alice, 4);
    verify_event(&reject_event).unwrap();
    state = state.apply("reject-quote").unwrap();

    assert_eq!(state, NegotiationState::Rejected);
    assert!(state.is_terminal());

    // Start a new negotiation from scratch
    let mut state2 = NegotiationState::Open;
    let mut quote2 = CommerceMessageBuilder::new("quote")
        .recipient(&pk_alice)
        .body(vec![
            SExpr::Atom(Atom::Keyword("item".into())),
            SExpr::Atom(Atom::Str("basic service".into())),
            SExpr::Atom(Atom::Keyword("price".into())),
            SExpr::Atom(Atom::Num(200)),
        ])
        .build()
        .unwrap();
    sign(&mut quote2, &sk_bob, 5);
    verify_event(&quote2).unwrap();
    state2 = state2.apply("quote").unwrap();

    let mut accept2 = CommerceMessageBuilder::new("accept-quote")
        .recipient(&pk_bob)
        .body(vec![
            SExpr::Atom(Atom::Keyword("quote-ref".into())),
            SExpr::Atom(Atom::Str(quote2.id.clone())),
        ])
        .build()
        .unwrap();
    sign(&mut accept2, &sk_alice, 6);
    verify_event(&accept2).unwrap();
    state2 = state2.apply("accept-quote").unwrap();

    assert_eq!(state2, NegotiationState::Accepted);

    // Fast-forward: invoice and pay
    state2 = state2.apply("invoice").unwrap();
    state2 = state2.apply("paid").unwrap();
    assert_eq!(state2, NegotiationState::Paid);
    assert!(state2.is_terminal());
}

// =========================================================================
// Variant: multiple counter rounds before agreement
// =========================================================================

#[test]
fn multiple_counter_rounds_with_signatures() {
    let (sk_alice, pk_alice) = gen_keypair();
    let (sk_bob, pk_bob) = gen_keypair();

    let mut state = NegotiationState::Open;

    // Bob quotes 1000
    let mut q1 = CommerceMessageBuilder::new("quote")
        .recipient(&pk_alice)
        .body(vec![
            SExpr::Atom(Atom::Keyword("price".into())),
            SExpr::Atom(Atom::Num(1000)),
        ])
        .build()
        .unwrap();
    sign(&mut q1, &sk_bob, 0);
    verify_event(&q1).unwrap();
    state = state.apply("quote").unwrap();

    // Alice counters 600
    let mut c1 = CommerceMessageBuilder::new("counter")
        .recipient(&pk_bob)
        .body(vec![
            SExpr::Atom(Atom::Keyword("quote-ref".into())),
            SExpr::Atom(Atom::Str(q1.id.clone())),
            SExpr::Atom(Atom::Keyword("price".into())),
            SExpr::Atom(Atom::Num(600)),
        ])
        .build()
        .unwrap();
    sign(&mut c1, &sk_alice, 1);
    verify_event(&c1).unwrap();
    state = state.apply("counter").unwrap();

    // Bob quotes 850
    let mut q2 = CommerceMessageBuilder::new("quote")
        .recipient(&pk_alice)
        .body(vec![
            SExpr::Atom(Atom::Keyword("price".into())),
            SExpr::Atom(Atom::Num(850)),
        ])
        .build()
        .unwrap();
    sign(&mut q2, &sk_bob, 2);
    verify_event(&q2).unwrap();
    state = state.apply("quote").unwrap();

    // Alice counters 700
    let mut c2 = CommerceMessageBuilder::new("counter")
        .recipient(&pk_bob)
        .body(vec![
            SExpr::Atom(Atom::Keyword("quote-ref".into())),
            SExpr::Atom(Atom::Str(q2.id.clone())),
            SExpr::Atom(Atom::Keyword("price".into())),
            SExpr::Atom(Atom::Num(700)),
        ])
        .build()
        .unwrap();
    sign(&mut c2, &sk_alice, 3);
    verify_event(&c2).unwrap();
    state = state.apply("counter").unwrap();

    // Bob quotes 750 (compromise)
    let mut q3 = CommerceMessageBuilder::new("quote")
        .recipient(&pk_alice)
        .body(vec![
            SExpr::Atom(Atom::Keyword("price".into())),
            SExpr::Atom(Atom::Num(750)),
        ])
        .build()
        .unwrap();
    sign(&mut q3, &sk_bob, 4);
    verify_event(&q3).unwrap();
    state = state.apply("quote").unwrap();

    // Alice accepts
    let mut accept = CommerceMessageBuilder::new("accept-quote")
        .recipient(&pk_bob)
        .body(vec![
            SExpr::Atom(Atom::Keyword("quote-ref".into())),
            SExpr::Atom(Atom::Str(q3.id.clone())),
        ])
        .build()
        .unwrap();
    sign(&mut accept, &sk_alice, 5);
    verify_event(&accept).unwrap();
    state = state.apply("accept-quote").unwrap();

    assert_eq!(state, NegotiationState::Accepted);

    // Complete the flow
    state = state.begin_work().unwrap();
    state = state.complete_work().unwrap();
    state = state.apply("invoice").unwrap();
    state = state.apply("paid").unwrap();
    assert!(state.is_terminal());
    assert_eq!(state, NegotiationState::Paid);
}
