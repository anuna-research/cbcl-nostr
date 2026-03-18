//! Integration tests against real Nostr relays.
//!
//! These tests are `#[ignore]`d by default. Run them with:
//!
//! ```sh
//! NOSTR_TEST_RELAY=ws://localhost:8080 cargo test --test integration -- --ignored
//! ```
//!
//! Or use a public test relay:
//!
//! ```sh
//! NOSTR_TEST_RELAY=wss://relay.damus.io cargo test --test integration -- --ignored
//! ```
//!
//! Tests cover:
//! 1. Full message flow: sign → publish → subscribe → receive → parse → dispatch
//! 2. Dialect publish / discover / verify / install cycle
//! 3. Conversation thread lifecycle end-to-end

use std::time::Duration;

use cbcl_core::dialect::{Dialect, DialectRegistry, PerformativeDef, ResourceBounds};
use cbcl_core::sexpr::{Atom, SExpr};
use cbcl_nostr::agent_discovery::{self, AgentRegistry};
use cbcl_nostr::conversation_threads::{self, ThreadManager, ThreadState};
use cbcl_nostr::dialect_negotiation::{self, DialectBuilder};
use cbcl_nostr::event_signing::{sign_event, verify_event};
use cbcl_nostr::event_types::{Event, Tag, KIND_AGENT_DIALECT, KIND_AGENT_MESSAGE};
use cbcl_nostr::inbox_handler::{InboxHandler, PerformativeKind};
use cbcl_nostr::message_builder::MessageBuilder;
use cbcl_nostr::relay_pool::{Filter, PoolConfig, RelayPool, RelayMessage, SubscriptionId};

use secp256k1::{Keypair, Secp256k1, XOnlyPublicKey};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Read the relay URL from the environment, or skip the test.
fn relay_url() -> String {
    std::env::var("NOSTR_TEST_RELAY").unwrap_or_else(|_| "ws://localhost:8080".into())
}

/// Generate a fresh secp256k1 keypair → (secret_key_hex, pubkey_hex).
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

/// Current unix timestamp in seconds.
fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Create a pool connected to the test relay with a short reconnect policy.
async fn test_pool() -> RelayPool {
    let config = PoolConfig {
        incoming_buffer: 256,
        ..Default::default()
    };
    let pool = RelayPool::new(config);
    pool.add_relay(&relay_url()).await.unwrap();
    // Give the connection a moment to establish.
    tokio::time::sleep(Duration::from_millis(500)).await;
    pool
}

/// Build, sign, and return a kind 21111 event.
fn build_and_sign(
    sk: &str,
    performative: &str,
    recipient: Option<&str>,
    body: Vec<SExpr>,
    thread: Option<&str>,
    dialect: Option<&str>,
) -> Event {
    let mut builder = MessageBuilder::new(performative);
    if let Some(r) = recipient {
        builder = builder.recipient(r);
    }
    if !body.is_empty() {
        builder = builder.body(body);
    }
    if let Some(t) = thread {
        builder = builder.thread(t);
    }
    if let Some(d) = dialect {
        builder = builder.dialect(d);
    }
    let mut event = builder.build().unwrap();
    sign_event(&mut event, sk, now()).unwrap();
    event
}

// =========================================================================
// 1. Full message flow: sign → publish → subscribe → receive → parse
// =========================================================================

#[tokio::test]
#[ignore]
async fn full_message_flow_tell() {
    let (sk_alice, pk_alice) = gen_keypair();
    let (_sk_bob, pk_bob) = gen_keypair();

    // Build and sign a "tell" message from Alice to Bob.
    let event = build_and_sign(
        &sk_alice,
        "tell",
        Some(&pk_bob),
        vec![SExpr::Atom(Atom::Str("hello from integration test".into()))],
        None,
        None,
    );
    let event_id = event.id.clone();

    // Verify the event locally before publishing.
    verify_event(&event).unwrap();

    // Connect to the relay.
    let pool = test_pool().await;
    let mut rx = pool.events_async().await;

    // Subscribe for events addressed to Bob.
    let sub_id = SubscriptionId::generate();
    let filters = vec![Filter {
        kinds: Some(vec![KIND_AGENT_MESSAGE]),
        p_tags: Some(vec![pk_bob.clone()]),
        since: Some(now() - 5),
        ..Default::default()
    }];
    pool.subscribe(sub_id.clone(), filters).await.unwrap();

    // Small delay to let subscription propagate.
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Publish the event.
    let results = pool.publish(event).await;
    assert!(!results.is_empty(), "should have at least one relay");
    assert!(
        results.iter().any(|r| r.success),
        "at least one relay should accept the publish"
    );

    // Wait for the event to arrive back via the subscription.
    let received = tokio::time::timeout(Duration::from_secs(10), async {
        while let Some((_url, msg)) = rx.recv().await {
            match msg {
                RelayMessage::Event(_sub, evt) if evt.id == event_id => return evt,
                _ => continue,
            }
        }
        panic!("channel closed without receiving event");
    })
    .await
    .expect("timed out waiting for event from relay");

    // Verify the received event.
    verify_event(&received).unwrap();
    assert_eq!(received.kind, KIND_AGENT_MESSAGE);
    assert_eq!(received.pubkey, pk_alice);

    // Run it through the inbox handler.
    let handler = InboxHandler::new(DialectRegistry::new());
    let inbound = handler
        .process(received, Some(relay_url()))
        .unwrap();

    assert_eq!(inbound.performative, "tell");
    assert_eq!(inbound.kind(), PerformativeKind::Tell);
    assert_eq!(inbound.sender(), pk_alice);
    assert_eq!(inbound.recipient(), Some(pk_bob.as_str()));

    // Clean up.
    pool.unsubscribe(&sub_id).await.unwrap();
    pool.shutdown().await;
}

#[tokio::test]
#[ignore]
async fn full_message_flow_broadcast_hello() {
    let (sk_agent, pk_agent) = gen_keypair();

    // Build and sign a "hello" broadcast.
    let mut event = agent_discovery::build_hello("test-agent", &["integration-test"]).unwrap();
    sign_event(&mut event, &sk_agent, now()).unwrap();
    let event_id = event.id.clone();

    let pool = test_pool().await;
    let mut rx = pool.events_async().await;

    // Subscribe for kind 21111 from this specific author.
    let sub_id = SubscriptionId::generate();
    let filters = vec![Filter {
        kinds: Some(vec![KIND_AGENT_MESSAGE]),
        authors: Some(vec![pk_agent.clone()]),
        since: Some(now() - 5),
        ..Default::default()
    }];
    pool.subscribe(sub_id.clone(), filters).await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;

    pool.publish(event).await;

    let received = tokio::time::timeout(Duration::from_secs(10), async {
        while let Some((_url, msg)) = rx.recv().await {
            match msg {
                RelayMessage::Event(_sub, evt) if evt.id == event_id => return evt,
                _ => continue,
            }
        }
        panic!("channel closed without receiving event");
    })
    .await
    .expect("timed out waiting for hello event");

    // Process through agent discovery registry.
    let mut agent_reg = AgentRegistry::new();
    let result = agent_reg.process_event(&received).unwrap();
    assert_eq!(result, "hello");

    let entry = agent_reg.get(&pk_agent).unwrap();
    assert_eq!(entry.agent_type, "test-agent");
    assert_eq!(entry.capabilities, vec!["integration-test"]);

    pool.unsubscribe(&sub_id).await.unwrap();
    pool.shutdown().await;
}

#[tokio::test]
#[ignore]
async fn full_message_flow_multiple_performatives() {
    let (sk, pk) = gen_keypair();
    let (_, pk_other) = gen_keypair();

    let pool = test_pool().await;
    let mut rx = pool.events_async().await;

    // Subscribe for events from our author.
    let sub_id = SubscriptionId::generate();
    let filters = vec![Filter {
        kinds: Some(vec![KIND_AGENT_MESSAGE]),
        authors: Some(vec![pk.clone()]),
        since: Some(now() - 5),
        ..Default::default()
    }];
    pool.subscribe(sub_id.clone(), filters).await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Publish tell, ask, and reply in sequence.
    let performatives = [
        ("tell", Some(pk_other.as_str()), r#""msg1""#),
        ("ask", Some(pk_other.as_str()), r#""question?""#),
        ("reply", Some(pk_other.as_str()), r#""answer""#),
    ];

    let mut event_ids = Vec::new();
    for (perf, recip, body_str) in &performatives {
        let event = build_and_sign(
            &sk,
            perf,
            *recip,
            vec![SExpr::Atom(Atom::Str(body_str.trim_matches('"').into()))],
            None,
            None,
        );
        event_ids.push(event.id.clone());
        pool.publish(event).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // Collect all three events.
    let handler = InboxHandler::new(DialectRegistry::new());
    let mut received_perfs = Vec::new();

    let _ = tokio::time::timeout(Duration::from_secs(15), async {
        while let Some((_url, msg)) = rx.recv().await {
            if let RelayMessage::Event(_sub, evt) = msg {
                if event_ids.contains(&evt.id) {
                    if let Ok(inbound) = handler.process(evt, None) {
                        received_perfs.push(inbound.performative.clone());
                    }
                    if received_perfs.len() == 3 {
                        return;
                    }
                }
            }
        }
    })
    .await;

    assert_eq!(received_perfs.len(), 3, "expected 3 events, got {received_perfs:?}");
    assert!(received_perfs.contains(&"tell".to_string()));
    assert!(received_perfs.contains(&"ask".to_string()));
    assert!(received_perfs.contains(&"reply".to_string()));

    pool.unsubscribe(&sub_id).await.unwrap();
    pool.shutdown().await;
}

// =========================================================================
// 2. Dialect publish / discover / verify / install cycle
// =========================================================================

fn test_dialect() -> Dialect {
    Dialect {
        name: "integration-test-dialect".into(),
        extends: vec!["cbcl".into()],
        author: Some("@integration-test".into()),
        performatives: vec![PerformativeDef {
            name: "test-action".into(),
            params: vec![
                SExpr::Atom(Atom::Symbol("payload".into())),
            ],
            template: SExpr::List(vec![
                SExpr::Atom(Atom::Symbol("effect".into())),
                SExpr::Atom(Atom::Symbol("test-action".into())),
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
        protocol: Some("ed25519".into()),
    }
}

#[tokio::test]
#[ignore]
async fn dialect_publish_discover_install() {
    let (sk, pk) = gen_keypair();

    // 1. Build a dialect event from a Dialect struct.
    let dialect = test_dialect();
    let mut event = DialectBuilder::from_dialect(&dialect).build();
    sign_event(&mut event, &sk, now()).unwrap();
    let event_id = event.id.clone();

    assert_eq!(event.kind, KIND_AGENT_DIALECT);
    verify_event(&event).unwrap();

    // 2. Publish the dialect event.
    let pool = test_pool().await;
    let mut rx = pool.events_async().await;

    // Subscribe for dialect events by this author.
    let sub_id = SubscriptionId::generate();
    let filter = dialect_negotiation::dialect_filter_by_author(&pk);
    pool.subscribe(sub_id.clone(), vec![filter])
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;

    pool.publish(event).await;

    // 3. Discover: receive the dialect event back.
    let received = tokio::time::timeout(Duration::from_secs(10), async {
        while let Some((_url, msg)) = rx.recv().await {
            match msg {
                RelayMessage::Event(_sub, evt) if evt.id == event_id => return evt,
                _ => continue,
            }
        }
        panic!("channel closed without receiving dialect event");
    })
    .await
    .expect("timed out waiting for dialect event");

    assert_eq!(received.kind, KIND_AGENT_DIALECT);
    verify_event(&received).unwrap();

    // 4. Verify + Install: parse and install the dialect into a registry.
    let mut registry = DialectRegistry::new();
    let installed = dialect_negotiation::install_dialect_event(received, &mut registry).unwrap();

    assert_eq!(installed.name, "integration-test-dialect");
    assert_eq!(installed.extends, vec!["cbcl"]);
    assert_eq!(installed.performatives.len(), 1);
    assert_eq!(installed.performatives[0].name, "test-action");
    assert_eq!(installed.resources.max_depth, 16);
    assert!(registry.find_by_name("integration-test-dialect").is_some());
    assert!(registry.find_performative_dialect("test-action").is_some());

    pool.unsubscribe(&sub_id).await.unwrap();
    pool.shutdown().await;
}

#[tokio::test]
#[ignore]
async fn dialect_filter_by_name_discovers_specific_dialect() {
    let (sk, _pk) = gen_keypair();

    let dialect = test_dialect();
    let mut event = DialectBuilder::from_dialect(&dialect).build();
    sign_event(&mut event, &sk, now()).unwrap();
    let event_id = event.id.clone();

    let pool = test_pool().await;
    let mut rx = pool.events_async().await;

    // Subscribe using name-specific filter.
    let sub_id = SubscriptionId::generate();
    let filter = dialect_negotiation::dialect_filter_by_name("integration-test-dialect");
    pool.subscribe(sub_id.clone(), vec![filter])
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;

    pool.publish(event).await;

    let received = tokio::time::timeout(Duration::from_secs(10), async {
        while let Some((_url, msg)) = rx.recv().await {
            match msg {
                RelayMessage::Event(_sub, evt) if evt.id == event_id => return evt,
                _ => continue,
            }
        }
        panic!("channel closed");
    })
    .await
    .expect("timed out waiting for dialect event by name");

    assert_eq!(received.kind, KIND_AGENT_DIALECT);

    // Install into registry and then use the dialect in a message.
    let mut registry = DialectRegistry::new();
    dialect_negotiation::install_dialect_event(received, &mut registry).unwrap();

    // Now build a message using the dialect's extended performative.
    let (sk2, _pk2) = gen_keypair();
    let (_, pk_recip) = gen_keypair();
    let msg_event = build_and_sign(
        &sk2,
        "test-action",
        Some(&pk_recip),
        vec![SExpr::Atom(Atom::Keyword("payload".into())), SExpr::Atom(Atom::Str("data".into()))],
        None,
        Some("integration-test-dialect"),
    );

    // The inbox handler with the installed dialect should accept this message.
    let handler = InboxHandler::new(registry);
    let inbound = handler.process(msg_event, None).unwrap();
    assert_eq!(inbound.performative, "test-action");
    assert_eq!(inbound.dialect(), Some("integration-test-dialect"));

    pool.unsubscribe(&sub_id).await.unwrap();
    pool.shutdown().await;
}

// =========================================================================
// 3. Conversation thread lifecycle end-to-end
// =========================================================================

#[tokio::test]
#[ignore]
async fn conversation_thread_lifecycle() {
    let (sk_alice, pk_alice) = gen_keypair();
    let (sk_bob, pk_bob) = gen_keypair();

    let pool = test_pool().await;
    let mut rx = pool.events_async().await;

    // Subscribe for messages involving both Alice and Bob.
    let sub_id = SubscriptionId::generate();
    let filters = vec![
        Filter {
            kinds: Some(vec![KIND_AGENT_MESSAGE]),
            authors: Some(vec![pk_alice.clone(), pk_bob.clone()]),
            since: Some(now() - 5),
            ..Default::default()
        },
    ];
    pool.subscribe(sub_id.clone(), filters).await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Start a new conversation thread.
    let (thread_id, ask_builder) = conversation_threads::start_thread("ask");

    // Alice asks Bob a question in the thread.
    let mut ask_event = ask_builder
        .recipient(&pk_bob)
        .body(vec![SExpr::Atom(Atom::Str("What is CBCL?".into()))])
        .build()
        .unwrap();
    sign_event(&mut ask_event, &sk_alice, now()).unwrap();
    let ask_id = ask_event.id.clone();
    pool.publish(ask_event).await;

    // Wait for Alice's ask to arrive.
    let ask_received = tokio::time::timeout(Duration::from_secs(10), async {
        while let Some((_url, msg)) = rx.recv().await {
            match msg {
                RelayMessage::Event(_sub, evt) if evt.id == ask_id => return evt,
                _ => continue,
            }
        }
        panic!("channel closed");
    })
    .await
    .expect("timed out waiting for ask event");

    // Process the ask through the inbox handler and thread manager.
    let handler = InboxHandler::new(DialectRegistry::new());
    let mut thread_mgr = ThreadManager::new();

    let ask_inbound = handler.process(ask_received, Some(relay_url())).unwrap();
    assert_eq!(ask_inbound.performative, "ask");
    assert_eq!(ask_inbound.thread(), Some(thread_id.as_str()));

    thread_mgr.record_inbound(&ask_inbound);
    let thread = thread_mgr.get(thread_id.as_str()).unwrap();
    assert_eq!(thread.state(), ThreadState::Open);
    assert_eq!(thread.message_count(), 1);
    assert_eq!(thread.initiator(), pk_alice);

    // Bob replies in the same thread.
    let reply_builder = conversation_threads::continue_thread(thread, "reply");
    let mut reply_event = reply_builder
        .recipient(&pk_alice)
        .body(vec![SExpr::Atom(Atom::Str(
            "CBCL is a Communication-Based Coordination Language".into(),
        ))])
        .build()
        .unwrap();
    sign_event(&mut reply_event, &sk_bob, now()).unwrap();
    let reply_id = reply_event.id.clone();
    pool.publish(reply_event).await;

    // Wait for Bob's reply.
    let reply_received = tokio::time::timeout(Duration::from_secs(10), async {
        while let Some((_url, msg)) = rx.recv().await {
            match msg {
                RelayMessage::Event(_sub, evt) if evt.id == reply_id => return evt,
                _ => continue,
            }
        }
        panic!("channel closed");
    })
    .await
    .expect("timed out waiting for reply event");

    let reply_inbound = handler.process(reply_received, Some(relay_url())).unwrap();
    assert_eq!(reply_inbound.performative, "reply");
    assert_eq!(reply_inbound.thread(), Some(thread_id.as_str()));
    assert_eq!(reply_inbound.in_reply_to(), Some(ask_id.as_str()));

    thread_mgr.record_inbound(&reply_inbound);
    let thread = thread_mgr.get(thread_id.as_str()).unwrap();
    assert_eq!(thread.state(), ThreadState::Open);
    assert_eq!(thread.message_count(), 2);
    assert_eq!(thread.participants().len(), 2);
    assert!(thread.participants().contains(&pk_alice));
    assert!(thread.participants().contains(&pk_bob));

    // Alice sends "ok" to close the thread, then manually complete it.
    let ok_builder = conversation_threads::continue_thread(thread, "ok");
    let mut ok_event = ok_builder
        .recipient(&pk_bob)
        .build()
        .unwrap();
    sign_event(&mut ok_event, &sk_alice, now()).unwrap();
    let ok_id = ok_event.id.clone();
    pool.publish(ok_event).await;

    let ok_received = tokio::time::timeout(Duration::from_secs(10), async {
        while let Some((_url, msg)) = rx.recv().await {
            match msg {
                RelayMessage::Event(_sub, evt) if evt.id == ok_id => return evt,
                _ => continue,
            }
        }
        panic!("channel closed");
    })
    .await
    .expect("timed out waiting for ok event");

    let ok_inbound = handler.process(ok_received, Some(relay_url())).unwrap();
    assert_eq!(ok_inbound.performative, "ok");

    thread_mgr.record_inbound(&ok_inbound);
    // Mark thread completed after the final ok.
    thread_mgr.complete(thread_id.as_str());

    let thread = thread_mgr.get(thread_id.as_str()).unwrap();
    assert_eq!(thread.state(), ThreadState::Completed);
    assert!(thread.state().is_terminal());
    assert_eq!(thread.message_count(), 3);

    pool.unsubscribe(&sub_id).await.unwrap();
    pool.shutdown().await;
}

#[tokio::test]
#[ignore]
async fn conversation_thread_cancel() {
    let (sk_alice, pk_alice) = gen_keypair();
    let (sk_bob, pk_bob) = gen_keypair();

    let pool = test_pool().await;
    let mut rx = pool.events_async().await;

    let sub_id = SubscriptionId::generate();
    let filters = vec![Filter {
        kinds: Some(vec![KIND_AGENT_MESSAGE]),
        authors: Some(vec![pk_alice.clone(), pk_bob.clone()]),
        since: Some(now() - 5),
        ..Default::default()
    }];
    pool.subscribe(sub_id.clone(), filters).await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;

    let handler = InboxHandler::new(DialectRegistry::new());
    let mut thread_mgr = ThreadManager::new();

    // Alice starts a thread with a tell.
    let (thread_id, tell_builder) = conversation_threads::start_thread("tell");
    let mut tell_event = tell_builder
        .recipient(&pk_bob)
        .body(vec![SExpr::Atom(Atom::Str("starting conversation".into()))])
        .build()
        .unwrap();
    sign_event(&mut tell_event, &sk_alice, now()).unwrap();
    let tell_id = tell_event.id.clone();
    pool.publish(tell_event).await;

    let tell_received = tokio::time::timeout(Duration::from_secs(10), async {
        while let Some((_url, msg)) = rx.recv().await {
            match msg {
                RelayMessage::Event(_sub, evt) if evt.id == tell_id => return evt,
                _ => continue,
            }
        }
        panic!("channel closed");
    })
    .await
    .expect("timed out");

    let tell_inbound = handler.process(tell_received, None).unwrap();
    thread_mgr.record_inbound(&tell_inbound);
    assert_eq!(
        thread_mgr.get(thread_id.as_str()).unwrap().state(),
        ThreadState::Open
    );

    // Bob cancels the thread.
    let thread = thread_mgr.get(thread_id.as_str()).unwrap();
    let cancel_builder = conversation_threads::continue_thread(thread, "cancel");
    let mut cancel_event = cancel_builder
        .recipient(&pk_alice)
        .build()
        .unwrap();
    sign_event(&mut cancel_event, &sk_bob, now()).unwrap();
    let cancel_id = cancel_event.id.clone();
    pool.publish(cancel_event).await;

    let cancel_received = tokio::time::timeout(Duration::from_secs(10), async {
        while let Some((_url, msg)) = rx.recv().await {
            match msg {
                RelayMessage::Event(_sub, evt) if evt.id == cancel_id => return evt,
                _ => continue,
            }
        }
        panic!("channel closed");
    })
    .await
    .expect("timed out");

    let cancel_inbound = handler.process(cancel_received, None).unwrap();
    thread_mgr.record_inbound(&cancel_inbound);

    let thread = thread_mgr.get(thread_id.as_str()).unwrap();
    assert_eq!(thread.state(), ThreadState::Cancelled);
    assert!(thread.state().is_terminal());
    assert_eq!(thread.message_count(), 2);

    pool.unsubscribe(&sub_id).await.unwrap();
    pool.shutdown().await;
}

// =========================================================================
// 4. Agent discovery end-to-end
// =========================================================================

#[tokio::test]
#[ignore]
async fn agent_discovery_hello_then_bye() {
    let (sk_agent, pk_agent) = gen_keypair();

    let pool = test_pool().await;
    let mut rx = pool.events_async().await;

    let sub_id = SubscriptionId::generate();
    let filters = vec![Filter {
        kinds: Some(vec![KIND_AGENT_MESSAGE]),
        authors: Some(vec![pk_agent.clone()]),
        since: Some(now() - 5),
        ..Default::default()
    }];
    pool.subscribe(sub_id.clone(), filters).await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Publish hello.
    let mut hello_event =
        agent_discovery::build_hello("coordinator", &["planning", "delegation"]).unwrap();
    sign_event(&mut hello_event, &sk_agent, now()).unwrap();
    let hello_id = hello_event.id.clone();
    pool.publish(hello_event).await;

    let hello_received = tokio::time::timeout(Duration::from_secs(10), async {
        while let Some((_url, msg)) = rx.recv().await {
            match msg {
                RelayMessage::Event(_sub, evt) if evt.id == hello_id => return evt,
                _ => continue,
            }
        }
        panic!("channel closed");
    })
    .await
    .expect("timed out waiting for hello");

    let mut agent_reg = AgentRegistry::new();
    agent_reg.process_event(&hello_received).unwrap();
    assert_eq!(agent_reg.len(), 1);
    let entry = agent_reg.get(&pk_agent).unwrap();
    assert_eq!(entry.agent_type, "coordinator");
    assert_eq!(entry.capabilities, vec!["planning", "delegation"]);

    // Publish bye.
    let mut bye_event = agent_discovery::build_bye().unwrap();
    sign_event(&mut bye_event, &sk_agent, now()).unwrap();
    let bye_id = bye_event.id.clone();
    pool.publish(bye_event).await;

    let bye_received = tokio::time::timeout(Duration::from_secs(10), async {
        while let Some((_url, msg)) = rx.recv().await {
            match msg {
                RelayMessage::Event(_sub, evt) if evt.id == bye_id => return evt,
                _ => continue,
            }
        }
        panic!("channel closed");
    })
    .await
    .expect("timed out waiting for bye");

    agent_reg.process_event(&bye_received).unwrap();
    assert_eq!(agent_reg.len(), 0);
    assert!(agent_reg.get(&pk_agent).is_none());

    pool.unsubscribe(&sub_id).await.unwrap();
    pool.shutdown().await;
}

// =========================================================================
// 5. Two-agent message exchange (publish + subscribe from both sides)
// =========================================================================

#[tokio::test]
#[ignore]
async fn two_agent_exchange() {
    let (sk_alice, pk_alice) = gen_keypair();
    let (sk_bob, pk_bob) = gen_keypair();

    // Both agents connect to the same relay.
    let pool = test_pool().await;
    let mut rx = pool.events_async().await;

    // Subscribe for messages to/from both agents.
    let sub_id = SubscriptionId::generate();
    let filters = vec![Filter {
        kinds: Some(vec![KIND_AGENT_MESSAGE]),
        authors: Some(vec![pk_alice.clone(), pk_bob.clone()]),
        since: Some(now() - 5),
        ..Default::default()
    }];
    pool.subscribe(sub_id.clone(), filters).await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Alice sends ask to Bob.
    let ask_event = build_and_sign(
        &sk_alice,
        "ask",
        Some(&pk_bob),
        vec![SExpr::Atom(Atom::Str("Are you there?".into()))],
        None,
        None,
    );
    let ask_id = ask_event.id.clone();
    pool.publish(ask_event).await;

    // Wait for Alice's ask.
    let ask_recv = tokio::time::timeout(Duration::from_secs(10), async {
        while let Some((_url, msg)) = rx.recv().await {
            match msg {
                RelayMessage::Event(_sub, evt) if evt.id == ask_id => return evt,
                _ => continue,
            }
        }
        panic!("channel closed");
    })
    .await
    .expect("timed out waiting for ask");

    let handler = InboxHandler::new(DialectRegistry::new());
    let ask_inbound = handler.process(ask_recv, None).unwrap();
    assert_eq!(ask_inbound.performative, "ask");

    // Bob responds with reply, referencing Alice's event.
    let reply_event = build_and_sign(
        &sk_bob,
        "reply",
        Some(&pk_alice),
        vec![SExpr::Atom(Atom::Str("Yes, I am here!".into()))],
        None,
        None,
    );
    let reply_id = reply_event.id.clone();
    pool.publish(reply_event).await;

    let reply_recv = tokio::time::timeout(Duration::from_secs(10), async {
        while let Some((_url, msg)) = rx.recv().await {
            match msg {
                RelayMessage::Event(_sub, evt) if evt.id == reply_id => return evt,
                _ => continue,
            }
        }
        panic!("channel closed");
    })
    .await
    .expect("timed out waiting for reply");

    let reply_inbound = handler.process(reply_recv, None).unwrap();
    assert_eq!(reply_inbound.performative, "reply");
    assert_eq!(reply_inbound.sender(), pk_bob);

    pool.unsubscribe(&sub_id).await.unwrap();
    pool.shutdown().await;
}

// =========================================================================
// 6. Signed event integrity across relay round-trip
// =========================================================================

#[tokio::test]
#[ignore]
async fn event_signature_survives_relay_round_trip() {
    let (sk, pk) = gen_keypair();

    // Build an event with complex content and multiple tags.
    let mut event = MessageBuilder::new("tell")
        .recipient(&pk)
        .body(vec![
            SExpr::List(vec![
                SExpr::Atom(Atom::Symbol("nested".into())),
                SExpr::Atom(Atom::Num(42)),
                SExpr::Atom(Atom::Bool(true)),
                SExpr::Atom(Atom::Str("special chars: \"quotes\" & \\slashes\\".into())),
            ]),
        ])
        .thread("integrity-test")
        .tag(Tag::Hashtag("cbcl-test".into()))
        .build()
        .unwrap();
    sign_event(&mut event, &sk, now()).unwrap();
    let original_id = event.id.clone();
    let original_sig = event.sig.clone();
    let original_content = event.content.clone();

    let pool = test_pool().await;
    let mut rx = pool.events_async().await;

    let sub_id = SubscriptionId::generate();
    let filters = vec![Filter {
        kinds: Some(vec![KIND_AGENT_MESSAGE]),
        authors: Some(vec![pk.clone()]),
        since: Some(now() - 5),
        ..Default::default()
    }];
    pool.subscribe(sub_id.clone(), filters).await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;

    pool.publish(event).await;

    let received = tokio::time::timeout(Duration::from_secs(10), async {
        while let Some((_url, msg)) = rx.recv().await {
            match msg {
                RelayMessage::Event(_sub, evt) if evt.id == original_id => return evt,
                _ => continue,
            }
        }
        panic!("channel closed");
    })
    .await
    .expect("timed out");

    // Verify the event survived the relay round-trip intact.
    assert_eq!(received.id, original_id);
    assert_eq!(received.sig, original_sig);
    assert_eq!(received.content, original_content);
    assert_eq!(received.pubkey, pk);
    verify_event(&received).unwrap();

    pool.unsubscribe(&sub_id).await.unwrap();
    pool.shutdown().await;
}
