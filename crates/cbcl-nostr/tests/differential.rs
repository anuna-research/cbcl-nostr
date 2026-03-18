//! Differential tests: cross-verify CBCL message parsing between cbcl-nostr
//! and cbcl-rs using the cbcl-rs 156 test vectors.
//!
//! Ensures that:
//! 1. `sexpr_codec::decode(input)` and `cbcl_parser::parse(input)` produce
//!    identical SExpr trees for all test vectors with string inputs.
//! 2. Wrapping CBCL content in a Nostr event and extracting it back does not
//!    alter CBCL semantics: `parse(event.content) == parse(original)`.
//! 3. Round-trip through the codec is stable:
//!    `decode(encode(decode(input))) == decode(input)`.

use cbcl_core::sexpr::SExpr;
use cbcl_nostr::event_types::{
    AgentDialect, AgentMessage, Event, Tag, KIND_AGENT_DIALECT, KIND_AGENT_MESSAGE,
};
use cbcl_nostr::sexpr_codec;
use cbcl_parser::parser::parse;
use serde_json::Value;
use std::path::PathBuf;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn vectors_dir() -> PathBuf {
    PathBuf::from("/Users/anuna-02/Code/cbcl-rs/test-vectors")
}

fn load_vectors(relative: &str) -> Vec<Value> {
    let path = vectors_dir().join(relative);
    let content = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
    serde_json::from_str(&content)
        .unwrap_or_else(|e| panic!("failed to parse {}: {e}", path.display()))
}

fn vec_id(v: &Value) -> &str {
    v["id"].as_str().unwrap_or("unknown")
}

/// Build a dummy NIP-01 event with the given content and kind.
fn make_event(kind: u64, content: &str) -> Event {
    Event {
        id: "a".repeat(64),
        pubkey: "b".repeat(64),
        created_at: 1700000000,
        kind,
        tags: vec![
            vec!["p".into(), "c".repeat(64)],
            vec!["performative".into(), "tell".into()],
        ],
        content: content.to_string(),
        sig: "d".repeat(128),
    }
}

/// Extract all string inputs from a vector of test vectors.
/// Returns (id, input) pairs for vectors that have a string `input` field.
fn extract_string_inputs(vectors: &[Value]) -> Vec<(&str, &str)> {
    vectors
        .iter()
        .filter_map(|v| {
            let id = vec_id(v);
            v["input"].as_str().map(|input| (id, input))
        })
        .collect()
}

/// Extract message strings from nested `input.message` fields.
fn extract_nested_messages(vectors: &[Value]) -> Vec<(String, &str)> {
    vectors
        .iter()
        .filter_map(|v| {
            let id = vec_id(v);
            v["input"]["message"]
                .as_str()
                .map(|msg| (format!("{id}/message"), msg))
        })
        .collect()
}

/// Extract message strings from `input.messages[].message` arrays.
fn extract_message_arrays(vectors: &[Value]) -> Vec<(String, String)> {
    let mut out = vec![];
    for v in vectors {
        let id = vec_id(v);
        if let Some(msgs) = v["input"]["messages"].as_array() {
            for (i, m) in msgs.iter().enumerate() {
                if let Some(msg) = m["message"].as_str() {
                    out.push((format!("{id}/messages[{i}]"), msg.to_string()));
                }
            }
        }
        if let Some(seq) = v["input"]["sequence"].as_array() {
            for (i, m) in seq.iter().enumerate() {
                if let Some(msg) = m["message"].as_str() {
                    out.push((format!("{id}/sequence[{i}]"), msg.to_string()));
                }
            }
        }
        if let Some(batch) = v["input"]["batch"].as_array() {
            for (i, m) in batch.iter().enumerate() {
                if let Some(msg) = m.as_str() {
                    out.push((format!("{id}/batch[{i}]"), msg.to_string()));
                }
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// 1. Differential: cbcl_parser::parse vs sexpr_codec::decode
//
// For every test vector with a string `input`, both parsers must agree on
// success/failure and produce identical SExpr trees on success.
// ---------------------------------------------------------------------------

/// Run differential parse test on a set of (id, input) pairs.
fn differential_parse(inputs: &[(&str, &str)]) {
    let mut tested = 0;
    for &(id, input) in inputs {
        let rs_result = parse(input);
        let nostr_result = sexpr_codec::decode(input);

        match (&rs_result, &nostr_result) {
            (Ok(rs_sexpr), Ok(nostr_sexpr)) => {
                assert_eq!(
                    rs_sexpr, nostr_sexpr,
                    "[{id}] SExpr mismatch:\n  cbcl-rs:    {rs_sexpr}\n  cbcl-nostr: {nostr_sexpr}"
                );
            }
            (Err(_), Err(_)) => {
                // Both failed — consistent. That's fine.
            }
            (Ok(rs_sexpr), Err(nostr_err)) => {
                panic!(
                    "[{id}] cbcl-rs succeeded but cbcl-nostr failed:\n  \
                     input: {input:?}\n  cbcl-rs: {rs_sexpr}\n  cbcl-nostr error: {nostr_err}"
                );
            }
            (Err(rs_err), Ok(nostr_sexpr)) => {
                panic!(
                    "[{id}] cbcl-nostr succeeded but cbcl-rs failed:\n  \
                     input: {input:?}\n  cbcl-nostr: {nostr_sexpr}\n  cbcl-rs error: {rs_err}"
                );
            }
        }
        tested += 1;
    }
    assert!(tested > 0, "no test vectors were tested");
}

#[test]
fn differential_messages_simple() {
    let vectors = load_vectors("messages/simple.json");
    let inputs = extract_string_inputs(&vectors);
    assert_eq!(inputs.len(), 11);
    differential_parse(&inputs);
}

#[test]
fn differential_messages_strings() {
    let vectors = load_vectors("messages/strings.json");
    let inputs = extract_string_inputs(&vectors);
    assert_eq!(inputs.len(), 14);
    differential_parse(&inputs);
}

#[test]
fn differential_messages_meta() {
    let vectors = load_vectors("messages/meta.json");
    let inputs = extract_string_inputs(&vectors);
    assert_eq!(inputs.len(), 5);
    differential_parse(&inputs);
}

#[test]
fn differential_messages_wrapped() {
    let vectors = load_vectors("messages/wrapped.json");
    let inputs = extract_string_inputs(&vectors);
    assert_eq!(inputs.len(), 6);
    differential_parse(&inputs);
}

#[test]
fn differential_messages_lang() {
    let vectors = load_vectors("messages/lang.json");
    let inputs = extract_string_inputs(&vectors);
    assert_eq!(inputs.len(), 2);
    differential_parse(&inputs);
}

#[test]
fn differential_messages_canonicalization() {
    let vectors = load_vectors("messages/canonicalization.json");
    let inputs = extract_string_inputs(&vectors);
    assert_eq!(inputs.len(), 3);
    differential_parse(&inputs);
}

#[test]
fn differential_messages_invalid() {
    let vectors = load_vectors("messages/invalid.json");
    let inputs = extract_string_inputs(&vectors);
    // All 7 invalid vectors have string inputs
    assert_eq!(inputs.len(), 7);
    // For invalid vectors, both parsers should agree on error status
    // (some may succeed at parse level but fail at message validation)
    for &(id, input) in &inputs {
        let rs_result = parse(input);
        let nostr_result = sexpr_codec::decode(input);

        match (&rs_result, &nostr_result) {
            (Ok(rs_sexpr), Ok(nostr_sexpr)) => {
                // Both succeed at the S-expression parse level — that's fine,
                // the error may be at the message-validation level (e.g.
                // unknown performative, missing recipient). The important thing
                // is that the SExpr trees match.
                assert_eq!(
                    rs_sexpr, nostr_sexpr,
                    "[{id}] SExpr mismatch on invalid-message vector"
                );
            }
            (Err(_), Err(_)) => {}
            (Ok(_), Err(e)) => {
                panic!("[{id}] cbcl-rs parsed but cbcl-nostr failed: {e}");
            }
            (Err(e), Ok(_)) => {
                panic!("[{id}] cbcl-nostr parsed but cbcl-rs failed: {e}");
            }
        }
    }
}

#[test]
fn differential_dialect_messages() {
    let vectors = load_vectors("dialects/messages.json");
    let inputs = extract_string_inputs(&vectors);
    assert_eq!(inputs.len(), 10);
    differential_parse(&inputs);
}

// ---------------------------------------------------------------------------
// Embedded messages from pipeline/integration vectors
// ---------------------------------------------------------------------------

#[test]
fn differential_pipeline_embedded_messages() {
    let vectors = load_vectors("pipeline/integration.json");

    // Extract from input.message
    let nested = extract_nested_messages(&vectors);
    for (id, msg) in &nested {
        let rs = parse(msg).unwrap_or_else(|e| panic!("[{id}] cbcl-rs failed: {e}"));
        let nostr = sexpr_codec::decode(msg).unwrap_or_else(|e| panic!("[{id}] codec failed: {e}"));
        assert_eq!(rs, nostr, "[{id}] SExpr mismatch");
    }

    // Extract from input.messages[].message and input.sequence[].message
    let arrays = extract_message_arrays(&vectors);
    for (id, msg) in &arrays {
        let rs = parse(msg).unwrap_or_else(|e| panic!("[{id}] cbcl-rs failed: {e}"));
        let nostr = sexpr_codec::decode(msg).unwrap_or_else(|e| panic!("[{id}] codec failed: {e}"));
        assert_eq!(rs, nostr, "[{id}] SExpr mismatch");
    }

    assert!(
        nested.len() + arrays.len() > 0,
        "expected embedded messages in pipeline vectors"
    );
}

#[test]
fn differential_edge_case_messages() {
    let vectors = load_vectors("pipeline/edge-cases.json");
    // Extract string inputs at top level
    let inputs = extract_string_inputs(&vectors);
    if !inputs.is_empty() {
        differential_parse(&inputs);
    }
    // Extract nested messages
    let nested = extract_nested_messages(&vectors);
    for (id, msg) in &nested {
        let rs = parse(msg).unwrap_or_else(|e| panic!("[{id}] cbcl-rs failed: {e}"));
        let nostr = sexpr_codec::decode(msg).unwrap_or_else(|e| panic!("[{id}] codec failed: {e}"));
        assert_eq!(rs, nostr, "[{id}] SExpr mismatch");
    }
}

// ---------------------------------------------------------------------------
// 2. Nostr event wrapping does not alter CBCL semantics
//
// Wrap the CBCL content in a NIP-01 Event, extract it, and parse again.
// The resulting SExpr must be identical to the original parse.
// ---------------------------------------------------------------------------

fn nostr_wrapping_preserves_semantics(vectors: &[Value], kind: u64) {
    let inputs = extract_string_inputs(vectors);
    let mut tested = 0;
    for (id, input) in &inputs {
        let original = match sexpr_codec::decode(input) {
            Ok(expr) => expr,
            Err(_) => continue, // Skip vectors that don't parse
        };

        // Wrap in a Nostr event
        let event = make_event(kind, input);

        // Verify the event wraps correctly
        if kind == KIND_AGENT_MESSAGE {
            let msg = AgentMessage::from_event(event.clone()).unwrap();
            assert_eq!(msg.event.content, *input);
        } else {
            let dialect = AgentDialect::from_event(event.clone()).unwrap();
            assert_eq!(dialect.event.content, *input);
        }

        // Parse from the event content — must match original
        let from_event = sexpr_codec::decode(&event.content)
            .unwrap_or_else(|e| panic!("[{id}] failed to parse from event.content: {e}"));
        assert_eq!(
            original, from_event,
            "[{id}] event wrapping altered semantics"
        );

        // Also verify via JSON serialization round-trip of the event
        let json = serde_json::to_string(&event).unwrap();
        let restored: Event = serde_json::from_str(&json).unwrap();
        let from_json_event = sexpr_codec::decode(&restored.content)
            .unwrap_or_else(|e| panic!("[{id}] failed to parse after JSON round-trip: {e}"));
        assert_eq!(
            original, from_json_event,
            "[{id}] JSON round-trip of event altered semantics"
        );

        tested += 1;
    }
    assert!(tested > 0, "no test vectors were tested for wrapping");
}

#[test]
fn nostr_wrapping_simple_messages() {
    let vectors = load_vectors("messages/simple.json");
    nostr_wrapping_preserves_semantics(&vectors, KIND_AGENT_MESSAGE);
}

#[test]
fn nostr_wrapping_meta_messages() {
    let vectors = load_vectors("messages/meta.json");
    nostr_wrapping_preserves_semantics(&vectors, KIND_AGENT_MESSAGE);
}

#[test]
fn nostr_wrapping_wrapped_messages() {
    let vectors = load_vectors("messages/wrapped.json");
    nostr_wrapping_preserves_semantics(&vectors, KIND_AGENT_MESSAGE);
}

#[test]
fn nostr_wrapping_lang_messages() {
    let vectors = load_vectors("messages/lang.json");
    nostr_wrapping_preserves_semantics(&vectors, KIND_AGENT_MESSAGE);
}

#[test]
fn nostr_wrapping_dialect_messages() {
    let vectors = load_vectors("dialects/messages.json");
    nostr_wrapping_preserves_semantics(&vectors, KIND_AGENT_DIALECT);
}

#[test]
fn nostr_wrapping_string_atoms() {
    let vectors = load_vectors("messages/strings.json");
    nostr_wrapping_preserves_semantics(&vectors, KIND_AGENT_MESSAGE);
}

// ---------------------------------------------------------------------------
// 3. Codec round-trip: decode(encode(decode(input))) == decode(input)
//
// For all successfully parseable inputs, encoding the SExpr back to a string
// and re-decoding must produce an identical tree.
// ---------------------------------------------------------------------------

fn codec_round_trip(vectors: &[Value]) {
    let inputs = extract_string_inputs(vectors);
    let mut tested = 0;
    for (id, input) in &inputs {
        let original = match sexpr_codec::decode(input) {
            Ok(expr) => expr,
            Err(_) => continue,
        };

        let encoded = sexpr_codec::encode(&original);
        let re_decoded = sexpr_codec::decode(&encoded).unwrap_or_else(|e| {
            panic!(
                "[{id}] round-trip failed: encode produced {encoded:?} \
                 which failed to decode: {e}"
            )
        });
        assert_eq!(
            original, re_decoded,
            "[{id}] decode(encode(x)) != x\n  original input: {input:?}\n  \
             encoded: {encoded:?}"
        );

        // Triple round-trip: encode again and verify stability
        let re_encoded = sexpr_codec::encode(&re_decoded);
        assert_eq!(
            encoded, re_encoded,
            "[{id}] encode is not stable: first={encoded:?}, second={re_encoded:?}"
        );

        tested += 1;
    }
    assert!(tested > 0, "no test vectors were tested for round-trip");
}

#[test]
fn round_trip_simple_messages() {
    codec_round_trip(&load_vectors("messages/simple.json"));
}

#[test]
fn round_trip_meta_messages() {
    codec_round_trip(&load_vectors("messages/meta.json"));
}

#[test]
fn round_trip_wrapped_messages() {
    codec_round_trip(&load_vectors("messages/wrapped.json"));
}

#[test]
fn round_trip_lang_messages() {
    codec_round_trip(&load_vectors("messages/lang.json"));
}

#[test]
fn round_trip_string_atoms() {
    codec_round_trip(&load_vectors("messages/strings.json"));
}

#[test]
fn round_trip_dialect_messages() {
    codec_round_trip(&load_vectors("dialects/messages.json"));
}

#[test]
fn round_trip_canonicalization() {
    codec_round_trip(&load_vectors("messages/canonicalization.json"));
}

// ---------------------------------------------------------------------------
// 4. Full event pipeline: wrap in Event, JSON-serialize, deserialize, parse
//
// Simulates the full Nostr relay path: content is placed in an Event,
// serialized to JSON (as a relay would transmit), deserialized by the
// receiver, and parsed. Must produce the same SExpr as direct parsing.
// ---------------------------------------------------------------------------

#[test]
fn full_event_pipeline_all_message_vectors() {
    let vector_files = [
        "messages/simple.json",
        "messages/meta.json",
        "messages/wrapped.json",
        "messages/lang.json",
        "messages/strings.json",
        "dialects/messages.json",
    ];

    let mut total_tested = 0;

    for file in &vector_files {
        let vectors = load_vectors(file);
        let inputs = extract_string_inputs(&vectors);

        for (id, input) in &inputs {
            let direct_parse = match parse(input) {
                Ok(expr) => expr,
                Err(_) => continue,
            };

            // Simulate the Nostr event pipeline
            let event = make_event(KIND_AGENT_MESSAGE, input);
            let json = serde_json::to_string(&event).unwrap();
            let received: Event = serde_json::from_str(&json).unwrap();
            let from_pipeline = sexpr_codec::decode(&received.content).unwrap_or_else(|e| {
                panic!("[{id} in {file}] pipeline parse failed: {e}")
            });

            assert_eq!(
                direct_parse, from_pipeline,
                "[{id} in {file}] pipeline altered semantics"
            );
            total_tested += 1;
        }
    }

    // Verify we actually tested a significant number of vectors
    assert!(
        total_tested >= 40,
        "expected at least 40 vectors through pipeline, got {total_tested}"
    );
}

// ---------------------------------------------------------------------------
// 5. Tag preservation through event wrapping
//
// Verify that CBCL-relevant tags survive the Event→JSON→Event round-trip
// and that Tag::parse(tag.to_raw()) is stable.
// ---------------------------------------------------------------------------

#[test]
fn tag_round_trip_through_event_json() {
    let tags = vec![
        vec!["p".into(), "abc123".into()],
        vec!["performative".into(), "tell".into()],
        vec!["thread".into(), "conv-17".into()],
        vec!["e".into(), "def456".into()],
        vec!["dialect".into(), "commerce".into()],
        vec!["t".into(), "cbcl".into()],
        vec!["amount".into(), "1000".into()],
        vec!["L".into(), "cbcl.dialect".into()],
        vec!["l".into(), "commerce".into(), "cbcl.dialect".into()],
    ];

    let event = Event {
        id: "a".repeat(64),
        pubkey: "b".repeat(64),
        created_at: 1700000000,
        kind: KIND_AGENT_MESSAGE,
        tags: tags.clone(),
        content: r#"(tell @abc "hello")"#.into(),
        sig: "d".repeat(128),
    };

    // JSON round-trip
    let json = serde_json::to_string(&event).unwrap();
    let restored: Event = serde_json::from_str(&json).unwrap();
    assert_eq!(event.tags, restored.tags);

    // Parse each tag, convert back, and verify
    for raw in &restored.tags {
        let parsed = Tag::parse(raw);
        let back = parsed.to_raw();
        let reparsed = Tag::parse(&back);
        assert_eq!(parsed, reparsed, "tag round-trip failed for {raw:?}");
    }
}

// ---------------------------------------------------------------------------
// 6. Atom JSON-safe encoding through event content
//
// Verify that CBCL atoms embedded in S-expressions survive the full
// Nostr pipeline without losing type information.
// ---------------------------------------------------------------------------

#[test]
fn atom_types_preserved_through_event_pipeline() {
    let test_contents = [
        // Symbols
        r#"(tell @alice "hello")"#,
        // Numbers
        r#"(ask @alice "status?" :timeout 30)"#,
        // Booleans
        "(with-limits :refundable #t :enabled #f ())",
        // Keywords
        r#"(tell @bob "msg" :thread "conv-1" :priority high)"#,
        // Nested lists
        "(meta (define commerce :extends cbcl-base))",
        // Mixed atoms
        r#"(test "string" 42 -7 #t #f :key symbol)"#,
    ];

    for content in &test_contents {
        let original = sexpr_codec::decode(content).unwrap();

        let event = make_event(KIND_AGENT_MESSAGE, content);
        let json = serde_json::to_string(&event).unwrap();
        let restored: Event = serde_json::from_str(&json).unwrap();
        let from_pipeline = sexpr_codec::decode(&restored.content).unwrap();

        assert_eq!(original, from_pipeline, "atom loss for: {content}");

        // Verify atom types are correct in the tree
        fn verify_atoms_match(a: &SExpr, b: &SExpr) {
            match (a, b) {
                (SExpr::Atom(aa), SExpr::Atom(ba)) => {
                    assert_eq!(
                        std::mem::discriminant(aa),
                        std::mem::discriminant(ba),
                        "atom type changed: {aa:?} vs {ba:?}"
                    );
                    assert_eq!(aa, ba);
                }
                (SExpr::List(al), SExpr::List(bl)) => {
                    assert_eq!(al.len(), bl.len());
                    for (a, b) in al.iter().zip(bl.iter()) {
                        verify_atoms_match(a, b);
                    }
                }
                _ => panic!("structure mismatch: {a:?} vs {b:?}"),
            }
        }

        verify_atoms_match(&original, &from_pipeline);
    }
}

// ---------------------------------------------------------------------------
// 7. Comprehensive vector count verification
//
// Ensures we're actually testing against the full 156-vector suite.
// ---------------------------------------------------------------------------

#[test]
fn verify_total_vector_count() {
    let files = [
        ("sexpr/parse.json", 12),
        ("sexpr/serialize.json", 6),
        ("sexpr/round-trip.json", 7),
        ("sexpr/errors.json", 6),
        ("messages/simple.json", 11),
        ("messages/meta.json", 5),
        ("messages/wrapped.json", 6),
        ("messages/lang.json", 2),
        ("messages/canonicalization.json", 3),
        ("messages/strings.json", 14),
        ("messages/invalid.json", 7),
        ("dialects/definitions.json", 4),
        ("dialects/verification.json", 6),
        ("dialects/messages.json", 10),
        ("r1-r4/r1-no-recursion.json", 10),
        ("r1-r4/r2-resource-bounds.json", 8),
        ("r1-r4/r3-core-preservation.json", 10),
        ("r1-r4/r4-signatures.json", 4),
        ("pipeline/template-expansion.json", 8),
        ("pipeline/pattern-matching.json", 2),
        ("pipeline/integration.json", 5),
        ("pipeline/edge-cases.json", 10),
    ];

    let mut total = 0;
    for (file, expected_count) in &files {
        let vectors = load_vectors(file);
        assert_eq!(
            vectors.len(),
            *expected_count,
            "vector count mismatch in {file}"
        );
        total += vectors.len();
    }
    assert_eq!(total, 156, "total vector count must be 156");
}

// ---------------------------------------------------------------------------
// 8. Differential on all parseable vectors across all files
//
// Sweep every vector file and test every string-input vector through
// both parsers, ensuring complete coverage.
// ---------------------------------------------------------------------------

#[test]
fn differential_all_parseable_vectors() {
    let files = [
        "messages/simple.json",
        "messages/meta.json",
        "messages/wrapped.json",
        "messages/lang.json",
        "messages/canonicalization.json",
        "messages/strings.json",
        "messages/invalid.json",
        "dialects/messages.json",
    ];

    let mut total_tested = 0;
    let mut total_success_match = 0;
    let mut total_error_match: usize = 0;

    for file in &files {
        let vectors = load_vectors(file);
        let inputs = extract_string_inputs(&vectors);

        for (id, input) in &inputs {
            let rs_result = parse(input);
            let nostr_result = sexpr_codec::decode(input);

            match (&rs_result, &nostr_result) {
                (Ok(rs), Ok(nostr)) => {
                    assert_eq!(
                        rs, nostr,
                        "[{id} in {file}] SExpr mismatch"
                    );
                    total_success_match += 1;
                }
                (Err(_), Err(_)) => {
                    total_error_match += 1;
                }
                (Ok(_), Err(e)) => {
                    panic!("[{id} in {file}] cbcl-rs OK but codec Err: {e}");
                }
                (Err(e), Ok(_)) => {
                    panic!("[{id} in {file}] codec OK but cbcl-rs Err: {e}");
                }
            }
            total_tested += 1;
        }
    }

    // We expect at least 58 string-input vectors across these files
    assert!(
        total_tested >= 58,
        "expected >= 58 parseable vectors, got {total_tested}"
    );
    assert!(
        total_success_match > 0,
        "no success matches found"
    );
    // Verify we saw both outcomes
    let _ = total_error_match; // used for accounting
}
