# cbcl-nostr

A Rust library implementing [NIP-XX](specs/nip-xx-agent-communication.md) — structured agent-to-agent communication over Nostr using [CBCL](https://datatracker.ietf.org/doc/draft-cbcl/) S-expressions.

## What is this?

Nostr provides signed events, relay-based delivery, and public key identity. CBCL provides formally specified message semantics with 8 core performatives (`tell`, `ask`, `reply`, `ok`, `error`, `cancel`, `hello`, `bye`) and safe runtime dialect extension.

This crate combines both: agents get a global, censorship-resistant communication network with unambiguous, machine-parseable messages.

## Event kinds

| Kind  | Description                 |
|-------|-----------------------------|
| 21111 | Agent message (regular)     |
| 31111 | Agent dialect (addressable) |

## Features

- **S-expression codec** — parse and serialize CBCL in Nostr event `content` fields
- **Typed event wrappers** — `AgentMessage` (kind 21111) and `AgentDialect` (kind 31111) with strongly-typed tags
- **Event signing** — secp256k1 Schnorr signatures per NIP-01
- **Gift wrap encryption** — NIP-59 two-layer encrypted envelopes for private agent messaging
- **Relay pool** — async WebSocket connections to multiple Nostr relays
- **Dialect negotiation** — runtime extension of performatives with safety verification
- **Agent discovery** — find agents by capability via hello/bye broadcast protocol
- **Commerce dialects** — task market, bounties, and zap integration
- **Spam prevention** — proof-of-work and reputation-based filtering
- **Payment safety** — escrow patterns and payment verification

## Usage

### Building messages

```rust
use cbcl_core::sexpr::{Atom, SExpr};
use cbcl_nostr::message_builder::MessageBuilder;

// Send a directed message
let event = MessageBuilder::new("tell")
    .recipient("abc123...") // recipient's hex pubkey
    .body(vec![
        SExpr::Atom(Atom::Symbol("@abc123...".into())),
        SExpr::Atom(Atom::Str("Deploy the frontend to staging".into())),
    ])
    .thread("conv-17")
    .build()?;
// event.content == r#"(tell @abc123... "Deploy the frontend to staging")"#

// Ask a question with a dialect
let event = MessageBuilder::new("ask")
    .recipient("def456...")
    .body(vec![
        SExpr::Atom(Atom::Symbol("@def456...".into())),
        SExpr::Atom(Atom::Str("What's the price?".into())),
    ])
    .dialect("commerce")
    .build()?;

// Broadcast presence
let event = MessageBuilder::new("hello").build()?;
// event.content == "(hello)"
```

### Signing and verifying events

```rust
use cbcl_nostr::event_signing::{sign_event, verify_event};

let mut event = MessageBuilder::new("tell")
    .recipient("abc123...")
    .body(vec![SExpr::Atom(Atom::Str("hello".into()))])
    .build()?;

// Sign with your secret key and current timestamp
sign_event(&mut event, "your_secret_key_hex", 1700000000)?;

// Verify a received event's ID and Schnorr signature
verify_event(&event)?;
```

### Parsing S-expressions from events

```rust
use cbcl_nostr::sexpr_codec::{decode, encode};

// Parse a CBCL message from a Nostr event content field
let expr = decode(r#"(tell @bob "Deploy to staging" :thread "conv-17")"#)?;

// Serialize back to a string
let content = encode(&expr);
```

### Agent discovery

```rust
use cbcl_nostr::agent_discovery::{build_hello, build_bye, AgentRegistry};

// Announce your agent's presence
let hello_event = build_hello("assistant", &["chat", "code-review"])?;

// Track discovered agents
let mut registry = AgentRegistry::new();
registry.process_event(&incoming_event)?;

// Find agents by iterating
for agent in registry.agents() {
    println!("{}: {:?}", agent.pubkey, agent.capabilities);
}

// Clean up stale agents (older than cutoff timestamp)
registry.evict_stale(cutoff_timestamp);

// Depart gracefully
let bye_event = build_bye()?;
```

### Private messaging with gift wrap (NIP-59)

```rust
use cbcl_nostr::gift_wrap::{gift_wrap, unwrap_gift};

// Wrap a message in a two-layer encrypted envelope
// (rumor → seal → gift wrap with ephemeral key)
let rumor = MessageBuilder::new("tell")
    .recipient(&recipient_pk)
    .body(vec![SExpr::Atom(Atom::Str("secret task".into()))])
    .build()?;

let wrapped = gift_wrap(rumor, &sender_sk, &recipient_pk, now)?;
// wrapped.kind == 1059, sender identity hidden behind ephemeral key

// Recipient unwraps to get the original message + verified sender
let result = unwrap_gift(&wrapped, &recipient_sk)?;
assert_eq!(result.rumor.content, r#"(tell "secret task")"#);
assert_eq!(result.sender_pubkey, sender_pk);
```

### NIP-44 encryption primitives

```rust
use cbcl_nostr::event_signing::{conversation_key, nip44_encrypt, nip44_decrypt};

// Derive a shared conversation key via ECDH + HKDF
let ck = conversation_key(&my_secret_key_hex, &their_pubkey_hex)?;

// Encrypt/decrypt with ChaCha20-Poly1305 + HMAC
let ciphertext = nip44_encrypt(&ck, "hello, agent!")?;
let plaintext = nip44_decrypt(&ck, &ciphertext)?;
```

## Project layout

```
crates/cbcl-nostr/       Rust library
  src/
    lib.rs               Crate root — re-exports all modules
    sexpr_codec.rs       Parse/serialize CBCL S-expressions
    event_types.rs       Kind 21111/31111 event structs and typed tags
    event_signing.rs     NIP-01 signing, verification, NIP-44 encryption
    message_builder.rs   Builder API for agent messages
    gift_wrap.rs         NIP-59 two-layer encrypted envelopes
    agent_discovery.rs   Hello/bye broadcast and agent registry
    dialect_negotiation.rs  Runtime dialect extension
    relay_pool/          Async WebSocket relay connections
    ...
  tests/                 Integration and property-based tests
specs/                   Protocol specifications (NIP-XX)
plans/                   Implementation plans (SPL)
```

## Requirements

- Rust 1.75+
- Depends on `cbcl-core` and `cbcl-parser` from [cbcl-rs](https://codeberg.org/anuna/cbcl-rs)

## License

Apache-2.0
