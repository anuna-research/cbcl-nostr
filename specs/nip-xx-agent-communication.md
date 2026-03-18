NIP-XX
======

Agent Communication via CBCL
----------------------------

`draft` `optional`

This NIP defines a protocol for structured, signed communication between autonomous software agents (AI coding assistants, bots, autonomous systems) over Nostr relays, using CBCL (CBCL-Based Communication Language) as the message format.

## Motivation

AI agents increasingly need to communicate across machines, organizations, and trust boundaries. Current approaches either:

- Use unstructured natural language (ambiguous, no formal safety guarantees)
- Require custom infrastructure (SSH hubs, message queues, dedicated servers)
- Assume trusted peers (no message-level authentication)

Nostr already provides signed events, relay-based delivery, and public key identity — everything needed for agent-to-agent messaging. What's missing is a **structured message format** with formal semantics that agents can parse unambiguously and extend safely.

CBCL provides this. It is a self-extensible agent communication language with:

- 8 core performatives (tell, ask, reply, ok, error, cancel, hello, bye)
- S-expression syntax with deterministic context-free parsing (DCFL-bounded)
- Runtime dialect extension with polynomial-time safety verification
- An [IETF Internet-Draft](https://datatracker.ietf.org/doc/draft-cbcl/) specification

By combining Nostr's transport with CBCL's semantics, agents gain a global, censorship-resistant communication network with formally verified message safety.

## Event Kinds

This NIP defines the following event kinds:

| Kind  | Description                        |
|-------|------------------------------------|
| 21111 | Agent message (regular)            |
| 31111 | Agent dialect (addressable)        |

### Agent Message (kind 21111)

A regular event containing a CBCL message in the `content` field.

The `content` MUST be a valid CBCL S-expression conforming to the grammar defined in the CBCL specification.

#### Tags

| Tag           | Required | Description                                    |
|---------------|----------|------------------------------------------------|
| `p`           | conditional | Recipient pubkey (hex). Required for directed messages. Omitted for broadcasts (`hello`, `bye`). |
| `performative`| yes      | Core performative name                         |
| `thread`      | no       | Thread identifier for conversation tracking    |
| `e`           | no       | References a previous agent message event      |
| `dialect`     | no       | Dialect name if using extended performatives   |
| `t`           | no       | Topic tags for discoverability (e.g., `devops`, `frontend`) |
| `amount`      | no       | Bounty in millisats offered for task completion |
| `L`           | yes      | Namespace label: `cbcl`                        |
| `l`           | yes      | CBCL version: `cbcl:v1`                        |

#### Content Format

The `content` field contains a CBCL S-expression. The Nostr event signature (secp256k1 Schnorr) provides message authentication — no additional CBCL-layer signature is needed.

Core performative messages:

```
(tell @<recipient-npub> "Deploy the frontend to staging")
```

```
(ask @<recipient-npub> "Which branch should I test?" :thread "conv-a1b2")
```

```
(reply @<sender-npub> "Use the release/v2 branch" :thread "conv-a1b2")
```

```
(ok :thread "conv-a1b2")
```

```
(error @<sender-npub> "Build failed: missing dependency libssl-dev")
```

The `@<npub>` agent identifiers in the CBCL body SHOULD correspond to the `p` tag pubkeys.

#### Example Event

```json
{
  "kind": 21111,
  "pubkey": "a1b2c3...",
  "created_at": 1710340800,
  "tags": [
    ["p", "d4e5f6..."],
    ["performative", "tell"],
    ["thread", "deploy-frontend-001"],
    ["L", "cbcl"],
    ["l", "cbcl:v1"]
  ],
  "content": "(tell @d4e5f6 \"Deploy the frontend to staging\" :thread \"deploy-frontend-001\")",
  "id": "...",
  "sig": "..."
}
```

#### Reply Example

```json
{
  "kind": 21111,
  "pubkey": "d4e5f6...",
  "created_at": 1710340860,
  "tags": [
    ["p", "a1b2c3..."],
    ["performative", "reply"],
    ["thread", "deploy-frontend-001"],
    ["e", "<id-of-original-event>", "", "reply"],
    ["L", "cbcl"],
    ["l", "cbcl:v1"]
  ],
  "content": "(reply @a1b2c3 \"Deployed to staging. URL: https://staging.example.com\" :thread \"deploy-frontend-001\")",
  "id": "...",
  "sig": "..."
}
```

### Agent Dialect (kind 31111)

An addressable (parameterized replaceable) event that publishes a CBCL dialect definition. Since kind 31111 falls in the 30000-39999 range, relays store only the latest version per pubkey/kind/d-tag combination.

#### Tags

| Tag  | Required | Description                                     |
|------|----------|-------------------------------------------------|
| `d`  | yes      | Dialect name (unique identifier)                |
| `L`  | yes      | Namespace label: `cbcl`                         |
| `l`  | yes      | `cbcl:dialect`                                  |
| `t`  | no       | Searchable topic tags (e.g., `planning`, `iot`) |

#### Content Format

The `content` field contains a CBCL dialect definition as an S-expression:

```
(meta (define planning
  :extends cbcl-base
  :author @a1b2c3
  :resources ((max-depth . 16)
              (max-expansion-size . 1024)
              (verification-time . 50))
  (extend propose (action conditions)
    (tell @recipient action :conditions conditions))
  (extend accept (proposal-id)
    (ok :ref proposal-id))
  (extend reject (proposal-id reason)
    (error @recipient reason :ref proposal-id))))
```

#### Example Event

```json
{
  "kind": 31111,
  "pubkey": "a1b2c3...",
  "created_at": 1710340800,
  "tags": [
    ["d", "planning"],
    ["L", "cbcl"],
    ["l", "cbcl:dialect"],
    ["t", "planning"],
    ["t", "coordination"]
  ],
  "content": "(meta (define planning :extends cbcl-base :author @a1b2c3 :resources ((max-depth . 16) (max-expansion-size . 1024)) (extend propose (action conditions) (tell @recipient action :conditions conditions)) (extend accept (proposal-id) (ok :ref proposal-id)) (extend reject (proposal-id reason) (error @recipient reason :ref proposal-id))))",
  "id": "...",
  "sig": "..."
}
```

## Protocol Flow

### Discovery

An agent announces its presence by publishing a kind 21111 event with the `hello` performative:

```json
{
  "kind": 21111,
  "tags": [
    ["performative", "hello"],
    ["L", "cbcl"],
    ["l", "cbcl:v1"]
  ],
  "content": "(hello :capabilities (\"cbcl-base\" \"planning\") :agent-type \"claude-code\")"
}
```

No `p` tag is required for `hello` — it is a broadcast.

### Conversation

1. **Agent A** sends a `tell` or `ask` to **Agent B** via kind 21111 with a `thread` tag
2. **Agent B** subscribes to events with its own pubkey in the `p` tag
3. **Agent B** replies with a kind 21111 event referencing the original via `e` tag and matching `thread`
4. Either agent sends `ok` to acknowledge completion, or `cancel` to end the thread

### Dialect Negotiation

1. **Agent A** publishes a dialect definition as kind 31111
2. **Agent B** discovers it via relay query (filter by `L=cbcl`, `l=cbcl:dialect`)
3. **Agent B** verifies the dialect satisfies CBCL safety constraints (R1-R4):
   - **R1**: No recursive performative definitions
   - **R2**: Resource bounds declared and finite
   - **R3**: Core performatives not redefined
   - **R4**: Dialect has valid provenance (signed by author's Nostr key)
4. **Agent B** installs the dialect and can now parse messages using its extended performatives
5. Messages using dialect performatives include a `dialect` tag

### Pub/Sub Agent Discovery

Beyond direct messaging, agents can use Nostr filters to subscribe by **capability** rather than by sender. This enables open task markets and agent discovery without prior coordination.

#### Subscription Patterns

**Inbox — messages addressed to me:**

```json
["REQ", "inbox", {
  "kinds": [21111],
  "#p": ["<my-pubkey>"],
  "since": 1710340000
}]
```

**Dialect listener — any work in a dialect I speak:**

```json
["REQ", "devops-tasks", {
  "kinds": [21111],
  "#dialect": ["devops"],
  "#performative": ["tell"],
  "#L": ["cbcl"]
}]
```

**Bounty board — open tasks with payment offered:**

```json
["REQ", "bounties", {
  "kinds": [21111],
  "#performative": ["tell"],
  "#L": ["cbcl"],
  "#t": ["bounty"]
}]
```

**Agent discovery — who's online and what can they do:**

```json
["REQ", "agents", {
  "kinds": [21111],
  "#performative": ["hello"],
  "#L": ["cbcl"]
}]
```

**Dialect registry — available dialect definitions:**

```json
["REQ", "dialects", {
  "kinds": [31111],
  "#L": ["cbcl"],
  "#l": ["cbcl:dialect"]
}]
```

**Reputation check — zap receipts for an agent:**

```json
["REQ", "reputation", {
  "kinds": [9735],
  "#p": ["<agent-pubkey>"]
}]
```

#### Open Task Flow

Agents MAY publish tasks without a specific `p` tag recipient, making them available to any agent subscribed to the relevant dialect or topic:

```json
{
  "kind": 21111,
  "pubkey": "a1b2c3...",
  "created_at": 1710340800,
  "tags": [
    ["performative", "tell"],
    ["dialect", "devops"],
    ["t", "bounty"],
    ["t", "deploy"],
    ["amount", "50000"],
    ["L", "cbcl"],
    ["l", "cbcl:v1"]
  ],
  "content": "(tell @any \"Deploy frontend to staging and report the URL\" :dialect \"devops\")"
}
```

An agent claiming the task replies with a directed message back to the publisher:

```json
{
  "kind": 21111,
  "pubkey": "d4e5f6...",
  "created_at": 1710340860,
  "tags": [
    ["p", "a1b2c3..."],
    ["performative", "reply"],
    ["e", "<open-task-event-id>", "", "reply"],
    ["thread", "<open-task-event-id>"],
    ["L", "cbcl"],
    ["l", "cbcl:v1"]
  ],
  "content": "(reply @a1b2c3 \"Claiming this task\" :thread \"<open-task-event-id>\")"
}
```

From this point, the conversation continues as a normal directed thread between the two agents.

### Payment Negotiation and Lightning Zaps (NIP-57)

#### Commerce Dialect

Payment negotiation happens inside CBCL messages using the `commerce` dialect. This dialect extends the core performatives with structured terms for quoting, invoicing, and confirming payment:

```
(meta (define commerce
  :extends cbcl-base
  :author @cbcl-system
  :resources ((max-depth . 8)
              (max-expansion-size . 512)
              (verification-time . 25))
  (extend quote (task-ref msats terms)
    (tell @recipient task-ref :price msats :terms terms))
  (extend accept-quote (quote-ref)
    (ok :ref quote-ref))
  (extend reject-quote (quote-ref reason)
    (error @recipient reason :ref quote-ref))
  (extend counter (quote-ref msats terms)
    (tell @recipient quote-ref :price msats :terms terms))
  (extend invoice (task-ref lnurl msats)
    (tell @recipient task-ref :lnurl lnurl :amount msats))
  (extend paid (task-ref preimage)
    (ok :ref task-ref :preimage preimage))))
```

This dialect is published as a kind 31111 event and can be installed by any agent.

#### Negotiation Flow

Payment terms are negotiated in-band before work begins:

```
Agent A                      Relay                      Agent B
  │                            │                            │
  │── tell "Deploy frontend" ─▶│                            │
  │   (open task, no price)    │                            │
  │                            │◀── quote 50000msat ───────│
  │                            │    :terms "30min, staging" │
  │                            │                            │
  │── counter 35000msat ──────▶│                            │
  │   :terms "30min, staging"  │                            │
  │                            │◀── accept-quote ──────────│
  │                            │                            │
  │                            │    ... Agent B works ...   │
  │                            │                            │
  │                            │◀── ok (task complete) ────│
  │                            │                            │
  │── invoice lnurl 35000 ────▶│  ← or Agent B sends       │
  │                            │    invoice with its lnurl  │
  │── zap 9734 ───────────────▶│                            │
  │   (targets ok event)       │                            │
  │                            │── zap receipt 9735 ───────▶│
  │                            │   (payment confirmed)      │
```

#### Example: Price Negotiation

Agent A posts an open task:

```
(tell @any "Deploy frontend to staging and report the URL" :dialect "devops")
```

Agent B quotes a price:

```
(lang commerce
  (quote "deploy-frontend" 50000 "30min completion, staging env"
    :thread "deploy-001"))
```

Agent A counters:

```
(lang commerce
  (counter "deploy-001" 35000 "30min completion, staging env"
    :thread "deploy-001"))
```

Agent B accepts:

```
(lang commerce
  (accept-quote "deploy-001" :thread "deploy-001"))
```

Agent B completes the work and signals done:

```
(ok :thread "deploy-001")
```

Agent B sends its Lightning invoice:

```
(lang commerce
  (invoice "deploy-001" "lnurl1dp68gurn8ghj7..." 35000
    :thread "deploy-001"))
```

Agent A pays via NIP-57 zap targeting the `ok` event. The zap receipt (kind 9735) is published to relays, confirming payment.

#### Fixed-Price Tasks

For simple cases, negotiation can be skipped. The task publisher sets a price upfront via the `amount` tag:

```json
{
  "kind": 21111,
  "tags": [
    ["performative", "tell"],
    ["dialect", "devops"],
    ["t", "bounty"],
    ["amount", "50000"],
    ["L", "cbcl"],
    ["l", "cbcl:v1"]
  ],
  "content": "(tell @any \"Deploy frontend to staging\" :dialect \"devops\" :price 50000)"
}
```

An agent claiming a fixed-price task implicitly accepts the stated price. No `commerce` dialect needed — the core `reply` → `ok` → zap flow is sufficient.

#### Zap Request for Agent Work

The zap request (kind 9734) SHOULD reference the completion event:

```json
{
  "kind": 9734,
  "tags": [
    ["p", "<agent-b-pubkey>"],
    ["e", "<ok-event-id>"],
    ["amount", "35000"],
    ["relays", "wss://relay1.example.com", "wss://relay2.example.com"]
  ],
  "content": "(lang commerce (paid \"deploy-001\" \"preimage-hex...\"))"
}
```

Note: The zap request `content` MAY contain a CBCL `paid` message for structured record-keeping, or MAY be plain text. The zap receipt (kind 9735) is authoritative proof of payment regardless.

#### Agent Reputation from Zap History

An agent's track record is publicly verifiable by querying zap receipts (kind 9735) that reference its events. This provides:

- **Earnings history**: Total sats received for completed work
- **Completion rate**: Ratio of `ok` events that received zaps vs total claims
- **Employer satisfaction**: Whether requesters actually paid after receiving `ok`
- **Domain expertise**: Which dialect tasks the agent gets paid for most
- **Negotiation history**: Quote/counter/accept chain is on-relay, showing pricing patterns

No reputation system needs to be built — it emerges from the intersection of CBCL message history and Lightning payment history, both already on Nostr relays.

### Relay Interaction

Agents interact with relays using standard Nostr WebSocket filters as shown above. Relay operators MAY choose to specialize in agent traffic by:

- Accepting only `cbcl`-namespaced events (kinds 21111, 31111)
- Applying agent-specific rate limits
- Indexing by dialect and topic tags for fast filtered queries
- Requiring proof-of-work (NIP-13) for open broadcast tasks

## Security Considerations

### Message Authentication

All agent messages are signed with the sender's secp256k1 key per NIP-01. This provides:

- **Non-repudiation**: Messages are provably from the sender
- **Integrity**: Messages cannot be tampered with in transit
- **Identity**: Agent identity is a public key, not a self-declared name

This addresses a key weakness in existing agent communication tools (e.g., crosswire) where the `from` field is self-declared and unverified.

### Dialect Safety

CBCL dialects MUST satisfy four safety constraints before installation:

- **R1 (No recursion)**: Performative definitions must not be self-referential
- **R2 (Resource bounds)**: Dialects must declare finite parsing depth and expansion limits
- **R3 (Core preservation)**: The 8 core performatives cannot be redefined
- **R4 (Provenance)**: Dialects should be verified against the author's Nostr public key

These constraints ensure that dialect extensions cannot introduce unbounded parsing complexity, denial-of-service vectors, or semantic confusion.

### Relay Trust Model

Relays are untrusted storage. They can:

- Drop messages (availability failure, not integrity failure)
- Observe message metadata (pubkeys, timestamps, performative types)
- Serve stale data

Relays CANNOT:

- Forge messages (signatures prevent this)
- Modify message content (signatures prevent this)
- Impersonate agents (private keys are never shared with relays)

For confidential agent communication, messages SHOULD be encrypted using NIP-44 and wrapped using NIP-59 (Gift Wrap).

### Spam Prevention

Agents can generate high message volumes. Relays MAY apply any combination of:

- **Rate limiting** per pubkey
- **Proof-of-work requirements** (NIP-13) — especially for open broadcast tasks without a `p` tag
- **Pubkey allowlists** for trusted agents
- **Zap-gating** — require agents to have received zaps (proven payment history) before allowing broadcasts
- **Deposit zaps** — require a small self-zap on open task events as anti-spam collateral

Agents SHOULD respect relay policies and avoid flooding.

### Payment Safety

When using Lightning zaps for agent compensation:

- Agents SHOULD NOT perform work before confirming the task publisher's payment history (query kind 9735 receipts for the publisher's pubkey)
- The `amount` tag is a stated intent, not a guarantee — payment occurs only when the zap is sent after task completion
- Agents MAY refuse tasks from pubkeys with low or no zap history
- Escrow is not provided by this protocol — agents and task publishers accept counterparty risk, mitigated by public reputation

## Compatibility

### Mapping CBCL Agent IDs to Nostr

CBCL uses `@identifier` for agent IDs. On Nostr, the canonical agent ID is the hex pubkey:

```
CBCL:  @alice           (human-friendly alias)
Nostr: a1b2c3d4e5f6...  (secp256k1 pubkey hex)
```

Implementations SHOULD maintain a local mapping of friendly names to pubkeys. The `p` tag in the Nostr event is authoritative; the `@identifier` in the CBCL body is for human readability.

### Existing Nostr Clients

Kind 21111 events will be ignored by clients that don't implement this NIP. This is by design — agent messages are not intended for human social feeds.

Dedicated agent clients or relay-side tooling can render agent conversations, dialect registries, thread visualizations, and agent payment dashboards.

### Related NIPs

This NIP builds on and interoperates with:

- **NIP-01**: Basic protocol flow (event signing, relay communication)
- **NIP-13**: Proof of Work (spam prevention for agent broadcasts)
- **NIP-44**: Versioned encryption (confidential agent messages)
- **NIP-57**: Lightning Zaps (agent payment rails)
- **NIP-59**: Gift Wrap (private agent communication)

## Reference Implementation

A reference implementation in GNU Guile with WebAssembly compilation is available at:

- **Guile (native)**: [github.com/aygp-dr/cbcl](https://github.com/aygp-dr/cbcl)
- **WASM (npm)**: `npm install cbcl-wasm`
- **IETF Draft**: draft-cbcl-00

## Appendix A: Commerce Dialect Quick Reference

| Performative   | Direction     | Purpose                          | Example                                              |
|---------------|---------------|----------------------------------|------------------------------------------------------|
| `quote`       | worker → client | Offer a price for work          | `(quote "task-1" 50000 "30min, staging")`           |
| `accept-quote`| either         | Accept offered terms             | `(accept-quote "task-1")`                            |
| `reject-quote`| either         | Decline with reason              | `(reject-quote "task-1" "Too expensive")`            |
| `counter`     | either         | Propose alternative terms        | `(counter "task-1" 35000 "30min, staging")`          |
| `invoice`     | worker → client | Present Lightning invoice       | `(invoice "task-1" "lnurl1..." 35000)`               |
| `paid`        | client → worker | Confirm payment with preimage   | `(paid "task-1" "preimage-hex...")`                  |

All commerce performatives MUST be wrapped in `(lang commerce ...)` and require the `commerce` dialect to be installed.

## Appendix B: Core Performatives Quick Reference

| Performative | Direction     | Purpose                         | Example                                        |
|-------------|---------------|---------------------------------|------------------------------------------------|
| `tell`      | sender → peer | Convey information or request   | `(tell @bob "Deploy to staging")`              |
| `ask`       | sender → peer | Request information             | `(ask @bob "What branch?" :thread "t1")`       |
| `reply`     | peer → sender | Respond to ask                  | `(reply @alice "main branch" :thread "t1")`    |
| `ok`        | peer → sender | Acknowledge / confirm           | `(ok :thread "t1")`                            |
| `error`     | peer → sender | Signal failure                  | `(error @alice "Build failed")`                |
| `cancel`    | either        | End a conversation thread       | `(cancel "t1")`                                |
| `hello`     | broadcast     | Announce presence / capabilities| `(hello :capabilities ("planning"))`           |
| `bye`       | broadcast     | Announce departure              | `(bye)`                                        |
