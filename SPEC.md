# Specification: Dacar (Decentralized Access Control for Reticulum)
**Version:** 1.0
**License:** EUPL-1.2
**Dependencies:** Reticulum Network Stack (RNS), LWW-Element-Set CRDT, MessagePack
## 1. Introduction
In traditional applications, access control is implemented using static lists of allowed identities provided via configuration files or central servers. This approach fails to scale across distributed mesh networks, lacking support for granular permissions, asynchronous delegation, and secure revocation when devices are offline.
Dacar defines a decentralized, offline-first authorization policy plane natively designed for delay-tolerant, low-bandwidth, and constrained hardware networks. By decoupling authorization state from transport using Conflict-free Replicated Data Types (CRDTs), Dacar allows edge nodes to evaluate permissions locally without real-time connectivity.
### 1.1 Design Goals
 * **Decentralized & Offline-Capable:** Nodes enforce permissions locally while completely isolated from the wider mesh.
 * **Zero-Overhead Client:** Routine application traffic requires no token injection or wire overhead.
 * **Permacomputing Frugality:** Employs strict cryptographic bounding and tombstone pruning to guarantee long-term viability on fixed-storage microcontrollers.
 * **Namespace Label Privacy:** Protects infrastructure labels from passive observers using salted namespace hashing.
 * **Delegated Trust:** Supports recursive permission delegation and multi-signature threshold governance.
 * **Transport Agnostic:** Deltas can be routed via RFed, LXMF, direct links, or physical optical transfers (QR codes).
## 2. Terminology
 * **Operation (Delta):** A cryptographically signed instruction to Add (Grant) or Remove (Revoke) a permission.
 * **Tuple:** The fundamental unit of permission: (Object, Relation, Grantee, Issuer).
 * **State Vector:** The serialized LWW-Element-Set CRDT containing all active and revoked Tuples.
 * **Root Trust Anchor:** The hardcoded identity or multi-sig group designated as the ultimate authority.
 * **Evaluation Engine:** The local runtime process that resolves requests against the CRDT.
## 3. Core Concepts
### 3.1 The Authorization Tuple
Permissions are defined by Tuples asserting that a Grantee holds a Relation over an Object, authorized by an Issuer.
Because the Issuer is incorporated into the tuple identity, two different administrators granting identical permissions to the same grantee produce two distinct Tuples. Revoking one only revokes that specific Tuple.
### 3.2 Reserved Relations & Cascade Scope
The relation string admin is reserved. Granting a user admin on an Object confers the authority to issue valid Grants and Revocations for that exact Object. Authority does *not* cascade to child namespaces by default unless a wildcard is explicitly authorized.
### 3.3 Namespace Label Privacy & Matching
*(Design Goal Clarification: This scheme provides **Namespace Label Privacy**. It prevents passive observers from reading the specific vocabulary of your infrastructure. It does **not** hide namespace topology; observers can still infer tree depth and branching structures by tracking repeated segment hashes).*
To prevent label disclosure over public transports, Dacar never transmits or stores Object or Relation strings in plaintext.
 * **The Privacy Salt:** Nodes MUST be configured out-of-band with a shared Privacy Salt (a 32-byte secure random string).
   > **WARNING:** If unused, this defaults to 32 null bytes (0x00). Using the default salt is **fail-open on privacy**, providing zero confidentiality and leaving the hashes fully vulnerable to trivial dictionary attacks.
   >
 * **Hashing Primitive:** All string hashing utilizes HMAC-SHA256, keyed with the Privacy Salt, strictly truncated to the first 16 bytes.
 * **Relation Hashing:** The Relation string is hashed in its entirety. Explicit denies include the hyphen prefix (e.g., Truncated_HMAC(Salt, "-calibrate")).
 * **Object Segmenting:** Objects are split by colons (:). Each segment is hashed individually. (e.g., sensor:wind becomes [ Truncated_HMAC(Salt, "sensor"), Truncated_HMAC(Salt, "wind") ]).
 * **Suffix Wildcards:** The terminal wildcard (*) is stripped prior to hashing and represented by a boolean flag on the tuple.
 * **Matching Algorithm:** To evaluate a plaintext request against a hashed tuple, the node hashes the request's segments using the local Privacy Salt and sequentially compares the byte arrays. A match succeeds if all tuple hashes match and the wildcard flag is true, or if the arrays are identical.
## 4. Bootstrapping & Trust Anchors
### 4.1 Configuration
Every Dacar-enabled service node MUST be configured out-of-band with one or more **Root Trust Anchors**. A recommended on-disk encoding for this configuration is specified in §13.2.
 1. **Single Identity:** A standard 16-byte `RNS.Identity` hash. RNS computes this hash as `SHA-256(P)[:16]`, where `P` is the identity's 64-byte public key — the 32-byte X25519 encryption public key concatenated with the 32-byte Ed25519 signing public key (`X25519_pub ‖ Ed25519_pub`).
 2. **Threshold Group (N-of-M):** A composite authority requiring consensus, defined by a set of M specific RNS.Identity hashes and an integer N (`1 ≤ N ≤ M`; `N == M` is the unanimous-consent case). The **Group ID** is the SHA-256 hash of the following packed binary pre-image, **strictly truncated to the first 16 bytes**: the M member hashes (16 bytes each) sorted ascending by raw byte value (equivalent to hex-alphabetical order), followed by the threshold N encoded as an 8-byte big-endian unsigned integer. The Group ID is itself a 16-byte value usable wherever an Issuer hash is expected.
   > **Note on Scope:** In v1.0, Threshold Groups MAY ONLY act as Issuers. A Grantee MUST be a single Identity. Granting permissions to a Threshold Group is not currently supported.
   >
   > **Identity Hash Requirement (verify-on-ingest):** An Operation's Issuer Hash and Grantee Hash MUST carry these canonical RNS identity hashes. Verify-on-ingest (§11.2.4) resolves a single-identity Issuer to its Ed25519 public key by recalling the `RNS.Identity` behind this hash from the network's announce store; an Issuer Hash that is not a recallable RNS identity hash (for example, a hash of the Ed25519 signing key alone) cannot be authenticated and MUST be dropped. Threshold Group IDs are exempt — being composite, they are resolved via explicit keyset registration rather than recall.
   >
### 4.2 Genesis Operations
For each configured Root Trust Anchor X (single or threshold), the node assumes an implicit Genesis Tuple: (*, admin, X, X). This ensures anchors independently possess terminal delegation authority.
The Genesis Tuple is never serialized, hashed, or transmitted — it exists solely to justify the direct identity-match termination rule in §7.2
## 5. Cryptography & Data Serialization
### 5.1 Hybrid Logical Clocks (HLC)
Dacar relies on HLCs packed into a 64-bit unsigned integer (Big-Endian):
 * **High 48 bits:** Physical Time (Unix epoch in milliseconds).
 * **Low 16 bits:** Logical Counter.
### 5.2 The Signature Pre-image
Operations MUST be signed using Ed25519. For Threshold Groups, the operation MUST carry exactly N valid signatures from the M members. The verifier MUST confirm the N signatures correspond to N distinct members of the M-set; duplicate signatures from the same member, or signatures that verify against the same public key more than once, MUST be rejected as invalid. Signatures are calculated over an unpadded binary Pre-image:
| Offset | Length | Field | Encoding |
|---|---|---|---|
| 0 | 16 bytes | **Issuer Hash** | 16-byte RNS.Identity hash, or truncated Threshold Group ID. |
| 16 | 16 bytes | **Grantee Hash** | 16-byte RNS.Identity hash. |
| 32 | 1 byte | **Action** | 0x01 for Grant (Add), 0x00 for Revoke (Remove). |
| 33 | 8 bytes | **Timestamp** | 64-bit unsigned integer (HLC), Big-Endian. |
| 41 | 16 bytes | **Relation Hash** | 16-byte HMAC-SHA256 hash of the relation string. |
| 57 | 1 byte | **Wildcard Flag** | 0x01 if object ends in :* or is *, else 0x00. |
| 58 | 1 byte | **Segment Count** | Unsigned 8-bit integer (S) representing object segments. |
| 59 | S × 16 bytes | **Object Hashes** | Contiguous 16-byte segment hashes. |
### 5.3 The Transport Payload
The Operation is serialized for transport as a MessagePack Array:
[ <16-byte issuer>, <16-byte grantee>, <action_int>, <hlc_int>, <16-byte relation_hash>, <array_of_16-byte_segment_hashes>, <wildcard_bool>, [<64-byte_sig_1>, ..., <64-byte_sig_N>] ]
## 6. The Authorization State (CRDT)
The global state is an LWW-Element-Set that maps a unique **Tuple Hash** to an HLC timestamp.
### 6.1 The Tuple Hash Calculation
To guarantee that Add (0x01) and Remove (0x00) Operations for the same logical permission resolve against each other, the Tuple Hash MUST uniquely identify the *permission itself*, not the operation.
The Tuple Hash is calculated as the SHA-256 hash over a packed binary array comprising ONLY:
[16-byte Issuer Hash] + [16-byte Grantee Hash] + [16-byte Relation Hash] + [1-byte Wildcard Flag] + [1-byte Segment Count] + [Array of Object Hashes].
**The Action byte and HLC timestamp are explicitly excluded from this hash.** This ensures that when a revocation is issued, its Tuple Hash perfectly matches the original grant, allowing the Evaluation Engine to compare the Add timestamp and Remove timestamp to determine the active state.
**Single-Delta Update Rule:** When receiving an Operation, the node updates the Add Set (A) or Remove Set (R) based on the Action byte, taking the maximum of the incoming HLC timestamp and the existing HLC timestamp.
> **Tie-Breaking:** If timestamps match exactly, the Tuple is considered revoked (Remove wins).
>
## 7. Evaluation Engine
### 7.1 Hypothesis Generation
When evaluating a request for Object O, Relation r, and Grantee U:
 1. **Deny Hypothesis:** Hash Grantee U, relation -r, and segment O. Generate all wildcard truncations.
 2. **Allow Hypothesis:** Hash Grantee U, relation r, and segment O. Generate all wildcard truncations.
### 7.2 Recursive Delegation & Termination
The engine verifies the Issuer's authority recursively. If the Issuer matches a Root Trust Anchor, recursion terminates successfully. Otherwise, the engine verifies if the Issuer holds the admin relation on O by generating a new request and processing it.
 * **Cycle Detection:** Circular delegations MUST be terminated immediately.
 * **Total Work Bound:** Implementations MUST enforce a maximum recursion depth of 10 hops.
### 7.3 Resolution Logic
 1. If ANY valid, active Tuple exists in the Deny Hypothesis, the request is **DENIED**.
 2. Else, if ANY valid, active Tuple exists in the Allow Hypothesis, the request is **ALLOWED**.
 3. Else, the request is **DENIED**.
## 8. Strict Consistency Challenge (Escape Hatch)
For destructive operations (e.g., wiping storage), eventual consistency is overridden via an **RNS Link** to guarantee synchronous evaluation. To maintain Namespace Label Privacy (§3.3), the local node MUST NOT transmit plaintext strings during the Challenge.
 1. **Local Pre-Check:** The node evaluates locally; if denied, the request fails.
 2. **Challenge Link:** The node establishes an RNS.Link to the Authoritative Anchor (App Name: dacar, Aspects: auth, v1). If unreachable, the operation defaults to **DENY**.
 3. **Challenge Payload:** The local node calculates hypothesized hashes across its Primary Salt and all configured Legacy Salts (§10) and transmits them over the Link as a MessagePack array:
   [ <nonce_32_bytes>, [ <entry>, ... ] ]
   Each entry is a self-contained, fully-hashed hypothesis for exactly one salt — a 5-element array:
   `[ <salt_id_tag(16)>, <grantee_hash(16)>, <allow_relation_hash(16)>, <deny_relation_hash(16)>, <[object_segment_hashes]> ]`.
   * **salt_id_tag** = `Truncated_HMAC(salt, "dacar.salt.id")`; the Authority uses it to bind each entry to its matching configured salt (required to derive the `admin` relation hash for delegation recursion, §7.2) without ever exchanging the salt itself.
   * **grantee_hash** = the 16-byte identity hash of the request Grantee U.
   * **allow_relation_hash** = `Truncated_HMAC(salt, r)`.
   * **deny_relation_hash** = `Truncated_HMAC(salt, "-" + r)`. Both relation hashes are carried because the Authority must apply the deny-beats-allow rule (§7.3) and cannot derive the deny hash from the allow hash without plaintext, which §8.4 forbids.
   * **object_segment_hashes** = the per-segment `Truncated_HMAC` hashes of the request Object O, exact (the §3.3 wildcard flag is unset for a concrete request); the array length conveys the segment count.
 4. **Authoritative Evaluation:** The Authority evaluates this hashed request directly against its own absolute-latest CRDT state, never falling back to plaintext.
 5. **The Verdict Receipt:** The Authority responds with a MessagePack array:
   [ <1-byte verdict_status>, <8-byte server_hlc>, <32-byte nonce>, <64-byte ed25519_sig> ].
   * verdict_status: 0x01 for ALLOW, 0x00 for DENY.
   * The ed25519_sig MUST be computed over the unpadded binary concatenation of the preceding three fields (verdict_status + server_hlc + nonce).
 6. **Enforcement:** An invalid signature, mismatched nonce, or DENY verdict fails the operation. An ALLOW verdict proceeds.
## 9. Garbage Collection & Storage Bounds
To guarantee bounded state growth, Dacar utilizes **Time-Horizon Tombstone Pruning**. However, Garbage Collection must never alter the resolved access state or destroy active re-grants.
 * **The Deletion Horizon:** Nodes enforce a hard horizon of H days (default: 180 days).
 * **Pairwise Pruning Condition:** Periodically, the node scans its state vector and identifies Tombstones (Remove Operations) that satisfy **ALL** of the following criteria:
   1. The tuple currently resolves to inactive (t_R(h) > t_A(h)).
   2. Both the Add timestamp and Remove timestamp are older than the deletion horizon (t_A(h) < Current Time - H and t_R(h) < Current Time - H).
 * **Pairwise Deletion:** For each qualifying tuple, the node MUST silently delete **BOTH** the Tombstone from the Remove Set AND its corresponding Operation from the Add Set.
   * *Constraint Note:* Time-Horizon Pruning bounds the history of revocations and historical denials. However, it does **not** cap the total count of currently-active, never-revoked grants. Deployments with many permanent grants and zero revocations maintain those active grants indefinitely.
 * **Intake Rejection:** Any incoming Delta (Add or Remove) older than Current Time - H MUST be immediately discarded to prevent highly delayed operations from bypassing pruned revocations.
   > **Note on Delay Tolerance:** Deployments relying heavily on high-latency optical/sneakernet transports (§11.3) SHOULD configure a significantly larger H (e.g., 365 days) to ensure valid, physically-delayed operations do not fall victim to Intake Rejection upon arrival.
   >
## 10. Privacy Salt Rotation & Grace Periods
To rotate a compromised Privacy Salt without global disruption:
### 10.1 Multi-Salt Configuration
Nodes support a Primary Salt (for new operations) and an ordered list of Legacy Salts.
### 10.2 Multi-Salt Evaluation Bounds
During the Hypothesis Generation phase (§7.1), the Evaluation Engine generates duplicate hypotheses for the Primary Salt and each configured Legacy Salt.
 * **Legacy Cap:** To prevent unbounded compute requirements, nodes MUST NOT configure more than 2 Legacy Salts concurrently.
 * **Shared Work Bound:** The total evaluation cap (maximum 50 visited nodes, §7.2) applies **per-request**, not per-salt. The engine MUST track visited nodes across all salt hypothesis tracks simultaneously. If the total shared cap is reached, the request fails.
### 10.3 Revocations and Sunsetting
 * **Overrides:** To revoke a legacy Tuple, an admin either copies the exact legacy byte hashes to issue a Remove (0x00), or issues an Explicit Deny (-relation) using the Primary Salt, which globally overrides the allowance.
 * **Sunsetting:** After H days, old Tuples naturally prune out, allowing the community to safely delete the Legacy Salt from configurations.
## 11. Synchronization & Transport Plane
Dacar delegates transport responsibilities to established Reticulum protocols.
### 11.1 Eventual Consistency via RFed (Many-to-Many)
Global convergence of the CRDT State Vector is handled via **RFed**. The default topic is `dacar.policy.v1`, but it is **configurable per deployment**: because RFed is a broadcast (many-to-many) medium, nodes that must isolate their policy feed from other Dacar deployments sharing an RNS network SHOULD set a deployment-specific topic. (By contrast, §11.2 LXMF delivery and the §8 Challenge destination are addressed point-to-point to a specific Identity, so they derive isolation from RNS addressing rather than from a configurable name.) Nodes rely on RFed's native store-and-forward to asynchronously retrieve new Operations and merge them into the local LWW-Element-Set, each one authenticated via verify-on-ingest (§11.2) before it may mutate the CRDT.

#### 11.1.1 Inner Format — Compact Dacar Envelope
A Dacar Delta is **not** wrapped in an LXMF message inside the RFed `inner_blob`. A §5.3 Delta is already self-describing — self-addressed (Issuer Hash, field [0]), self-timed (HLC, field [3]), and self-signed (Ed25519, field [7]) — so an LXMF envelope would only duplicate the destination hash (RFed's `channel_hash` already routes it), the source hash (field [0]), the signature (field [7]), and the timestamp (field [3]), while adding ~111 bytes that push a typical 170-byte Delta past the 500-byte RNS path MTU (the `rfed.channel.publish` destination is fire-and-forget and does not accept links, so it cannot rely on RNS Resource fragmentation).

Instead, the channel `inner_blob` for a Dacar Delta reuses the RFed RTID source-identity prelude but carries the raw Delta in place of the LXMF tail:

```
plaintext    = "RTID"(4) ‖ sender_identity_pub(64) ‖ delta
inner_blob   = EC_encrypt(channel_identity.X25519_pub, plaintext)
rfed_payload = channel_hash(16) ‖ inner_blob ‖ stamp(32)?
```

* `sender_identity_pub` is the publishing node's 64-byte RNS Identity public-key bundle (32-byte X25519 ‖ 32-byte Ed25519); it identifies the transport sender only.
* `delta` is the raw §5.3 transport payload (already signed by the Issuer).
* `stamp` is the standard RFed channel proof-of-work stamp, appended when the node advertises a non-zero `stamp_cost` (omitted otherwise).

RFed treats `inner_blob` **opaquely** — it never decrypts, parses, or modifies it, only validates the stamp, stores it, and fans `channel_hash ‖ inner_blob` out to subscribers — so this is a private agreement between Dacar publishers and subscribers, invisible to the Rust or JavaScript RFed nodes and to other RFed channel applications (which are keyed by `channel_hash` and may still use full LXMF `inner_blob`s of their own).

On receipt, the subscriber EC-decrypts `inner_blob` with the derived channel identity, verifies the `"RTID"` magic, recovers `sender_identity_pub`, and feeds the remaining `delta` bytes through the **same** verify-on-ingest seam as every other transport (§11.2): the Delta's own Ed25519 signature is the sole authenticity check, so a forged or stale Delta is dropped before it can mutate the CRDT, exactly as for LXMF or optical delivery. No envelope signature is added — and none is needed, since reaching the EC-decrypt step already required the channel private key (i.e. an authorised subscriber).

This compact format keeps a typical 170-byte Delta within the 500-byte RNS MTU (multi-hop, with stamp): ~499 bytes on the wire (467 without a stamp).

**One Delta per message.** A node MUST publish each §5.3 Operation as its own `rfed_payload` (one envelope per Delta), never a batch of Deltas in a single `inner_blob`. The `rfed.channel.publish` destination is fire-and-forget (it does not accept link requests, so it cannot rely on RNS Resource fragmentation), so a single message cannot exceed the ~500-byte path MTU — and a multi-Delta msgpack array would not fit anyway. Receivers correspondingly apply Deltas one at a time through verify-on-ingest (`apply_payload`, single); there is no multi-Delta batch decode on the RFed path. A node that has accumulated several Deltas (e.g. an outbox being flushed) simply performs one publish per Delta in order.

> **Note — LXMF framing retained.** Only the RFed broadcast channel uses the compact envelope. §11.2 targeted delivery and §11.3 Paper Messages still embed Deltas in full LXMF messages (title `dacar/sync/delta`); that path is unaffected.
### 11.2 Targeted Asynchronous Delivery (LXMF Store-and-Forward)
For forward-secret, point-to-point delivery to offline nodes (bypassing the public RFed broadcast):
 1. **LXMF & Ratchets:** The target node configures an LXMF destination and calls enable_ratchets() (or enforce_ratchets()).
 2. **The Wrapper:** The Delta Push payload is embedded in an LXMF message with the exact title dacar/sync/delta.
 3. **Wake-Up Integration:** LXMF Propagation Nodes queue the message. When the edge node wakes, it pulls pending messages, decrypts via ratchets, and applies the Delta to the CRDT.
 4. **Cryptographic Boundaries:** Reticulum's destination ratchets provide *transport confidentiality and forward secrecy* only. The receiving node MUST verify each Operation's Ed25519 signature(s) against the claimed Issuer's public key(s) — obtained by recalling the `RNS.Identity` behind the Issuer Hash (a standard RNS identity hash, §4.1) from the network's announce store, or from an explicitly registered keyset for Threshold Groups — **before** the Operation is allowed to mutate the CRDT (§5.2; verify-on-ingest). An Operation whose Issuer is unknown to the node, or whose signature fails this check, is dropped. The signature remains the sole source of authorization authenticity, ensuring a Delta is equally valid whether received via RFed, LXMF, or Optical Sneakernet. (Whether the verified Issuer is itself *authorized* — i.e. its authority traces to a Root Trust Anchor — is resolved separately by the Evaluation Engine, §7, against the converged state.)
### 11.3 Air-Gapped & Optical Transport (Paper Messages)
Because targeted Deltas are LXMF messages, they natively support LXMF’s **Paper Message** format. Administrators can export Deltas to high-density QR codes for physical sneakernet transport to air-gapped or radio-silent infrastructure. The receiving node scans the optical data and authenticates the payload exactly as if received via RF.
## 12. Security Considerations
 * **Permanent Deny Veto:** An Explicit Deny unconditionally overrides Allows until that specific Deny Tuple is revoked.
 * **Timestamp Manipulation:** Operations projecting >24 hours into the future MUST be rejected to prevent LWW bias.
 * **Partition Penalties:** A demoted administrator's stale grants remain valid on any node that has not yet synced the demotion operation, emphasizing the need for Strict Consistency Challenges on destructive actions.

## 13. Local Node Store

How a node persists its configuration, signing identity, HLC, CRDT state, aliases, plaintext ledger, issuer-identity cache, and outbox is an **implementation choice** — a node MAY use a relational database, a key-value store, cloud storage, or no persistence at all. This section defines a **recommended file-based layout** that implementations are **encouraged** to adopt when they persist to the local filesystem, so that independently-developed CLIs (e.g. the Python and JavaScript reference implementations) can read and write the **same** store directory interchangeably.

The byte formats below are **normative for implementations that choose this file layout**: to claim compatibility with the reference store, an implementation MUST produce byte-identical files for every record except the identity private key (§13.9). The canonical Python `Store` is the reference implementation; other implementations SHOULD match its on-disk bytes. Implementations using a different persistence backend (database, cloud, etc.) need not follow this layout, but SHOULD preserve the same logical records and field semantics where applicable.

### 13.1 File Layout

The store directory (conventionally `~/.dacar/`, mode `0700`) contains loose files at its root — one per record, with the exact filenames below. Implementations choosing this layout SHOULD NOT use subdirectories or a key-value `.bin` layout for these records.

| File | Mode | Record |
|---|---|---|
| `config` | `0600` | Node configuration (INI text, §13.2) |
| `clock.msgpack` | `0644` | Persisted HLC (§5.1, §13.3) |
| `state.msgpack` | `0600` | CRDT snapshot (§6, §13.4) |
| `aliases` | `0644` | Human-readable name map (§13.5) |
| `ledger.msgpack` | `0600` | Plaintext grant ledger (§13.6) |
| `identities.msgpack` | `0600` | Issuer public-key cache (§11.2.4, §13.7) |
| `outbox.msgpack` | `0600` | Locally-issued, unpublished Deltas (§11, §13.8) |
| `identity` | `0600` | Node signing identity private key (§13.9) |

Secret records (the salt, CRDT state, plaintext labels, and node-local signed payloads) are `0600`; the HLC and aliases are `0644` (they carry no secret material). Modes SHOULD be set explicitly (independent of umask).

`identities.msgpack` and `outbox.msgpack` are **lazy**: a fresh `init` SHOULD NOT create them. They appear only when first written (first issuer remembered / first unpublished Delta queued).

### 13.2 `config` — INI

The node configuration is an INI text file (as written by Python's `configparser` and RNS's own config files). Option keys are lowercase. Sections appear in fixed order, each followed by a blank line:

```ini
[salt]
primary = <64 hex chars (32-byte Privacy Salt)>
legacy0 = <64 hex chars>   # optional, up to 2 (§10.1)
legacy1 = <64 hex chars>   # optional

[trust]
anchors = <16-byte hex>, <16-byte hex>, ...   # Root Trust Anchors (§4.1)
authoritative = <16-byte hex>                  # optional

[policy]
deletion_horizon_days = <int>                 # §9, default 180

[rfed]
topic = <string>            # §11.1, default dacar.policy.v1
node = <16-byte hex>         # optional: the rfed peer to publish to
```

The `anchors` value is a comma-separated list of 16-byte RNS identity hashes (hex). `authoritative` is a single identity hash (optional). Hex values are lowercase, no `0x` prefix.

### 13.3 `clock.msgpack` — HLC

A MessagePack map with two integer keys (snake_case):

```json
{ "last_ms": <uint48>, "logical": <uint16> }
```

### 13.4 `state.msgpack` — CRDT Snapshot

The serialized CRDT state vector (§6): a MessagePack array of rows, one per Tuple, in insertion order. Each row is a 7-element array:

```json
[ relation_hash(16), [object_hash(16), ...], wildcard_bool, grantee(16), issuer(16), add_ts|null, remove_ts|null ]
```

The Tuple Hash (§6.1) is recoverable from the first five fields and is not stored. `add_ts`/`remove_ts` are HLC integers (§5.1) or `nil`. This payload is **trusted-local-only** — it carries no signature material and MUST NOT be accepted from the network; network convergence uses signed §5.3 Operations via verify-on-ingest (§11.2.4).

### 13.5 `aliases` — rnns Text

A UTF-8 text file naming known identities, one entry per line:

```
<16-byte hex hash> <name> [<name2> ...] [  # note]
```

Multiple names for one hash are space-separated on the same line. An optional `# note` (preceded by two spaces) may follow. The file ends with a trailing newline; an empty registry serializes to zero bytes. The reserved name `self` always points to the node's own signing identity. Lines whose first token is not a 32-hex-char hash are ignored.

### 13.6 `ledger.msgpack` — Plaintext Ledger

A MessagePack map keyed by the **hex-encoded Tuple Hash** (§6.1 — `sha256(preimage).hex()`) to a row recording the plaintext annotation for grants issued locally:

```json
{ "<tuple_hash_hex>": { "object": "<string>|null", "relation": "<string>|null", "wildcard": <bool>|null, "first_seen": <uint> } }
```

Keys are snake_case (`first_seen`). Network-received Deltas have no plaintext and are absent from this ledger. `first_seen` is the physical HLC timestamp (high 48 bits) of the issuing operation.

### 13.7 `identities.msgpack` — Issuer Public-Key Cache

A MessagePack map from a 16-byte Issuer hash (hex key) to its **32-byte Ed25519 public key** (the signing half of the 64-byte RNS public key):

```json
{ "<16-byte hex>": <32 raw bytes> }
```

Only single-identity entries (threshold 1) are stored; Threshold Group keysets (§4.1) are not persisted here (resolved via explicit registration). Entries with a value length other than 32 bytes MUST be dropped on load (defensive: a poisoned entry causes a signature mismatch, not a trust breach).

### 13.8 `outbox.msgpack` — Unpublished Deltas

A MessagePack array of raw §5.3 transport payloads — signed Operations issued locally but not yet published via RFed (§11.1) or LXMF (§11.2), in issuance order:

```json
[ <payload bytes>, ... ]
```

`publish --all` flushes and clears the outbox. A corrupted or non-array record MUST be treated as empty (the CLI must not crash).

### 13.9 `identity` — Node Signing Identity

The node's own RNS signing identity private key, persisted library-natively. Because different Reticulum implementations own different private-key serialization formats (Python RNS writes 64 bytes — 32-byte X25519 private + 32-byte Ed25519 private; other runtimes may write 128 bytes including the public halves), this **one file is the sole intentional divergence** between implementations adopting this layout.

A store directory therefore carries the signing identity of whichever implementation initialized it. All other records (§13.2–§13.8) are byte-identical across implementations, so a store created by one CLI is fully readable — and writable — by any other. An implementation that did not initialize the store cannot sign with the foreign identity file; it SHOULD re-`init` or load a format-native identity to issue Operations.

### 13.10 Cross-Implementation Interoperability

Implementations adopting this file layout SHOULD produce a store in which every record except `identity` is byte-identical to the canonical format above, so that two independently-developed `dacar` CLIs sharing one store directory (e.g. over a mounted volume or sneakernet) interoperate without conversion:

 * `init` produces the same file set (config, clock.msgpack, state.msgpack, ledger.msgpack, aliases — the lazy records are absent).
 * `grants` / `check` read the CRDT, ledger, and aliases written by either implementation.
 * `grant` / `revoke` append to the ledger using the §6.1 Tuple Hash as the key, and queue to the outbox, in a format readable by either.
 * `identity remember` writes the 32-byte Ed25519 public key to `identities.msgpack`.

The canonical Python `Store` is the reference implementation; other implementations SHOULD match its on-disk bytes.
