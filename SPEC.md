# Specification: Dacar (Decentralized Access Control for Reticulum)
**Version:** 1.0-RC7
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
Every Dacar-enabled service node MUST be configured out-of-band with one or more **Root Trust Anchors**.
 1. **Single Identity:** A standard 16-byte RNS.Identity hash.
 2. **Threshold Group (N-of-M):** A composite authority requiring consensus, defined by a set of M specific RNS.Identity hashes and an integer N. The **Group ID** is the SHA-256 hash of the following packed binary pre-image, **strictly truncated to the first 16 bytes**: the M member hashes (16 bytes each) sorted ascending by raw byte value (equivalent to hex-alphabetical order), followed by the threshold N encoded as an 8-byte big-endian unsigned integer. The Group ID is itself a 16-byte value usable wherever an Issuer hash is expected.
   > **Note on Scope:** In v1.0, Threshold Groups MAY ONLY act as Issuers. A Grantee MUST be a single Identity. Granting permissions to a Threshold Group is not currently supported.
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
Global convergence of the CRDT State Vector is handled via **RFed** (default topic: dacar.policy.v1). Nodes rely on RFed's native store-and-forward to asynchronously retrieve new Operations and merge them into the local LWW-Element-Set.
### 11.2 Targeted Asynchronous Delivery (LXMF Store-and-Forward)
For forward-secret, point-to-point delivery to offline nodes (bypassing the public RFed broadcast):
 1. **LXMF & Ratchets:** The target node configures an LXMF destination and calls enable_ratchets() (or enforce_ratchets()).
 2. **The Wrapper:** The Delta Push payload is embedded in an LXMF message with the exact title dacar/sync/delta.
 3. **Wake-Up Integration:** LXMF Propagation Nodes queue the message. When the edge node wakes, it pulls pending messages, decrypts via ratchets, and applies the Delta to the CRDT.
 4. **Cryptographic Boundaries:** Reticulum's destination ratchets provide *transport confidentiality and forward secrecy* only. The Evaluation Engine MUST extract the payload and verify the internal Ed25519 signatures (§5.2). The signature remains the sole source of authorization authenticity, ensuring a Delta is equally valid whether received via RFed, LXMF, or Optical Sneakernet.
### 11.3 Air-Gapped & Optical Transport (Paper Messages)
Because targeted Deltas are LXMF messages, they natively support LXMF’s **Paper Message** format. Administrators can export Deltas to high-density QR codes for physical sneakernet transport to air-gapped or radio-silent infrastructure. The receiving node scans the optical data and authenticates the payload exactly as if received via RF.
## 12. Security Considerations
 * **Permanent Deny Veto:** An Explicit Deny unconditionally overrides Allows until that specific Deny Tuple is revoked.
 * **Timestamp Manipulation:** Operations projecting >24 hours into the future MUST be rejected to prevent LWW bias.
 * **Partition Penalties:** A demoted administrator's stale grants remain valid on any node that has not yet synced the demotion operation, emphasizing the need for Strict Consistency Challenges on destructive actions.
