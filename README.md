# Specification: Dacar (Decentralized Access Control for Reticulum)
**Version:** 1.0-RC3
**License:** EUPL-1.2
**Dependencies:** Reticulum Network Stack (RNS), LWW-Element-Set CRDT, MessagePack
## 1. Introduction
In traditional Reticulum applications, access control is implemented using static lists of allowed identities provided via configuration files. While functional for isolated deployments, this approach fails to scale across distributed mesh networks. It forces administrators to manually synchronize 16-byte RNS.Identity hashes across every node, lacks support for granular permissions, and offers no secure mechanism for dynamic revocation when devices are offline.
Dacar defines a decentralized, offline-first authorization policy plane that solves this scaling problem. It is a tuple-based authorization system inspired by Google Zanzibar, designed natively for delay-tolerant, low-bandwidth networks.
By decoupling authorization state from transport using Conflict-free Replicated Data Types (CRDTs), Dacar allows nodes to evaluate permissions locally without real-time connectivity to a central server.
### 1.1 Design Goals
 * **Decentralized & Offline-Capable:** Nodes enforce permissions locally while isolated from the wider mesh.
 * **Zero-Overhead Client:** Routine application traffic requires no token injection or authorization overhead.
 * **Eventually Consistent:** Authorization state automatically converges mathematically.
 * **Delegated Trust:** Supports recursive permission delegation chaining back to a Root Trust Anchor.
 * **Transport Agnostic:** Deltas can be routed via LXMF, RFed, or physical optical transfers (QR codes).
## 2. Terminology
 * **Operation (Delta):** A cryptographically signed instruction to Add (Grant) or Remove (Revoke) a specific permission.
 * **Tuple:** The fundamental unit of permission, defining a relationship between an Object, Relation, Grantee, and Issuer.
 * **State Vector:** The full serialized LWW-Element-Set CRDT containing all active and revoked Tuples.
 * **Root Trust Anchor:** The hardcoded RNS.Identity hash(es) designated as the ultimate authority for a given service node.
 * **Authoritative Identity:** The configured RNS.Identity designated to provide synchronous Freshness Receipts for Strict Consistency operations.
 * **Evaluation Engine:** The local runtime process that resolves a request against the State Vector and the delegation graph.
## 3. Core Concepts
### 3.1 The Authorization Tuple
Permissions in Dacar are defined by Tuples. A Tuple asserts that a specific Grantee holds a specific Relation over a specific Object, as authorized by a specific Issuer.
The logical tuple is: (Object, Relation, Grantee, Issuer).
 * Object: The resource identifier (String). e.g., sensor:wind.
 * Relation: The granted permission (String). e.g., calibrate.
 * Grantee: The 16-byte RNS.Identity hash receiving the permission.
 * Issuer: The 16-byte RNS.Identity hash of the administrator who signed the Operation.
> **Per-Issuer Tuple Identity:** Because the Issuer is incorporated into the tuple identity, two different administrators granting the identical permission to the same grantee produce two mathematically distinct Tuples. Revoking one issuer's Operation only revokes that specific Tuple; the parallel Tuple remains active.
> 
### 3.2 Reserved Relations & Cascade Scope
To enable recursive trust graphs, Dacar reserves the relation string **admin**.
Granting a user the admin relation on an Object confers the authority to issue valid Grants and Revocations for that exact Object.
**Cascade Scope:** Authority does *not* inherently cascade to child namespaces by default. For example, admin on sensor:wind only allows delegating permissions for sensor:wind. To delegate permissions for sensor:wind:north, the issuer must hold admin on an Object ending in a wildcard (e.g., sensor:wind:*, sensor:*, or *).
### 3.3 Namespace Grammar & Matching Algorithm
Dacar employs segment-aware namespace matching, not raw string prefixes.
 * **Hierarchy Delimiter:** Namespaces within an Object string are delineated by the colon character (:).
 * **Suffix Wildcards (*):** The wildcard acts as a match for all subsequent segments. It MUST be the terminal segment of the string.
 * **Matching Algorithm:** To evaluate if a requested object matches a tuple object:
   1. Split both strings by :.
   2. Compare segments sequentially.
   3. If the tuple object segment is *, the match is immediately successful.
   4. If any segments differ before a * is reached, the match fails.
 * **Explicit Deny:** To revoke a specific action granted by a wildcard, the Relation is prefixed with a hyphen (e.g., -calibrate).
## 4. Bootstrapping & Trust Anchors
An empty CRDT State Vector provides no access to anyone. The system must be bootstrapped with predefined trust anchors.
### 4.1 Configuration
Every Dacar-enabled service node MUST be configured out-of-band with one or more **Root Trust Anchor** RNS.Identity hashes.
If the node supports Strict Consistency operations (Section 8), it MUST also be configured with exactly one **Authoritative Identity** hash. The Authoritative Identity MAY be identical to one of the Root Trust Anchors, or it MAY be a separate, dedicated identity. *(Future specifications may support N-of-M threshold Authoritative Identities to mitigate single-point-of-failure availability risks).*
### 4.2 Genesis Operations
The Root Trust Anchor acts as the terminal point for all delegation recursion. For each configured Root Trust Anchor X, the node assumes an implicit Genesis Tuple: (*, admin, X, X).
This ensures that every Root Trust Anchor independently possesses terminal delegation authority across all namespaces.
## 5. Cryptography & Data Serialization
### 5.1 Hybrid Logical Clocks (HLC)
Dacar relies on HLCs packed into a single 64-bit unsigned integer (Big-Endian):
 * **High 48 bits:** Physical Time (Unix epoch in milliseconds).
 * **Low 16 bits:** Logical Counter.
### 5.2 The Signature Pre-image
Every Operation MUST be signed. The Ed25519 signature is calculated over an unpadded binary Pre-image. Object Length is intentionally omitted as it is the terminal field, making parsing mathematically unambiguous without the extra byte overhead.
| Offset | Length | Field | Encoding |
|---|---|---|---|
| 0 | 16 bytes | **Issuer Hash** | Raw bytes of the granting admin's RNS.Identity hash |
| 16 | 16 bytes | **Grantee Hash** | Raw bytes of the grantee's RNS.Identity hash |
| 32 | 1 byte | **Action** | 0x01 for Grant (Add), 0x00 for Revoke (Remove) |
| 33 | 8 bytes | **Timestamp** | 64-bit unsigned integer (HLC), Big-Endian |
| 41 | 1 byte | **Relation Length** | Unsigned 8-bit integer |
| 42 | Variable | **Relation String** | UTF-8 |
| 42 + len | Variable | **Object String** | UTF-8 |
### 5.3 The Transport Payload
The Operation is serialized for transport as a 7-element MessagePack Array:
[ <16-byte issuer_hash>, <16-byte grantee_hash>, <action_int>, <hlc_int>, <relation_str>, <object_str>, <64-byte_ed25519_sig> ]
## 6. The Authorization State (CRDT)
The global state is an LWW-Element-Set mapping a Tuple Hash to an HLC timestamp.
### 6.1 Tuple Hashing
To guarantee cross-language convergence, the Tuple Hash is derived using **SHA-256**. The hash is calculated over a packed binary byte array consisting of:
[16-byte Issuer Hash] + [16-byte Grantee Hash] + [1-byte Relation Length] + [Variable Relation String] + [Variable Object String].
### 6.2 Node Synchronization & Convergence
When nodes sync Full State Vectors, the incoming state (S_{\text{remote}}) is mathematically merged with the local state (S_{\text{local}}) by taking the maximum timestamp for every known Tuple Hash (h) present in either vector.
**Single-Delta Update Rule:**
When a node receives a single Operation (Delta), the update is applied directly to either the Add Set (A) or Remove Set (R) depending on the Action byte. The node takes the maximum of the incoming HLC timestamp and any existing HLC timestamp for that specific Tuple Hash.
> **Tie-Breaking:** If t_A(h) = t_R(h) precisely, the Tuple is considered revoked (Remove wins).
> 
## 7. Evaluation Engine
When evaluating a request for Object O, Relation r, and Grantee U:
### 7.1 Hypothesis Generation
 1. Generate exact and wildcard permutations for the negative relation (O, -r, U). Let this be \mathbb{H}_{\text{deny}}.
 2. Generate exact and wildcard permutations for (O, r, U). Let this be \mathbb{H}_{\text{allow}}.
### 7.2 Recursive Delegation & Termination
If an active Tuple is found, the engine MUST verify the Issuer's authority recursively. Before checking cycle detection or generating further hypotheses, the engine MUST check whether the current Issuer matches any configured **Root Trust Anchor** (§4.1). If so, the delegation chain terminates successfully without further recursion.
If the Issuer is not a Root Trust Anchor, the engine evaluates if the Issuer holds the admin relation on O by generating a new request (O, admin, Issuer) and processing it through the Hypothesis Generation and Evaluation pipeline.
 * **Cycle Detection:** The engine MUST maintain a visited_issuers set during evaluation. If an Issuer is encountered twice in the same evaluation path prior to hitting a Root Trust Anchor, the path is immediately terminated as invalid.
 * **Total Work Bound:** Implementations MUST strictly enforce a maximum recursion depth of 10 hops AND a total evaluation cap (e.g., maximum 50 visited nodes per request). If the cap is reached without tracing back to a Root Trust Anchor, the request fails.
 * **Memoization:** Implementations SHOULD memoize Issuer validation results for the duration of a request.
### 7.3 Resolution Logic
 1. If ANY valid, active Tuple exists in \mathbb{H}_{\text{deny}}, the request is **DENIED**.
 2. Else, if ANY valid, active Tuple exists in \mathbb{H}_{\text{allow}}, the request is **ALLOWED**.
 3. Else, the request is **DENIED**.
## 8. Strict Consistency Challenge (Escape Hatch)
For destructive operations (e.g., DROP_TABLES), eventual consistency is dangerous.
 1. **Local Pre-Check:** The node verifies the permission locally. If denied, the request fails immediately.
 2. **Challenge:** The node opens an RNS.Link to the Authoritative Identity to request a Freshness Receipt. To guarantee full-chain integrity and prevent stale upstream delegations, the Challenge payload MUST transmit the complete evaluation context: the target Object O, Relation r, Grantee U, and a locally generated, cryptographically secure 32-byte nonce.
 3. **Authoritative Evaluation:** The Authoritative Identity evaluates the complete request against its own absolute-latest CRDT state using the full Evaluation Engine (§7).
 4. **Receipt Evaluation:** The Authoritative Identity responds with a MessagePack array containing its verdict: [ <1-byte verdict_status>, <8-byte server_hlc>, <32-byte nonce>, <64-byte sig> ].
   * The verdict_status byte is strictly binary: 0x01 for ALLOW, 0x00 for DENY.
   * The local node MUST verify sig against the Authoritative Identity's known public key (computed over the unpadded binary concatenation of the preceding array fields) AND verify the nonce exactly matches the Challenge. An invalid signature or mismatched nonce MUST be treated identically to a link timeout (immediately **DENIED**).
   * If the signature and nonce are valid and verdict_status == 0 (DENY), the local node MUST **DENY** the request. If any upstream tuples were found to be revoked on the server during its evaluation, the local node updates its local CRDT to match.
   * If verdict_status == 1 (ALLOW), the local node **PROCEEDS** with the destructive operation.
 5. **Partition Penalty:** If the link times out or cannot be established, the destructive request MUST be **DENIED**.
## 9. Security Considerations
 * **The Permanent Deny Veto:** An Explicit Deny unconditionally overrides Allows. If a delegated admin issues a Deny, it permanently blocks access until that specific Deny Tuple is revoked.
 * **Timestamp Manipulation:** A malicious admin could artificially inflate their HLC to bias the LWW resolution. Dacar mitigates this by rejecting operations >24 hours in the future.
 * **Security Implications During Partition:** A demoted administrator's stale grants remain valid on any node that has not yet synced the demotion operation (except when performing Strict Consistency Challenges against an online Authoritative Identity).
 * **Trust Anchor & Authoritative Identity Compromise:** If a Root Trust Anchor is compromised, the entire mesh is compromised. The Authoritative Identity represents a distinct single point of failure; its compromise allows an attacker to falsify Freshness Receipts for destructive operations. Keys must be kept in highly secure environments.
 * **CRDT Flooding & Storage Exhaustion:** An attacker could flood the mesh with meaningless grants to exhaust the RAM/disk space of edge nodes. Constrained devices must enforce total payload size limits during sync.
## 10. Future Work: CRDT Garbage Collection
Because the LWW-Element-Set is append-only, the Remove Set (R) will eventually dominate storage. Future specifications will define an Epoch Compaction algorithm using Tombstones to safely purge historically superseded Tuples and abandoned RNS.Identity hashes once all nodes in the mesh acknowledge the Epoch.
