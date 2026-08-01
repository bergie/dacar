/**
 * The evaluation engine (§7).
 *
 * Resolves a plaintext request `(Object, Relation, Grantee)` against the local
 * CRDT state and the recursive delegation graph, terminating at a Root Trust
 * Anchor.
 *
 * Resolution (§7.3): DENY if any valid active Deny Tuple exists; else ALLOW if
 * any valid active Allow Tuple exists; else DENY. "Valid" means the granting
 * Issuer's authority traces back to a Root Trust Anchor (directly, or recursively
 * via the reserved `admin` relation).
 *
 * Namespace Label Privacy (§3.3) means the engine never compares plaintext
 * labels: it hashes the request with every configured salt (§10.2) and matches
 * the byte arrays against hashed Tuples. The total-work bound (§7.2) is enforced
 * *per request across all salt tracks simultaneously* (§10.2).
 *
 * Hashing (Web Crypto) is asynchronous, so `evaluate()` is async. To keep the
 * recursive core fast and synchronous, every per-salt hash needed during
 * evaluation — including the `admin`/`-admin` relation hashes used by authority
 * recursion — is precomputed up front into a hypothesis object. The challenge
 * server (§8) builds the same hypothesis objects straight from the wire and
 * calls the synchronous `evaluateHashes()`.
 */

import { toHex } from "@reticulum/core";
import { covers } from "./namespace.js";

/** Maximum delegation hops in a single evaluation path (§7.2). */
export const DEFAULT_MAX_DEPTH = 10;
/** Maximum evaluation steps (visited nodes) per request (§7.2). */
export const DEFAULT_MAX_VISITED = 50;
/** The reserved relation that confers the authority to delegate (§3.2). */
export const ADMIN_RELATION = "admin";

/**
 * @typedef {Object} Hypothesis
 * @property {import("./namespace.js").NamespaceHasher} hasher
 * @property {Uint8Array[]} objectHashes Exact request object hashes for this salt.
 * @property {Uint8Array} allowRelationHash HMAC of the requested relation.
 * @property {Uint8Array} denyRelationHash HMAC of "-"+requested relation.
 * @property {Uint8Array} adminAllowHash HMAC of "admin".
 * @property {Uint8Array} adminDenyHash HMAC of "-admin".
 */

/**
 * @typedef {Object} EngineOptions
 * @property {number} [maxDepth]
 * @property {number} [maxVisited]
 */

export class Engine {
  /**
   * @param {import("./config.js").Config} config
   * @param {import("./crdt.js").StateVector} state
   * @param {EngineOptions} [options]
   */
  constructor(config, state, options = {}) {
    this.config = config;
    this.state = state;
    this.maxDepth = options.maxDepth ?? DEFAULT_MAX_DEPTH;
    this.maxVisited = options.maxVisited ?? DEFAULT_MAX_VISITED;
  }

  /**
   * Hash the plaintext request with every configured salt (§7.1, §10.2) and
   * resolve it. Returns true iff (object, relation, grantee) is ALLOWED.
   * @param {string} objectId
   * @param {string} relation
   * @param {Uint8Array} grantee
   * @returns {Promise<boolean>}
   */
  async evaluate(objectId, relation, grantee) {
    const denyRelation = "-" + relation;
    const hypotheses = await Promise.all(
      this.config.hashers.map(async (hasher) => {
        const [objectHashes, allowRelationHash, denyRelationHash, adminAllowHash, adminDenyHash] =
          await Promise.all([
            hasher.hashObject(objectId),
            hasher.hashRelation(relation),
            hasher.hashRelation(denyRelation),
            hasher.hashRelation(ADMIN_RELATION),
            hasher.hashRelation("-" + ADMIN_RELATION),
          ]);
        return {
          hasher,
          objectHashes: objectHashes.hashes,
          allowRelationHash,
          denyRelationHash,
          adminAllowHash,
          adminDenyHash,
        };
      }),
    );
    return this.evaluateHashes(grantee, hypotheses);
  }

  /**
   * Evaluate pre-hashed per-salt hypotheses (§7.3, §10.2). Synchronous: all
   * required hashes are already present in each hypothesis. The total-work bound
   * is shared across all hypotheses. Used by the §8 challenge server.
   * @param {Uint8Array} grantee
   * @param {Hypothesis[]} hypotheses
   * @returns {boolean}
   */
  evaluateHashes(grantee, hypotheses) {
    // Index active tuples by grantee hex for this request.
    /** @type {Map<string, import("./tuple.js").Tuple[]>} */
    const index = new Map();
    const granteeHex = toHex(grantee);
    for (const t of this.state.activeTuples()) {
      const g = toHex(t.grantee);
      const arr = index.get(g);
      if (arr) arr.push(t);
      else index.set(g, [t]);
    }
    /** @type {Map<string, boolean>} memo of positive authority results */
    const memo = new Map();
    let counter = 0;
    const { config, maxDepth, maxVisited } = this;
    const hyps = [...hypotheses];

    /** @param {Hypothesis[]} hs @returns {string} */
    const objectKey = (hs) => hs.map((h) => toHex(h.hasher.salt) + "|" + h.objectHashes.map(toHex).join(".")).join(";");

    /**
     * @param {Uint8Array} issuer
     * @param {Hypothesis[]} hs
     * @param {number} depth
     * @param {Set<string>} visited
     * @returns {boolean}
     */
    function authority(issuer, hs, depth, visited) {
      if (config.isRootAnchor(issuer)) return true; // §7.2 terminal trust anchor
      const key = toHex(issuer) + "|" + objectKey(hs);
      if (memo.has(key)) return /** @type {boolean} */ (memo.get(key));
      if (depth >= maxDepth) return false; // §7.2 recursion depth bound
      const issuerHex = toHex(issuer);
      if (visited.has(issuerHex)) return false; // §7.2 cycle detection
      const nextVisited = new Set(visited);
      nextVisited.add(issuerHex);
      // Build admin hypotheses reusing the same object hashes.
      const adminHyps = hs.map((h) => ({
        hasher: h.hasher,
        objectHashes: h.objectHashes,
        allowRelationHash: h.adminAllowHash,
        denyRelationHash: h.adminDenyHash,
        adminAllowHash: h.adminAllowHash,
        adminDenyHash: h.adminDenyHash,
      }));
      const result = _resolve(adminHyps, issuer, depth + 1, nextVisited) === "allow";
      if (result) memo.set(key, true);
      return result;
    }

    /**
     * @param {Hypothesis[]} hs
     * @param {Uint8Array} granteeId
     * @param {number} depth
     * @param {Set<string>} visited
     * @returns {"deny" | "allow" | "none"}
     */
    function _resolve(hs, granteeId, depth, visited) {
      counter += 1;
      if (counter > maxVisited) return "none"; // §7.2 / §10.2 shared total-work bound
      const gid = toHex(granteeId);
      const candidates = index.get(gid) ?? [];
      let denyValid = false;
      let allowValid = false;
      for (const candidate of candidates) {
        for (const h of hs) {
          if (bytesEqualHash(candidate.relationHash, h.denyRelationHash)) {
            if (covers(candidate.objectHashes, candidate.wildcard, h.objectHashes)) {
              if (authority(candidate.issuer, hs, depth, visited)) denyValid = true;
            }
          } else if (bytesEqualHash(candidate.relationHash, h.allowRelationHash)) {
            if (covers(candidate.objectHashes, candidate.wildcard, h.objectHashes)) {
              if (authority(candidate.issuer, hs, depth, visited)) allowValid = true;
            }
          }
        }
      }
      if (denyValid) return "deny";
      if (allowValid) return "allow";
      return "none";
    }

    return _resolve(hyps, grantee, 0, new Set()) === "allow";
  }
}

/** Fast hex-free 16-byte equality for relation hashes. @param {Uint8Array} a @param {Uint8Array} b @returns {boolean} */
function bytesEqualHash(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}
