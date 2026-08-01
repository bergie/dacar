/**
 * The evaluation engine (§7).
 *
 * Resolves a request `(Object, Relation, Grantee)` against the local CRDT state
 * and the recursive delegation graph, terminating at a Root Trust Anchor.
 *
 * Resolution (§7.3): DENY if any valid active Deny tuple exists; else ALLOW if
 * any valid active Allow tuple exists; else DENY. "Valid" means the granting
 * Issuer's authority traces back to a Root Trust Anchor (directly, or
 * recursively via the reserved `admin` relation).
 *
 * The engine touches neither hashing nor cryptography, so evaluation is
 * synchronous and fast.
 */

import { toHex } from "@reticulum/core";
import { permutations } from "./namespace.js";

/** Maximum delegation hops in a single evaluation path (§7.2). */
export const DEFAULT_MAX_DEPTH = 10;
/** Maximum evaluation steps (visited nodes) per request (§7.2). */
export const DEFAULT_MAX_VISITED = 50;
/** The reserved relation that confers the authority to delegate (§3.2). */
export const ADMIN_RELATION = "admin";

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
   * @param {string} objectId
   * @param {string} relation
   * @param {Uint8Array} grantee
   * @returns {boolean} true if (object, relation, grantee) is ALLOWED.
   */
  evaluate(objectId, relation, grantee) {
    // Index active tuples by grantee for this request.
    /** @type {Map<string, import("./tuple.js").Tuple[]>} */
    const index = new Map();
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

    /**
     * @param {Uint8Array} issuer
     * @param {string} obj
     * @param {number} depth
     * @param {Set<string>} visited
     * @returns {boolean}
     */
    function authority(issuer, obj, depth, visited) {
      if (config.isRootAnchor(issuer)) return true; // §7.2 terminal trust anchor
      const memoKey = toHex(issuer) + "|" + obj;
      if (memo.has(memoKey)) return /** @type {boolean} */ (memo.get(memoKey));
      if (depth >= maxDepth) return false; // §7.2 recursion depth bound
      const issuerHex = toHex(issuer);
      if (visited.has(issuerHex)) return false; // §7.2 cycle detection
      const nextVisited = new Set(visited);
      nextVisited.add(issuerHex);
      // Only positive results are memoized: path-independent, unlike a negative
      // result that may merely reflect an ancestor cycle.
      const result = resolve(obj, ADMIN_RELATION, issuer, depth + 1, nextVisited) === "allow";
      if (result) memo.set(memoKey, true);
      return result;
    }

    /**
     * @param {string} obj
     * @param {string} rel
     * @param {Uint8Array} granteeId
     * @param {number} depth
     * @param {Set<string>} visited
     * @returns {"deny"|"allow"|"none"}
     */
    function resolve(obj, rel, granteeId, depth, visited) {
      counter += 1;
      if (counter > maxVisited) return "none"; // §7.2 total work bound
      const patterns = new Set(permutations(obj));
      const denyRelation = "-" + rel;
      let denyValid = false;
      let allowValid = false;
      for (const candidate of index.get(toHex(granteeId)) ?? []) {
        if (!patterns.has(candidate.object)) continue;
        if (candidate.relation === denyRelation) {
          if (authority(candidate.issuer, obj, depth, visited)) denyValid = true;
        } else if (candidate.relation === rel) {
          if (authority(candidate.issuer, obj, depth, visited)) allowValid = true;
        }
      }
      if (denyValid) return "deny";
      if (allowValid) return "allow";
      return "none";
    }

    return resolve(objectId, relation, grantee, 0, new Set()) === "allow";
  }
}
