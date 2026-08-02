/**
 * The authorization state: an LWW-Element-Set CRDT (§6).
 *
 * The global state maps a Tuple identity to an HLC timestamp, split into an Add
 * set and a Remove set. A Tuple is active iff its Add timestamp is strictly
 * greater than its Remove timestamp; ties resolve to removed (Remove wins).
 *
 * Storage is bounded by **Time-Horizon Tombstone Pruning** (§9): once a tuple
 * resolves inactive *and* both its Add and Remove timestamps are older than the
 * deletion horizon, both entries are silently deleted. Incoming Operations
 * older than the horizon are rejected outright (intake rejection, §9).
 */

import { MsgPack } from "@reticulum/core";
import { Action } from "./operation.js";
import { MAX_HLC, physicalNowMs, unpackHlc } from "./hlc.js";
import { Tuple } from "./tuple.js";
import { verifyOperation } from "./verifier.js";

const MS_PER_DAY = 24 * 60 * 60 * 1000;
/** Operations more than this far in the future are rejected (§12). */
const DEFAULT_MAX_FUTURE_MS = MS_PER_DAY;
/** Default deletion horizon H for Time-Horizon Tombstone Pruning (§9). */
export const DEFAULT_DELETION_HORIZON_DAYS = 180;

/**
 * @typedef {Object} Entry
 * @property {Tuple} tuple
 * @property {bigint | null} addTs
 * @property {bigint | null} removeTs
 */

/** @param {bigint | null} existing @param {bigint} incoming @returns {bigint} */
function maxTs(existing, incoming) {
  return existing === null ? incoming : existing > incoming ? existing : incoming;
}

/** @param {bigint | null} a @param {bigint | null} b @returns {bigint | null} */
function maxBoth(a, b) {
  if (a === null) return b;
  if (b === null) return a;
  return a > b ? a : b;
}

/**
 * Guard ensuring the trusted-local-only notice for `StateVector.fromPayload()`
 * is logged at most once per process, so legitimate snapshot/restore does not
 * flood logs while still flagging the footgun the first time.
 */
let __trustedLocalWarned = false;

/** @param {number | bigint | null} value @returns {bigint | null} */
function normalizeTs(value) {
  return value === null ? null : BigInt(value);
}

export class StateVector {
  /**
   * @param {Object} [opts]
   * @param {number} [opts.deletionHorizonDays] Deletion horizon H (§9).
   */
  constructor({ deletionHorizonDays = DEFAULT_DELETION_HORIZON_DAYS } = {}) {
    if (!(Number.isInteger(deletionHorizonDays) && deletionHorizonDays >= 1)) {
      throw new Error("deletionHorizonDays must be >= 1");
    }
    /** @type {Map<string, Entry>} */
    this._entries = new Map();
    this.deletionHorizonDays = deletionHorizonDays;
  }

  /** Deletion horizon in milliseconds. @returns {number} */
  get deletionHorizonMs() {
    return this.deletionHorizonDays * MS_PER_DAY;
  }

  /** Number of distinct tuples known (active or revoked). @returns {number} */
  get size() {
    return this._entries.size;
  }

  /** @param {string} key @returns {boolean} */
  has(key) {
    return this._entries.has(key);
  }

  /** @param {string} key @returns {Entry | undefined} */
  get(key) {
    return this._entries.get(key);
  }

  /**
   * Authenticate then apply a network-received Delta (§11.2.4, §5.2).
   *
   * This is the secure entry point for Operations received over any transport
   * (RFed, LXMF, optical sneakernet). The Operation's Ed25519 signature(s)
   * MUST verify against the public key(s) resolved for its claimed Issuer
   * before the pure CRDT update (`apply()`) is allowed to mutate state. Any
   * authentication failure — unknown Issuer, bad signature, wrong threshold —
   * drops the Operation (returns `false`).
   *
   * Returns `true` iff authenticated *and* applied. Distinct from `apply()`,
   * which trusts its caller and performs no cryptography.
   * @param {import("./operation.js").Operation} operation
   * @param {import("./verifier.js").KeyResolver | import("./verifier.js").Keyring} keyResolver
   * @param {Object} [options]
   * @param {number} [options.nowMs]
   * @param {number | null} [options.maxFutureMs]
   * @returns {Promise<boolean>}
   */
  async ingest(operation, keyResolver, options = {}) {
    if (!(await verifyOperation(operation, keyResolver))) return false;
    return this.apply(operation, options);
  }

  /**
   * Apply one Operation (Delta) to the appropriate set (§6.1, §9, §12).
   * @param {import("./operation.js").Operation} operation
   * @param {Object} [options]
   * @param {number} [options.nowMs] Override the wall clock for testing.
   * @param {number | null} [options.maxFutureMs] Max clock skew; null disables.
   * @returns {boolean} true if applied, false if rejected.
   */
  apply(operation, { nowMs, maxFutureMs = DEFAULT_MAX_FUTURE_MS } = {}) {
    const { physicalMs } = unpackHlc(operation.hlc);
    const now = nowMs ?? physicalNowMs();
    if (maxFutureMs !== null && physicalMs > now + maxFutureMs) return false; // §12
    if (physicalMs < now - this.deletionHorizonMs) return false; // §9 intake rejection
    const key = operation.tuple.key;
    let entry = this._entries.get(key);
    if (!entry) {
      entry = { tuple: operation.tuple, addTs: null, removeTs: null };
      this._entries.set(key, entry);
    }
    if (operation.action === Action.GRANT) {
      entry.addTs = maxTs(entry.addTs, operation.hlc);
    } else {
      entry.removeTs = maxTs(entry.removeTs, operation.hlc);
    }
    return true;
  }

  /**
   * Merge another StateVector by taking the max HLC per set per tuple (§6.1).
   *
   * > **Warning: Trusted-local-only — never feed network bytes.**
   * > `merge()` trusts its argument completely and performs **no** signature
   * > verification, so it can inject or alter authorization state (including
   * > Root Trust Anchor grants) for any tuple. It also skips the §9
   * > stale-horizon and §12 future-skew intake checks that `apply()`/`ingest()`
   * > enforce per-delta, so even a trusted source can silently reintroduce
   * > operations per-delta ingestion would have rejected.
   * >
   * > Legitimate uses are confined to a node's own trusted state: CRDT unit
   * > testing and restoring a snapshot previously produced by `toPayload()` on
   * > the *same* node. For network convergence use `DeltaReceiver.applyPayloads()`
   * > (a batch of signed Deltas) instead.
   * @param {StateVector} other
   */
  merge(other) {
    for (const [key, otherEntry] of other._entries) {
      let entry = this._entries.get(key);
      if (!entry) {
        entry = { tuple: otherEntry.tuple, addTs: null, removeTs: null };
        this._entries.set(key, entry);
      }
      entry.addTs = maxBoth(entry.addTs, otherEntry.addTs);
      entry.removeTs = maxBoth(entry.removeTs, otherEntry.removeTs);
    }
  }

  /**
   * Run Time-Horizon Tombstone Pruning (§9). Deletes both the Add and Remove
   * entries for any tuple that resolves inactive *and* whose Add and Remove
   * timestamps are both older than the horizon. Returns the count pruned.
   * @param {Object} [opts]
   * @param {number} [opts.nowMs]
   * @returns {number}
   */
  prune({ nowMs } = {}) {
    const now = nowMs ?? physicalNowMs();
    const cutoff = now - this.deletionHorizonMs;
    let pruned = 0;
    for (const [key, entry] of this._entries) {
      if (this._isActiveEntry(entry)) continue;
      const { addTs, removeTs } = entry;
      if (addTs === null || removeTs === null) continue;
      if (unpackHlc(addTs).physicalMs < cutoff && unpackHlc(removeTs).physicalMs < cutoff) {
        this._entries.delete(key);
        pruned += 1;
      }
    }
    return pruned;
  }

  /** @param {string} key @returns {boolean} */
  isActive(key) {
    const entry = this._entries.get(key);
    return entry !== undefined && this._isActiveEntry(entry);
  }

  /** @param {Entry} entry @returns {boolean} */
  _isActiveEntry(entry) {
    return (
      entry.addTs !== null &&
      (entry.removeTs === null || entry.addTs > entry.removeTs)
    );
  }

  /** Generator yielding every currently active Tuple. @returns {Generator<Tuple>} */
  *activeTuples() {
    for (const entry of this._entries.values()) {
      if (this._isActiveEntry(entry)) yield entry.tuple;
    }
  }

  /**
   * Serialize the full state vector as a MessagePack array of entries. Each
   * entry is `[relationHash(16), [objectHashes], wildcard_bool, grantee(16),
   * issuer(16), addTs | null, removeTs | null]`.
   *
   * > **Warning: Trusted-local-only.** The payload is an unauthenticated dump
   * > of this node's CRDT and carries **no** Ed25519 signature material; it
   * > exists for a node to snapshot *its own* state (e.g. a local backup or
   * > CRDT unit test). It MUST NOT be accepted from the network — deserialize
   * > such bytes only via your own trusted store, and if it ever crosses a
   * > trust boundary use `DeltaReceiver.applyPayloads()` (a batch of signed
   * > §5.3 Operations) instead.
   * @returns {Uint8Array}
   */
  toPayload() {
    const rows = [];
    for (const entry of this._entries.values()) {
      rows.push([
        entry.tuple.relationHash,
        [...entry.tuple.objectHashes],
        entry.tuple.wildcard,
        entry.tuple.grantee,
        entry.tuple.issuer,
        entry.addTs,
        entry.removeTs,
      ]);
    }
    return MsgPack.encode(rows);
  }

  /**
   * Deserialize a state vector produced by `toPayload()`.
   *
   * > **Warning: Trusted-local-only — never feed network bytes.** The payload
   * > carries **no** signature material, so deserializing attacker bytes and
   * > then `merge()`-ing it lets a peer forge arbitrary authorization state
   * > (including Root Trust Anchor grants) and silently bypass the §9
   * > stale-horizon and §12 future-skew intake checks. Only deserialize bytes
   * > from your own trusted store (a snapshot you previously produced with
   * > `toPayload()` on this node). For network convergence use
   * > `DeltaReceiver.applyPayloads()` (a batch of signed §5.3 Operations)
   * > instead.
   * >
   * > A one-time `console.warn` is emitted to make this contract audible.
   * @param {Uint8Array} data
   * @param {Object} [opts]
   * @param {number} [opts.deletionHorizonDays]
   * @returns {StateVector}
   */
  static fromPayload(data, { deletionHorizonDays = DEFAULT_DELETION_HORIZON_DAYS } = {}) {
    if (!__trustedLocalWarned) {
      __trustedLocalWarned = true;
      console.warn(
        "StateVector.fromPayload() is trusted-local-only: it performs no " +
          "signature verification and must not be fed network bytes. For " +
          "network convergence use DeltaReceiver.applyPayloads() instead.",
      );
    }
    const rows = MsgPack.decode(data);
    if (!Array.isArray(rows)) {
      throw new Error("state vector payload must be a MessagePack array");
    }
    const state = new StateVector({ deletionHorizonDays });
    for (const row of rows) {
      if (!Array.isArray(row) || row.length !== 7) {
        throw new Error("each state entry must be a 7-element array");
      }
      const [relationHash, objectHashes, wildcard, grantee, issuer, addTs, removeTs] = row;
      const tuple = new Tuple({
        relationHash: expectBytes(relationHash, 16, "relation_hash"),
        objectHashes: objectHashes.map((h) => expectBytes(h, 16, "object_hash")),
        wildcard: expectBool(wildcard, "wildcard"),
        grantee: expectBytes(grantee, 16, "grantee"),
        issuer: expectBytes(issuer, 16, "issuer"),
      });
      state._entries.set(tuple.key, {
        tuple,
        addTs: normalizeTs(addTs),
        removeTs: normalizeTs(removeTs),
      });
    }
    return state;
  }
}

/**
 * @param {unknown} value
 * @param {number} len
 * @param {string} name
 * @returns {Uint8Array}
 */
function expectBytes(value, len, name) {
  if (!(value instanceof Uint8Array) || value.length !== len) {
    throw new Error(`${name} must be a ${len}-byte Uint8Array`);
  }
  return value;
}

/** @param {unknown} value @param {string} name @returns {boolean} */
function expectBool(value, name) {
  if (typeof value !== "boolean") throw new Error(`${name} must be a boolean`);
  return value;
}
