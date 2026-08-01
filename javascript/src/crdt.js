/**
 * The authorization state: an LWW-Element-Set CRDT (§6).
 *
 * The global state maps a Tuple identity to an HLC timestamp, split into an Add
 * set and a Remove set. A Tuple is active iff its Add timestamp is strictly
 * greater than its Remove timestamp; ties resolve to removed (Remove wins).
 */

import { MsgPack } from "@reticulum/core";
import { Action } from "./operation.js";
import { physicalNowMs, unpackHlc } from "./hlc.js";
import { HASH_SIZE, Tuple } from "./tuple.js";

/** Operations more than this far in the future are rejected (§9). */
const MS_PER_DAY = 24 * 60 * 60 * 1000;

/**
 * @typedef {Object} StateVectorOptions
 * @property {number} [nowMs] Override the wall clock for testing.
 * @property {number|null} [maxFutureMs] Max allowed clock skew; null disables.
 */

/**
 * @typedef {Object} Entry
 * @property {Tuple} tuple
 * @property {bigint|null} addTs
 * @property {bigint|null} removeTs
 */

/** @param {bigint|null} existing @param {bigint} incoming @returns {bigint} */
function maxTs(existing, incoming) {
  return existing === null ? incoming : existing > incoming ? existing : incoming;
}

/** @param {bigint|null} a @param {bigint|null} b @returns {bigint|null} */
function maxBoth(a, b) {
  if (a === null) return b;
  if (b === null) return a;
  return a > b ? a : b;
}

export class StateVector {
  constructor() {
    /** @type {Map<string, Entry>} */
    this._entries = new Map();
  }

  /** Number of distinct tuples known (active or revoked). @returns {number} */
  get size() {
    return this._entries.size;
  }

  /** @param {string} key @returns {boolean} */
  has(key) {
    return this._entries.has(key);
  }

  /** @param {string} key @returns {Entry|undefined} */
  get(key) {
    return this._entries.get(key);
  }

  /**
   * Apply one Operation (Delta) to the appropriate set (§6.2).
   * @param {import("./operation.js").Operation} operation
   * @param {StateVectorOptions} [options]
   * @returns {boolean} true if applied, false if rejected as too far in the future.
   */
  apply(operation, { nowMs, maxFutureMs = MS_PER_DAY } = {}) {
    if (maxFutureMs !== null) {
      const now = nowMs ?? physicalNowMs();
      const { physicalMs } = unpackHlc(operation.hlc);
      if (physicalMs > now + maxFutureMs) return false;
    }
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

  /** Merge another StateVector by taking the max HLC per set per tuple (§6.2). */
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

  /** @param {string} key @returns {boolean} */
  isActive(key) {
    const entry = this._entries.get(key);
    return entry !== undefined && entry.addTs !== null &&
      (entry.removeTs === null || entry.addTs > entry.removeTs);
  }

  /** Generator yielding every currently active Tuple. @returns {Generator<Tuple>} */
  *activeTuples() {
    for (const entry of this._entries.values()) {
      if (entry.addTs !== null && (entry.removeTs === null || entry.addTs > entry.removeTs)) {
        yield entry.tuple;
      }
    }
  }

  /**
   * Serialize the full state vector as a MessagePack array of entries.
   * Each entry is `[object, relation, grantee(16), issuer(16), addTs|nil, removeTs|nil]`.
   * @returns {Uint8Array}
   */
  toPayload() {
    const rows = [];
    for (const entry of this._entries.values()) {
      rows.push([
        entry.tuple.object,
        entry.tuple.relation,
        entry.tuple.grantee,
        entry.tuple.issuer,
        entry.addTs,
        entry.removeTs,
      ]);
    }
    return MsgPack.encode(rows);
  }

  /** @param {Uint8Array} data @returns {StateVector} */
  static fromPayload(data) {
    const rows = MsgPack.decode(data);
    if (!Array.isArray(rows)) {
      throw new Error("state vector payload must be a MessagePack array");
    }
    const state = new StateVector();
    for (const row of rows) {
      if (!Array.isArray(row) || row.length !== 6) {
        throw new Error("each state entry must be a 6-element array");
      }
      const [object, relation, grantee, issuer, addTs, removeTs] = row;
      const tuple = new Tuple({ object, relation, grantee: expectBytes(grantee, HASH_SIZE), issuer: expectBytes(issuer, HASH_SIZE) });
      state._entries.set(tuple.key, {
        tuple,
        addTs: normalizeTs(addTs),
        removeTs: normalizeTs(removeTs),
      });
    }
    return state;
  }
}

/** @param {unknown} value @param {number} len @returns {Uint8Array} */
function expectBytes(value, len) {
  if (!(value instanceof Uint8Array) || value.length !== len) {
    throw new Error(`expected a ${len}-byte Uint8Array`);
  }
  return value;
}

/** @param {number|bigint|null} value @returns {bigint|null} */
function normalizeTs(value) {
  return value === null ? null : BigInt(value);
}
