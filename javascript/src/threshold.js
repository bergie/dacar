/**
 * Threshold Trust Anchors: N-of-M identity groups (Dacar spec §4.1).
 *
 * A Threshold Group is a composite authority requiring consensus: an Operation
 * issued *by* the group MUST carry exactly `N` valid signatures from `N`
 * distinct members of the `M`-member set (§5.2).
 *
 * The **Group ID** is the SHA-256 hash of the alphabetically sorted member
 * hashes concatenated with the threshold `N`, truncated to the first 16 bytes
 * (§4.1). The Group ID is itself a 16-byte value usable wherever an Issuer hash
 * is expected.
 *
 * > Scope (§4.1): in v1.0, Threshold Groups MAY ONLY act as Issuers.
 *
 * SHA-256 uses Web Crypto, so `groupId()` is asynchronous. Compute it once and
 * cache the result (`group.id` after the first `await group.groupId()`).
 */

import { HASH_SIZE } from "./namespace.js";

const encoder = new TextEncoder();

/** The threshold `N` is folded into the Group ID as an 8-byte big-endian int. */
const THRESHOLD_BYTES = 8;

/** Compare two 16-byte member hashes for ascending sort (byte-wise === hex). */
function compareHashes(a, b) {
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return a[i] - b[i];
  }
  return 0;
}

/** Synchronously validate member hashes and threshold (shared by all paths). */
function validateMembers(members, threshold) {
  if (!(Number.isInteger(threshold) && threshold >= 1 && threshold <= members.length)) {
    throw new Error(
      `threshold must satisfy 1 <= N <= M (got N=${threshold}, M=${members.length})`,
    );
  }
  for (const m of members) {
    if (!(m instanceof Uint8Array) || m.length !== HASH_SIZE) {
      throw new RangeError(`member hash must be ${HASH_SIZE} bytes`);
    }
  }
  if (members.length < 2) {
    throw new Error("a threshold group needs at least 2 members (M)");
  }
}

/**
 * Compute the 16-byte Group ID for a member set and threshold (§4.1).
 *
 * Members are 16-byte identity hashes, sorted ascending by raw byte value
 * (equivalent to hex-alphabetical order). The threshold `N` is appended as an
 * 8-byte big-endian unsigned integer, then SHA-256 of the whole blob is
 * truncated to 16 bytes.
 * @param {Uint8Array[]} members
 * @param {number} threshold
 * @returns {Promise<Uint8Array>}
 */
export async function groupId(members, threshold) {
  const normalized = [...members].sort(compareHashes);
  validateMembers(normalized, threshold);
  const nBytes = new Uint8Array(THRESHOLD_BYTES);
  new DataView(nBytes.buffer).setBigUint64(0, BigInt(threshold), false); // big-endian
  const total = normalized.length * HASH_SIZE + THRESHOLD_BYTES;
  const blob = new Uint8Array(total);
  let o = 0;
  for (const m of normalized) {
    blob.set(m, o);
    o += HASH_SIZE;
  }
  blob.set(nBytes, o);
  const digest = await crypto.subtle.digest("SHA-256", blob);
  return new Uint8Array(digest).slice(0, HASH_SIZE);
}

export class ThresholdGroup {
  /**
   * @param {Uint8Array[]} members M member identity hashes (16 bytes each).
   * @param {number} threshold The consensus threshold N.
   */
  constructor(members, threshold) {
    validateMembers([...members], threshold);
    /** @readonly @type {Uint8Array[]} sorted ascending. */
    this.members = [...members].sort(compareHashes);
    /** @readonly */ this.threshold = threshold;
    /** Cached Group ID once computed. @type {Uint8Array | null} */
    this._id = null;
    this._idPromise = null;
  }

  /** The number of members `M`. @returns {number} */
  get size() {
    return this.members.length;
  }

  /** The 16-byte Group ID (cached after the first call). @returns {Promise<Uint8Array>} */
  groupId() {
    if (this._id) return Promise.resolve(this._id);
    if (!this._idPromise) {
      this._idPromise = groupId(this.members, this.threshold).then((id) => {
        this._id = id;
        return id;
      });
    }
    return this._idPromise;
  }
}
