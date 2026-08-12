/**
 * The authorization Tuple and its canonical hash (Dacar spec §3.1, §6.1).
 *
 * A Tuple asserts that a Grantee holds a Relation over an Object, authorized by
 * an Issuer: `(Object, Relation, Grantee, Issuer)`.
 *
 * For Namespace Label Privacy (§3.3), the Relation and Object are stored *only*
 * as their 16-byte salted hashes. The **Tuple Hash** (§6.1) is SHA-256 over:
 *
 *   [16-byte Issuer] + [16-byte Grantee] + [16-byte Relation Hash]
 *   + [1-byte Wildcard Flag] + [1-byte Segment Count] + [Object Hashes]
 *
 * Action and HLC are deliberately excluded, so a Grant and its Revoke for the
 * same permission resolve to the *same* Tuple Hash. The pre-image is built
 * synchronously and uniquely identifies a Tuple, so `toHex(preimage)` doubles as
 * the CRDT's internal map key; the full async SHA-256 is available via `hash()`.
 */

import { toHex } from "@reticulum/core";
import { HASH_SIZE, bytesEqual } from "./namespace.js";

/** Maximum number of Object segments (the Segment Count field is one byte). */
export const MAX_SEGMENTS = 0xff;

/**
 * @typedef {Object} HashedTupleInit
 * @property {Uint8Array} relationHash 16-byte HMAC of the relation string.
 * @property {Uint8Array[]} objectHashes 16-byte HMAC per non-wildcard segment.
 * @property {boolean} wildcard True iff the Object ended in the suffix `*`.
 * @property {Uint8Array} grantee 16-byte holder identity hash.
 * @property {Uint8Array} issuer 16-byte issuer identity hash or Group ID.
 */

export class Tuple {
  /** @param {HashedTupleInit} init */
  constructor({ relationHash, objectHashes, wildcard, grantee, issuer }) {
    if (!(relationHash instanceof Uint8Array) || relationHash.length !== HASH_SIZE) {
      throw new RangeError(`relationHash must be ${HASH_SIZE} bytes`);
    }
    if (!(grantee instanceof Uint8Array) || grantee.length !== HASH_SIZE) {
      throw new RangeError(`grantee must be ${HASH_SIZE} bytes`);
    }
    if (!(issuer instanceof Uint8Array) || issuer.length !== HASH_SIZE) {
      throw new RangeError(`issuer must be ${HASH_SIZE} bytes`);
    }
    if (objectHashes.length > MAX_SEGMENTS) {
      throw new RangeError(`too many object segments (${objectHashes.length} > ${MAX_SEGMENTS})`);
    }
    for (const h of objectHashes) {
      if (!(h instanceof Uint8Array) || h.length !== HASH_SIZE) {
        throw new RangeError(`object segment hash must be ${HASH_SIZE} bytes`);
      }
    }
    /** @readonly */ this.relationHash = relationHash;
    /** @readonly */ this.objectHashes = Object.freeze([...objectHashes]);
    /** @readonly */ this.wildcard = wildcard;
    /** @readonly */ this.grantee = grantee;
    /** @readonly */ this.issuer = issuer;
  }

  /**
   * Build a Tuple by hashing plaintext labels with `hasher` (§3.3).
   * @param {Object} opts
   * @param {string} opts.objectId
   * @param {string} opts.relation
   * @param {Uint8Array} opts.grantee
   * @param {Uint8Array} opts.issuer
   * @param {import("./namespace.js").NamespaceHasher} opts.hasher
   * @returns {Promise<Tuple>}
   */
  static async fromPlaintext({ objectId, relation, grantee, issuer, hasher }) {
    const [relationHash, { hashes, wildcard }] = await Promise.all([
      hasher.hashRelation(relation),
      hasher.hashObject(objectId),
    ]);
    return new Tuple({ relationHash, objectHashes: hashes, wildcard, grantee, issuer });
  }

  /** §6.1 hash pre-image (excludes Action + HLC). @returns {Uint8Array} */
  get preimage() {
    let len = HASH_SIZE * 3 + 2; // issuer + grantee + relationHash + flags
    for (const h of this.objectHashes) len += h.length;
    const out = new Uint8Array(len);
    let o = 0;
    out.set(this.issuer, o); o += HASH_SIZE;
    out.set(this.grantee, o); o += HASH_SIZE;
    out.set(this.relationHash, o); o += HASH_SIZE;
    out[o++] = this.wildcard ? 0x01 : 0x00;
    out[o++] = this.objectHashes.length;
    for (const h of this.objectHashes) {
      out.set(h, o);
      o += h.length;
    }
    return out;
  }

  /** Canonical 32-byte SHA-256 Tuple Hash (§6.1). @returns {Promise<Uint8Array>} */
  async hash() {
    const digest = await crypto.subtle.digest("SHA-256", this.preimage);
    return new Uint8Array(digest);
  }

  /** Stable unique key derived from the §6.1 pre-image (sync). @returns {string} */
  get key() {
    return toHex(this.preimage);
  }

  /** Structural equality with another Tuple. @param {Tuple} other @returns {boolean} */
  equals(other) {
    if (!(other instanceof Tuple)) return false;
    return (
      bytesEqual(this.relationHash, other.relationHash) &&
      this.objectHashes.length === other.objectHashes.length &&
      this.objectHashes.every((h, i) => bytesEqual(h, other.objectHashes[i])) &&
      this.wildcard === other.wildcard &&
      bytesEqual(this.grantee, other.grantee) &&
      bytesEqual(this.issuer, other.issuer)
    );
  }
}
