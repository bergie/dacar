/**
 * The authorization Tuple and its canonical hash (Dacar spec §3.1, §6.1).
 *
 * A Tuple asserts that a Grantee holds a Relation over an Object, as authorized
 * by an Issuer: `(Object, Relation, Grantee, Issuer)`.
 *
 * The Tuple Hash is SHA-256 over a packed pre-image (§6.1):
 *   [16-byte Issuer] + [16-byte Grantee] + [1-byte Relation Length]
 *                    + [Relation (UTF-8)] + [Object (UTF-8)]
 *
 * The pre-image is built synchronously and uniquely identifies a Tuple, so it
 * doubles as the CRDT's internal map key; the full SHA-256 hash is computed
 * (asynchronously, via Web Crypto) where the spec requires it.
 */

import { toHex } from "@reticulum/core";

export const HASH_SIZE = 16;
export const RELATION_MAX_LEN = 0xff;

const encoder = new TextEncoder();

/**
 * @typedef {Object} TupleInit
 * @property {string} object
 * @property {string} relation
 * @property {Uint8Array} grantee 16-byte RNS.Identity hash of the holder.
 * @property {Uint8Array} issuer 16-byte RNS.Identity hash of the signer.
 */

export class Tuple {
  /** @param {TupleInit} init */
  constructor({ object, relation, grantee, issuer }) {
    const relLen = encoder.encode(relation).length;
    if (!(grantee instanceof Uint8Array) || grantee.length !== HASH_SIZE) {
      throw new TypeError(`grantee must be ${HASH_SIZE} bytes`);
    }
    if (!(issuer instanceof Uint8Array) || issuer.length !== HASH_SIZE) {
      throw new TypeError(`issuer must be ${HASH_SIZE} bytes`);
    }
    if (relLen > RELATION_MAX_LEN) {
      throw new RangeError(`relation too long (${relLen} > ${RELATION_MAX_LEN})`);
    }
    this.object = object;
    this.relation = relation;
    this.grantee = grantee;
    this.issuer = issuer;
  }

  /** §6.1 hash pre-image. @returns {Uint8Array} */
  get preimage() {
    const relation = encoder.encode(this.relation);
    const object = encoder.encode(this.object);
    const out = new Uint8Array(HASH_SIZE * 2 + 1 + relation.length + object.length);
    out.set(this.issuer, 0);
    out.set(this.grantee, HASH_SIZE);
    out[HASH_SIZE * 2] = relation.length;
    out.set(relation, HASH_SIZE * 2 + 1);
    out.set(object, HASH_SIZE * 2 + 1 + relation.length);
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

  /** Structural equality with another Tuple. @param {unknown} other @returns {boolean} */
  equals(other) {
    return (
      other instanceof Tuple &&
      this.object === other.object &&
      this.relation === other.relation &&
      bytesEqual(this.grantee, other.grantee) &&
      bytesEqual(this.issuer, other.issuer)
    );
  }
}

/**
 * Constant-time-ish byte comparison.
 * @param {Uint8Array} a
 * @param {Uint8Array} b
 * @returns {boolean}
 */
export function bytesEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}
