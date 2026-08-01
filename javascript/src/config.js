/**
 * Node configuration: trust anchors and authoritative identity (§4).
 *
 * Every Dacar node is bootstrapped out-of-band with one or more Root Trust
 * Anchors. A node that supports Strict Consistency (§8) is additionally
 * configured with exactly one Authoritative Identity.
 */

import { toHex } from "@reticulum/core";
import { HASH_SIZE } from "./tuple.js";

/**
 * @typedef {Object} ConfigInit
 * @property {Iterable<Uint8Array>} rootTrustAnchors One or more 16-byte hashes.
 * @property {Uint8Array} [authoritativeIdentity] Exactly one identity for §8, or omit.
 */

export class Config {
  /** @param {ConfigInit} init */
  constructor({ rootTrustAnchors, authoritativeIdentity }) {
    const anchors = new Set();
    for (const anchor of rootTrustAnchors) {
      if (!(anchor instanceof Uint8Array) || anchor.length !== HASH_SIZE) {
        throw new TypeError(`trust anchor must be ${HASH_SIZE} bytes`);
      }
      anchors.add(toHex(anchor));
    }
    if (anchors.size === 0) {
      throw new Error("at least one Root Trust Anchor is required (§4.1)");
    }
    if (authoritativeIdentity !== undefined) {
      if (
        !(authoritativeIdentity instanceof Uint8Array) ||
        authoritativeIdentity.length !== HASH_SIZE
      ) {
        throw new TypeError(`authoritative identity must be ${HASH_SIZE} bytes`);
      }
      this.authoritativeIdentity = authoritativeIdentity;
    } else {
      this.authoritativeIdentity = undefined;
    }
    /** @type {Set<string>} hex of each Root Trust Anchor. */
    this.rootTrustAnchors = anchors;
  }

  /** @param {Uint8Array} identityHash @returns {boolean} */
  isRootAnchor(identityHash) {
    return this.rootTrustAnchors.has(toHex(identityHash));
  }
}
