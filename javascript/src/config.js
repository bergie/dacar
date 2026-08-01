/**
 * Node configuration: trust anchors, salts, and thresholds (§4, §10).
 *
 * Every Dacar node is bootstrapped out-of-band with one or more Root Trust
 * Anchors (single identities or Threshold Groups), a Privacy Salt (plus up to
 * two Legacy Salts for rotation, §10), and optionally an Authoritative Identity
 * for Strict Consistency (§8).
 */

import { toHex } from "@reticulum/core";
import {
  DEFAULT_SALT,
  HASH_SIZE,
  MAX_LEGACY_SALTS,
  SALT_SIZE,
  NamespaceHasher,
} from "./namespace.js";

/** Default deletion horizon H (days), see §9. */
export const DEFAULT_DELETION_HORIZON_DAYS = 180;
const MS_PER_DAY = 24 * 60 * 60 * 1000;

/**
 * @typedef {Object} ConfigInit
 * @property {Iterable<Uint8Array>} rootTrustAnchors One or more 16-byte hashes.
 * @property {Uint8Array} [primarySalt] 32-byte Primary Privacy Salt.
 * @property {Uint8Array[]} [legacySalts] Ordered Legacy Salts (≤ MAX_LEGACY_SALTS).
 * @property {import("./threshold.js").ThresholdGroup[]} [thresholdGroups]
 * @property {Uint8Array} [authoritativeIdentity] One identity for §8, or omit.
 * @property {number} [deletionHorizonDays] Deletion horizon H (§9).
 */

export class Config {
  /** @param {ConfigInit} init */
  constructor({
    rootTrustAnchors,
    primarySalt = DEFAULT_SALT,
    legacySalts = [],
    thresholdGroups = [],
    authoritativeIdentity,
    deletionHorizonDays = DEFAULT_DELETION_HORIZON_DAYS,
  }) {
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
    /** @type {Set<string>} hex of each Root Trust Anchor. */
    this.rootTrustAnchors = anchors;

    if (!(primarySalt instanceof Uint8Array) || primarySalt.length !== SALT_SIZE) {
      throw new TypeError(`primarySalt must be ${SALT_SIZE} bytes`);
    }
    /** @type {Uint8Array} */
    this.primarySalt = primarySalt;

    if (legacySalts.length > MAX_LEGACY_SALTS) {
      throw new Error(
        `at most ${MAX_LEGACY_SALTS} Legacy Salts are allowed (§10.2), got ${legacySalts.length}`,
      );
    }
    /** @type {Uint8Array[]} */
    this.legacySalts = legacySalts.map((s) => {
      if (!(s instanceof Uint8Array) || s.length !== SALT_SIZE) {
        throw new TypeError(`each legacy salt must be ${SALT_SIZE} bytes`);
      }
      return s;
    });

    /** @type {import("./threshold.js").ThresholdGroup[]} */
    this.thresholdGroups = [...thresholdGroups];

    if (authoritativeIdentity !== undefined) {
      if (!(authoritativeIdentity instanceof Uint8Array) || authoritativeIdentity.length !== HASH_SIZE) {
        throw new TypeError(`authoritativeIdentity must be ${HASH_SIZE} bytes`);
      }
      this.authoritativeIdentity = authoritativeIdentity;
    } else {
      this.authoritativeIdentity = undefined;
    }

    if (!(Number.isInteger(deletionHorizonDays) && deletionHorizonDays >= 1)) {
      throw new Error("deletionHorizonDays must be >= 1");
    }
    /** @type {number} */
    this.deletionHorizonDays = deletionHorizonDays;
  }

  /** Primary hasher, then Legacy hashers in order (§10.2). @returns {NamespaceHasher[]} */
  get hashers() {
    return [new NamespaceHasher(this.primarySalt), ...this.legacySalts.map((s) => new NamespaceHasher(s))];
  }

  /** @returns {NamespaceHasher} */
  get primaryHasher() {
    return new NamespaceHasher(this.primarySalt);
  }

  /** @param {Uint8Array} identityHash @returns {boolean} */
  isRootAnchor(identityHash) {
    return this.rootTrustAnchors.has(toHex(identityHash));
  }

  /**
   * The Threshold Group with the given Group ID, or undefined (§4.1). Async
   * because Group IDs are SHA-256 hashes (Web Crypto).
   * @param {Uint8Array} groupIdBytes
   * @returns {Promise<import("./threshold.js").ThresholdGroup | undefined>}
   */
  async groupFor(groupIdBytes) {
    const target = toHex(groupIdBytes);
    for (const group of this.thresholdGroups) {
      if (toHex(await group.groupId()) === target) return group;
    }
    return undefined;
  }

  /** Deletion horizon in milliseconds. @returns {number} */
  get deletionHorizonMs() {
    return this.deletionHorizonDays * MS_PER_DAY;
  }
}
