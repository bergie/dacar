/** Default deletion horizon H (days), see §9. */
export const DEFAULT_DELETION_HORIZON_DAYS: 180;
/**
 * @typedef {Object} ConfigInit
 * @property {Iterable<Uint8Array>} rootTrustAnchors One or more 16-byte hashes.
 * @property {Uint8Array} [primarySalt] 32-byte Primary Privacy Salt.
 * @property {Uint8Array[]} [legacySalts] Ordered Legacy Salts (≤ MAX_LEGACY_SALTS).
 * @property {import("./threshold.d.ts").ThresholdGroup[]} [thresholdGroups]
 * @property {Uint8Array} [authoritativeIdentity] One identity for §8, or omit.
 * @property {number} [deletionHorizonDays] Deletion horizon H (§9).
 */
export class Config {
    /** @param {ConfigInit} init */
    constructor({ rootTrustAnchors, primarySalt, legacySalts, thresholdGroups, authoritativeIdentity, deletionHorizonDays, }: ConfigInit);
    /** @type {Set<string>} hex of each Root Trust Anchor. */
    rootTrustAnchors: Set<string>;
    /** @type {Uint8Array} */
    primarySalt: Uint8Array;
    /** @type {Uint8Array[]} */
    legacySalts: Uint8Array[];
    /** @type {import("./threshold.d.ts").ThresholdGroup[]} */
    thresholdGroups: import("./threshold.d.ts").ThresholdGroup[];
    authoritativeIdentity: Uint8Array<ArrayBufferLike>;
    /** @type {number} */
    deletionHorizonDays: number;
    /** Primary hasher, then Legacy hashers in order (§10.2). @returns {NamespaceHasher[]} */
    get hashers(): NamespaceHasher[];
    /** @returns {NamespaceHasher} */
    get primaryHasher(): NamespaceHasher;
    /** @param {Uint8Array} identityHash @returns {boolean} */
    isRootAnchor(identityHash: Uint8Array): boolean;
    /**
     * The Threshold Group with the given Group ID, or undefined (§4.1). Async
     * because Group IDs are SHA-256 hashes (Web Crypto).
     * @param {Uint8Array} groupIdBytes
     * @returns {Promise<import("./threshold.d.ts").ThresholdGroup | undefined>}
     */
    groupFor(groupIdBytes: Uint8Array): Promise<import("./threshold.d.ts").ThresholdGroup | undefined>;
    /** Deletion horizon in milliseconds. @returns {number} */
    get deletionHorizonMs(): number;
}
export type ConfigInit = {
    /**
     * One or more 16-byte hashes.
     */
    rootTrustAnchors: Iterable<Uint8Array>;
    /**
     * 32-byte Primary Privacy Salt.
     */
    primarySalt?: Uint8Array;
    /**
     * Ordered Legacy Salts (≤ MAX_LEGACY_SALTS).
     */
    legacySalts?: Uint8Array[];
    thresholdGroups?: import("./threshold.d.ts").ThresholdGroup[];
    /**
     * One identity for §8, or omit.
     */
    authoritativeIdentity?: Uint8Array;
    /**
     * Deletion horizon H (§9).
     */
    deletionHorizonDays?: number;
};
import { NamespaceHasher } from "./namespace.d.ts";
