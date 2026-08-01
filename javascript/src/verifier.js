/**
 * Verify-on-ingest: authenticating network Deltas by Ed25519 signature.
 *
 * The CRDT update itself (`StateVector.apply()`) is a *pure* mutation that
 * trusts its caller; it deliberately performs no cryptography so the layering
 * stays simple and the hot path stays fast. Network-received Deltas instead
 * enter the state through `StateVector.ingest()`, which **must** authenticate
 * each Operation against the claimed Issuer's public key(s) before it is
 * allowed to mutate state (spec §11.2.4: *"The signature remains the sole
 * source of authorization authenticity"*).
 *
 * This module bridges an Issuer hash to the public-key material needed to
 * verify it:
 *
 *   - `IssuerKeyset`   — M public keys + a threshold (1 for a single identity,
 *     N for a Threshold Group, §4.1).
 *   - `KeyResolver`    — `issuerHash(16) -> IssuerKeyset | null | Promise`.
 *   - `Keyring`        — a Map-backed resolver for offline / test use.
 *   - `verifyOperation()` — resolve + verify, returning a plain boolean.
 *
 * Authentication is *not* authorization. Verifying a signature proves the
 * Operation was genuinely issued by the claimed Issuer; whether that Issuer is
 * itself authorized (its authority traces to a Root Trust Anchor) is resolved
 * later by the Evaluation Engine (§7) against the converged CRDT state.
 */

import { toHex } from "@reticulum/core";
import { HASH_SIZE } from "./namespace.js";

/** The full RNS public key (X25519 ‖ Ed25519) is 64 raw bytes. */
const RNS_PUBLIC_KEY_SIZE = 64;

/**
 * Public-key material needed to verify an Operation from one Issuer.
 *
 * A single-identity Issuer has `threshold === 1` and one member key; a
 * Threshold Group Issuer (§4.1) has `threshold === N` and `M >= N` member keys.
 * Each member key is the full 64-byte RNS public key returned by
 * `Identity.getPublicKey()` (X25519 ‖ Ed25519), reconstructable via
 * `Identity.fromPublicKey()`.
 */
export class IssuerKeyset {
  /**
   * @param {Uint8Array[]} memberPublicKeys One (single identity) or M (group)
   *   64-byte RNS public keys.
   * @param {number} [threshold] Consensus threshold N (defaults to 1).
   */
  constructor(memberPublicKeys, threshold = 1) {
    if (!(Number.isInteger(threshold) && threshold >= 1)) {
      throw new Error("threshold must be a positive integer");
    }
    if (!Array.isArray(memberPublicKeys) || memberPublicKeys.length < threshold) {
      throw new Error("need at least `threshold` member public keys");
    }
    const keys = [];
    for (const k of memberPublicKeys) {
      if (!(k instanceof Uint8Array) || k.length !== RNS_PUBLIC_KEY_SIZE) {
        throw new RangeError(`RNS public keys are ${RNS_PUBLIC_KEY_SIZE} raw bytes`);
      }
      keys.push(new Uint8Array(k));
    }
    /** @type {Uint8Array[]} */
    this.memberPublicKeys = Object.freeze(keys);
    /** @type {number} */
    this.threshold = threshold;
    Object.freeze(this);
  }

  /**
   * Keyset for a single-identity Issuer (threshold 1).
   * @param {Uint8Array} publicKey
   * @returns {IssuerKeyset}
   */
  static single(publicKey) {
    return new IssuerKeyset([publicKey], 1);
  }

  /**
   * Keyset for an N-of-M Threshold Group Issuer (§4.1).
   * @param {Uint8Array[]} memberPublicKeys
   * @param {number} threshold
   * @returns {IssuerKeyset}
   */
  static group(memberPublicKeys, threshold) {
    return new IssuerKeyset(memberPublicKeys, threshold);
  }
}

/**
 * Resolves a 16-byte Issuer hash to its verification keyset, or `null` when the
 * Issuer is unknown (the Operation is then rejected as unverifiable). May be
 * async (e.g. backed by RNS Identity resolution over the network).
 * @typedef {(issuerHash: Uint8Array) => (IssuerKeyset | null | Promise<IssuerKeyset | null>)} KeyResolver
 */

/**
 * A Map-backed {@link KeyResolver} for offline and test use.
 *
 * Production nodes will typically back this with RNS Identity resolution
 * (querying the network for the public key behind a 16-byte Identity hash);
 * this in-memory implementation is sufficient for single-node reference
 * deployments, air-gapped sneakernet, and the test suite.
 */
export class Keyring {
  constructor() {
    /** @type {Map<string, IssuerKeyset>} */
    this._map = new Map();
  }

  /**
   * Map a 16-byte Issuer hash to its `IssuerKeyset`.
   * @param {Uint8Array} issuerHash
   * @param {IssuerKeyset} keyset
   * @returns {Keyring}
   */
  register(issuerHash, keyset) {
    this._map.set(toHex(_asHash(issuerHash)), keyset);
    return this;
  }

  /**
   * @param {Uint8Array} issuerHash
   * @param {Uint8Array} publicKey
   * @returns {Keyring}
   */
  registerSingle(issuerHash, publicKey) {
    return this.register(issuerHash, IssuerKeyset.single(publicKey));
  }

  /**
   * @param {Uint8Array} groupId
   * @param {Uint8Array[]} memberPublicKeys
   * @param {number} threshold
   * @returns {Keyring}
   */
  registerGroup(groupId, memberPublicKeys, threshold) {
    return this.register(groupId, IssuerKeyset.group(memberPublicKeys, threshold));
  }

  /**
   * @param {Uint8Array} issuerHash
   * @returns {IssuerKeyset | null}
   */
  resolve(issuerHash) {
    return this._map.get(toHex(_asHash(issuerHash))) ?? null;
  }
}

/**
 * Authenticate one Operation against its claimed Issuer (§5.2, §11.2.4).
 *
 * Returns `true` iff the Issuer hash is known to `resolver` *and* the Operation
 * carries a valid threshold signature from the resolved keyset. An unknown
 * Issuer or any cryptographic failure yields `false` — the Operation MUST be
 * dropped rather than merged.
 * @param {import("./operation.js").Operation} operation
 * @param {KeyResolver | Keyring} resolver A function or a Keyring.
 * @returns {Promise<boolean>}
 */
export async function verifyOperation(operation, resolver) {
  const keyset = await resolveKeyset(resolver, operation.issuer);
  if (!keyset) return false;
  return operation.verifyKeyset(keyset);
}

/**
 * @param {KeyResolver | Keyring} resolver
 * @param {Uint8Array} hash
 * @returns {Promise<IssuerKeyset | null>}
 */
async function resolveKeyset(resolver, hash) {
  if (typeof resolver === "function") return await resolver(hash);
  if (resolver && typeof resolver.resolve === "function") return resolver.resolve(hash);
  throw new TypeError("resolver must be a function or a Keyring");
}

/** @param {Uint8Array} value @returns {Uint8Array} */
function _asHash(value) {
  if (!(value instanceof Uint8Array) || value.length !== HASH_SIZE) {
    throw new RangeError(`issuer hash must be ${HASH_SIZE} bytes`);
  }
  return value;
}
