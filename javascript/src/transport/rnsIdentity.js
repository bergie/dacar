/**
 * RNS Identity-backed KeyResolver (spec §3.1, §11.2.4).
 *
 * By spec a Dacar single-identity Issuer Hash **is** a standard 16-byte
 * `RNS.Identity` hash — `SHA-256(P)[:16]` where `P` is the 64-byte RNS public
 * key (`X25519_pub ‖ Ed25519_pub`). This resolver turns such a hash into the
 * full 64-byte public key needed to verify an Operation's signature, by
 * querying RNS's Identity *recall* store — the same store a live Reticulum
 * populates from announce interception.
 *
 * Dacar's verify-on-ingest (§11.2.4) therefore works on real network Deltas
 * with no out-of-band key exchange: an announced Identity is recalled by its
 * hash, and the Operation it claims to be from is signature-checked against
 * that Identity's signing key.
 *
 * Threshold Groups (§4.1) cannot be resolved this way — their Group ID is a
 * composite hash, not an RNS identity, so RNS has nothing to recall. They —
 * and any out-of-band single identities — fall through to an optional
 * *fallback* resolver (e.g. a {@link Keyring} of pre-registered group
 * keysets). RNS is consulted first, then the fallback, so announced
 * identities always win.
 *
 * This module is part of the optional transport layer: importing the pure
 * core (`@reticulum/dacar`) never pulls it in. It depends only on
 * `@reticulum/core`'s `Destination.recall`, which the core already depends on
 * for `Identity` / `MsgPack`, so it adds no new dependency.
 */

import { Destination } from "@reticulum/core";
import { IssuerKeyset } from "../verifier.js";

/**
 * Invokes a resolver (`KeyResolver` function or a {@link Keyring}) and awaits
 * its result, tolerating either shape. Mirrors the dispatch in verifier.js.
 * @param {import("../verifier.js").KeyResolver | import("../verifier.js").Keyring | null} resolver
 * @param {Uint8Array} hash
 * @returns {Promise<import("../verifier.js").IssuerKeyset | null>}
 */
async function resolveWith(resolver, hash) {
  if (typeof resolver === "function") return await resolver(hash);
  if (resolver && typeof resolver.resolve === "function") {
    return await resolver.resolve(hash);
  }
  return null;
}

/**
 * Resolves single-identity Issuer hashes via the RNS Identity recall store.
 *
 * Usable directly as a {@link import("../verifier.js").KeyResolver KeyResolver}
 * — both `resolve()` and the callable form (via `resolve` being the only
 * method) are accepted by `DeltaReceiver` / `verifyOperation`, which dispatch
 * on `typeof resolver === "function"`. Pass the resolver itself (or its
 * `.resolve` method) where a `KeyResolver` function is expected.
 */
export class RnsIdentityResolver {
  /**
   * @param {import("../verifier.js").KeyResolver | import("../verifier.js").Keyring | null} [fallback]
   *   Consulted when RNS has no Identity for a hash — e.g. for Threshold Group
   *   IDs and out-of-band identities. RNS is consulted first, then the fallback.
   */
  constructor(fallback = null) {
    this._fallback = fallback;
  }

  /**
   * Resolve a 16-byte Issuer hash to an {@link IssuerKeyset}, or `null` when
   * the Issuer is unknown to both RNS and the fallback (the Operation is then
   * rejected as unverifiable).
   * @param {Uint8Array} issuerHash
   * @returns {Promise<import("../verifier.js").IssuerKeyset | null>}
   */
  async resolve(issuerHash) {
    // `fromIdentityHash = true` scans the recall store matching by the
    // identity hash (SHA-256(P)[:16]) rather than by destination hash.
    const identity = await Destination.recall(issuerHash, true);
    if (identity) {
      // IssuerKeyset carries the full 64-byte RNS public key (X25519 ‖ Ed25519).
      return IssuerKeyset.single(await identity.getPublicKey());
    }
    if (this._fallback) return resolveWith(this._fallback, issuerHash);
    return null;
  }
}
