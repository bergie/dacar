/**
 * Resolves single-identity Issuer hashes via the RNS Identity recall store.
 *
 * Usable directly as a {@link import("../verifier.d.ts").KeyResolver KeyResolver}
 * — both `resolve()` and the callable form (via `resolve` being the only
 * method) are accepted by `DeltaReceiver` / `verifyOperation`, which dispatch
 * on `typeof resolver === "function"`. Pass the resolver itself (or its
 * `.resolve` method) where a `KeyResolver` function is expected.
 */
export class RnsIdentityResolver {
    /**
     * @param {import("@reticulum/core").Reticulum} rns A booted Reticulum whose
     *   transport owns the instance-scoped identity recall store
     *   (`rns.transport.recallIdentity`). A bare `TransportCore` is accepted
     *   too (its `recallIdentity` is resolved directly).
     * @param {import("../verifier.d.ts").KeyResolver | import("../verifier.d.ts").Keyring | null} [fallback]
     *   Consulted when RNS has no Identity for a hash — e.g. for Threshold Group
     *   IDs and out-of-band identities. RNS is consulted first, then the fallback.
     */
    constructor(rns: import("@reticulum/core").Reticulum, fallback?: import("../verifier.d.ts").KeyResolver | import("../verifier.d.ts").Keyring | null);
    /** @type {import("@reticulum/core").Reticulum} */
    _rns: import("@reticulum/core").Reticulum;
    _fallback: import("../verifier.d.ts").Keyring | import("../verifier.d.ts").KeyResolver;
    /**
     * Resolve a 16-byte Issuer hash to an {@link IssuerKeyset}, or `null` when
     * the Issuer is unknown to both RNS and the fallback (the Operation is then
     * rejected as unverifiable).
     * @param {Uint8Array} issuerHash
     * @returns {Promise<import("../verifier.d.ts").IssuerKeyset | null>}
     */
    resolve(issuerHash: Uint8Array): Promise<import("../verifier.d.ts").IssuerKeyset | null>;
}
