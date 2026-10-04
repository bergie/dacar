/**
 * Transport-agnostic Delta receive boundary (spec §11.2.4).
 *
 * Every transport — RFed (§11.1), LXMF store-and-forward (§11.2), and optical
 * Paper Messages (§11.3) — funnels incoming bytes through one identical path:
 * decode the §5.3 Operation payload, authenticate it via verify-on-ingest
 * (§5.2 / §11.2.4), and merge it into the CRDT. `DeltaReceiver` is that shared
 * boundary. Malformed or unauthenticated Deltas are dropped silently rather
 * than propagated into state or crashing a transport callback.
 *
 * This keeps the (optional) transport adapters thin: an adapter only has to
 * hand received bytes to `DeltaReceiver.applyPayload()`, regardless of whether
 * they arrived over RFed, LXMF, or a scanned QR code.
 */
export class DeltaReceiver {
    /**
     * Encode a list of §5.3 Operation payloads as a batch (§11.1). Inverse of
     * `applyPayloads()`: `MsgPack.encode([...])` of already-signed Operation
     * payload byte-strings, suitable for publishing as one bulk sync message.
     * @param {Uint8Array[]} operationPayloads
     * @returns {Uint8Array}
     */
    static packPayloads(operationPayloads: Uint8Array[]): Uint8Array;
    /**
     * Decode -> verify -> apply incoming Delta payloads (§11.2.4).
     * @param {import("./crdt.d.ts").StateVector} state
     * @param {import("./verifier.d.ts").KeyResolver | import("./verifier.d.ts").Keyring} keyResolver
     */
    constructor(state: import("./crdt.d.ts").StateVector, keyResolver: import("./verifier.d.ts").KeyResolver | import("./verifier.d.ts").Keyring);
    _state: import("./crdt.d.ts").StateVector;
    _resolver: import("./verifier.d.ts").Keyring | import("./verifier.d.ts").KeyResolver;
    /**
     * Apply one wire-format Delta.
     *
     * Returns `true` iff the payload decoded, authenticated, and was applied to
     * the CRDT. Malformed payloads are swallowed (return `false`) — a transport
     * callback must never crash on arbitrary bytes. Signature and CRDT-level
     * rejection (unknown Issuer, bad sig, stale/future) is delegated to
     * `StateVector.ingest()`.
     * @param {Uint8Array} payload
     * @param {Object} [options]
     * @param {number} [options.nowMs]
     * @param {number | null} [options.maxFutureMs]
     * @returns {Promise<boolean>}
     */
    applyPayload(payload: Uint8Array, options?: {
        nowMs?: number;
        maxFutureMs?: number | null;
    }): Promise<boolean>;
    /**
     * Authenticate and apply a *batch* of Deltas (§11.1, §11.2.4).
     *
     * The secure alternative to `StateVector.merge()` for network sync.
     * `payload` is a MessagePack array of §5.3 Operation payloads
     * (`MsgPack.encode([opA.toPayload(), opB.toPayload(), ...])`); each element
     * is decoded and run through `applyPayload()`, i.e. it is independently
     * Ed25519/threshold-authenticated before it may touch state. A single
     * forged, stale (§9), or future-skewed (§12) element is dropped without
     * affecting the rest of the batch.
     *
     * Returns the number of Deltas authenticated *and* applied. A malformed
     * outer payload (not a MessagePack array, undecodable) yields `0` and is
     * swallowed, so a transport callback can never crash on arbitrary bytes —
     * exactly like `applyPayload()`.
     *
     * > **Warning:** This is the *only* safe entry point for full-state / bulk
     * > convergence received over the network. `StateVector.merge()` /
     * > `StateVector.fromPayload()` are trusted-local snapshot primitives that
     * > perform **no** signature verification and **must not** be fed network
     * > bytes.
     *
     * @param {Uint8Array} payload A MessagePack array of Operation payloads.
     * @param {Object} [options]
     * @param {number} [options.nowMs]
     * @param {number | null} [options.maxFutureMs]
     * @returns {Promise<number>}
     */
    applyPayloads(payload: Uint8Array, options?: {
        nowMs?: number;
        maxFutureMs?: number | null;
    }): Promise<number>;
}
