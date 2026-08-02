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

import { Operation } from "./operation.js";

export class DeltaReceiver {
  /**
   * Decode -> verify -> apply incoming Delta payloads (§11.2.4).
   * @param {import("./crdt.js").StateVector} state
   * @param {import("./verifier.js").KeyResolver | import("./verifier.js").Keyring} keyResolver
   */
  constructor(state, keyResolver) {
    this._state = state;
    this._resolver = keyResolver;
  }

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
  async applyPayload(payload, options = {}) {
    let operation;
    try {
      operation = Operation.fromPayload(payload);
    } catch {
      return false; // malformed -> drop silently
    }
    return this._state.ingest(operation, this._resolver, options);
  }
}
