/**
 * Portable RNS session + online command helpers (work doc #6, §11.1).
 *
 * Browser- and Node-portable: no filesystem, no argv. The caller constructs a
 * `Reticulum` (with its own `StorageAdapter`) and passes it in — keeping
 * shared-instance discovery out of the portable core (the same decision
 * `@reticulum/core` itself makes). A Node/Deno CLI (`dacar.js`) composes these
 * helpers with `@reticulum/node`'s interfaces and `FileStorageAdapter`.
 *
 * This module is part of the CLI layer but has **no** Node-only dependencies:
 * it imports only `@reticulum/core` (already a core dep) and the dacar pure
 * core. It mirrors Python's `dacar/cli/rns.py` + `run_publish`/`run_sync`.
 */

import { Destination, Identity } from "@reticulum/core";
import { APP_NAME } from "../naming.js";
import { RfedDeltaSync } from "../transport/rfedSync.js";

/**
 * Announce the node's identity on the `dacar.node` destination (§11.2.4).
 *
 * Any announced destination under an identity makes that identity recallable by
 * peers via `Destination.recall(hash, true)` — the announce invariant: without
 * it, receivers drop the node's signed Deltas as "unknown issuer" because the
 * `RnsIdentityResolver` cannot recall the issuer's public key.
 *
 * Returns the announced destination hash. Call before publishing or pulling.
 * @param {import("@reticulum/core").Identity} identity
 * @returns {Promise<Uint8Array>}
 */
export async function announceIdentity(identity) {
  const dest = await Destination.IN(`${APP_NAME}.node`, "single", identity, null);
  await dest.announce();
  return dest.destinationHash;
}

/**
 * Publish a signed Delta to the rfed channel (§11.1, work doc #6).
 *
 * Testable core: takes an explicit `client` (`RFedClient` or compatible fake)
 * so tests inject doubles without booting RNS. The `cmd_*` wrappers handle RNS
 * boot + announce + real client creation.
 * @param {Object} opts
 * @param {Uint8Array} opts.deltaPayload Signed §5.3 Operation payload.
 * @param {Uint8Array} opts.nodeHash The rfed node's `rfed.*` destination hash.
 * @param {string} [opts.topic] RFed channel name (default `dacar.policy.v1`).
 * @param {import("../transport/rfedSync.js").RFedClientLike} opts.client
 * @returns {Promise<import("@reticulum/core").LXMessage>}
 */
export async function runPublish({ deltaPayload, nodeHash, topic, client }) {
  const sync = new RfedDeltaSync({ client, topic });
  await sync.subscribe(nodeHash);
  return sync.publish(deltaPayload, nodeHash);
}

/**
 * Pull pending Deltas from the rfed channel and apply via verify-on-ingest.
 *
 * Testable core: takes an explicit `client` and `receiver` so tests inject
 * doubles. Routes every blob through `DeltaReceiver.applyPayload()` (§11.2.4)
 * — never through the unauthenticated `StateVector.merge()` path. Returns the
 * count applied (the caller persists the CRDT).
 * @param {Object} opts
 * @param {Uint8Array} opts.nodeHash
 * @param {string} [opts.topic]
 * @param {import("../transport/rfedSync.js").RFedClientLike} opts.client
 * @param {import("../delta.js").DeltaReceiver} opts.receiver
 * @returns {Promise<number>}
 */
export async function runSync({ nodeHash, topic, client, receiver }) {
  const sync = new RfedDeltaSync({ receiver, client, topic });
  await sync.subscribe(nodeHash);
  return sync.pull(nodeHash);
}

/**
 * Register a dacar-scoped announce handler that seeds the durable issuer cache
 * (work doc #5, design decision #3).
 *
 * Listens to the RNS transport `"announce"` event and, on a validated
 * `dacar.node` announce (verified by recomputing the destination hash under
 * the announced identity), registers the issuer's public key into `keyring`.
 * Non-`dacar` announces are ignored (dacar is not a general identity directory).
 * Returns an unsubscribe function.
 * @param {Object} opts
 * @param {import("@reticulum/core").Reticulum} opts.rns A booted Reticulum.
 * @param {import("../verifier.js").Keyring} opts.keyring
 * @param {(keyring: import("../verifier.js").Keyring) => void} [opts.onSave]
 *   Called after each seed so the caller can persist the keyring.
 * @returns {Promise<{ unsubscribe: () => void, seeded: number }>}
 */
export async function registerAnnounceHandler({ rns, keyring, onSave }) {
  /** @type {() => void} */ let unsubscribe = () => {};
  const state = { seeded: 0 };

  // The transport emits a CustomEvent("announce", { detail }) on each validated
  // announce. We filter to dacar.node and seed the keyring.
  const handler = async (event) => {
    const detail = event.detail;
    if (!detail || !detail.identity) return;
    const announced = detail.identity;
    const announcedDestHash = detail.destinationHash;
    if (!(announcedDestHash instanceof Uint8Array)) return;
    // Only dacar.node: recompute the destination hash under the dacar app.
    const expected = await _dacarNodeHash(announced);
    const { toHex } = await import("@reticulum/core");
    if (toHex(announcedDestHash) !== toHex(expected)) return; // not dacar.node
    const publicKey = await announced.getPublicKey();
    keyring.registerSingle(announced.identityHash, publicKey);
    state.seeded += 1;
    if (onSave) onSave(keyring);
  };

  // core's TransportCore is an EventTarget on `rns.transport`.
  if (rns && rns.transport && typeof rns.transport.addEventListener === "function") {
    rns.transport.addEventListener("announce", handler);
    unsubscribe = () => rns.transport.removeEventListener("announce", handler);
  }
  return { unsubscribe, get seeded() { return state.seeded; } };
}

/**
 * Compute the `dacar.node` destination hash for an identity (§11.2.4).
 *
 * `nameHash = SHA-256("dacar.node")[:10]`; `destHash = SHA-256(nameHash ‖
 * identityHash)[:16]` — matching `@reticulum/core`'s `Destination._computeHashes`.
 * @param {import("@reticulum/core").Identity} identity
 * @returns {Promise<Uint8Array>}
 */
async function _dacarNodeHash(identity) {
  const encoder = new TextEncoder();
  const nameBytes = encoder.encode(`${APP_NAME}.node`);
  const nameHashBuffer = await crypto.subtle.digest("SHA-256", nameBytes);
  const nameHash = new Uint8Array(nameHashBuffer.slice(0, 10));
  const combined = new Uint8Array(nameHash.length + identity.identityHash.length);
  combined.set(nameHash, 0);
  combined.set(identity.identityHash, nameHash.length);
  const destHashBuffer = await crypto.subtle.digest("SHA-256", combined);
  return new Uint8Array(destHashBuffer.slice(0, 16));
}
