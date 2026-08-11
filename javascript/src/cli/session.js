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

import { Destination, DestType, Identity, toHex } from "@reticulum/core";
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
export async function announceIdentity(identity, rns = null) {
  // `Destination.IN` is a static factory (`Destination.IN(name, type, identity,
  // interfaceLayer)`) — NOT a Direction enum value (unlike Python RNS's
  // `RNS.Destination.IN` constant). The destination must be bound to `rns` as
  // its interface layer, or `announce()` throws "Destination not bound to an
  // RNS instance." Mirrors `@reticulum/core`'s rfed/client.js `listen()`.
  const dest = await Destination.IN(
    `${APP_NAME}.node`,
    DestType.SINGLE,
    identity,
    rns,
  );
  await dest.announce();
  return dest.destinationHash;
}

/**
 * How long {@link ensureNodeIdentity} waits for a path-response announce
 * after sending a `path?` request before giving up, in milliseconds.
 */
export const DEFAULT_NODE_DISCOVERY_TIMEOUT = 15_000;

/**
 * Recall a node's identity, proactively requesting its path if unknown.
 *
 * When `--node <hash>` (or `--discover`) resolves to an rfed destination whose
 * announce isn't in the recall store yet, `RFedClient.subscribe` can't open a
 * link and fails with `rfed node identity unknown for <hash>; wait for its
 * announce`. Rather than fail immediately, this sends a `path?` request for
 * the destination and polls `Destination.recall` until the node's
 * path-response announce populates it (or `timeout` elapses), then returns
 * the identity.
 *
 * The rfed node announces every `rfed.*` destination under one shared
 * identity, so a path request for any of them is answered with an announce
 * that makes that identity recallable by destination hash.
 *
 * `onRequest` (if given) is invoked once when the path request is sent, so the
 * CLI can surface "requesting node identity…" progress to the user. Throws
 * the same `rfed node identity unknown for …` error the client raises if
 * still unknown after `timeout` — so callers that skip this helper see no
 * behavior change.
 * @param {import("@reticulum/core").Reticulum} rns A booted Reticulum.
 * @param {Uint8Array} nodeHash An `rfed.*` destination hash of the node.
 * @param {Object} [opts]
 * @param {number} [opts.timeout=15000] Max wait in milliseconds.
 * @param {number} [opts.pollInterval=250] Poll interval in milliseconds.
 * @param {() => void} [opts.onRequest] Invoked once when the path request fires.
 * @returns {Promise<import("@reticulum/core").Identity>}
 */
export async function ensureNodeIdentity(
  rns,
  nodeHash,
  { timeout = DEFAULT_NODE_DISCOVERY_TIMEOUT, pollInterval = 250, onRequest } = {},
) {
  let identity = await Destination.recall(nodeHash);
  if (identity) return identity;
  // Not yet known — proactively request the destination's path (§7.1). The
  // rfed node answers with a path-response announce (§7.2.4) that populates
  // the recall store; poll until it arrives or the timeout elapses.
  if (onRequest) onRequest();
  await rns.transport.requestPath(nodeHash);
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    identity = await Destination.recall(nodeHash);
    if (identity) return identity;
    await new Promise((resolve) => setTimeout(resolve, pollInterval));
  }
  throw new Error(
    `rfed node identity unknown for ${toHex(nodeHash)}; wait for its announce`,
  );
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
 * @returns {Promise<import("@reticulum/core/src/lxmf/index.js").LXMessage>}
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

/**
 * Autodiscover an rfed node from its `rfed.node` announce.
 *
 * Listens for a validated `rfed.node` announce on the live transport and
 * resolves with that announce's `destinationHash` — the rfed node's canonical
 * identifier (the same hash `--node <hash>` accepts and `RFedClient` recalls
 * to open a link).
 *
 * The rfed daemon is an external process (dacar ships only the client); it
 * announces `rfed.node` and the `rfed.channel.*` service destinations under
 * one shared identity. A `dacar.node` announce is a *different* thing — it is
 * a dacar peer advertising its own signing identity (the announce invariant,
 * §11.2.4), not an rfed transport node. Discovery therefore filters for
 * `rfed.node` announces (by `nameHash`), not `dacar.node`, and returns the
 * announced destination hash directly (no derivation — the announce *is* the
 * node hash).
 *
 * @param {Object} opts
 * @param {import("@reticulum/core").Reticulum} opts.rns A booted Reticulum.
 * @param {number} [opts.timeout=30000] Timeout in milliseconds.
 * @returns {Promise<Uint8Array>} The `rfed.node` destination hash of the
 *   discovered node.
 * @throws {CliError} If no `rfed.node` announce is received within the timeout.
 */
export async function discoverRfedNode({ rns, timeout = 30000 }) {
  if (!rns?.transport?.addEventListener) {
    throw new CliError("RNS transport not available for discovery");
  }
  const encoder = new TextEncoder();
  // nameHash = SHA-256("rfed.node")[:10] — matches `@reticulum/core`'s
  // Destination._computeHashes. The announce event carries this as
  // `detail.nameHash`; filtering on it selects only `rfed.node` announces
  // (the rfed.channel.* services share the identity but have different names).
  const expectedNameHash = new Uint8Array(
    (await crypto.subtle.digest("SHA-256", encoder.encode("rfed.node"))).slice(0, 10),
  );

  return new Promise((resolve, reject) => {
    let settled = false;

    const onAnnounce = (event) => {
      const detail = event.detail;
      if (!detail?.nameHash) return;
      // Only resolve on rfed.node announces.
      if (toHex(detail.nameHash) !== toHex(expectedNameHash)) return;
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      rns.transport.removeEventListener("announce", onAnnounce);
      // The announce's destinationHash *is* the rfed node's canonical hash.
      resolve(detail.destinationHash);
    };

    rns.transport.addEventListener("announce", onAnnounce);
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      rns.transport.removeEventListener("announce", onAnnounce);
      reject(
        new CliError(
          `no rfed.node announce received within ${timeout}ms ` +
            "(ensure an rfed node is reachable and announcing)",
        ),
      );
    }, timeout);
  });
}

class CliError extends Error {}
