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
 * rfed service destination names (SPEC §2), all sharing the node identity.
 * Mirrors Python's ``dacar.rfed.constants`` and ``@reticulum/core``'s internal
 * ``client.js`` constants. Used to compute per-destination hashes so dacar can
 * request transport paths to the *specific* rfed service a link targets
 * (a path to ``rfed.node`` does not establish a route to ``rfed.channel.*``).
 */
const RFED_SUBSCRIBE_DEST = "rfed.channel.subscribe";
const RFED_PULL_DEST = "rfed.channel.pull";
const RFED_PUBLISH_DEST = "rfed.channel.publish";

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
 * How long {@link ensureRfedPath} waits for a path-response announce after
 * sending a `path?` request before giving up, in milliseconds. Mirrors rngit's
 * `PATH_TIMEOUT` (15 s) and Python's `DEFAULT_PATH_TIMEOUT`.
 */
export const DEFAULT_PATH_TIMEOUT = 15_000;

/**
 * Ensure a transport path to a specific rfed service destination before the
 * client links to it.
 *
 * `@reticulum/core`'s `RFedClient` opens a `Link` via `Destination.createLink()`,
 * which sends a `LINKREQUEST` addressed to the *derived* channel destination
 * (e.g. `rfed.channel.subscribe`). The JS `Link` does not proactively request a
 * path before the first attempt — and a `LINKREQUEST` to a destination with no
 * known route is silently dropped by multi-hop peers (Transport "branch 5"),
 * so the link times out with no recourse. This mirrors rngit's
 * `RNS.Transport.await_path` and the LXMF router's `_requestAndAwaitPath`:
 * compute the derived destination hash, send a `path?` request for it, and wait
 * for the node's path-response announce to populate the path table before the
 * client links.
 *
 * A path to `rfed.node` does **not** establish a route to `rfed.channel.*` (RNS
 * path entries are per-destination-hash), so the *specific* service destination
 * a link targets must be requested. The node identity must already be
 * recallable (call {@link ensureNodeIdentity} first). No-op when a path is
 * already known, or when the transport lacks the path API (mock/test
 * transports). Throws if none is found within `timeout`.
 * @param {import("@reticulum/core").Reticulum} rns A booted Reticulum.
 * @param {Uint8Array} nodeHash An `rfed.*` destination hash of the node.
 * @param {string} destName The rfed service name (e.g. `rfed.channel.subscribe`).
 * @param {Object} [opts]
 * @param {number} [opts.timeout=15000] Max wait in milliseconds.
 * @param {number} [opts.pollInterval=100] Poll interval in milliseconds.
 * @param {() => void} [opts.onRequest] Invoked once when the path request fires.
 * @returns {Promise<Uint8Array>} The resolved destination hash.
 */
export async function ensureRfedPath(
  rns,
  nodeHash,
  destName,
  { timeout = DEFAULT_PATH_TIMEOUT, pollInterval = 100, onRequest } = {},
) {
  const identity = await Destination.recall(nodeHash);
  if (!identity) {
    throw new Error(
      `rfed node identity unknown for ${toHex(nodeHash)}; wait for its announce`,
    );
  }
  const destHash = await _singleDestinationHash(identity, destName);
  const transport = rns?.transport;
  // No-op when a path is already known.
  if (transport?.hasPath?.(destHash)) return destHash;
  // Mock/test transports without the path-discovery API: nothing to wait for.
  if (!transport?.requestPath) return destHash;
  if (onRequest) onRequest();
  await transport.requestPath(destHash).catch(() => {});
  // A fast path-response may already have been ingested.
  if (transport.hasPath?.(destHash)) return destHash;
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    if (transport.hasPath?.(destHash)) return destHash;
    await new Promise((resolve) => setTimeout(resolve, pollInterval));
  }
  throw new Error(
    `no path to ${toHex(destHash)} (${destName}) could be resolved ` +
      `within ${timeout}ms (is the rfed node announcing and reachable?)`,
  );
}

/**
 * Publish signed Deltas to the rfed channel (§11.1, work doc #4/#10/#11).
 *
 * Testable core: takes an explicit `client` (`RFedClient` or compatible
 * fake) so tests inject doubles without booting RNS. The `cmd_*` wrappers
 * handle RNS boot + announce + real client creation.
 *
 * Subscribes **once** then publishes each Delta as its own compact inner-format
 * message (one §5.3 Operation per envelope, §11.1.1) — RNS is a singleton that
 * cannot be re-booted, and re-subscribing per Delta would be wasteful. Returns
 * a per-Delta list of transport-acceptance flags (fire-and-forget: transport
 * acceptance ≠ node storage). The caller records accepted deltas in the sent
 * box / removes them from the outbox (work doc #11).
 * @param {Object} opts
 * @param {Uint8Array[]} opts.deltaPayloads Signed §5.3 Operation payloads.
 * @param {Uint8Array} opts.nodeHash The rfed node's `rfed.*` destination hash.
 * @param {string} [opts.topic] RFed channel name (default `dacar.policy.v1`).
 * @param {import("../transport/rfedSync.js").RFedClientLike} opts.client
 * @param {import("@reticulum/core").Reticulum} [opts.rns] A booted
 *   Reticulum. When given, transport paths to the rfed `subscribe` +
 *   `publish` destinations are requested before the client links (rngit
 *   `await_path` pattern); omitted in tests that inject a fake client.
 * @returns {Promise<boolean[]>}
 */
export async function runPublishMany({ deltaPayloads, nodeHash, topic, client, rns = null }) {
  const sync = new RfedDeltaSync({ client, topic });
  if (rns) {
    await ensureRfedPath(rns, nodeHash, RFED_SUBSCRIBE_DEST);
    await ensureRfedPath(rns, nodeHash, RFED_PUBLISH_DEST);
  }
  const result = await sync.subscribe(nodeHash);
  if (result?.ok === false) {
    throw new Error(
      `rfed subscribe to ${toHex(nodeHash)} failed; the node rejected the ` +
        "subscription (signature/channel mismatch) or returned no response — " +
        "the topic will not sync with peers",
    );
  }
  // Per-Delta transport acceptance (fire-and-forget: transport acceptance ≠
  // node storage). The caller records accepted deltas in the sent box /
  // removes them from the outbox (doc #11).
  const accepted = [];
  for (const payload of deltaPayloads) {
    accepted.push(await sync.publish(payload, nodeHash));
  }
  return accepted;
}

/**
 * Publish a single signed Delta to the rfed channel (§11.1, work doc #4).
 *
 * Thin convenience wrapper over {@link runPublishMany} for the single-Delta
 * case (`grant --publish` / `revoke --publish`). Returns the per-Delta
 * transport acceptance.
 * @param {Object} opts
 * @param {Uint8Array} opts.deltaPayload Signed §5.3 Operation payload.
 * @param {Uint8Array} opts.nodeHash The rfed node's `rfed.*` destination hash.
 * @param {string} [opts.topic] RFed channel name (default `dacar.policy.v1`).
 * @param {import("../transport/rfedSync.js").RFedClientLike} opts.client
 * @param {import("@reticulum/core").Reticulum} [opts.rns] A booted
 *   Reticulum. When given, transport paths to the rfed `subscribe` +
 *   `publish` destinations are requested before the client links (rngit
 *   `await_path` pattern); omitted in tests that inject a fake client.
 * @returns {Promise<boolean>}
 */
export async function runPublish({ deltaPayload, nodeHash, topic, client, rns = null }) {
  const [accepted] = await runPublishMany({
    deltaPayloads: [deltaPayload],
    nodeHash,
    topic,
    client,
    rns,
  });
  return accepted;
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
 * @param {import("@reticulum/core").Reticulum} [opts.rns] A booted
 *   Reticulum. When given, transport paths to the rfed `subscribe` + `pull`
 *   destinations are requested before the client links (rngit `await_path`
 *   pattern); omitted in tests that inject a fake client.
 * @returns {Promise<number>}
 */
export async function runSync({ nodeHash, topic, client, receiver, rns = null }) {
  const sync = new RfedDeltaSync({ receiver, client, topic });
  if (rns) {
    await ensureRfedPath(rns, nodeHash, RFED_SUBSCRIBE_DEST);
    await ensureRfedPath(rns, nodeHash, RFED_PULL_DEST);
  }
  const result = await sync.subscribe(nodeHash);
  if (result?.ok === false) {
    throw new Error(
      `rfed subscribe to ${toHex(nodeHash)} failed; the node rejected the ` +
        "subscription (signature/channel mismatch) or returned no response — " +
        "the topic will not sync with peers",
    );
  }
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
 * Compute the 16-byte SINGLE destination hash for ``name`` under ``identity``.
 *
 * ``nameHash = SHA-256(name)[:10]``; ``destHash = SHA-256(nameHash ‖
 * identityHash)[:16]`` — matching ``@reticulum/core``'s
 * ``Destination._computeHashes``. Generalised from {@link _dacarNodeHash} so any
 * rfed service destination (``rfed.channel.subscribe`` etc.) hash can be derived
 * to request a transport path to it.
 * @param {import("@reticulum/core").Identity} identity
 * @param {string} name The full dotted destination name (e.g. ``rfed.node``).
 * @returns {Promise<Uint8Array>}
 */
async function _singleDestinationHash(identity, name) {
  const encoder = new TextEncoder();
  const nameHash = new Uint8Array(
    (await crypto.subtle.digest("SHA-256", encoder.encode(name))).slice(0, 10),
  );
  const combined = new Uint8Array(nameHash.length + identity.identityHash.length);
  combined.set(nameHash, 0);
  combined.set(identity.identityHash, nameHash.length);
  return new Uint8Array((await crypto.subtle.digest("SHA-256", combined)).slice(0, 16));
}

/**
 * Compute the `dacar.node` destination hash for an identity (§11.2.4).
 *
 * Delegates to {@link _singleDestinationHash} with the ``dacar.node`` name.
 * @param {import("@reticulum/core").Identity} identity
 * @returns {Promise<Uint8Array>}
 */
async function _dacarNodeHash(identity) {
  return await _singleDestinationHash(identity, `${APP_NAME}.node`);
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
