/**
 * Direct-link Delta push over a real RNS Link (§11, work doc #16 Phase 4a).
 *
 * Optional transport wiring around the already pure-and-tested receive
 * boundary (`DeltaReceiver` from `../delta.js`). The use case is a constrained
 * node — e.g. an MCU running microReticulum — that cannot subscribe to rfed or
 * run an LXMF router: it exposes the `dacar.sync.v1` destination, and a peer
 * pushes raw §5.3 Delta payloads to it over Link requests. Verify-on-ingest
 * (§11.2.4) authenticates each Delta by the *issuer's* signature, so the
 * transport adds no trust — the same precedent as optical Paper Messages
 * (§11.3). The pusher therefore needs no Dacar state at all; its identity hash
 * is just a grantee.
 *
 * Three pieces:
 *
 *   - `handlePush()` is the transport-free inbound seam: it applies one
 *     request payload (a raw §5.3 Delta, or a §11.1 batch of them) to a
 *     `DeltaReceiver` and resolves with the applied count.
 *   - `syncRequestHandler()` wraps that into the `responseGenerator` a server
 *     registers on the `delta` request path; the response is the ack — a
 *     MessagePack map `{applied: <n>}` (byte-identical to the Python/C++
 *     acks).
 *   - `RnsSyncServer` exposes a node identity on `dacar.sync.v1`, accepts
 *     Links, registers the handler, and announces.
 *   - `pushDeltas()` is the client side: derive the target's `dacar.sync.v1`
 *     destination from its recalled identity, await a transport path, open a
 *     Link, and send one request per Delta, collecting per-Delta acceptance
 *     flags from the acks.
 *
 * An `applied === 0` ack means the node decoded the request but accepted
 * nothing (unknown issuer, bad signature, stale §9 / future-skewed §12); a
 * missing/undecodable response counts as failure. CRDT merge is idempotent,
 * so re-pushing after either outcome is always safe — the outbox drains only
 * on `applied >= 1`.
 *
 * This module is part of the optional transport layer: importing the pure core
 * never pulls it in. It depends only on `@reticulum/core` (Destination, Link,
 * MsgPack), which the core already depends on.
 */

import { Destination, DestType, Link, MsgPack } from "@reticulum/core";
import { APP_NAME, SYNC_ASPECTS } from "../naming.js";
import { establishLink, DEFAULT_ESTABLISH_TIMEOUT_MS } from "./rnsChallenge.js";

/** The RNS request path Deltas are pushed on. */
export const SYNC_REQUEST_PATH = "delta";

/** Default per-Delta round-trip timeout in milliseconds. */
export const DEFAULT_PUSH_TIMEOUT_MS = 15_000;

/** Default wait for the target's path-response announce, in milliseconds. */
export const DEFAULT_PATH_TIMEOUT_MS = 15_000;

/**
 * @typedef {import("../delta.js").DeltaReceiver} DeltaReceiverType
 * @typedef {import("@reticulum/core").Destination} DestinationType
 * @typedef {import("@reticulum/core").Link} LinkType
 * @typedef {import("@reticulum/core").Identity} IdentityType
 * @typedef {import("@reticulum/core").Reticulum} ReticulumType
 */

/**
 * Encodes the push ack: a MessagePack map `{applied: <n>}`.
 * @param {number} applied
 * @returns {Uint8Array}
 */
export function packAck(applied) {
  return MsgPack.encode({ applied: Math.max(0, Math.trunc(applied)) });
}

/**
 * Decodes a push ack; `null` when missing/undecodable (counts as failure).
 *
 * Returns the applied count (`0` = the node refused the Delta — kept in the
 * sender's outbox; `>= 1` = accepted and merged).
 * @param {Uint8Array | null | undefined} data
 * @returns {number | null}
 */
export function unpackAck(data) {
  if (!data || !data.length) return null;
  let decoded;
  try {
    decoded = MsgPack.decode(data);
  } catch {
    return null;
  }
  if (typeof decoded !== "object" || decoded === null || Array.isArray(decoded)) {
    return null;
  }
  const applied = decoded.applied;
  if (typeof applied !== "number" || !Number.isInteger(applied) || applied < 0) {
    return null;
  }
  return applied;
}

/**
 * Transport-free inbound seam: apply one push request to `receiver`.
 *
 * Tries the payload as a single raw §5.3 Delta first, then as a §11.1 batch
 * (a MessagePack array of Delta payloads). The two shapes are unambiguous: an
 * Operation payload is an 8-element mixed array, a batch is an array of
 * binary elements. Resolves with the number of Deltas applied (0 = decoded
 * but nothing accepted, or undecodable garbage — never rejects: a request
 * handler must not crash on arbitrary bytes).
 * @param {DeltaReceiverType} receiver
 * @param {Uint8Array} data
 * @returns {Promise<number>}
 */
export async function handlePush(receiver, data) {
  if (!data || !data.length) return 0;
  if (await receiver.applyPayload(data)) return 1;
  try {
    return await receiver.applyPayloads(data);
  } catch {
    return 0;
  }
}

/**
 * @callback ResponseGenerator
 * @param {string} path
 * @param {Uint8Array} data
 * @param {Uint8Array} requestId
 * @param {LinkType | null} linkId
 * @param {IdentityType | null} remoteIdentity
 * @param {number} requestTime
 * @returns {Promise<Uint8Array | null>}
 */

/**
 * Builds the responseGenerator ingesting pushed Deltas (§11).
 *
 * The returned callable matches the `@reticulum/core` `responseGenerator`
 * contract: it feeds `data` to {@link handlePush} and resolves with the ack
 * bytes. Every outcome yields a response — even `{applied: 0}` — so the
 * pusher can distinguish "node refused (kept in outbox)" from "request lost
 * (retry)".
 * @param {DeltaReceiverType} receiver
 * @returns {ResponseGenerator}
 */
export function syncRequestHandler(receiver) {
  return async (_path, data) => {
    try {
      return packAck(await handlePush(receiver, data));
    } catch {
      return null;
    }
  };
}

/**
 * Direct-link Delta ingestion endpoint over RNS Links (§11, doc #16 4a).
 *
 * Because destination creation is asynchronous, construct via the static
 * {@link RnsSyncServer.create} factory. The server creates the
 * `dacar.sync.v1` destination for `identity`, accepts Links, registers the
 * Delta push request handler, and (by default) announces so pushers can
 * resolve a path. A running `Reticulum` instance is assumed. This is also the
 * seam an MCU firmware's request handler mirrors: verified Link identity →
 * `DeltaReceiver.applyPayload()` → act.
 */
export class RnsSyncServer {
  /** The request path pushed Deltas are served on. */
  static REQUEST_PATH = SYNC_REQUEST_PATH;

  /**
   * @param {Object} opts
   * @param {IdentityType} opts.identity The node identity (deltas are ingested
   *   by issuer signatures, not the server's — this signs nothing).
   * @param {DeltaReceiverType} opts.receiver The shared receive boundary.
   * @param {ReticulumType} opts.rns A running Reticulum instance.
   * @param {string} [opts.appName] Override the `dacar` app name.
   * @param {readonly string[]} [opts.aspects] Override the `sync.v1` aspects.
   * @param {boolean} [opts.announce] Whether to announce immediately (default true).
   * @returns {Promise<RnsSyncServer>}
   */
  static async create({
    identity,
    receiver,
    rns,
    appName = APP_NAME,
    aspects = SYNC_ASPECTS,
    announce = true,
  }) {
    const self = new RnsSyncServer(receiver);
    const name = [appName, ...aspects].join(".");

    // Build the `dacar.sync.v1` IN SINGLE destination and bind it to the
    // transport so routed packets reach it (mirrors RnsChallengeServer).
    const dest = await Destination.IN(name, DestType.SINGLE, identity, rns);
    rns.transport.bindLocalDestination(dest);
    rns.registerDestination(dest);

    // Accept Links so pushers can issue Delta requests over them.
    dest.addEventListener("link_request", async (/** @type {any} */ event) => {
      try {
        await dest.acceptLink(event.detail.packet);
      } catch {
        // A failed handshake tears itself down; never fatal to the server.
      }
    });

    await dest.registerRequestHandler(RnsSyncServer.REQUEST_PATH, {
      responseGenerator: syncRequestHandler(receiver),
    });

    if (announce) await dest.announce();
    self._destination = dest;
    return self;
  }

  /** @param {DeltaReceiverType} receiver */
  constructor(receiver) {
    /** @type {DeltaReceiverType} */
    this._receiver = receiver;
    /** @type {DestinationType | null} */
    this._destination = null;
  }

  /** @returns {DeltaReceiverType} */
  get receiver() {
    return this._receiver;
  }

  /** @returns {DestinationType | null} */
  get destination() {
    return this._destination;
  }

  /** @returns {Uint8Array | null} The 16-byte destination hash. */
  get destinationHash() {
    return this._destination ? this._destination.destinationHash : null;
  }

  /**
   * (Re)announce the destination so pushers can resolve a path to it.
   * @returns {Promise<void>}
   */
  async announce() {
    if (!this._destination) throw new Error("Server not created");
    await this._destination.announce();
  }
}

/**
 * Build the OUT `dacar.sync.v1` destination for a recalled identity and await
 * a transport path to it.
 *
 * `targetHash` must be recallable (an earlier announce or the durable keyring
 * path — the CLI seeds both before calling). Sends a `path?` request for the
 * derived destination hash and polls until the node's path-response announce
 * populates the path table (a `LINKREQUEST` to a destination with no known
 * route is silently dropped — see `ensureRfedPath` in cli/session for the
 * same rationale).
 *
 * @param {ReticulumType} rns A booted Reticulum.
 * @param {Uint8Array} targetHash The node's 16-byte identity hash.
 * @param {Object} [opts]
 * @param {string} [opts.appName] Override the `dacar` app name.
 * @param {readonly string[]} [opts.aspects] Override the `sync.v1` aspects.
 * @param {number} [opts.timeoutMs] Max path wait in milliseconds.
 * @param {number} [opts.pollIntervalMs] Poll interval in milliseconds.
 * @param {() => void} [opts.onRequest] Invoked once when the path request fires.
 * @returns {Promise<{destination: DestinationType, destinationHash: Uint8Array}>}
 * @throws {Error} When the identity is unknown or no path resolves in time.
 */
export async function ensureSyncPath(rns, targetHash, {
  appName = APP_NAME,
  aspects = SYNC_ASPECTS,
  timeoutMs = DEFAULT_PATH_TIMEOUT_MS,
  pollIntervalMs = 100,
  onRequest,
} = {}) {
  const identity = await rns.transport.recallIdentity(targetHash);
  if (!identity) {
    throw new Error(
      `node identity unknown for ${toHex(targetHash)}; ` +
        "wait for its announce (or `dacar identity remember` it)",
    );
  }
  const destination = await Destination.OUT(
    [appName, ...aspects].join("."), DestType.SINGLE, identity, rns,
  );
  const destinationHash = destination.destinationHash;
  const transport = rns?.transport;
  if (transport?.hasPath?.(destinationHash)) {
    return { destination, destinationHash };
  }
  if (!transport?.requestPath) {
    // Mock/test transports without the path-discovery API: nothing to wait for.
    return { destination, destinationHash };
  }
  if (onRequest) onRequest();
  await transport.requestPath(destinationHash).catch(() => {});
  if (transport.hasPath?.(destinationHash)) {
    return { destination, destinationHash };
  }
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (transport.hasPath?.(destinationHash)) {
      return { destination, destinationHash };
    }
    await new Promise((resolve) => setTimeout(resolve, pollIntervalMs));
  }
  throw new Error(
    `no path to ${toHex(destinationHash)} (${appName}.${aspects.join(".")}) ` +
      `resolved within ${timeoutMs}ms (is the node announcing and reachable?)`,
  );
}

/**
 * Push raw §5.3 Delta payloads to a node over one Link (§11, doc #16 4a).
 *
 * `targetHash` is the *node identity hash* (16 bytes) — the sync destination
 * `dacar.sync.v1` is derived from it. Opens one Link, sends one request per
 * payload, and parses each ack: `applied >= 1` → accepted (`true`); `applied
 * === 0` → the node refused (`false` — e.g. unknown issuer, stale §9,
 * future-skewed §12); no/undecodable response → `false` (lost request —
 * retry is safe, CRDT merge is idempotent).
 *
 * Returns the per-payload acceptance flags. The caller records accepted
 * Deltas in the sent box / drains them from the outbox (work doc #11 — the
 * same durable-issuance lifecycle as rfed/LXMF publishes).
 *
 * @param {Uint8Array[]} payloads Signed §5.3 Operation payloads.
 * @param {Uint8Array} targetHash The node's 16-byte identity hash.
 * @param {Object} opts
 * @param {ReticulumType} opts.rns A booted Reticulum instance.
 * @param {string} [opts.requestPath] Override the `delta` request path.
 * @param {number} [opts.timeoutMs] Per-Delta round-trip timeout in milliseconds.
 * @param {number} [opts.pathTimeoutMs] Path resolution timeout in milliseconds.
 * @param {number} [opts.establishTimeoutMs] Link establishment timeout.
 * @param {() => void} [opts.onRequest] Invoked once when the path request fires.
 * @returns {Promise<boolean[]>}
 */
export async function pushDeltas(payloads, targetHash, {
  rns,
  requestPath = SYNC_REQUEST_PATH,
  timeoutMs = DEFAULT_PUSH_TIMEOUT_MS,
  pathTimeoutMs = DEFAULT_PATH_TIMEOUT_MS,
  establishTimeoutMs = DEFAULT_ESTABLISH_TIMEOUT_MS,
  onRequest,
} = {}) {
  const { destination } = await ensureSyncPath(rns, targetHash, {
    timeoutMs: pathTimeoutMs,
    onRequest,
  });
  const link = await establishLink(destination, { timeoutMs: establishTimeoutMs });
  if (!link) return payloads.map(() => false);

  /** @type {boolean[]} */
  const accepted = [];
  try {
    for (const payload of payloads) {
      accepted.push(await pushOne(link, requestPath, payload, timeoutMs));
    }
  } finally {
    try {
      await link.teardown();
    } catch {
      // teardown is best-effort; results already collected
    }
  }
  return accepted;
}

/**
 * Send one Delta as a Link request and resolve with the ack verdict.
 *
 * Exported as the client-side seam (mirrors the Python ``_push_one``): an
 * inactive link, a send failure, a timeout, an undecodable response, and an
 * `{applied: 0}` refusal all resolve `false` — every failure mode is
 * retry-safe because CRDT merge is idempotent.
 *
 * @param {LinkType} link
 * @param {string} requestPath
 * @param {Uint8Array} payload
 * @param {number} timeoutMs
 * @returns {Promise<boolean>}
 */
export async function pushOne(link, requestPath, payload, timeoutMs) {
  try {
    const response = await link.request(requestPath, payload, { timeout: timeoutMs });
    if (!(response instanceof Uint8Array)) return false;
    const applied = unpackAck(response);
    return applied !== null && applied >= 1;
  } catch {
    return false; // inactive link / send failure / timeout → retry-safe failure
  }
}

/**
 * @param {Uint8Array} bytes
 * @returns {string}
 */
function toHex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}
