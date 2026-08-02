/**
 * §8 Strict Consistency Challenge over a real RNS Link.
 *
 * Optional transport wiring around the already pure-and-tested §8 logic
 * (`Challenge`, `AuthoritativeServer`, `Receipt`, `ChallengeClient` from
 * `../challenge.js`). Three pieces:
 *
 *   - `challengeRequestHandler(server)` builds the response_generator a server
 *     registers on the `dacar.auth.v1` destination: it feeds each incoming
 *     challenge payload to `AuthoritativeServer.handle()` and returns the
 *     signed Freshness Receipt bytes (or nothing on a malformed challenge).
 *   - `RnsChallengeServer` exposes an Authoritative Identity on
 *     `dacar.auth.v1`, accepts Links, and registers that handler.
 *   - `RnsLinkTransport` is the client-side
 *     {@link import("../challenge.js").Transport Transport} callable: it sends
 *     a challenge payload over an established Link and awaits the signed
 *     receipt, returning `null` on timeout/partition (which §8 treats as DENY).
 *   - `establishLink()` opens a Link and awaits ACTIVE.
 *
 * The Dacar-specific glue (handler wrapping, partition → DENY) is covered by
 * injected-fake unit tests; the pure §8 protocol is covered by
 * `test/challenge.test.js`.
 *
 * This module is part of the optional transport layer: importing the pure core
 * never pulls it in. It depends only on `@reticulum/core` (Destination, Link),
 * which the core already depends on.
 */

import { Destination, DestType, Link } from "@reticulum/core";
import { APP_NAME, CHALLENGE_ASPECTS } from "../naming.js";

/** The RNS request path used for the Challenge exchange (§8). */
export const CHALLENGE_REQUEST_PATH = "challenge";

/** Default Challenge round-trip timeout in milliseconds. Partition → §8 DENY. */
export const DEFAULT_CHALLENGE_TIMEOUT_MS = 15_000;

/** Default Link establishment timeout in milliseconds (§8.2). */
export const DEFAULT_ESTABLISH_TIMEOUT_MS = 15_000;

/**
 * @typedef {import("../challenge.js").AuthoritativeServer} AuthoritativeServer
 * @typedef {import("@reticulum/core").Destination} DestinationType
 * @typedef {import("@reticulum/core").Link} LinkType
 * @typedef {import("@reticulum/core").Identity} IdentityType
 * @typedef {import("../challenge.js").Transport} Transport
 */

/**
 * @callback ResponseGenerator
 * @param {string} path
 * @param {any} data The §8.3 challenge payload (a `Uint8Array`).
 * @param {Uint8Array} requestId
 * @param {IdentityType | null} remoteIdentity
 * @param {number} requestTime
 * @returns {Promise<Uint8Array | null>}
 */

/**
 * Builds the response_generator answering Challenge requests (§8.4).
 *
 * The returned callable matches the `@reticulum/core` `responseGenerator`
 * contract (PROTOCOL-SPEC.md §11.2): it feeds `data` (the §8.3 challenge
 * payload) to `AuthoritativeServer.handle()` and returns the signed Receipt
 * payload. Malformed or unprocessable challenges yield `null` (no response),
 * which the client treats as a partition → DENY (§8).
 * @param {AuthoritativeServer} server
 * @returns {ResponseGenerator}
 */
export function challengeRequestHandler(server) {
  return async (_path, data) => {
    try {
      return await server.handle(data);
    } catch {
      return null; // malformed/unprocessable → no response → partition → DENY (§8)
    }
  };
}

/**
 * Authoritative endpoint: answers Challenge requests over RNS Links (§8).
 *
 * Because destination creation is asynchronous, construct via the static
 * {@link RnsChallengeServer.create} factory. The server creates the
 * `dacar.auth.v1` destination for `identity`, accepts Links, registers the
 * Challenge request handler, and (by default) announces so clients can find
 * it. A running `Reticulum` instance is assumed.
 */
export class RnsChallengeServer {
  /** The request path Challenge requests are served on (§8). */
  static REQUEST_PATH = CHALLENGE_REQUEST_PATH;

  /**
   * @param {Object} opts
   * @param {IdentityType} opts.identity The Authoritative Identity (signs receipts).
   * @param {AuthoritativeServer} opts.server The pure §8 authoritative evaluator.
   * @param {import("@reticulum/core").Reticulum} opts.rns A running Reticulum instance.
   * @param {string} [opts.appName] Override the `dacar` app name.
   * @param {readonly string[]} [opts.aspects] Override the `auth.v1` aspects.
   * @param {boolean} [opts.announce] Whether to announce immediately (default true).
   * @returns {Promise<RnsChallengeServer>}
   */
  static async create({
    identity,
    server,
    rns,
    appName = APP_NAME,
    aspects = CHALLENGE_ASPECTS,
    announce = true,
  }) {
    const self = new RnsChallengeServer(server);
    const name = [appName, ...aspects].join(".");

    // Build the `dacar.auth.v1` IN SINGLE destination and bind it to the
    // transport so routed packets reach it (mirrors LXMRouter.init).
    const dest = await Destination.IN(name, DestType.SINGLE, identity, rns);
    rns.transport.bindLocalDestination(dest);
    rns.registerDestination(dest);

    // Accept Links so clients can issue Challenge requests over them.
    dest.addEventListener("link_request", async (/** @type {any} */ event) => {
      try {
        await dest.acceptLink(event.detail.packet);
      } catch {
        // A failed handshake tears itself down; never fatal to the server.
      }
    });

    await dest.registerRequestHandler(RnsChallengeServer.REQUEST_PATH, {
      responseGenerator: challengeRequestHandler(server),
    });

    if (announce) await dest.announce();
    self._destination = dest;
    return self;
  }

  /** @param {AuthoritativeServer} server */
  constructor(server) {
    /** @type {AuthoritativeServer} */
    this._server = server;
    /** @type {DestinationType | null} */
    this._destination = null;
  }

  /** @returns {AuthoritativeServer} */
  get server() {
    return this._server;
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
   * (Re)announce the destination so clients can resolve a path to it.
   * @returns {Promise<void>}
   */
  async announce() {
    if (!this._destination) throw new Error("Server not created");
    await this._destination.announce();
  }
}

/**
 * Client-side {@link Transport} over an established Link.
 *
 * Call it with the §8.3 challenge payload: it issues an RNS request on the
 * link and resolves with the signed Receipt bytes, or `null` on any failure —
 * a non-ACTIVE link, a send failure, a timeout, or a partition — which
 * {@link import("../challenge.js").ChallengeClient ChallengeClient} treats as
 * a partition → DENY (§8).
 *
 * `@reticulum/core`'s `Link.request()` throws when the link is not ACTIVE and
 * rejects on timeout/failure, so a single try/catch maps every failure mode to
 * the §8 partition penalty without issuing a request on a link that cannot
 * carry one.
 */
export class RnsLinkTransport {
  /** The request path Challenge requests are sent on (§8). */
  static REQUEST_PATH = CHALLENGE_REQUEST_PATH;

  /**
   * @param {LinkType} link An established (or establishable) RNS Link.
   * @param {Object} [opts]
   * @param {string} [opts.requestPath] Override the request path.
   * @param {number} [opts.timeoutMs] Round-trip timeout in milliseconds.
   */
  constructor(link, { requestPath = CHALLENGE_REQUEST_PATH, timeoutMs = DEFAULT_CHALLENGE_TIMEOUT_MS } = {}) {
    this._link = link;
    this._path = requestPath;
    this._timeoutMs = timeoutMs;
  }

  /**
   * @param {Uint8Array} challengePayload
   * @returns {Promise<Uint8Array | null>}
   */
  async call(challengePayload) {
    try {
      const response = await this._link.request(this._path, challengePayload, {
        timeout: this._timeoutMs,
      });
      if (!(response instanceof Uint8Array)) return null;
      return response;
    } catch {
      return null; // inactive link / send failure / timeout → partition → DENY (§8)
    }
  }
}

/**
 * Opens an RNS Link to `destination` and awaits ACTIVE (§8.2).
 *
 * @param {DestinationType} destination An OUT destination whose identity is the
 *   authoritative responder.
 * @param {Object} [opts]
 * @param {number} [opts.timeoutMs] Establishment timeout in milliseconds.
 * @returns {Promise<LinkType | null>} The active Link, or `null` if it could
 *   not be established within `timeoutMs` (partition → §8 DENY).
 */
export async function establishLink(destination, { timeoutMs = DEFAULT_ESTABLISH_TIMEOUT_MS } = {}) {
  let link;
  try {
    link = await Link.initiate(destination, destination.interfaceLayer.transport);
    return await link.whenActive(timeoutMs);
  } catch {
    if (link) {
      try {
        await link.teardown();
      } catch {
        // teardown is best-effort on a failed handshake
      }
    }
    return null;
  }
}
