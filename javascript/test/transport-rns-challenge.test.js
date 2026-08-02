import { describe, it, before } from "node:test";
import assert from "node:assert/strict";
import { Identity } from "@reticulum/core";
import {
  AuthoritativeServer,
  Challenge,
  Receipt,
  Verdict,
} from "../src/challenge.js";
import { Config } from "../src/config.js";
import { StateVector } from "../src/crdt.js";
import { HASH_SIZE, NamespaceHasher } from "../src/namespace.js";
import { Action, Operation } from "../src/operation.js";
import { Tuple } from "../src/tuple.js";
import { packHlc } from "../src/hlc.js";
import {
  CHALLENGE_REQUEST_PATH,
  RnsLinkTransport,
  challengeRequestHandler,
} from "../src/transport/rnsChallenge.js";

const SALT = Uint8Array.from({ length: 32 }, (_, i) => i);
const HASHER = new NamespaceHasher(SALT);
const ROOT = Uint8Array.from({ length: HASH_SIZE }, (_, i) => i);
const BOB = Uint8Array.from({ length: HASH_SIZE }, (_, i) => i + HASH_SIZE);
const BASE = 1_700_000_000_000;

/** @returns {Promise<StateVector>} BOB may calibrate sensor:wind, issued by ROOT. */
async function allowState() {
  const state = new StateVector();
  state.apply(
    new Operation({
      tuple: await Tuple.fromPlaintext({
        objectId: "sensor:wind", relation: "calibrate", grantee: BOB, issuer: ROOT, hasher: HASHER,
      }),
      action: Action.GRANT,
      hlc: packHlc(BASE, 0),
    }),
    { nowMs: BASE },
  );
  return state;
}

function config() {
  return new Config({ rootTrustAnchors: [ROOT], primarySalt: SALT, authoritativeIdentity: ROOT });
}

/** LinkStatus.ACTIVE == 2, CLOSED == 4 (@reticulum/core transport/link.js). */
const ACTIVE = 2;
const CLOSED = 4;

/**
 * Fakes the `@reticulum/core` `Link.request` contract used by RnsLinkTransport:
 * throws when not ACTIVE, rejects on failure/timeout, otherwise resolves the
 * response value.
 */
class FakeLink {
  /**
   * @param {Object} opts
   * @param {number} [opts.status]
   * @param {Uint8Array | null} [opts.response]
   * @param {boolean} [opts.fail]
   * @param {number} [opts.delayMs]
   */
  constructor({ status = ACTIVE, response = null, fail = false, delayMs = 0 } = {}) {
    this.status = status;
    this._response = response;
    this._fail = fail;
    this._delayMs = delayMs;
    /** @type {string | null} */ this.lastPath = null;
    /** @type {Uint8Array | null} */ this.lastData = null;
    this.requested = false;
  }
  /** @param {string} path @param {Uint8Array} data @param {Object} [opts] */
  async request(path, data, opts = {}) {
    // Mirrors the real Link.request, which throws on the FIRST line before any
    // side effect — so an inactive link records nothing.
    if (this.status !== ACTIVE) {
      throw new Error("Link must be ACTIVE to issue a REQUEST.");
    }
    this.lastPath = path;
    this.lastData = data;
    this.lastTimeout = opts.timeout;
    if (this._delayMs > 0) await new Promise((r) => setTimeout(r, this._delayMs));
    if (this._fail) throw new Error("request failed");
    this.requested = true;
    return this._response;
  }
}

describe("challengeRequestHandler (§8.4)", () => {
  /** @type {Identity} */ let identity;
  /** @type {Uint8Array} */ let publicKey;

  before(async () => {
    identity = await Identity.generate();
    publicKey = await identity.getPublicKey();
  });

  it("returns a signed ALLOW receipt for a granted request", async () => {
    const server = new AuthoritativeServer(config(), await allowState(), identity);
    const handler = challengeRequestHandler(server);
    const challenge = Challenge.generate("sensor:wind", "calibrate", BOB, config().hashers);
    const payload = await handler(CHALLENGE_REQUEST_PATH, await challenge.toPayload(), new Uint8Array(16), null, 0);
    assert.ok(payload instanceof Uint8Array);
    const receipt = Receipt.fromPayload(payload);
    assert.equal(receipt.verdict, Verdict.ALLOW);
    assert.equal(await receipt.verify(publicKey), true);
    assert.deepEqual(receipt.nonce, challenge.nonce);
  });

  it("returns a signed DENY receipt without a grant", async () => {
    const server = new AuthoritativeServer(config(), new StateVector(), identity);
    const handler = challengeRequestHandler(server);
    const challenge = Challenge.generate("sensor:wind", "calibrate", BOB, config().hashers);
    const payload = await handler(CHALLENGE_REQUEST_PATH, await challenge.toPayload(), new Uint8Array(16), null, 0);
    const receipt = Receipt.fromPayload(payload);
    assert.equal(receipt.verdict, Verdict.DENY);
    assert.equal(await receipt.verify(publicKey), true); // still properly signed
  });

  it("returns null (no response) for a malformed payload → partition → DENY", async () => {
    const server = new AuthoritativeServer(config(), await allowState(), identity);
    const handler = challengeRequestHandler(server);
    assert.equal(
      await handler(CHALLENGE_REQUEST_PATH, new TextEncoder().encode("not msgpack"), new Uint8Array(16), null, 0),
      null,
    );
  });
});

describe("RnsLinkTransport (§8)", () => {
  it("resolves the receipt bytes on response", async () => {
    const receipt = (await new Receipt({ verdict: Verdict.ALLOW, serverHlc: packHlc(1, 0), nonce: new Uint8Array(32) }).sign(await Identity.generate())).toPayload();
    const link = new FakeLink({ response: receipt });
    const transport = new RnsLinkTransport(link);
    assert.deepEqual(await transport.call(new TextEncoder().encode("challenge")), receipt);
    assert.equal(link.lastPath, CHALLENGE_REQUEST_PATH);
    assert.equal(link.requested, true);
  });

  it("returns null on a failed/timeout request (partition → DENY)", async () => {
    const link = new FakeLink({ fail: true });
    const transport = new RnsLinkTransport(link, { timeoutMs: 250 });
    assert.equal(await transport.call(new TextEncoder().encode("challenge")), null);
  });

  it("returns null for a non-byte response", async () => {
    const link = new FakeLink({ response: null });
    const transport = new RnsLinkTransport(link);
    assert.equal(await transport.call(new TextEncoder().encode("challenge")), null);
  });

  it("returns null without requesting on an inactive link", async () => {
    const link = new FakeLink({ status: CLOSED });
    const transport = new RnsLinkTransport(link);
    assert.equal(await transport.call(new TextEncoder().encode("challenge")), null);
    assert.equal(link.requested, false); // request() threw before sending
    assert.equal(link.lastData, null);
  });
});

describe("establishLink (§8.2)", () => {
  it("returns null when the destination cannot be established", async () => {
    const { establishLink } = await import("../src/transport/rnsChallenge.js");
    // A destination whose interfaceLayer is missing → Link.initiate rejects.
    const fakeDest = /** @type {any} */ ({
      interfaceLayer: { transport: { registerLink() { throw new Error("no route"); } } },
    });
    assert.equal(await establishLink(fakeDest, { timeoutMs: 250 }), null);
  });
});
