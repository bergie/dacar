/**
 * Smoketests for the direct-link Delta push transport (§11, doc #16 Phase 4a).
 *
 * Covers the new RNS glue around the already-tested `DeltaReceiver` boundary:
 *
 *   - `packAck` / `unpackAck` — the ack codec (a MessagePack map
 *     `{applied: <n>}`), byte-pinned so the Python/C++ ports produce and
 *     parse identical acks.
 *   - `handlePush` — the transport-free inbound seam: single §5.3 payload,
 *     §11.1 batch, garbage, duplicates, unknown issuer (verify-on-ingest).
 *   - `syncRequestHandler` — the `responseGenerator` wrapper.
 *   - `pushOne` — the client-side per-Delta request over a faked Link (ack →
 *     accepted, `applied: 0` → refused, lost request → retry-safe failure).
 *   - `ensureSyncPath` — unknown-identity rejection (no live network).
 *
 * The §8-style server (`RnsSyncServer.create`) and the full `pushDeltas` loop
 * need a live Reticulum; their Python counterparts cover the same seams with
 * fakes, and the two-process interop happens against real firmware/nodes.
 */

import { describe, it, before } from "node:test";
import assert from "node:assert/strict";
import { Identity } from "@reticulum/core";

import { Action, Operation } from "../src/operation.js";
import { Tuple } from "../src/tuple.js";
import { HASH_SIZE, NamespaceHasher } from "../src/namespace.js";
import { packHlc, physicalNowMs } from "../src/hlc.js";
import { StateVector } from "../src/crdt.js";
import { Keyring } from "../src/verifier.js";
import { DeltaReceiver } from "../src/delta.js";
import {
  SYNC_REQUEST_PATH,
  packAck,
  unpackAck,
  handlePush,
  syncRequestHandler,
  pushOne,
  ensureSyncPath,
} from "../src/transport/rnsSync.js";

const SALT = Uint8Array.from({ length: 32 }, (_, i) => i);
const HASHER = new NamespaceHasher(SALT);
const GRANTEE = Uint8Array.from({ length: HASH_SIZE }, (_, i) => i + HASH_SIZE);

/** LinkStatus.ACTIVE == 2 (@reticulum/core transport/link.js). */
const ACTIVE = 2;

/**
 * Fakes the `@reticulum/core` `Link.request` contract used by pushOne:
 * throws when not ACTIVE, rejects on failure/timeout, otherwise resolves the
 * response value.
 */
class FakeLink {
  /**
   * @param {Object} opts
   * @param {number} [opts.status]
   * @param {Uint8Array | Error | null} [opts.respond] Response for the next request.
   */
  constructor({ status = ACTIVE, respond = null } = {}) {
    this.status = status;
    this._respond = respond;
    this.requests = [];
    this.tornDown = false;
  }

  async request(path, data, _opts) {
    if (this.status !== ACTIVE) throw new Error("link not ACTIVE");
    this.requests.push({ path, data });
    if (this._respond instanceof Error) throw this._respond;
    return this._respond;
  }

  async teardown() {
    this.tornDown = true;
  }
}

describe("push ack codec (byte-pinned, cross-implementation)", () => {
  it("packAck produces the exact wire bytes (fixmap | fixstr | int)", () => {
    assert.deepEqual(packAck(1), Uint8Array.of(0x81, 0xa7, ...new TextEncoder().encode("applied"), 0x01));
  });

  it("round-trips applied counts", () => {
    for (const n of [0, 1, 7, 200]) {
      assert.equal(unpackAck(packAck(n)), n);
    }
  });

  it("unpackAck rejects missing/garbage/hostile acks", () => {
    assert.equal(unpackAck(null), null);
    assert.equal(unpackAck(new Uint8Array(0)), null);
    assert.equal(unpackAck(new TextEncoder().encode("not msgpack")), null);
    assert.equal(unpackAck(new TextEncoder().encode("…")), null); // invalid utf-8-ish garbage
  });
});

describe("handlePush — the transport-free inbound seam (§11.2.4)", () => {
  /** @type {Identity} */ let issuer;
  /** @type {Keyring} */ let keyring;
  /** @type {StateVector} */ let state;
  /** @type {DeltaReceiver} */ let receiver;

  before(async () => {
    issuer = await Identity.generate();
    keyring = new Keyring();
    keyring.registerSingle(issuer.identityHash, await issuer.getPublicKey());
  });

  const fresh = () => {
    state = new StateVector();
    receiver = new DeltaReceiver(state, keyring);
    return receiver;
  };

  async function signedPayload(opts = {}) {
    const { relation = "sound", objectId = "buzzer" } = opts;
    const tuple = await Tuple.fromPlaintext({
      objectId, relation, grantee: GRANTEE, issuer: issuer.identityHash, hasher: HASHER,
    });
    const op = await new Operation({
      tuple, action: Action.GRANT, hlc: packHlc(physicalNowMs(), 0),
    }).sign(issuer);
    return op.toPayload();
  }

  it("applies a single raw §5.3 Delta and returns 1", async () => {
    const rx = fresh();
    assert.equal(await handlePush(rx, await signedPayload()), 1);
    assert.equal([...state.activeTuples()].length, 1);
  });

  it("applies a §11.1 batch and returns the applied count", async () => {
    const rx = fresh();
    const { MsgPack } = await import("@reticulum/core");
    const batch = MsgPack.encode([await signedPayload({ relation: "sound" }), await signedPayload({ relation: "light" })]);
    assert.equal(await handlePush(rx, batch), 2);
    assert.equal([...state.activeTuples()].length, 2);
  });

  it("counts a duplicate re-push as applied (CRDT idempotency drains the outbox)", async () => {
    const rx = fresh();
    const payload = await signedPayload();
    assert.equal(await handlePush(rx, payload), 1);
    assert.equal(await handlePush(rx, payload), 1);
    assert.equal([...state.activeTuples()].length, 1);
  });

  it("returns 0 for garbage (never rejects)", async () => {
    const rx = fresh();
    assert.equal(await handlePush(rx, new Uint8Array(0)), 0);
    assert.equal(await handlePush(rx, new TextEncoder().encode("not msgpack")), 0);
  });

  it("refuses a Delta from an unknown issuer (verify-on-ingest)", async () => {
    const rx = fresh();
    const stranger = await Identity.generate();
    const tuple = await Tuple.fromPlaintext({
      objectId: "buzzer", relation: "sound", grantee: GRANTEE,
      issuer: stranger.identityHash, hasher: HASHER,
    });
    const op = await new Operation({
      tuple, action: Action.GRANT, hlc: packHlc(physicalNowMs(), 0),
    }).sign(stranger);
    assert.equal(await handlePush(rx, op.toPayload()), 0);
    assert.equal([...state.activeTuples()].length, 0);
  });
});

describe("syncRequestHandler — the responseGenerator wrapper", () => {
  let issuer;
  let receiver;
  let state;

  before(async () => {
    issuer = await Identity.generate();
    const keyring = new Keyring();
    keyring.registerSingle(issuer.identityHash, await issuer.getPublicKey());
    state = new StateVector();
    receiver = new DeltaReceiver(state, keyring);
  });

  it("acks applied:1 for a valid Delta", async () => {
    const tuple = await Tuple.fromPlaintext({
      objectId: "buzzer", relation: "sound", grantee: GRANTEE,
      issuer: issuer.identityHash, hasher: HASHER,
    });
    const op = await new Operation({
      tuple, action: Action.GRANT, hlc: packHlc(physicalNowMs(), 0),
    }).sign(issuer);
    const handler = syncRequestHandler(receiver);
    const ack = await handler(SYNC_REQUEST_PATH, op.toPayload(), new Uint8Array(8), null, null, Date.now());
    assert.deepEqual(unpackAck(ack), 1);
  });

  it("acks applied:0 for garbage (so the pusher can retry knowingly)", async () => {
    const handler = syncRequestHandler(receiver);
    const ack = await handler(SYNC_REQUEST_PATH, new TextEncoder().encode("x"), new Uint8Array(8), null, null, Date.now());
    assert.deepEqual(unpackAck(ack), 0);
  });
});

describe("pushOne — the client-side per-Delta request", () => {
  const payload = Uint8Array.of(0x98, 0x01);

  it("resolves true on an applied:1 ack", async () => {
    const link = new FakeLink({ respond: packAck(1) });
    assert.equal(await pushOne(link, SYNC_REQUEST_PATH, payload, 1000), true);
    assert.equal(link.requests[0].path, "delta");
    assert.deepEqual(link.requests[0].data, payload);
  });

  it("resolves false on an applied:0 refusal", async () => {
    const link = new FakeLink({ respond: packAck(0) });
    assert.equal(await pushOne(link, SYNC_REQUEST_PATH, payload, 1000), false);
  });

  it("resolves false on a lost response (non-bytes)", async () => {
    const link = new FakeLink({ respond: "garbage" });
    assert.equal(await pushOne(link, SYNC_REQUEST_PATH, payload, 1000), false);
  });

  it("resolves false on a failed/timed-out request", async () => {
    const link = new FakeLink({ respond: new Error("request timeout") });
    assert.equal(await pushOne(link, SYNC_REQUEST_PATH, payload, 1000), false);
  });

  it("refuses to request on an inactive link", async () => {
    const link = new FakeLink({ status: 4 /* CLOSED */, respond: packAck(1) });
    assert.equal(await pushOne(link, SYNC_REQUEST_PATH, payload, 1000), false);
    assert.equal(link.requests.length, 0);
  });
});

describe("ensureSyncPath — target identity resolution", () => {
  it("rejects an unknown node identity with a hint", async () => {
    const fakeRns = { transport: { recallIdentity: async () => null } };
    await assert.rejects(
      ensureSyncPath(/** @type {any} */ (fakeRns), new Uint8Array(16).fill(1)),
      /node identity unknown.*wait for its announce/,
    );
  });

  it("short-circuits when a path is already known (no request)", async () => {
    const requested = [];
    const fakeRns = {
      transport: {
        recallIdentity: async () => ({ identityHash: new Uint8Array(16) }),
        hasPath: () => true,
        requestPath: async (h) => requested.push(h),
      },
    };
    const { destinationHash } = await ensureSyncPath(/** @type {any} */ (fakeRns), new Uint8Array(16));
    assert.equal(destinationHash.length, 16);
    assert.equal(requested.length, 0);
  });
});
