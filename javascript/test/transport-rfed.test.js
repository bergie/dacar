import { describe, it, before } from "node:test";
import assert from "node:assert/strict";
import { Identity } from "@reticulum/core";
import {
  deriveChannel,
  wrapRawChannelMessage,
} from "@reticulum/core/src/rfed/index.js";
import { Action, Operation } from "../src/operation.js";
import { Tuple } from "../src/tuple.js";
import { HASH_SIZE, NamespaceHasher } from "../src/namespace.js";
import { packHlc, physicalNowMs } from "../src/hlc.js";
import { RFED_TOPIC } from "../src/naming.js";
import { StateVector } from "../src/crdt.js";
import { Keyring } from "../src/verifier.js";
import { DeltaReceiver } from "../src/delta.js";
import { RfedDeltaSync } from "../src/transport/rfedSync.js";

const HASHER = new NamespaceHasher(Uint8Array.from({ length: 32 }, (_, i) => i));
const GRANTEE = Uint8Array.from({ length: HASH_SIZE }, (_, i) => i + HASH_SIZE);
// Dated "now" so the §9 stale-horizon intake check (wall-clock default used by
// listen/pull, which call applyPayload without a nowMs override) accepts them.
const NOW = physicalNowMs();
const NODE = new Uint8Array(16).fill(7); // any rfed.* destination hash

/** @param {Uint8Array} issuer @param {Identity[]} signers @returns {Promise<Operation>} */
async function makeOp(issuer, signers = []) {
  const tuple = await Tuple.fromPlaintext({
    objectId: "sensor:wind", relation: "calibrate", grantee: GRANTEE, issuer, hasher: HASHER,
  });
  const base = new Operation({ tuple, action: Action.GRANT, hlc: packHlc(NOW, 0) });
  return signers.length ? base.sign(...signers) : base;
}

/**
 * A minimal RFedClient double for the raw (compact inner format) API.
 *
 * `subscribeRaw` records the call; `publishRaw` records each payload;
 * `listen` stashes the callback so a test can invoke it with a decoded raw
 * fanout object (`{ kind: "raw", payload }`); `pull` drains enqueued blobs
 * (which a test builds with `wrapRawChannelMessage` so the EC-decrypt unwrap is
 * exercised).
 */
class FakeRFedClient {
  constructor() {
    /** @type {Array<{ nodeHash: Uint8Array, channelName: string, payload: Uint8Array }>} */
    this.published = [];
    /** @type {((decoded: any) => void) | null} */ this.listener = null;
    /** @type {Array<{ channelHash: Uint8Array, blob: Uint8Array }>} */ this.deferred = [];
    this.deliveryHash = new Uint8Array(16).fill(9);
    this.subscribed = null;
  }
  async subscribeRaw(nodeHash, channelName) {
    this.subscribed = { nodeHash, channelName };
    return { ok: true, stampCost: null };
  }
  async unsubscribe(nodeHash, channelName) {
    return { ok: true };
  }
  /** @param {Uint8Array} nodeHash @param {string} channelName @param {Uint8Array} payload */
  async publishRaw(nodeHash, channelName, payload) {
    this.published.push({ nodeHash, channelName, payload });
  }
  /** @param {(decoded: any) => void} onMessage */
  async listen(onMessage) {
    this.listener = onMessage;
    return this.deliveryHash;
  }
  async pull(nodeHash, channelName) {
    const items = this.deferred.splice(0);
    return { items, morePending: false };
  }
}

describe("RfedDeltaSync (§11.1, compact inner format)", () => {
  /** @type {Identity} */ let sender;
  /** @type {Uint8Array} */ let issuer;
  /** @type {Uint8Array} */ let publicKey;

  before(async () => {
    sender = await Identity.generate();
    issuer = sender.identityHash;
    publicKey = await sender.getPublicKey();
  });

  /** A DeltaReceiver keyed for the test sender. */
  function receiver() {
    const state = new StateVector();
    const keyring = new Keyring().registerSingle(issuer, publicKey);
    return { state, rx: new DeltaReceiver(state, keyring) };
  }

  it("subscribe uses subscribeRaw (marks the channel for raw decode)", async () => {
    const client = new FakeRFedClient();
    const sync = new RfedDeltaSync({ client, topic: "dacar.policy.v1" });
    await sync.subscribe(NODE);
    assert.equal(client.subscribed.channelName, "dacar.policy.v1");
  });

  it("publish sends the Delta as the raw payload (no LXMF envelope)", async () => {
    const client = new FakeRFedClient();
    const sync = new RfedDeltaSync({ client });
    const delta = (await makeOp(issuer, [sender])).toPayload();

    const accepted = await sync.publish(delta, NODE);
    assert.equal(accepted, true); // fire-and-forget: no throw ⇒ accepted
    assert.equal(client.published.length, 1);
    assert.equal(client.published[0].channelName, RFED_TOPIC);
    // The raw Delta bytes are published verbatim — the client wraps them in
    // the RTID prelude + EC-encrypts; no LXMF serialisation.
    assert.deepEqual(client.published[0].payload, new Uint8Array(delta));
  });

  it("listen routes a received raw Delta through verify-on-ingest", async () => {
    const { state, rx } = receiver();
    const client = new FakeRFedClient();
    const sync = new RfedDeltaSync({ receiver: rx, client });
    await sync.listen();

    const delta = (await makeOp(issuer, [sender])).toPayload();
    // The real client would EC-decrypt + unwrap the RTID prelude and deliver
    // `{ kind: "raw", payload }`; the fake hands the payload straight through.
    /** @type {any} */ (client.listener)({ kind: "raw", payload: new Uint8Array(delta) });
    for (let i = 0; i < 50 && state.size === 0; i++) {
      await new Promise((r) => setTimeout(r, 5));
    }

    assert.equal(state.size, 1);
  });

  it("listen swallows a malformed/forged Delta (never crashes, never mutates)", async () => {
    const { state, rx } = receiver();
    const client = new FakeRFedClient();
    const sync = new RfedDeltaSync({ receiver: rx, client });
    await sync.listen();

    /** @type {any} */ (client.listener)({
      kind: "raw",
      payload: new TextEncoder().encode("not a dacar delta"),
    });
    for (let i = 0; i < 20 && state.size !== 0; i++) {
      await new Promise((r) => setTimeout(r, 5));
    }

    assert.equal(state.size, 0);
  });

  it("listen ignores non-raw deliveries (defensive — not a raw channel)", async () => {
    const { state, rx } = receiver();
    const client = new FakeRFedClient();
    const sync = new RfedDeltaSync({ receiver: rx, client });
    await sync.listen();

    // A stray lxmf-kind delivery (shouldn't happen on a raw channel, but the
    // guard must not crash or apply it).
    /** @type {any} */ (client.listener)({ kind: "lxmf" });
    for (let i = 0; i < 10 && state.size !== 0; i++) {
      await new Promise((r) => setTimeout(r, 5));
    }
    assert.equal(state.size, 0);
  });

  it("pull unwraps deferred raw blobs and applies their Deltas (verify-on-ingest)", async () => {
    const { state, rx } = receiver();
    const client = new FakeRFedClient();
    const sync = new RfedDeltaSync({ receiver: rx, client });

    // Produce a REAL rfed raw inner_blob so the EC-decrypt unwrap is exercised:
    // derive the channel, wrap a Delta with the raw codec, enqueue the blob.
    const { identity: channelIdentity, channelHash } = await deriveChannel(RFED_TOPIC);
    const delta = (await makeOp(issuer, [sender])).toPayload();
    const { innerBlob } = await wrapRawChannelMessage({
      channelIdentity,
      senderIdentity: sender,
      payload: delta,
    });
    client.deferred.push({ channelHash, blob: innerBlob });

    const applied = await sync.pull(NODE);
    assert.equal(applied, 1);
    assert.equal(state.size, 1);
  });

  it("pull drops a foreign/undecryptable blob (never fatal)", async () => {
    const { state, rx } = receiver();
    const client = new FakeRFedClient();
    const sync = new RfedDeltaSync({ receiver: rx, client });

    // A blob encrypted to a *different* channel identity: unwrapRawChannelMessage
    // fails to decrypt, and the adapter drops it rather than throwing.
    const { identity: otherIdentity, channelHash } = await deriveChannel("other.channel");
    const { innerBlob } = await wrapRawChannelMessage({
      channelIdentity: otherIdentity,
      senderIdentity: sender,
      payload: new Uint8Array([1, 2, 3]),
    });
    client.deferred.push({ channelHash, blob: innerBlob });

    const applied = await sync.pull(NODE);
    assert.equal(applied, 0);
    assert.equal(state.size, 0);
  });

  it("listen/pull throw without a receiver", async () => {
    const sync = new RfedDeltaSync({ client: new FakeRFedClient() });
    await assert.rejects(() => sync.listen());
    await assert.rejects(() => sync.pull(NODE));
  });
});
