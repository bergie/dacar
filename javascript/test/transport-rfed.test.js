import { describe, it, before } from "node:test";
import assert from "node:assert/strict";
import { Identity } from "@reticulum/core";
import { LXMessage } from "@reticulum/core/src/lxmf/index.js";
import {
  deliveryHashFor,
  deriveChannel,
  wrapChannelMessage,
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
import { messageContent } from "../src/transport/lxmfSync.js";

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

/** A minimal RFedClient double that records publishes and replays listen/pull. */
class FakeRFedClient {
  constructor() {
    /** @type {Array<{ nodeHash: Uint8Array, channelName: string, message: LXMessage }>} */
    this.published = [];
    /** @type {((decoded: any) => void) | null} */ this.listener = null;
    /** @type {Array<{ channelHash: Uint8Array, blob: Uint8Array }>} */ this.deferred = [];
    this.deliveryHash = new Uint8Array(16).fill(9);
  }
  async subscribe(nodeHash, channelName) {
    this.subscribed = { nodeHash, channelName };
    return { ok: true, stampCost: null };
  }
  async unsubscribe(nodeHash, channelName) {
    return { ok: true };
  }
  /** @param {Uint8Array} nodeHash @param {string} channelName @param {LXMessage} lxmMessage */
  async publish(nodeHash, channelName, lxmMessage) {
    this.published.push({ nodeHash, channelName, message: lxmMessage });
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

describe("RfedDeltaSync (§11.1)", () => {
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

  it("publish wraps the Delta as LXMF content under the dacar title", async () => {
    const client = new FakeRFedClient();
    const sync = new RfedDeltaSync({ client });
    const delta = (await makeOp(issuer, [sender])).toPayload();

    const message = await sync.publish(delta, NODE);
    assert.equal(client.published.length, 1);
    assert.equal(client.published[0].channelName, RFED_TOPIC);
    assert.deepEqual(messageContent(message), delta);
    // The rfed codec overwrites these; placeholders are fine pre-publish.
    assert.deepEqual(message.destinationHash, new Uint8Array(16));
  });

  it("subscribe caches the channel and topic", async () => {
    const client = new FakeRFedClient();
    const sync = new RfedDeltaSync({ client, topic: "dacar.policy.v1" });
    await sync.subscribe(NODE);
    assert.equal(client.subscribed.channelName, "dacar.policy.v1");
  });

  it("listen routes a received Delta through verify-on-ingest", async () => {
    const { state, rx } = receiver();
    const client = new FakeRFedClient();
    const sync = new RfedDeltaSync({ receiver: rx, client });
    await sync.listen();

    const delta = (await makeOp(issuer, [sender])).toPayload();
    const message = new LXMessage({
      destinationHash: new Uint8Array(16),
      sourceHash: new Uint8Array(16),
      content: delta,
    });
    const { wireData } = await message.serialize(sender);
    const recovered = await LXMessage.deserialize(wireData, new Uint8Array(16));

    // RFedClient.invoke does not await the callback; applyPayload is async
    // (Ed25519 verify over Web Crypto), so poll for it to settle.
    /** @type {any} */ (client.listener)({ message: recovered, signatureValid: true });
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

    const message = new LXMessage({
      destinationHash: new Uint8Array(16),
      sourceHash: new Uint8Array(16),
      content: new TextEncoder().encode("not a dacar delta"),
    });
    const { wireData } = await message.serialize(sender);
    const recovered = await LXMessage.deserialize(wireData, new Uint8Array(16));
    /** @type {any} */ (client.listener)({ message: recovered });
    for (let i = 0; i < 20 && state.size !== 0; i++) {
      await new Promise((r) => setTimeout(r, 5));
    }

    assert.equal(state.size, 0);
  });

  it("pull unwraps deferred blobs and applies their Deltas (verify-on-ingest)", async () => {
    const { state, rx } = receiver();
    const client = new FakeRFedClient();
    const sync = new RfedDeltaSync({ receiver: rx, client });

    // Produce a REAL rfed inner_blob so the EC-decrypt unwrap is exercised:
    // derive the channel, wrap a Delta-bearing LXMF message, enqueue the blob.
    const { identity: channelIdentity } = await deriveChannel(RFED_TOPIC);
    const senderDeliveryHash = await deliveryHashFor(sender);
    const delta = (await makeOp(issuer, [sender])).toPayload();
    const lxmMessage = new LXMessage({
      destinationHash: new Uint8Array(16),
      sourceHash: new Uint8Array(16),
      content: delta,
    });
    const { innerBlob, channelHash } = await wrapChannelMessage({
      channelIdentity,
      senderIdentity: sender,
      senderLxmDeliveryHash: senderDeliveryHash,
      lxmMessage,
    });
    client.deferred.push({ channelHash, blob: innerBlob });

    const applied = await sync.pull(NODE);
    assert.equal(applied, 1);
    assert.equal(state.size, 1);
  });

  it("listen/pull throw without a receiver", async () => {
    const sync = new RfedDeltaSync({ client: new FakeRFedClient() });
    await assert.rejects(() => sync.listen());
    await assert.rejects(() => sync.pull(NODE));
  });
});
