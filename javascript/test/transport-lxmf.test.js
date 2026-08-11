import { describe, it, before } from "node:test";
import assert from "node:assert/strict";
import {
  DestType,
  Destination,
  Identity,
  Reticulum,
} from "@reticulum/core";
import { Action, Operation } from "../src/operation.js";
import { Tuple } from "../src/tuple.js";
import { HASH_SIZE, NamespaceHasher } from "../src/namespace.js";
import { packHlc, physicalNowMs } from "../src/hlc.js";
import { StateVector } from "../src/crdt.js";
import { Keyring } from "../src/verifier.js";
import { DeltaReceiver } from "../src/delta.js";
import {
  LxmfDeltaDelivery,
  messageContent,
  messageTitle,
} from "../src/transport/lxmfSync.js";

const HASHER = new NamespaceHasher(Uint8Array.from({ length: 32 }, (_, i) => i));
const GRANTEE = Uint8Array.from({ length: HASH_SIZE }, (_, i) => i + HASH_SIZE);
// Dated "now" so the §9 stale-horizon intake check (wall-clock default used by
// handleMessage) accepts the operations, mirroring the Python LXMF smoketest.
const NOW = physicalNowMs();

/** @param {Uint8Array} issuer @param {Identity[]} signers @returns {Promise<Operation>} */
async function makeOp(issuer, signers = []) {
  const tuple = await Tuple.fromPlaintext({
    objectId: "sensor:wind", relation: "calibrate", grantee: GRANTEE, issuer, hasher: HASHER,
  });
  const base = new Operation({ tuple, action: Action.GRANT, hlc: packHlc(NOW, 0) });
  return signers.length ? base.sign(...signers) : base;
}

/** @param {Uint8Array} haystack @param {Uint8Array} needle @returns {boolean} */
function contains(haystack, needle) {
  if (needle.length === 0) return true;
  outer: for (let i = 0; i + needle.length <= haystack.length; i++) {
    for (let j = 0; j < needle.length; j++) {
      if (haystack[i + j] !== needle[j]) continue outer;
    }
    return true;
  }
  return false;
}

describe("LxmfDeltaDelivery (§11.2, §11.3)", () => {
  /** @type {Identity} */ let source;
  /** @type {Identity} */ let recipient;
  /** @type {Uint8Array} */ let destHash;
  /** @type {Uint8Array} */ let srcHash;

  before(async () => {
    source = await Identity.generate();
    recipient = await Identity.generate();
    srcHash = source.identityHash;
    destHash = recipient.identityHash;
  });

  /** Build a message, round-trip it through the LXMF wire codec, and return the recovered message. */
  async function roundTrip(content, title, sender) {
    const { LXMessage } = await import("@reticulum/core/src/lxmf/index.js");
    const message = new LXMessage({ destinationHash: destHash, sourceHash: srcHash, content, title });
    const { wireData } = await message.serialize(sender);
    return { message, recovered: await LXMessage.deserialize(wireData, destHash) };
  }

  // -- §11.2 send: wrap round-trips through the LXMF wire format ----------

  it("makeMessage round-trips the Delta payload and title", async () => {
    const delta = Uint8Array.from([1, 2, 3, 4, 5, 6, 7, 8, 9]);
    const delivery = new LxmfDeltaDelivery();
    const built = delivery.makeMessage(delta, destHash, srcHash);
    const { wireData } = await built.serialize(source);
    const { LXMessage } = await import("@reticulum/core/src/lxmf/index.js");
    const recovered = await LXMessage.deserialize(wireData, destHash);
    assert.equal(messageTitle(recovered), LxmfDeltaDelivery.TITLE);
    assert.deepEqual(messageContent(recovered), delta);
  });

  it("messageContent recovers raw bytes from a deserialized message (binary-safe)", async () => {
    // Non-UTF-8 bytes would be corrupted by the UTF-8 content decode; the raw
    // bytes survive on _decodedPayload[2].
    const delta = Uint8Array.from({ length: 64 }, (_, i) => (i * 37) % 256);
    const { recovered } = await roundTrip(delta, LxmfDeltaDelivery.TITLE, source);
    assert.deepEqual(messageContent(recovered), delta);
  });

  // -- §11.2 receive: title filter + verify-on-ingest through DeltaReceiver -

  it("handleMessage applies a signed Delta", async () => {
    const issuer = source.identityHash;
    const op = await makeOp(issuer, [source]);
    const keyring = new Keyring().registerSingle(issuer, await source.getPublicKey());
    const state = new StateVector();
    const delivery = new LxmfDeltaDelivery({ receiver: new DeltaReceiver(state, keyring) });

    const built = delivery.makeMessage(op.toPayload(), destHash, srcHash);
    const { wireData } = await built.serialize(source);
    const { LXMessage } = await import("@reticulum/core/src/lxmf/index.js");
    const recovered = await LXMessage.deserialize(wireData, destHash);

    assert.equal(await delivery.handleMessage(recovered), true);
    assert.equal(state.size, 1);
  });

  it("handleMessage ignores a non-Dacar title", async () => {
    const state = new StateVector();
    const delivery = new LxmfDeltaDelivery({ receiver: new DeltaReceiver(state, new Keyring()) });
    const { recovered } = await roundTrip(Uint8Array.from([1, 2, 3]), "chat/hello", source);
    assert.equal(await delivery.handleMessage(recovered), false);
    assert.equal(state.size, 0);
  });

  it("handleMessage swallows malformed content (transport callbacks never crash)", async () => {
    const state = new StateVector();
    const delivery = new LxmfDeltaDelivery({ receiver: new DeltaReceiver(state, new Keyring()) });
    const { recovered } = await roundTrip(
      new TextEncoder().encode("not msgpack"),
      LxmfDeltaDelivery.TITLE,
      source,
    );
    assert.equal(await delivery.handleMessage(recovered), false);
    assert.equal(state.size, 0);
  });

  it("handleMessage throws without a receiver", async () => {
    const delivery = new LxmfDeltaDelivery();
    await assert.rejects(() => delivery.handleMessage({ title: LxmfDeltaDelivery.TITLE, _decodedPayload: [0, new Uint8Array(), new Uint8Array(), {}] }));
  });

  // -- §11.3 Paper Messages: encrypted QR-encodable export ---------------

  it("makePaperUri produces an encrypted lxm:// URI", async () => {
    const rns = new Reticulum({});
    const outbound = await Destination.OUT("lxmf.delivery", DestType.SINGLE, recipient, rns);
    const delta = (await makeOp(recipient.identityHash, [recipient])).toPayload();
    const delivery = new LxmfDeltaDelivery();

    const uri = await delivery.makePaperUri(delta, /** @type {Uint8Array} */ (outbound.destinationHash), {
      sourceIdentity: source,
      outboundDestination: outbound,
    });

    assert.ok(uri.startsWith("lxm://"));
    const { LXMessage } = await import("@reticulum/core/src/lxmf/index.js");
    const paperData = LXMessage.paperDataFromUri(uri);
    assert.ok(paperData.length > 0);
    assert.equal(contains(paperData, delta), false); // encrypted — no plaintext Delta leak
  });
});
