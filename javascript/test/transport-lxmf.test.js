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
    const { LXMessage } = await import("@reticulum/lxmf");
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
    const { LXMessage } = await import("@reticulum/lxmf");
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
    const { LXMessage } = await import("@reticulum/lxmf");
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
    const { LXMessage } = await import("@reticulum/lxmf");
    const paperData = LXMessage.paperDataFromUri(uri);
    assert.ok(paperData.length > 0);
    assert.equal(contains(paperData, delta), false); // encrypted — no plaintext Delta leak
  });
});

// ---------------------------------------------------------------------------
// Batch envelope (§11.2, work doc #14)
// ---------------------------------------------------------------------------

describe("LXMF batch envelope (§11.2, work doc #14)", () => {
  const PYTHON_VECTOR_PAYLOADS = Array.from({ length: 5 }, (_, i) =>
    new Uint8Array(1 + i * 37).fill(i),
  );

  // The hex constant is minted by the Python reference (encode_batch of the
  // payloads above) — see the `python-vector` generation note in work doc #14.
const PYTHON_VECTOR_HEX =
    "95c40100c4260101010101010101010101010101010101010101010101010101010101010101" +
    "010101010101c44b020202020202020202020202020202020202020202020202020202020202" +
    "0202020202020202020202020202020202020202020202020202020202020202020202020202" +
    "02020202020202c4700303030303030303030303030303030303030303030303030303030303" +
    "0303030303030303030303030303030303030303030303030303030303030303030303030303" +
    "0303030303030303030303030303030303030303030303030303030303030303030303030303" +
    "03030303030303c4950404040404040404040404040404040404040404040404040404040404" +
    "0404040404040404040404040404040404040404040404040404040404040404040404040404" +
    "0404040404040404040404040404040404040404040404040404040404040404040404040404" +
    "0404040404040404040404040404040404040404040404040404040404040404040404040404" +    "040404040404";

  it("encodeBatch is byte-identical with the Python reference", async () => {
    const { encodeBatch } = await import("../src/transport/lxmfSync.js");
    assert.equal(
      toHex(encodeBatch(PYTHON_VECTOR_PAYLOADS)),
      PYTHON_VECTOR_HEX,
    );
  });

  it("decodeBatch accepts the Python-minted vector", async () => {
    const { decodeBatch } = await import("../src/transport/lxmfSync.js");
    const decoded = decodeBatch(hexToBytes(PYTHON_VECTOR_HEX));
    assert.equal(decoded.length, 5);
    for (let i = 0; i < 5; i++) {
      assert.deepEqual(decoded[i], PYTHON_VECTOR_PAYLOADS[i]);
    }
  });

  it("decodeBatch is strict", async () => {
    const { decodeBatch } = await import("../src/transport/lxmfSync.js");
    assert.throws(() => decodeBatch(new Uint8Array(0)));
    assert.throws(() => decodeBatch(new Uint8Array([0xc0]))); // nil
    assert.throws(() => decodeBatch(hexToBytes("90"))); // empty array
    assert.throws(() => decodeBatch(hexToBytes("93010203"))); // int elements
  });

  it("packChunks is greedy, ordered, and budget-bound", async () => {
    const { encodeBatch, packChunks } = await import("../src/transport/lxmfSync.js");
    const payloads = Array.from({ length: 50 }, (_, i) => new Uint8Array(100).fill(i));
    const chunks = packChunks(payloads, 500);
    const flat = chunks.flat();
    assert.equal(flat.length, 50);
    for (let i = 0; i < 50; i++) assert.deepEqual(flat[i], payloads[i]);
    assert.ok(chunks.length > 1);
    for (const c of chunks) assert.ok(encodeBatch(c).length <= 500);
  });

  it("handleMessage applies every valid batch element (no short-circuit)", async () => {
    const { encodeBatch } = await import("../src/transport/lxmfSync.js");
    const issuer = await Identity.generate();
    const issuerHash = issuer.identityHash;
    const payloads = [];
    for (let i = 0; i < 3; i++) {
      const tuple = await Tuple.fromPlaintext({
        objectId: `sensor:${i}`, relation: "calibrate", grantee: GRANTEE,
        issuer: issuerHash, hasher: HASHER,
      });
      payloads.push(
        (await (await new Operation({ tuple, action: Action.GRANT, hlc: packHlc(NOW, 0) }).sign(issuer)).toPayload()),
      );
    }
    const state = new StateVector();
    const keyring = new Keyring();
    keyring.registerSingle(issuerHash, await issuer.getPublicKey());
    const delivery = new LxmfDeltaDelivery({ receiver: new DeltaReceiver(state, keyring) });
    const applied = await delivery.handleMessage({
      title: "dacar/sync/batch",
      content: encodeBatch(payloads),
    });
    assert.ok(applied);
    assert.equal(state.size, 3);
  });

  it("handleMessage drops malformed batches whole and ignores other titles", async () => {
    const { encodeBatch } = await import("../src/transport/lxmfSync.js");
    const state = new StateVector();
    const delivery = new LxmfDeltaDelivery({ receiver: new DeltaReceiver(state, new Keyring()) });
    assert.equal(await delivery.handleMessage({ title: "dacar/sync/batch", content: new Uint8Array([1, 2, 3]) }), false);
    assert.equal(await delivery.handleMessage({ title: "dacar/sync/batch", content: new Uint8Array(0) }), false);
    assert.equal(await delivery.handleMessage({ title: "chat/hello", content: encodeBatch([new Uint8Array(4)]) }), false);
    assert.equal(state.size, 0);
  });

  it("packPaperUris keeps every paper payload within PAPER_MDU", async () => {
    const { packPaperUris } = await import("../src/transport/lxmfSync.js");
    const { LXMessage, LXMFConstants } = await import("@reticulum/lxmf");
    const source = await Identity.generate();
    const recipient = await Identity.generate();
    // Recipient OUT destination for encryption (no router needed).
    const outboundDestination = await Destination.OUT(
      "lxmf.delivery", DestType.SINGLE, recipient, null,
    );
    const payloads = Array.from({ length: 40 }, (_, i) => new Uint8Array(170).fill(i));
    const uris = await packPaperUris(payloads, outboundDestination.destinationHash, {
      sourceIdentity: source, outboundDestination,
    });
    assert.ok(uris.length > 1, "40 deltas must spill to multiple QRs");
    for (const uri of uris) {
      assert.ok(uri.startsWith("lxm://"));
      const paperData = LXMessage.paperDataFromUri(uri);
      assert.ok(paperData.length <= LXMFConstants.PAPER_MDU);
    }
  });
});

/** @param {string} hex @returns {Uint8Array} */
function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/** @param {Uint8Array} bytes @returns {string} */
function toHex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}
