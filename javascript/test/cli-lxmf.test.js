/**
 * Smoketests for the LXMF CLI paths (§11.2/§11.3, work doc #14).
 *
 * Covers the testable send/sync cores (`runLxmfPublish`/`runLxmfSync` with a
 * fake router — no live proprietor), the `[lxmf] proprietor` config round-trip
 * (byte-parity with the Python-written INI), and an end-to-end paper
 * export → import round-trip through real LXMF paper messages on a headless
 * Reticulum. Mirrors Python's `tests/test_cli_lxmf.py` (the canonical
 * implementation).
 */

import assert from "node:assert/strict";
import { before, describe, it } from "node:test";
import {
  Destination,
  DestType,
  Identity,
  MemoryStorageAdapter,
  Reticulum,
} from "@reticulum/core";
import {
  bootLxmfRouter,
  runLxmfPublish,
  runLxmfSync,
} from "../src/cli/session.js";
import { DacarStore } from "../src/cli/store.js";
import { StateVector } from "../src/crdt.js";
import { DeltaReceiver } from "../src/delta.js";
import { packHlc, physicalNowMs } from "../src/hlc.js";
import { HASH_SIZE, NamespaceHasher } from "../src/namespace.js";
import { Action, Operation } from "../src/operation.js";
import {
  decodeBatch,
  encodeBatch,
  LxmfDeltaDelivery,
} from "../src/transport/lxmfSync.js";
import { Tuple } from "../src/tuple.js";
import { Keyring } from "../src/verifier.js";

const HASHER = new NamespaceHasher(
  Uint8Array.from({ length: 32 }, (_, i) => i),
);
const GRANTEE = Uint8Array.from({ length: HASH_SIZE }, (_, i) => i + HASH_SIZE);

/** @param {Identity} signer @param {string} objectId */
async function signedDelta(signer, objectId = "sensor:wind") {
  const tuple = await Tuple.fromPlaintext({
    objectId,
    relation: "read",
    grantee: GRANTEE,
    issuer: signer.identityHash,
    hasher: HASHER,
  });
  const op = await new Operation({
    tuple,
    action: Action.GRANT,
    hlc: packHlc(physicalNowMs(), 0),
  }).sign(signer);
  return op.toPayload();
}

/**
 * Duck-typed LXMRouter: records outbound submissions, queues inbound messages
 * for the sync core, dispatches them as `message` events.
 */
class FakeLxmRouter extends EventTarget {
  constructor() {
    super();
    this.outboundPropagationNode = null;
    /** @type {any[]} */ this.submitted = [];
    /** @type {any[]} */ this.sent = [];
    /** @type {any[]} */ this._pending = [];
    this.identity = null;
  }
  setOutboundPropagationNode(hash) {
    if (!(hash instanceof Uint8Array) || hash.length !== 16) {
      throw new Error("Invalid destination hash for outbound propagation node");
    }
    this.outboundPropagationNode = hash;
  }
  /** @param {any} message @param {any} [identity] */
  async submitToPropagationNode(message, identity) {
    this.submitted.push({ message, identity });
  }
  /** @param {any} message @param {any} [identity] */
  async send(message, identity) {
    this.sent.push({ message, identity });
  }
  async syncFromPropagationNode() {
    for (const message of this._pending) {
      this.dispatchEvent(new CustomEvent("message", { detail: { message } }));
    }
  }
}

// ===========================================================================
// runLxmfPublish / runLxmfSync cores
// ===========================================================================

describe("runLxmfPublish (§11.2, work doc #14)", () => {
  /** @type {Identity} */ let sender;
  /** @type {Uint8Array} */ let target;
  const proprietor = Uint8Array.from({ length: 16 }, (_, i) => i);

  before(async () => {
    sender = await Identity.generate();
    target = (await Identity.generate()).identityHash;
  });

  const run = (router, payloads, opts = {}) =>
    runLxmfPublish({
      payloads,
      targetHash: target,
      proprietor,
      router,
      delivery: new LxmfDeltaDelivery(),
      identity: sender,
      ...opts,
    });

  it("single delta uses the wire-compat single title", async () => {
    const router = new FakeLxmRouter();
    const { accepted, messages } = await run(router, [
      new Uint8Array([1, 2, 3]),
    ]);
    assert.deepEqual(accepted, [true]);
    assert.equal(messages, 1);
    assert.equal(router.submitted.length, 1);
    assert.equal(router.submitted[0].message.title, "dacar/sync/delta");
    assert.deepEqual(router.outboundPropagationNode, proprietor);
  });

  it("multiple deltas batch; chunking expands flags", async () => {
    const router = new FakeLxmRouter();
    const payloads = Array.from({ length: 8 }, (_, i) =>
      new Uint8Array(200).fill(i),
    );
    const { accepted, messages } = await run(router, payloads, {
      chunkBudget: 500,
    });
    assert.ok(messages > 1);
    assert.equal(accepted.length, 8);
    assert.ok(accepted.every(Boolean));
    assert.ok(
      router.submitted.every((s) => s.message.title === "dacar/sync/batch"),
    );
    const flat = router.submitted.flatMap((s) =>
      decodeBatch(s.message.content),
    );
    assert.equal(flat.length, 8);
  });

  it("rejects missing proprietor unless direct", async () => {
    const router = new FakeLxmRouter();
    await assert.rejects(() =>
      run(router, [new Uint8Array(1)], { proprietor: null }),
    );
    const { accepted } = await run(router, [new Uint8Array(1)], {
      proprietor: null,
      direct: true,
    });
    assert.deepEqual(accepted, [true]);
    assert.equal(router.sent.length, 1); // direct goes through router.send
  });
});

describe("runLxmfSync (§11.2.3, work doc #14)", () => {
  /** @type {Identity} */ let issuer;

  before(async () => {
    issuer = await Identity.generate();
  });

  it("applies pending messages and reports the count", async () => {
    const state = new StateVector();
    const keyring = new Keyring();
    keyring.registerSingle(issuer.identityHash, await issuer.getPublicKey());
    const delivery = new LxmfDeltaDelivery({
      receiver: new DeltaReceiver(state, keyring),
    });
    const router = new FakeLxmRouter();
    for (let i = 0; i < 3; i++) {
      router._pending.push({
        title: "dacar/sync/delta",
        content: await signedDelta(issuer, `sensor:${i}`),
      });
    }
    const applied = await runLxmfSync({
      identity: issuer,
      proprietor: Uint8Array.from({ length: 16 }, (_, i) => i),
      router,
      delivery,
    });
    assert.equal(applied, 3);
    assert.equal(state.size, 3);
  });

  it("wrong titles and forged payloads apply nothing", async () => {
    const state = new StateVector();
    const delivery = new LxmfDeltaDelivery({
      receiver: new DeltaReceiver(state, new Keyring()),
    });
    const router = new FakeLxmRouter();
    router._pending.push({ title: "chat/hello", content: new Uint8Array([1]) });
    router._pending.push({
      title: "dacar/sync/delta",
      content: new Uint8Array([9, 9]),
    });
    const applied = await runLxmfSync({
      identity: issuer,
      proprietor: Uint8Array.from({ length: 16 }, (_, i) => i),
      router,
      delivery,
    });
    assert.equal(applied, 0);
    assert.equal(state.size, 0);
  });
});

// ===========================================================================
// [lxmf] proprietor config (Python-parity INI)
// ===========================================================================

describe("[lxmf] proprietor config (work doc #14)", () => {
  it("round-trips and is unset by default", async () => {
    const adapter = new MemoryStorageAdapter();
    const store = await DacarStore.init(adapter, { salt: HASHER.salt });
    let cfg = await store.loadConfig();
    assert.equal(cfg.lxmfProprietor, null);
    cfg.lxmfProprietor = Uint8Array.from({ length: 16 }, () => 7);
    await store.saveConfig(cfg);
    cfg = await new DacarStore(adapter).loadConfig();
    assert.deepEqual(
      cfg.lxmfProprietor,
      Uint8Array.from({ length: 16 }, () => 7),
    );
  });

  it("writes the [lxmf] section byte-identically with Python", async () => {
    const adapter = new MemoryStorageAdapter();
    const store = await DacarStore.init(adapter, {
      salt: Uint8Array.from({ length: 32 }, () => 1),
    });
    const cfg = await store.loadConfig();
    cfg.lxmfProprietor = Uint8Array.from({ length: 16 }, () => 7);
    await store.saveConfig(cfg);
    const ini = new TextDecoder().decode(await adapter.get("dacar", "config"));
    // Section layout minted by Python's configparser for the same config.
    assert.ok(
      ini.endsWith(
        "[rfed]\ntopic = dacar.policy.v1\n\n[lxmf]\nproprietor = 07070707070707070707070707070707\n\n",
      ),
    );
  });
});

// ===========================================================================
// Paper export → import round-trip (§11.3, work doc #14)
// ===========================================================================

describe("paper round-trip (§11.3, work doc #14)", () => {
  it("exports URIs that the recipient's router ingests and applies", async () => {
    const rns = new Reticulum({});
    const exporter = await Identity.generate();
    const recipient = await Identity.generate();

    // Exporter packs 3 deltas (all in one batch chunk).
    const payloads = [];
    for (let i = 0; i < 3; i++)
      payloads.push(await signedDelta(exporter, `sensor:${i}`));
    const { packPaperUris } = await import("../src/transport/lxmfSync.js");
    const outboundDestination = await Destination.OUT(
      "lxmf.delivery",
      DestType.SINGLE,
      recipient,
      rns,
    );
    // The paper message's destination is the recipient's lxmf.delivery
    // *destination* hash (identity + name), not the bare identity hash.
    const uris = await packPaperUris(
      payloads,
      outboundDestination.destinationHash,
      {
        sourceIdentity: exporter,
        outboundDestination,
      },
    );
    assert.ok(uris.length >= 1);
    assert.ok(uris.every((u) => u.startsWith("lxm://")));

    // Recipient boots a router on its own identity and ingests each URI.
    const state = new StateVector();
    const keyring = new Keyring();
    keyring.registerSingle(
      exporter.identityHash,
      await exporter.getPublicKey(),
    );
    const router = await bootLxmfRouter({ identity: recipient, rns });
    const delivery = new LxmfDeltaDelivery({
      receiver: new DeltaReceiver(state, keyring),
      router,
    });
    // EventTarget dispatch is synchronous but the listener is async — collect
    // the in-flight promises so the assertions see the final applied state.
    /** @type {Promise<void>[]} */
    const inflight = [];
    router.addEventListener("message", (event) => {
      const message = /** @type {any} */ (event).detail?.message;
      if (!message) return;
      inflight.push(
        (async () => {
          await delivery.handleMessage(message);
        })(),
      );
    });
    for (const uri of uris) await delivery.ingestPaperUri(uri);
    await Promise.all(inflight);
    assert.equal(state.size, 3);
  });
});
