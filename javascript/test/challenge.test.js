import { describe, it, before } from "node:test";
import assert from "node:assert/strict";
import { Identity } from "@reticulum/core";
import {
  AuthoritativeServer,
  Challenge,
  ChallengeClient,
  Receipt,
  Verdict,
} from "../src/challenge.js";
import { Config } from "../src/config.js";
import { StateVector } from "../src/crdt.js";
import { HASH_SIZE, NamespaceHasher } from "../src/namespace.js";
import { Action, Operation } from "../src/operation.js";
import { Tuple } from "../src/tuple.js";
import { packHlc } from "../src/hlc.js";

const SALT = Uint8Array.from({ length: 32 }, (_, i) => i);
const HASHER = new NamespaceHasher(SALT);
const ROOT = Uint8Array.from({ length: HASH_SIZE }, (_, i) => i);
const BOB = Uint8Array.from({ length: HASH_SIZE }, (_, i) => i + HASH_SIZE);
const NONCE = Uint8Array.from({ length: 32 }, (_, i) => i);
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

describe("Receipt (§8.5)", () => {
  /** @type {Identity} */ let identity;
  /** @type {Uint8Array} */ let publicKey;

  before(async () => {
    identity = await Identity.generate();
    publicKey = await identity.getPublicKey();
  });

  it("pre-image is verdict + server_hlc + nonce (41 bytes)", () => {
    const r = new Receipt({ verdict: Verdict.ALLOW, serverHlc: packHlc(42, 1), nonce: NONCE });
    assert.equal(r.preimage.length, 41);
    const expected = new Uint8Array(1 + 8 + 32);
    expected[0] = 0x01;
    new DataView(expected.buffer).setBigUint64(1, packHlc(42, 1), false);
    expected.set(NONCE, 9);
    assert.deepEqual(r.preimage, expected);
  });

  it("signs and verifies", async () => {
    const r = await new Receipt({ verdict: Verdict.ALLOW, serverHlc: packHlc(1, 0), nonce: NONCE }).sign(identity);
    assert.equal(await r.verify(publicKey), true);
  });

  it("detects verdict tampering", async () => {
    const r = await new Receipt({ verdict: Verdict.ALLOW, serverHlc: packHlc(1, 0), nonce: NONCE }).sign(identity);
    const bad = new Receipt({ verdict: Verdict.DENY, serverHlc: packHlc(1, 0), nonce: NONCE, signature: r.signature });
    assert.equal(await bad.verify(publicKey), false);
  });

  it("round-trips the payload", async () => {
    const r = await new Receipt({ verdict: Verdict.ALLOW, serverHlc: packHlc(7, 2), nonce: NONCE }).sign(identity);
    const restored = Receipt.fromPayload(r.toPayload());
    assert.equal(restored.verdict, r.verdict);
    assert.equal(restored.serverHlc, r.serverHlc);
    assert.equal(await restored.verify(publicKey), true);
  });
});

describe("Challenge payload (§8.3)", () => {
  it("round-trips nonce, grantee, and per-salt relation hashes", async () => {
    const ch = Challenge.generate("sensor:wind", "calibrate", BOB, [HASHER], { nonce: NONCE });
    const decoded = Challenge.fromPayload(await ch.toPayload());
    assert.deepEqual(decoded.nonce, NONCE);
    assert.deepEqual(decoded.grantee, BOB);
    assert.equal(decoded.entries.length, 1);
    const e = decoded.entries[0];
    assert.deepEqual(e.allowRelationHash, await HASHER.hashRelation("calibrate"));
    assert.deepEqual(e.denyRelationHash, await HASHER.hashRelation("-calibrate"));
  });

  it("carries no plaintext labels", async () => {
    const ch = Challenge.generate("sensor:wind", "calibrate", BOB, [HASHER], { nonce: NONCE });
    const payload = await ch.toPayload();
    const text = new TextDecoder().decode(payload);
    assert.equal(text.includes("sensor"), false);
    assert.equal(text.includes("wind"), false);
    assert.equal(text.includes("calibrate"), false);
  });

  it("emits one entry per salt", async () => {
    const legacy = new NamespaceHasher(Uint8Array.from({ length: 32 }, (_, i) => 31 - i));
    const ch = Challenge.generate("o", "r", BOB, [HASHER, legacy], { nonce: NONCE });
    const decoded = Challenge.fromPayload(await ch.toPayload());
    assert.equal(decoded.entries.length, 2);
    const tags = new Set(decoded.entries.map((e) => e.saltIdTag));
    assert.equal(tags.size, 2);
  });
});

describe("Challenge flow (§8)", () => {
  /** @type {Identity} */ let identity;
  /** @type {Uint8Array} */ let publicKey;

  before(async () => {
    identity = await Identity.generate();
    publicKey = await identity.getPublicKey();
  });

  /** @param {StateVector} clientState @param {StateVector} serverState @returns {Promise<ChallengeClient>} */
  async function wire(clientState, serverState) {
    const server = new AuthoritativeServer(config(), serverState, identity);
    return new ChallengeClient(config(), clientState, publicKey, (p) => server.handle(p));
  }

  it("server allows and client proceeds", async () => {
    const client = await wire(await allowState(), await allowState());
    assert.equal(await client.authorize("sensor:wind", "calibrate", BOB), true);
  });

  it("local pre-check denies without a challenge", async () => {
    const calls = [];
    const server = new AuthoritativeServer(config(), await allowState(), identity);
    const transport = (p) => {
      calls.push(p);
      return server.handle(p);
    };
    const client = new ChallengeClient(config(), new StateVector(), publicKey, transport);
    assert.equal(await client.authorize("sensor:wind", "calibrate", BOB), false);
    assert.equal(calls.length, 0);
  });

  it("server deny overrides a local allow", async () => {
    const revoked = await allowState();
    revoked.apply(
      new Operation({
        tuple: await Tuple.fromPlaintext({
          objectId: "sensor:wind", relation: "calibrate", grantee: BOB, issuer: ROOT, hasher: HASHER,
        }),
        action: Action.REVOKE,
        hlc: packHlc(BASE, 5),
      }),
      { nowMs: BASE },
    );
    const client = await wire(await allowState(), revoked);
    assert.equal(await client.authorize("sensor:wind", "calibrate", BOB), false);
  });

  it("partition (null transport) is denied", async () => {
    const client = new ChallengeClient(config(), await allowState(), publicKey, () => null);
    assert.equal(await client.authorize("sensor:wind", "calibrate", BOB), false);
  });

  it("transport exception is a partition", async () => {
    const boom = () => {
      throw new Error("link down");
    };
    const client = new ChallengeClient(config(), await allowState(), publicKey, boom);
    assert.equal(await client.authorize("sensor:wind", "calibrate", BOB), false);
  });

  it("wrong nonce is rejected", async () => {
    const server = new AuthoritativeServer(config(), await allowState(), identity);
    const transport = async (payload) => {
      const r = Receipt.fromPayload(await server.handle(payload));
      const swapped = new Receipt({
        verdict: r.verdict,
        serverHlc: r.serverHlc,
        nonce: Uint8Array.from({ length: 32 }, (_, i) => i + 1),
        signature: r.signature,
      });
      return swapped.toPayload();
    };
    const client = new ChallengeClient(config(), await allowState(), publicKey, transport);
    assert.equal(await client.authorize("sensor:wind", "calibrate", BOB), false);
  });

  it("bad signature is rejected", async () => {
    const attacker = await Identity.generate();
    const server = new AuthoritativeServer(config(), await allowState(), attacker);
    const client = new ChallengeClient(config(), await allowState(), publicKey, (p) => server.handle(p));
    assert.equal(await client.authorize("sensor:wind", "calibrate", BOB), false);
  });

  it("requires an authoritative identity", () => {
    const cfg = new Config({ rootTrustAnchors: [ROOT], primarySalt: SALT });
    assert.throws(() => new ChallengeClient(cfg, new StateVector(), publicKey, () => null));
  });
});
