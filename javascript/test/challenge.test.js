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
import { Action, Operation } from "../src/operation.js";
import { Tuple } from "../src/tuple.js";
import { packHlc } from "../src/hlc.js";

const ROOT = Uint8Array.from({ length: 16 }, (_, i) => i);
const BOB = Uint8Array.from({ length: 16 }, (_, i) => i + 16);
const NONCE = Uint8Array.from({ length: 32 }, (_, i) => i);
const BASE = 1_700_000_000_000;

/** @returns {StateVector} a state where BOB may calibrate sensor:wind via ROOT */
function allowState() {
  const s = new StateVector();
  s.apply(
    new Operation({
      tuple: new Tuple({ object: "sensor:wind", relation: "calibrate", grantee: BOB, issuer: ROOT }),
      action: Action.GRANT,
      hlc: packHlc(BASE, 0),
    }),
  );
  return s;
}

function config() {
  return new Config({ rootTrustAnchors: [ROOT], authoritativeIdentity: ROOT });
}

describe("Receipt (§8)", () => {
  let identity;
  let publicKey;

  before(async () => {
    identity = await Identity.generate();
    publicKey = identity.publicKey;
  });

  it("builds the 41-byte pre-image layout", () => {
    const r = new Receipt({ verdict: Verdict.ALLOW, serverHlc: packHlc(42, 1), nonce: NONCE });
    const hlcBytes = new Uint8Array(8);
    new DataView(hlcBytes.buffer).setBigUint64(0, packHlc(42, 1), false);
    const expected = new Uint8Array([0x01, ...hlcBytes, ...NONCE]);
    assert.equal(r.preimage.length, 41);
    assert.deepEqual(r.preimage, expected);
  });

  it("signs and verifies", async () => {
    const r = await new Receipt({ verdict: Verdict.ALLOW, serverHlc: packHlc(1, 0), nonce: NONCE }).sign(identity);
    assert.equal(await r.verify(publicKey), true);
  });

  it("detects tampering", async () => {
    const r = await new Receipt({ verdict: Verdict.ALLOW, serverHlc: packHlc(1, 0), nonce: NONCE }).sign(identity);
    const bad = new Receipt({ verdict: Verdict.DENY, serverHlc: packHlc(1, 0), nonce: NONCE, signature: r.signature });
    assert.equal(await bad.verify(publicKey), false);
  });

  it("round-trips through the payload", async () => {
    const r = await new Receipt({ verdict: Verdict.ALLOW, serverHlc: packHlc(7, 2), nonce: NONCE }).sign(identity);
    const restored = Receipt.fromPayload(r.toPayload());
    assert.equal(restored.verdict, r.verdict);
    assert.equal(restored.serverHlc, r.serverHlc);
    assert.deepEqual(restored.nonce, r.nonce);
    assert.deepEqual(restored.signature, r.signature);
    assert.equal(await restored.verify(publicKey), true);
  });
});

describe("Challenge (§8)", () => {
  it("generates a 32-byte nonce and round-trips", () => {
    const c = Challenge.generate("o", "r", BOB);
    assert.equal(c.nonce.length, 32);
    const restored = Challenge.fromPayload(c.toPayload());
    assert.deepEqual(restored.nonce, c.nonce);
  });

  it("accepts a fixed nonce", () => {
    const c = Challenge.generate("o", "r", BOB, { nonce: NONCE });
    assert.deepEqual(c.nonce, NONCE);
  });
});

describe("Strict Consistency flow (§8)", () => {
  let identity;
  let publicKey;

  before(async () => {
    identity = await Identity.generate();
    publicKey = identity.publicKey;
  });

  function wire(clientState, serverState) {
    const server = new AuthoritativeServer(config(), serverState, identity);
    return new ChallengeClient(config(), clientState, publicKey, (p) => server.handle(p));
  }

  it("server allows and client proceeds", async () => {
    const client = wire(allowState(), allowState());
    assert.equal(await client.authorize("sensor:wind", "calibrate", BOB), true);
  });

  it("local pre-check denies without challenging", async () => {
    let called = false;
    const server = new AuthoritativeServer(config(), allowState(), identity);
    const client = new ChallengeClient(config(), new StateVector(), publicKey, (p) => {
      called = true;
      return server.handle(p);
    });
    assert.equal(await client.authorize("sensor:wind", "calibrate", BOB), false);
    assert.equal(called, false);
  });

  it("server DENY overrides a stale local ALLOW", async () => {
    const revoked = allowState();
    revoked.apply(
      new Operation({
        tuple: new Tuple({ object: "sensor:wind", relation: "calibrate", grantee: BOB, issuer: ROOT }),
        action: Action.REVOKE,
        hlc: packHlc(BASE, 5),
      }),
    );
    const client = wire(allowState(), revoked);
    assert.equal(await client.authorize("sensor:wind", "calibrate", BOB), false);
  });

  it("partition (null transport) is denied", async () => {
    const client = new ChallengeClient(config(), allowState(), publicKey, async () => null);
    assert.equal(await client.authorize("sensor:wind", "calibrate", BOB), false);
  });

  it("partition (throwing transport) is denied", async () => {
    const client = new ChallengeClient(config(), allowState(), publicKey, async () => {
      throw new Error("link down");
    });
    assert.equal(await client.authorize("sensor:wind", "calibrate", BOB), false);
  });

  it("rejects a receipt with the wrong nonce", async () => {
    const server = new AuthoritativeServer(config(), allowState(), identity);
    const client = new ChallengeClient(config(), allowState(), publicKey, async (p) => {
      const r = Receipt.fromPayload(await server.handle(p));
      const wrong = new Uint8Array(32).fill(1);
      return new Receipt({ verdict: r.verdict, serverHlc: r.serverHlc, nonce: wrong, signature: r.signature }).toPayload();
    });
    assert.equal(await client.authorize("sensor:wind", "calibrate", BOB), false);
  });

  it("rejects a receipt signed by an attacker", async () => {
    const attacker = await Identity.generate();
    const server = new AuthoritativeServer(config(), allowState(), attacker);
    const client = new ChallengeClient(config(), allowState(), publicKey, (p) => server.handle(p));
    assert.equal(await client.authorize("sensor:wind", "calibrate", BOB), false);
  });

  it("requires an Authoritative Identity", () => {
    const cfg = new Config({ rootTrustAnchors: [ROOT] });
    assert.throws(() => new ChallengeClient(cfg, new StateVector(), publicKey, async () => null));
  });
});
