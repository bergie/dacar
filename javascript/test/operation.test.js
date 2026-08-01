import { describe, it, before } from "node:test";
import assert from "node:assert/strict";
import { Identity } from "@reticulum/core";
import { Action, Operation } from "../src/operation.js";
import { Tuple } from "../src/tuple.js";
import { HASH_SIZE, NamespaceHasher } from "../src/namespace.js";
import { packHlc } from "../src/hlc.js";

const HASHER = new NamespaceHasher(Uint8Array.from({ length: 32 }, (_, i) => i));
const ISSUER = Uint8Array.from({ length: HASH_SIZE }, (_, i) => i);
const GRANTEE = Uint8Array.from({ length: HASH_SIZE }, (_, i) => i + HASH_SIZE);
const HLC = packHlc(1_700_000_000_000, 9);

/** @param {Object} [opts] @returns {Promise<Tuple>} */
async function tuple({ object = "sensor:wind", relation = "calibrate", issuer = ISSUER } = {}) {
  return Tuple.fromPlaintext({ objectId: object, relation, grantee: GRANTEE, issuer, hasher: HASHER });
}

/** @param {bigint} hlc @returns {Uint8Array} */
function hlcBytes(hlc) {
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, hlc, false);
  return b;
}

describe("Operation pre-image (§5.2)", () => {
  it("matches the spec binary layout", async () => {
    const op = new Operation({ tuple: await tuple(), action: Action.REVOKE, hlc: packHlc(42, 7) });
    const rel = await HASHER.hashRelation("calibrate");
    const { hashes } = await HASHER.hashObject("sensor:wind");
    const total = 16 + 16 + 1 + 8 + 16 + 1 + 1 + 16 * 2;
    const expected = new Uint8Array(total);
    let o = 0;
    expected.set(ISSUER, o); o += 16;
    expected.set(GRANTEE, o); o += 16;
    expected[o++] = 0x00; // REVOKE
    expected.set(hlcBytes(packHlc(42, 7)), o); o += 8;
    expected.set(rel, o); o += 16;
    expected[o++] = 0x00; // wildcard flag
    expected[o++] = 2; // segment count
    expected.set(hashes[0], o); o += 16;
    expected.set(hashes[1], o);
    assert.deepEqual(op.preimage, expected);
  });

  it("sets the wildcard flag for sensor:*", async () => {
    const op = new Operation({
      tuple: await tuple({ object: "sensor:*", relation: "admin" }),
      action: Action.GRANT,
      hlc: HLC,
    });
    assert.equal(op.preimage[16 + 16 + 1 + 8 + 16], 0x01); // wildcard byte
  });
});

describe("Operation single-identity signing (§5.2)", () => {
  /** @type {Identity} */ let identity;

  before(async () => {
    identity = await Identity.generate();
  });

  it("signs and verifies", async () => {
    const op = await new Operation({ tuple: await tuple(), action: Action.GRANT, hlc: HLC }).sign(identity);
    assert.equal(await op.verify(identity), true);
    assert.equal(await op.verify(await Identity.generate()), false);
  });

  it("detects timestamp tampering", async () => {
    const op = await new Operation({ tuple: await tuple({ object: "o", relation: "r" }), action: Action.GRANT, hlc: packHlc(1, 0) }).sign(identity);
    const tampered = new Operation({
      tuple: await tuple({ object: "o", relation: "r" }),
      action: Action.GRANT,
      hlc: packHlc(2, 0),
      signatures: op.signatures,
    });
    assert.equal(await tampered.verify(identity), false);
  });

  it("round-trips the §5.3 payload", async () => {
    const op = await new Operation({
      tuple: await tuple({ object: "sensor:wind:north", relation: "read" }),
      action: Action.GRANT,
      hlc: HLC,
    }).sign(identity);
    const restored = Operation.fromPayload(op.toPayload());
    assert.equal(restored.tuple.key, op.tuple.key);
    assert.equal(restored.hlc, op.hlc);
    assert.equal(await restored.verify(identity), true);
  });

  it("refuses to serialize unsigned", async () => {
    const op = new Operation({ tuple: await tuple(), action: Action.GRANT, hlc: HLC });
    assert.throws(() => op.toPayload());
  });
});

describe("Operation threshold signing (§5.2, §4.1)", () => {
  it("verifies N-of-M from distinct members", async () => {
    const keys = await Promise.all([Identity.generate(), Identity.generate(), Identity.generate()]);
    const pubs = keys; // Identity instances double as public-key handles
    const op = await new Operation({ tuple: await tuple(), action: Action.GRANT, hlc: HLC }).sign(keys[0], keys[1]);
    assert.equal(await op.verifyThreshold(pubs, 2), true);
  });

  it("rejects the wrong signature count", async () => {
    const keys = await Promise.all([Identity.generate(), Identity.generate(), Identity.generate()]);
    const op = await new Operation({ tuple: await tuple(), action: Action.GRANT, hlc: HLC }).sign(keys[0], keys[1], keys[2]);
    assert.equal(await op.verifyThreshold(keys, 2), false); // 3 sigs, threshold 2
  });

  it("rejects a duplicated member", async () => {
    const keys = await Promise.all([Identity.generate(), Identity.generate(), Identity.generate()]);
    const pre = new Operation({ tuple: await tuple(), action: Action.GRANT, hlc: HLC }).preimage;
    const dup = new Operation({
      tuple: await tuple(),
      action: Action.GRANT,
      hlc: HLC,
      signatures: [await keys[0].sign(pre), await keys[0].sign(pre)],
    });
    assert.equal(await dup.verifyThreshold(keys, 2), false);
  });

  it("rejects a non-member signature", async () => {
    const keys = await Promise.all([Identity.generate(), Identity.generate(), Identity.generate()]);
    const outsider = await Identity.generate();
    const pre = new Operation({ tuple: await tuple(), action: Action.GRANT, hlc: HLC }).preimage;
    const op = new Operation({
      tuple: await tuple(),
      action: Action.GRANT,
      hlc: HLC,
      signatures: [await keys[0].sign(pre), await outsider.sign(pre)],
    });
    assert.equal(await op.verifyThreshold(keys, 2), false);
  });

  it("round-trips a multi-sig payload", async () => {
    const keys = await Promise.all([Identity.generate(), Identity.generate(), Identity.generate()]);
    const op = await new Operation({ tuple: await tuple(), action: Action.GRANT, hlc: HLC }).sign(keys[0], keys[1]);
    const restored = Operation.fromPayload(op.toPayload());
    assert.equal(restored.signatures.length, 2);
    assert.equal(await restored.verifyThreshold(keys, 2), true);
  });
});
