import { describe, it, before } from "node:test";
import assert from "node:assert/strict";
import { Identity } from "@reticulum/core";
import { Action, Operation } from "../src/operation.js";
import { Tuple, HASH_SIZE } from "../src/tuple.js";
import { packHlc } from "../src/hlc.js";

const ISSUER = Uint8Array.from({ length: HASH_SIZE }, (_, i) => i);
const GRANTEE = Uint8Array.from({ length: HASH_SIZE }, (_, i) => i + HASH_SIZE);
const encoder = new TextEncoder();

/** @param {bigint} hlc @returns {Uint8Array} */
function hlcBytes(hlc) {
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, hlc, false); // big-endian
  return b;
}

describe("Operation (§5.2, §5.3)", () => {
  /** @type {import("@reticulum/core").Identity} */
  let identity;
  /** @type {Uint8Array} */
  let publicKey;

  before(async () => {
    identity = await Identity.generate();
    publicKey = identity.publicKey; // 64 bytes: X25519[32] || Ed25519[32]
  });

  it("signs and verifies against the identity and its raw public key", async () => {
    const op = await new Operation({
      tuple: new Tuple({ object: "sensor:wind", relation: "calibrate", grantee: GRANTEE, issuer: ISSUER }),
      action: Action.GRANT,
      hlc: packHlc(1_700_000_000_000, 0),
    }).sign(identity);
    assert.equal(await op.verify(identity), true);
    assert.equal(await op.verify(publicKey), true);
  });

  it("rejects verification under a foreign key", async () => {
    const op = await new Operation({
      tuple: new Tuple({ object: "o", relation: "r", grantee: GRANTEE, issuer: ISSUER }),
      action: Action.GRANT,
      hlc: packHlc(1, 0),
    }).sign(identity);
    const other = await Identity.generate();
    assert.equal(await op.verify(other), false);
  });

  it("builds the §5.2 signature pre-image layout", () => {
    const op = new Operation({
      tuple: new Tuple({ object: "o", relation: "rel", grantee: GRANTEE, issuer: ISSUER }),
      action: Action.REVOKE,
      hlc: packHlc(42, 7),
    });
    const relation = encoder.encode("rel");
    const object = encoder.encode("o");
    const expected = new Uint8Array([
      ...ISSUER,
      ...GRANTEE,
      0x00,
      ...hlcBytes(packHlc(42, 7)),
      relation.length,
      ...relation,
      ...object,
    ]);
    assert.deepEqual(op.preimage, expected);
  });

  it("detects tampering with the timestamp", async () => {
    const op = await new Operation({
      tuple: new Tuple({ object: "o", relation: "r", grantee: GRANTEE, issuer: ISSUER }),
      action: Action.GRANT,
      hlc: packHlc(1, 0),
    }).sign(identity);
    const tampered = new Operation({
      tuple: new Tuple({ object: "o", relation: "r", grantee: GRANTEE, issuer: ISSUER }),
      action: Action.GRANT,
      hlc: packHlc(2, 0),
      signature: op.signature,
    });
    assert.equal(await tampered.verify(identity), false);
  });

  it("round-trips through the §5.3 transport payload", async () => {
    const op = await new Operation({
      tuple: new Tuple({ object: "sensor:wind:north", relation: "calibrate", grantee: GRANTEE, issuer: ISSUER }),
      action: Action.GRANT,
      hlc: packHlc(1_700_000_000_000, 9),
    }).sign(identity);
    const restored = Operation.fromPayload(op.toPayload());
    assert.equal(restored.tuple.key, op.tuple.key);
    assert.equal(restored.action, op.action);
    assert.equal(restored.hlc, op.hlc);
    assert.deepEqual(restored.signature, op.signature);
    assert.equal(await restored.verify(identity), true);
  });

  it("refuses to serialize an unsigned operation", () => {
    const op = new Operation({
      tuple: new Tuple({ object: "o", relation: "r", grantee: GRANTEE, issuer: ISSUER }),
      action: Action.GRANT,
      hlc: packHlc(1, 0),
    });
    assert.throws(() => op.toPayload());
  });
});
