import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { Tuple, HASH_SIZE } from "../src/tuple.js";

const ISSUER = Uint8Array.from({ length: HASH_SIZE }, (_, i) => i);
const GRANTEE = Uint8Array.from({ length: HASH_SIZE }, (_, i) => i + HASH_SIZE);
const encoder = new TextEncoder();

describe("Tuple (§3.1, §6.1)", () => {
  it("hash matches the spec pre-image layout", async () => {
    const t = new Tuple({
      object: "sensor:wind",
      relation: "calibrate",
      grantee: GRANTEE,
      issuer: ISSUER,
    });
    const relation = encoder.encode("calibrate");
    const object = encoder.encode("sensor:wind");
    const preimage = new Uint8Array(16 + 16 + 1 + relation.length + object.length);
    preimage.set(ISSUER, 0);
    preimage.set(GRANTEE, 16);
    preimage[32] = relation.length;
    preimage.set(relation, 33);
    preimage.set(object, 33 + relation.length);
    const expected = new Uint8Array(await crypto.subtle.digest("SHA-256", preimage));
    assert.deepEqual(await t.hash(), expected);
  });

  it("per-issuer distinctness", async () => {
    const other = Uint8Array.from({ length: HASH_SIZE }, (_, i) => i + 1);
    const t1 = new Tuple({ object: "o", relation: "r", grantee: GRANTEE, issuer: ISSUER });
    const t2 = new Tuple({ object: "o", relation: "r", grantee: GRANTEE, issuer: other });
    assert.notDeepEqual(await t1.hash(), await t2.hash());
  });

  it("per-grantee distinctness", async () => {
    const other = Uint8Array.from({ length: HASH_SIZE }, (_, i) => i + 2);
    const t1 = new Tuple({ object: "o", relation: "r", grantee: GRANTEE, issuer: ISSUER });
    const t2 = new Tuple({ object: "o", relation: "r", grantee: other, issuer: ISSUER });
    assert.notDeepEqual(await t1.hash(), await t2.hash());
  });

  it("rejects malformed inputs", () => {
    assert.throws(() =>
      new Tuple({ object: "o", relation: "r", grantee: new Uint8Array(3), issuer: ISSUER }),
    );
    assert.throws(() =>
      new Tuple({ object: "o", relation: "r", grantee: GRANTEE, issuer: new Uint8Array(3) }),
    );
    assert.throws(() =>
      new Tuple({ object: "o", relation: "x".repeat(256), grantee: GRANTEE, issuer: ISSUER }),
    );
  });

  it("exposes a stable sync key", () => {
    const t1 = new Tuple({ object: "o", relation: "r", grantee: GRANTEE, issuer: ISSUER });
    const t2 = new Tuple({ object: "o", relation: "r", grantee: GRANTEE, issuer: ISSUER });
    assert.equal(typeof t1.key, "string");
    assert.equal(t1.key, t2.key);
  });
});
