import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { StateVector, DEFAULT_DELETION_HORIZON_DAYS } from "../src/crdt.js";
import { Action, Operation } from "../src/operation.js";
import { Tuple } from "../src/tuple.js";
import { NamespaceHasher } from "../src/namespace.js";
import { packHlc } from "../src/hlc.js";

const HASHER = new NamespaceHasher(Uint8Array.from({ length: 32 }, (_, i) => i));
const ISSUER = Uint8Array.from({ length: 16 }, (_, i) => i);
const GRANTEE = Uint8Array.from({ length: 16 }, (_, i) => i + 16);
const BASE = 1_700_000_000_000;
const DAY = 24 * 60 * 60 * 1000;

/** @param {Object} [opts] @returns {Promise<Operation>} */
async function op({
  object = "sensor:wind",
  relation = "calibrate",
  action = Action.GRANT,
  ms = BASE,
  logical = 0,
} = {}) {
  return new Operation({
    tuple: await Tuple.fromPlaintext({ objectId: object, relation, grantee: GRANTEE, issuer: ISSUER, hasher: HASHER }),
    action,
    hlc: packHlc(ms, logical),
  });
}

describe("StateVector apply (§6)", () => {
  it("grant activates", async () => {
    const s = new StateVector();
    assert.equal(s.apply(await op(), { nowMs: BASE }), true);
    assert.equal(s.isActive((await op()).tuple.key), true);
  });

  it("revoke deactivates", async () => {
    const s = new StateVector();
    s.apply(await op(), { nowMs: BASE });
    s.apply(await op({ action: Action.REVOKE, ms: BASE + 1 }), { nowMs: BASE + 1 });
    assert.equal(s.isActive((await op()).tuple.key), false);
  });

  it("LWW tie resolves to removed (Remove wins)", async () => {
    const s = new StateVector();
    s.apply(await op({ logical: 5 }), { nowMs: BASE });
    s.apply(await op({ action: Action.REVOKE, logical: 5 }), { nowMs: BASE });
    assert.equal(s.isActive((await op()).tuple.key), false);
  });

  it("older operations do not override newer ones", async () => {
    const s = new StateVector();
    s.apply(await op({ logical: 5 }), { nowMs: BASE });
    s.apply(await op({ action: Action.REVOKE, logical: 1 }), { nowMs: BASE });
    assert.equal(s.isActive((await op()).tuple.key), true);
  });
});

describe("StateVector intake rejection (§9, §12)", () => {
  it("rejects far-future operations (§12)", async () => {
    const s = new StateVector();
    assert.equal(s.apply(await op({ ms: BASE + 365 * DAY }), { nowMs: BASE }), false);
    assert.equal(s.size, 0);
  });

  it("rejects stale deltas beyond the horizon (§9 intake rejection)", async () => {
    const s = new StateVector({ deletionHorizonDays: 180 });
    assert.equal(s.apply(await op({ ms: BASE - 181 * DAY }), { nowMs: BASE }), false);
    assert.equal(s.size, 0);
  });

  it("accepts deltas within the horizon", async () => {
    const s = new StateVector({ deletionHorizonDays: 180 });
    assert.equal(s.apply(await op({ ms: BASE - 100 * DAY }), { nowMs: BASE }), true);
    assert.equal(s.size, 1);
  });
});

describe("StateVector prune (§9)", () => {
  it("pairwise-deletes an old, inactive pair", async () => {
    const s = new StateVector({ deletionHorizonDays: 180 });
    const key = (await op()).tuple.key;
    s.apply(await op({ ms: BASE, logical: 1 }), { nowMs: BASE });
    s.apply(await op({ action: Action.REVOKE, ms: BASE, logical: 2 }), { nowMs: BASE });
    assert.equal(s.isActive(key), false);
    assert.equal(s.prune({ nowMs: BASE + 365 * DAY }), 1);
    assert.equal(s.has(key), false);
  });

  it("never prunes active grants", async () => {
    const s = new StateVector({ deletionHorizonDays: 180 });
    const key = (await op()).tuple.key;
    s.apply(await op({ ms: BASE }), { nowMs: BASE });
    assert.equal(s.prune({ nowMs: BASE + 365 * DAY }), 0);
    assert.equal(s.isActive(key), true);
  });

  it("keeps recent revocations", async () => {
    const s = new StateVector({ deletionHorizonDays: 180 });
    const key = (await op()).tuple.key;
    s.apply(await op({ ms: BASE }), { nowMs: BASE });
    s.apply(await op({ action: Action.REVOKE, ms: BASE + 10 * DAY }), { nowMs: BASE + 10 * DAY });
    assert.equal(s.prune({ nowMs: BASE + 20 * DAY }), 0);
  });
});

describe("StateVector merge (§6)", () => {
  it("takes the max HLC per set", async () => {
    const a = new StateVector();
    const b = new StateVector();
    a.apply(await op({ logical: 1 }), { nowMs: BASE });
    b.apply(await op({ logical: 3 }), { nowMs: BASE });
    a.merge(b);
    assert.equal(a.get((await op()).tuple.key).addTs, packHlc(BASE, 3));
  });

  it("is order-independent", async () => {
    const key = (await op()).tuple.key;
    const a = new StateVector();
    const b = new StateVector();
    a.apply(await op({ logical: 1 }), { nowMs: BASE });
    a.apply(await op({ action: Action.REVOKE, logical: 2 }), { nowMs: BASE });
    b.apply(await op({ logical: 3 }), { nowMs: BASE });
    const x = new StateVector();
    x.apply(await op({ logical: 1 }), { nowMs: BASE });
    x.merge(a); x.merge(b);
    const y = new StateVector();
    y.apply(await op({ logical: 1 }), { nowMs: BASE });
    y.merge(b); y.merge(a);
    assert.equal(x.isActive(key), y.isActive(key));
  });
});

describe("StateVector serialization", () => {
  it("round-trips through MessagePack", async () => {
    const s = new StateVector();
    s.apply(await op({ object: "sensor:wind:north", relation: "read" }), { nowMs: BASE });
    s.apply(await op({ object: "sensor:wind", relation: "-write", ms: BASE + 1 }), { nowMs: BASE + 1 });
    const restored = StateVector.fromPayload(s.toPayload());
    assert.equal(restored.size, s.size);
    for (const t of s.activeTuples()) {
      assert.equal(restored.isActive(t.key), true);
    }
    assert.equal(DEFAULT_DELETION_HORIZON_DAYS, 180);
  });
});
