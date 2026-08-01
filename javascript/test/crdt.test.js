import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { StateVector } from "../src/crdt.js";
import { Action, Operation } from "../src/operation.js";
import { Tuple } from "../src/tuple.js";
import { packHlc } from "../src/hlc.js";

const ISSUER = Uint8Array.from({ length: 16 }, (_, i) => i);
const GRANTEE = Uint8Array.from({ length: 16 }, (_, i) => i + 16);
const BASE = 1_700_000_000_000;

/**
 * @param {Object} [opts]
 * @returns {Operation}
 */
function op(opts = {}) {
  const {
    object = "sensor:wind",
    relation = "calibrate",
    action = Action.GRANT,
    ms = BASE,
    logical = 0,
  } = opts;
  return new Operation({
    tuple: new Tuple({ object, relation, grantee: GRANTEE, issuer: ISSUER }),
    action,
    hlc: packHlc(ms, logical),
  });
}

describe("StateVector apply (§6)", () => {
  it("grant activates", () => {
    const s = new StateVector();
    assert.equal(s.apply(op()), true);
    assert.equal(s.isActive(op().tuple.key), true);
  });

  it("revoke deactivates", () => {
    const s = new StateVector();
    s.apply(op());
    s.apply(op({ action: Action.REVOKE, ms: BASE + 1 }));
    assert.equal(s.isActive(op().tuple.key), false);
  });

  it("LWW tie resolves to removed (Remove wins)", () => {
    const s = new StateVector();
    s.apply(op({ logical: 5 }));
    s.apply(op({ action: Action.REVOKE, logical: 5 }));
    assert.equal(s.isActive(op().tuple.key), false);
  });

  it("older operations do not override newer ones", () => {
    const s = new StateVector();
    s.apply(op({ logical: 5 }));
    s.apply(op({ action: Action.REVOKE, logical: 1 }));
    assert.equal(s.isActive(op().tuple.key), true);
  });

  it("rejects far-future operations (§9)", () => {
    const s = new StateVector();
    const future = op({ ms: BASE + 365 * 24 * 3600 * 1000 });
    assert.equal(s.apply(future, { nowMs: BASE }), false);
    assert.equal(s.size, 0);
  });
});

describe("StateVector merge (§6.2)", () => {
  it("takes the max HLC per set", () => {
    const a = new StateVector();
    const b = new StateVector();
    a.apply(op({ logical: 1 }));
    b.apply(op({ logical: 3 }));
    a.merge(b);
    assert.deepEqual(a.get(op().tuple.key).addTs, packHlc(BASE, 3));
  });

  it("is order-independent", () => {
    const a = new StateVector();
    const b = new StateVector();
    a.apply(op({ logical: 1 }));
    a.apply(op({ action: Action.REVOKE, logical: 2 }));
    b.apply(op({ logical: 3 }));
    const x = new StateVector();
    x.apply(op({ logical: 1 }));
    x.merge(a);
    x.merge(b);
    const y = new StateVector();
    y.apply(op({ logical: 1 }));
    y.merge(b);
    y.merge(a);
    assert.equal(x.isActive(op().tuple.key), y.isActive(op().tuple.key));
  });
});

describe("StateVector serialization", () => {
  it("round-trips through MessagePack", () => {
    const s = new StateVector();
    s.apply(op({ object: "sensor:wind:north", relation: "read" }));
    s.apply(op({ object: "sensor:wind", relation: "-write", ms: BASE + 1 }));
    const restored = StateVector.fromPayload(s.toPayload());
    assert.equal(restored.size, s.size);
    for (const t of s.activeTuples()) {
      assert.equal(restored.isActive(t.key), true);
    }
  });
});
