import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { Config } from "../src/config.js";
import { StateVector } from "../src/crdt.js";
import { Engine } from "../src/engine.js";
import { Clock } from "../src/hlc.js";
import { Action, Operation } from "../src/operation.js";
import { Tuple } from "../src/tuple.js";

/** @param {number} n @returns {Uint8Array} a distinct 16-byte identity hash */
function id(n) {
  // Injective over the small range of test identities: vary the final byte,
  // keep the rest constant. Avoids the wraparound collisions that a naive
  // `(n*16+i) & 0xff` scheme produces for n >= 16.
  const b = new Uint8Array(16);
  b[0] = 0x01;
  b[15] = n & 0xff;
  return b;
}

const ROOT = id(0);
const ADMIN1 = id(1);
const ADMIN2 = id(2);
const BOB = id(3);
const ALICE = id(4);

/**
 * @param {Object} [opts]
 * @returns {{ state: StateVector, clock: Clock, engine: Engine, grant: (o: string, r: string, g: Uint8Array, i: Uint8Array) => void }}
 */
function fixture(opts = {}) {
  const { maxDepth = 10, maxVisited = 50 } = opts;
  const state = new StateVector();
  const clock = new Clock();
  const engine = new Engine(
    new Config({ rootTrustAnchors: [ROOT] }),
    state,
    { maxDepth, maxVisited },
  );
  /** @param {string} o @param {string} r @param {Uint8Array} g @param {Uint8Array} i */
  function grant(o, r, g, i) {
    state.apply(
      new Operation({
        tuple: new Tuple({ object: o, relation: r, grantee: g, issuer: i }),
        action: Action.GRANT,
        hlc: clock.now(),
      }),
    );
  }
  return { state, clock, engine, grant };
}

describe("Engine resolution (§7.3)", () => {
  it("default deny", () => {
    const { engine } = fixture();
    assert.equal(engine.evaluate("sensor:wind", "calibrate", BOB), false);
  });

  it("root anchor direct grant", () => {
    const { engine, grant } = fixture();
    grant("sensor:wind", "calibrate", BOB, ROOT);
    assert.equal(engine.evaluate("sensor:wind", "calibrate", BOB), true);
  });

  it("wrong grantee denied", () => {
    const { engine, grant } = fixture();
    grant("sensor:wind", "calibrate", BOB, ROOT);
    assert.equal(engine.evaluate("sensor:wind", "calibrate", ALICE), false);
  });

  it("wrong relation denied", () => {
    const { engine, grant } = fixture();
    grant("sensor:wind", "read", BOB, ROOT);
    assert.equal(engine.evaluate("sensor:wind", "write", BOB), false);
  });
});

describe("Engine delegation (§7.2, §3.2)", () => {
  it("delegated admin chain", () => {
    const { engine, grant } = fixture();
    grant("sensor:wind", "admin", ADMIN1, ROOT);
    grant("sensor:wind", "calibrate", BOB, ADMIN1);
    assert.equal(engine.evaluate("sensor:wind", "calibrate", BOB), true);
  });

  it("undelegated issuer denied", () => {
    const { engine, grant } = fixture();
    grant("sensor:wind", "calibrate", BOB, ADMIN1);
    assert.equal(engine.evaluate("sensor:wind", "calibrate", BOB), false);
  });

  it("wildcard admin cascades to child namespaces", () => {
    const { engine, grant } = fixture();
    grant("sensor:*", "admin", ADMIN1, ROOT);
    grant("sensor:wind:north", "calibrate", BOB, ADMIN1);
    assert.equal(engine.evaluate("sensor:wind:north", "calibrate", BOB), true);
  });

  it("exact admin does NOT cascade", () => {
    const { engine, grant } = fixture();
    grant("sensor:wind", "admin", ADMIN1, ROOT);
    grant("sensor:wind:north", "calibrate", BOB, ADMIN1);
    assert.equal(engine.evaluate("sensor:wind:north", "calibrate", BOB), false);
  });
});

describe("Engine explicit deny", () => {
  it("deny overrides allow", () => {
    const { engine, grant } = fixture();
    grant("sensor:wind", "calibrate", BOB, ROOT);
    grant("sensor:wind", "-calibrate", BOB, ROOT);
    assert.equal(engine.evaluate("sensor:wind", "calibrate", BOB), false);
  });

  it("exact deny overrides wildcard allow, sibling still allowed", () => {
    const { engine, grant } = fixture();
    grant("sensor:*", "calibrate", BOB, ROOT);
    grant("sensor:wind", "-calibrate", BOB, ROOT);
    assert.equal(engine.evaluate("sensor:wind", "calibrate", BOB), false);
    assert.equal(engine.evaluate("sensor:rain", "calibrate", BOB), true);
  });
});

describe("Engine safety bounds", () => {
  it("rejects cycles and terminates", () => {
    const { engine, grant } = fixture();
    grant("o", "admin", ADMIN1, ADMIN2);
    grant("o", "admin", ADMIN2, ADMIN1);
    grant("o", "r", BOB, ADMIN1);
    assert.equal(engine.evaluate("o", "r", BOB), false);
  });

  it("depth cap rejects overlong chains", () => {
    const { engine, grant } = fixture({ maxDepth: 10 });
    const ids = [];
    for (let i = 1; i <= 16; i++) ids.push(id(i));
    for (let k = 1; k < ids.length; k++) grant("o", "admin", ids[k], ids[k - 1]);
    grant("o", "r", BOB, ids[ids.length - 1]);
    assert.equal(engine.evaluate("o", "r", BOB), false);
  });

  it("valid chain within depth is allowed", () => {
    const { engine, grant } = fixture({ maxDepth: 10 });
    const a = id(10);
    const b = id(20);
    grant("o", "admin", a, ROOT);
    grant("o", "admin", b, a);
    grant("o", "read", BOB, b);
    assert.equal(engine.evaluate("o", "read", BOB), true);
  });
});
