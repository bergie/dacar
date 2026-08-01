import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  packHlc,
  unpackHlc,
  MAX_HLC,
  MAX_PHYSICAL,
  LOGICAL_MASK,
  Clock,
} from "../src/hlc.js";

describe("HLC (§5.1)", () => {
  it("packs/unpacks round-trip", () => {
    const ms = 1_700_000_000_000;
    const hlc = packHlc(ms, 1234);
    assert.deepEqual(unpackHlc(hlc), { physicalMs: ms, logical: 1234 });
  });

  it("places logical in the low 16 bits, physical in the high 48", () => {
    assert.equal(packHlc(0, 1), 1n);
    assert.equal(packHlc(1, 0) >> 16n, 1n);
  });

  it("hits the exact extremes", () => {
    assert.equal(packHlc(0, 0), 0n);
    assert.equal(
      packHlc(Number(MAX_PHYSICAL), Number(LOGICAL_MASK)),
      MAX_HLC,
    );
    assert.deepEqual(unpackHlc(MAX_HLC), {
      physicalMs: Number(MAX_PHYSICAL),
      logical: Number(LOGICAL_MASK),
    });
  });

  it("rejects out-of-range values", () => {
    assert.throws(() => packHlc(Number(MAX_PHYSICAL) + 1, 0));
    assert.throws(() => packHlc(0, Number(LOGICAL_MASK) + 1));
    assert.throws(() => unpackHlc(-1n));
  });
});

describe("Clock", () => {
  it("is monotonic", () => {
    const clock = new Clock();
    let prev = 0n;
    for (let i = 0; i < 1000; i++) {
      const v = clock.now();
      assert.ok(v > prev);
      prev = v;
    }
  });

  it("observe() preserves happens-before", () => {
    const clock = new Clock();
    const a = clock.now();
    const remote = a + 5000n;
    const b = clock.observe(remote);
    assert.ok(b > remote);
    assert.ok(clock.now() > b);
  });
});
