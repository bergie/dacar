import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { Config } from "../src/config.js";

const ROOT = Uint8Array.from({ length: 16 }, (_, i) => i);

describe("Config (§4)", () => {
  it("requires at least one anchor", () => {
    assert.throws(() => new Config({ rootTrustAnchors: [] }));
  });

  it("validates anchor length", () => {
    assert.throws(() => new Config({ rootTrustAnchors: [new Uint8Array(3)] }));
  });

  it("authoritative identity is optional", () => {
    const cfg = new Config({ rootTrustAnchors: [ROOT] });
    assert.equal(cfg.authoritativeIdentity, undefined);
    assert.equal(cfg.isRootAnchor(ROOT), true);
  });

  it("validates authoritative identity length", () => {
    assert.throws(() =>
      new Config({ rootTrustAnchors: [ROOT], authoritativeIdentity: new Uint8Array(3) }),
    );
  });

  it("supports multiple anchors", () => {
    const other = Uint8Array.from({ length: 16 }, (_, i) => i + 16);
    const cfg = new Config({ rootTrustAnchors: [ROOT, other] });
    assert.equal(cfg.isRootAnchor(ROOT), true);
    assert.equal(cfg.isRootAnchor(other), true);
  });
});
