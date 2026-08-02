import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const coreIndex = readFileSync(join(here, "..", "src", "index.js"), "utf8");

describe("core purity (transport layering)", () => {
  it("the public core entry does not import the transport subpath", () => {
    // Importing the pure core must stay free of the RNS/RFed/LXMF transport
    // adapters — they are opt-in via @reticulum/dacar/transport (spec §8/§11).
    assert.equal(/transport\//.test(coreIndex), false, "core leaked the transport layer");
    assert.equal(/rnsIdentity|rnsChallenge|lxmfSync|rfedSync/.test(coreIndex), false);
  });
});
