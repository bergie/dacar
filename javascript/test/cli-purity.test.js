import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));

/**
 * Read a source file as text.
 * @param {string} rel Path relative to the package root.
 * @returns {string}
 */
function src(rel) {
  return readFileSync(join(here, "..", rel), "utf8");
}

describe("browser purity (work doc #6)", () => {
  it("the public core entry never imports @reticulum/node", () => {
    const files = ["src/index.js", "src/verifier.js", "src/delta.js"];
    for (const f of files) {
      assert.match(src(f), /^[^]*$/); // sanity: file reads
      assert.doesNotMatch(
        src(f),
        /@reticulum\/node/,
        `${f} must not import @reticulum/node`,
      );
    }
  });

  it("the portable CLI helpers (session/store) never import @reticulum/node", () => {
    // These are browser-safe entry points (exposed via ./cli/session, ./cli/store).
    // Only the Node-only bin (dacar.js) and its Node-only helpers (fileStore.js)
    // may import @reticulum/node.
    for (const f of ["src/cli/session.js", "src/cli/store.js"]) {
      const text = src(f);
      assert.doesNotMatch(
        text,
        /from\s+["']@reticulum\/node/,
        `${f} must not import @reticulum/node (it is browser-portable)`,
      );
    }
  });

  it("the Node-only CLI bin + file adapter import @reticulum/node", () => {
    // dacar.js is the CLI entry; fileStore.js is the Python-parity loose-file
    // adapter (imports node:fs + @reticulum/node's FileStorageAdapter).
    assert.match(
      src("src/cli/fileStore.js"),
      /from\s+["']@reticulum\/node/,
      "fileStore.js should import @reticulum/node (delegates identity + ratchets)",
    );
  });

  it("the core index does not re-export the cli subpath", () => {
    const core = src("src/index.js");
    assert.doesNotMatch(core, /cli\//, "core index must not re-export the cli layer");
  });

  it("the transport index does not import @reticulum/node", () => {
    const transport = src("src/transport/index.js");
    assert.doesNotMatch(
      transport,
      /@reticulum\/node/,
      "transport layer must not import @reticulum/node",
    );
  });
});
