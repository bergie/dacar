// Post-processes the generated declaration files in types/src:
//
// 1. tsc emits relative specifiers as "./x.js", relying on TypeScript's
//    .js -> .d.ts companion mapping. Deno does not apply that mapping to local
//    declaration files, so package consumers that resolve types through the
//    @ts-self-types pragmas (JSR / deno check) fail with TS2307. Rewriting the
//    specifiers to "./x.d.ts" resolves under Deno as well as tsc.
//
// 2. For re-export-only modules (barrels), tsc drops the module JSDoc — a
//    .d.ts with bare re-export statements carries no leading doc block. Deno's
//    doc tooling then reports such modules as having no module docs (which
//    costs JSR score points for non-main entrypoints), so copy the JS file's
//    leading doc block onto its .d.ts when the .d.ts lacks one.
//
// Run after tsc: npm run types
import { readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { join, relative, resolve } from "node:path";

const root = fileURLToPath(new URL("../types/src", import.meta.url));
const srcRoot = resolve(root, "../../src");

function walk(dir) {
  return readdirSync(dir).flatMap((entry) => {
    const path = join(dir, entry);
    return statSync(path).isDirectory() ? walk(path) : [path];
  });
}

/** Leading `/** ... *\/` doc block of a JS source file, if any. */
function moduleDocOf(jsPath) {
  const text = readFileSync(jsPath, "utf8");
  if (!text.startsWith("/**")) return null;
  const end = text.indexOf("*/");
  if (end === -1) return null;
  return text.slice(0, end + 2);
}

let updated = 0;
let addedModuleDocs = 0;
for (const path of walk(root)) {
  if (!path.endsWith(".d.ts")) continue;
  const original = readFileSync(path, "utf8");

  // 1. rewrite relative ".js" specifiers (from-clauses and import() types)
  let output = original.replace(
    /(["'])(\.{1,2}\/[^"']*?)\.js\1/g,
    (_match, quote, specifier) => `${quote}${specifier}.d.ts${quote}`,
  );

  // 2. carry the JS module doc over to the declaration file
  const jsPath = resolve(
    srcRoot,
    relative(root, path).replace(/\.d\.ts$/, ".js"),
  );
  const moduleDoc = moduleDocOf(jsPath);
  if (moduleDoc && !output.startsWith("/**")) {
    output = `${moduleDoc}\n${output}`;
    addedModuleDocs += 1;
  }

  if (output !== original) {
    writeFileSync(path, output);
    updated += 1;
  }
}
console.log(`fix-dts: updated ${updated} declaration file(s)`);
console.log(`fix-dts: added module docs to ${addedModuleDocs} declaration file(s)`);
