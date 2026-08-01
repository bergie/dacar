#!/bin/sh
# Run the Dacar JS test suite under every installed runtime (node, deno, bun).
#
#   * Each installed runtime runs the suite in turn.
#   * Exits non-zero if NO runtime is installed.
#   * Exits non-zero if any installed runtime's run fails.
#
# The tests use `node:test`, which Node runs natively and Deno/Bun support via
# their Node compatibility layers. Run from the package root or via `npm test`.

set -u

root="$(cd "$(dirname "$0")/.." && pwd)"
ok=0      # 0 = success, 1 = at least one runtime failed
ran=0     # 1 = at least one runtime was available

if command -v node >/dev/null 2>&1; then
  ran=1
  echo "==> node ($(node --version))"
  ( cd "$root" && node --test --test-force-exit "test/**/*.test.js" ) || ok=1
fi

if command -v deno >/dev/null 2>&1; then
  ran=1
  echo "==> deno ($(deno --version 2>&1 | head -1))"
  ( cd "$root" && deno test --allow-read=test,src --allow-env --no-check "test/**/*.test.js" ) || ok=1
fi

if command -v bun >/dev/null 2>&1; then
  ran=1
  echo "==> bun ($(bun --version))"
  ( cd "$root" && bun test "test/**/*.test.js" ) || ok=1
fi

if [ "$ran" -eq 0 ]; then
  echo "dacar: no JavaScript runtime found (install node, deno, or bun)." >&2
  exit 1
fi

exit "$ok"
