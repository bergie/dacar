#!/bin/sh
# Run the Dacar JS test suite under every installed runtime (node, deno, bun).
#
#   * Each installed runtime runs the suite in turn.
#   * Exits non-zero if NO runtime is installed.
#   * Exits non-zero if any installed runtime's run fails.
#
# The test files live flat in test/ (*.test.js). We pass an UNQUOTED POSIX glob
# (test/*.test.js) so /bin/sh expands it to an explicit file list before handing
# it to each runtime. This is portable across Node 18+ (no reliance on Node 21+
# --test globbing), Deno, and Bun (which treats a bare "**" arg as a filter,
# not a path). If test files ever nest into subdirectories, switch to
# runtime-native discovery or a `find`-built list.

set -u

root="$(cd "$(dirname "$0")/.." && pwd)"
ok=0      # 0 = success, 1 = at least one runtime failed
ran=0     # 1 = at least one runtime was available

if command -v node >/dev/null 2>&1; then
  ran=1
  echo "==> node ($(node --version))"
  ( cd "$root" && node --test --test-force-exit test/*.test.js ) || ok=1
fi

if command -v deno >/dev/null 2>&1; then
  ran=1
  echo "==> deno ($(deno --version 2>&1 | head -1))"
  # --allow-read/--allow-write are unscoped: test/cli-rns-boot.test.js boots a
  # real Reticulum via FileStorageAdapter(configDir) against an OS temp dir
  # (mkdtempSync(os.tmpdir())), which both reads and writes there. The temp
  # dir path is OS/user-specific (macOS /var/folders, Linux /tmp), so it can't
  # be portably added to --allow-read=test,src — read+write must cover it.
  ( cd "$root" && deno test --allow-read --allow-write --allow-env --no-check test/*.test.js ) || ok=1
fi

if command -v bun >/dev/null 2>&1; then
  ran=1
  echo "==> bun ($(bun --version))"
  ( cd "$root" && bun test test/*.test.js ) || ok=1
fi

if [ "$ran" -eq 0 ]; then
  echo "dacar: no JavaScript runtime found (install node, deno, or bun)." >&2
  exit 1
fi

exit "$ok"
