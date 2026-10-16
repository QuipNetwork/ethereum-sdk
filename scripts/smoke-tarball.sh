#!/usr/bin/env bash
# Smoke test: pack the SDK, install the tarball into a scratch project,
# and verify a small set of imports + a purely-local code path execute
# cleanly. Catches packaging/exports/dist-layout regressions that the
# in-repo tests (which import from `src/`) can't see.
#
# Usage:
#   scripts/smoke-tarball.sh        # builds + runs smoke
#   scripts/smoke-tarball.sh --no-build  # reuse existing dist/
#
# Exit codes:
#   0  — all imports and the local op succeeded
#   1  — pack/install/check failed; details on stderr
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CHECK_SCRIPT="$SCRIPT_DIR/smoke-check.mjs"

cd "$REPO_ROOT"

# 1. Build (unless explicitly skipped).
if [[ "${1:-}" != "--no-build" ]]; then
  echo "==> Building SDK..."
  npm run build > /tmp/smoke-build.log 2>&1 || {
    echo "FAIL: build failed; see /tmp/smoke-build.log" >&2
    exit 1
  }
fi

# 2. Pack into a tarball. `npm pack` writes the .tgz into the cwd and
#    prints the filename on the last line of stdout.
echo "==> Packing tarball..."
TARBALL_NAME="$(npm pack 2>/dev/null | tail -n 1)"
TARBALL_PATH="$REPO_ROOT/$TARBALL_NAME"
if [[ ! -f "$TARBALL_PATH" ]]; then
  echo "FAIL: expected tarball at $TARBALL_PATH but file missing" >&2
  exit 1
fi
echo "    -> $TARBALL_NAME"

# 3. Create a scratch project, install the tarball + viem peer dep.
SCRATCH_DIR="$(mktemp -d -t quip-smoke-XXXXXX)"
trap 'rm -rf "$SCRATCH_DIR" "$TARBALL_PATH"' EXIT
echo "==> Scratch project: $SCRATCH_DIR"

cd "$SCRATCH_DIR"
cat > package.json <<EOF
{
  "name": "quip-smoke",
  "version": "0.0.0",
  "private": true,
  "type": "module"
}
EOF

echo "==> Installing tarball..."
# Install the SDK plus its peer/runtime deps that exporting consumers
# need: viem (v1) and ethers (v0, optional peer — required when
# importing from /v0).
npm install --no-audit --no-fund --silent "$TARBALL_PATH" viem ethers > /tmp/smoke-install.log 2>&1 || {
  echo "FAIL: install failed; see /tmp/smoke-install.log" >&2
  exit 1
}

# 4. Run the check script (imports + local-only ops).
echo "==> Running smoke check..."
cp "$CHECK_SCRIPT" ./smoke-check.mjs
node ./smoke-check.mjs || {
  echo "FAIL: smoke check failed" >&2
  exit 1
}

echo "==> PASS"
