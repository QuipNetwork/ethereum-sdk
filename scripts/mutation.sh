#!/usr/bin/env bash
# Mutation testing for the Foundry suite via Certora Gambit.
#
# Generates source mutants for one contract, runs the scoped forge tests
# against each mutant, and reports the kill score. A surviving mutant is a
# test gap: the scoped suite passes on code that is wrong.
#
# Usage:
#   ./run mutation [source-file] [match-contract]
#
#   source-file    Contract to mutate, repo-relative.
#                  Default: contracts/shrincs/ShrincsWalletCodec.sol
#   match-contract Forge --match-contract filter for the scoped tests.
#                  Default: ShrincsWalletCodec
#
# Environment:
#   MUTATION_OUTDIR  Where gambit writes mutants. Default: /cache/gambit
#                    (/cache persists across ./run invocations; the repo
#                    itself is never polluted — swapped files are restored).
#   MUTATION_TIMEOUT Per-mutant `forge test` timeout in seconds. Default: 600.
#
# Recovery: if the run is killed violently (SIGKILL/OOM/CI timeout) the trap
# below cannot fire and the swapped mutant persists in the worktree — recover
# with `git checkout -- <source-file>`. The preflight refuses to start when
# the target file has uncommitted changes, so the trap can only ever discard
# the runner's own swap, never user edits.
#
# Examples:
#   ./run mutation
#   ./run mutation contracts/storage/WalletFactoryStorage.sol WalletFactory
#
# Exit codes:
#   0 — every mutant killed
#   1 — at least one mutant survived (test gap; ids listed on stdout)
#   2 — usage or tooling error
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

[ "$#" -le 2 ] || {
    echo "✗ too many arguments (expected [source-file] [match-contract])" >&2
    exit 2
}
FILE="${1:-contracts/shrincs/ShrincsWalletCodec.sol}"
FILTER="${2:-ShrincsWalletCodec}"
OUTDIR="${MUTATION_OUTDIR-/cache/gambit}"
TIMEOUT_SECS="${MUTATION_TIMEOUT:-600}"

OUTDIR="$(realpath -m -- "$OUTDIR")"
case "$OUTDIR" in
/cache/*) ;;
*)
    echo "✗ refusing to clear OUTDIR=$OUTDIR (must be under /cache)" >&2
    exit 2
    ;;
esac

for tool in gambit jq forge timeout git solc; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "✗ $tool not found. Rebuild the toolchain image: ./run build" >&2
        exit 2
    }
done
[ -f "$FILE" ] || {
    echo "✗ source file not found: $FILE" >&2
    exit 2
}
git ls-files --error-unmatch -- "$FILE" >/dev/null 2>&1 || {
    echo "✗ $FILE is not tracked in this repo" >&2
    exit 2
}
[ -z "$(git status --porcelain -- "$FILE")" ] || {
    echo "✗ $FILE has uncommitted changes; commit or stash first" >&2
    exit 2
}

restore() {
    git checkout -- "$FILE"
}
trap restore EXIT INT TERM HUP

mapfile -t REMAPPINGS < <(grep -v '^[[:space:]]*$' remappings.txt) || {
    echo "✗ cannot read remappings.txt" >&2
    exit 2
}
rm -rf "$OUTDIR"
mkdir -p "$OUTDIR"
gambit mutate \
    --filename "$FILE" \
    --outdir "$OUTDIR" \
    --solc_remappings "${REMAPPINGS[@]}" \
    >"$OUTDIR/gambit.log" 2>&1 || {
    echo "✗ gambit failed (see $OUTDIR/gambit.log)" >&2
    exit 2
}

TOTAL="$(jq '. | length' "$OUTDIR/gambit_results.json")" || {
    echo "✗ cannot parse $OUTDIR/gambit_results.json" >&2
    exit 2
}
[ "$TOTAL" -gt 0 ] || {
    echo "✗ gambit generated no mutants for $FILE" >&2
    exit 2
}

echo "Baseline: scoped suite on unmutated code…"
timeout "$TIMEOUT_SECS" forge test --match-contract "$FILTER" >/dev/null 2>&1 || {
    echo "✗ baseline suite fails on unmutated code; fix the suite first" >&2
    exit 2
}

echo "Mutants: $TOTAL for $FILE (tests: --match-contract $FILTER)"
killed=0
survived=()
for i in $(seq 0 $((TOTAL - 1))); do
    id="$(jq -r ".[$i].id" "$OUTDIR/gambit_results.json")"
    name="$(jq -r ".[$i].name" "$OUTDIR/gambit_results.json")"
    desc="$(jq -r ".[$i].description" "$OUTDIR/gambit_results.json")"
    cp "$OUTDIR/$name" "$FILE"
    if timeout "$TIMEOUT_SECS" forge test --match-contract "$FILTER" >/dev/null 2>&1; then
        survived+=("$id ($desc)")
        echo "SURVIVED  #$id $desc"
    else
        status=$?
        killed=$((killed + 1))
        if [ "$status" -eq 124 ]; then
            echo "timeout   #$id $desc (counted killed)"
        else
            echo "killed    #$id $desc"
        fi
    fi
done

restore
trap - EXIT INT TERM HUP

score=$((100 * killed / TOTAL))
echo "Score: $killed/$TOTAL killed (${score}%)"
if [ "${#survived[@]}" -gt 0 ]; then
    echo "Survivors (test gaps):"
    printf '  - %s\n' "${survived[@]}"
    exit 1
fi
