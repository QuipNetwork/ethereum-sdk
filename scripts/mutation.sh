#!/usr/bin/env bash
# Generate Gambit mutants and run the matching Forge tests; exit nonzero if any survive.
# Run: ./run mutation [source-file] [match-contract]
# Defaults: contracts/shrincs/ShrincsWalletCodec.sol and ShrincsWalletCodec.
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
