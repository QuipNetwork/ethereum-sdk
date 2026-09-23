#!/usr/bin/env bash
# Generate Gambit mutants and run the matching Forge tests; exit nonzero if any survive.
# Run: ./run mutation [source-file] [match-contract]
# Defaults: contracts/shrincs/ShrincsWalletCodec.sol and ShrincsWalletCodec.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

show_usage() {
    cat <<'USAGE'
Usage: ./run mutation [source-file] [match-contract]

Mutate a Solidity source file and run the matching Forge tests against each mutant.

Defaults:
  source-file     contracts/shrincs/ShrincsWalletCodec.sol
  match-contract  ShrincsWalletCodec

Options:
  MUTATION_OUTDIR   Output directory under /cache (default: /cache/gambit)
  MUTATION_TIMEOUT  Seconds allowed for each test run (default: 600)
USAGE
}

fail() {
    echo "Error: $1" >&2
    exit 2
}

check_arguments() {
    if test "$#" -gt 2; then
        show_usage >&2
        fail "Expected at most two arguments."
    fi
}

check_tools() {
    for tool in gambit jq forge timeout git solc; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            fail "$tool is missing. Rebuild the toolchain image with ./run build."
        fi
    done
}

check_source_file() {
    if ! test -f "$SOURCE_FILE"; then
        fail "Source file does not exist: $SOURCE_FILE"
    fi

    if ! git ls-files --error-unmatch -- "$SOURCE_FILE" >/dev/null 2>&1; then
        fail "Source file is not tracked by Git: $SOURCE_FILE"
    fi

    if test -n "$(git status --porcelain -- "$SOURCE_FILE")"; then
        fail "Source file has uncommitted changes. Commit or stash them first: $SOURCE_FILE"
    fi
}

check_output_directory() {
    OUTPUT_DIRECTORY="$(realpath -m -- "$OUTPUT_DIRECTORY")"

    case "$OUTPUT_DIRECTORY" in
        /cache/*) ;;
        *) fail "Output directory must be inside /cache: $OUTPUT_DIRECTORY" ;;
    esac
}

check_timeout() {
    if ! test "$TEST_TIMEOUT_SECONDS" -gt 0 2>/dev/null; then
        fail "MUTATION_TIMEOUT must be a positive number of seconds."
    fi
}

load_remappings() {
    if ! test -f remappings.txt; then
        fail "Cannot find remappings.txt. Run this command from the project root."
    fi

    mapfile -t REMAPPINGS < <(sed '/^[[:space:]]*$/d' remappings.txt)
    if test "${#REMAPPINGS[@]}" -eq 0; then
        fail "remappings.txt is empty."
    fi
}

restore_source_file() {
    git restore --source=HEAD -- "$SOURCE_FILE"
}

generate_mutants() {
    rm -rf -- "$OUTPUT_DIRECTORY"
    mkdir -p -- "$OUTPUT_DIRECTORY"

    if ! gambit mutate \
        --filename "$SOURCE_FILE" \
        --outdir "$OUTPUT_DIRECTORY" \
        --solc_remappings "${REMAPPINGS[@]}" \
        >"$OUTPUT_DIRECTORY/gambit.log" 2>&1; then
        fail "Gambit failed. See $OUTPUT_DIRECTORY/gambit.log"
    fi

    if ! TOTAL_MUTANTS="$(jq 'length' "$RESULTS_FILE")"; then
        fail "Cannot read Gambit results: $RESULTS_FILE"
    fi

    if ! test "$TOTAL_MUTANTS" -gt 0; then
        fail "Gambit generated no mutants for $SOURCE_FILE"
    fi
}

run_baseline_tests() {
    echo "Checking the unchanged source against tests matching $TEST_CONTRACT..."
    if ! timeout "$TEST_TIMEOUT_SECONDS" forge test --match-contract "$TEST_CONTRACT" >/dev/null 2>&1; then
        fail "The baseline tests failed or timed out. Check them before running mutation tests."
    fi
}

read_mutant_field() {
    local mutant_index="$1"
    local field="$2"
    jq -r --argjson index "$mutant_index" --arg field "$field" '.[$index][$field]' "$RESULTS_FILE"
}

test_mutants() {
    local mutant_index=0
    local mutant_id
    local mutant_file
    local description
    local test_status

    echo "Testing $TOTAL_MUTANTS mutants of $SOURCE_FILE..."
    while test "$mutant_index" -lt "$TOTAL_MUTANTS"; do
        mutant_id="$(read_mutant_field "$mutant_index" id)"
        mutant_file="$(read_mutant_field "$mutant_index" name)"
        description="$(read_mutant_field "$mutant_index" description)"

        if ! cp -- "$OUTPUT_DIRECTORY/$mutant_file" "$SOURCE_FILE"; then
            fail "Cannot install mutant #$mutant_id from $OUTPUT_DIRECTORY/$mutant_file"
        fi
        if timeout "$TEST_TIMEOUT_SECONDS" forge test --match-contract "$TEST_CONTRACT" >/dev/null 2>&1; then
            SURVIVORS+=("$mutant_id ($description)")
            echo "Survived: #$mutant_id $description"
        else
            test_status=$?
            KILLED_MUTANTS=$((KILLED_MUTANTS + 1))
            if test "$test_status" -eq 124; then
                echo "Timed out: #$mutant_id $description (counted as killed)"
            else
                echo "Killed:   #$mutant_id $description"
            fi
        fi

        mutant_index=$((mutant_index + 1))
    done
}

report_results() {
    local score=$((100 * KILLED_MUTANTS / TOTAL_MUTANTS))
    echo "Score: $KILLED_MUTANTS/$TOTAL_MUTANTS mutants killed ($score%)"

    if test "${#SURVIVORS[@]}" -gt 0; then
        echo "Surviving mutants (possible test gaps):"
        printf '  - %s\n' "${SURVIVORS[@]}"
        return 1
    fi
}

if test "${1:-}" = "--help"; then
    show_usage
    exit 0
fi

check_arguments "$@"
SOURCE_FILE="${1:-contracts/shrincs/ShrincsWalletCodec.sol}"
TEST_CONTRACT="${2:-ShrincsWalletCodec}"
OUTPUT_DIRECTORY="${MUTATION_OUTDIR-/cache/gambit}"
TEST_TIMEOUT_SECONDS="${MUTATION_TIMEOUT:-600}"
RESULTS_FILE=""
TOTAL_MUTANTS=0
KILLED_MUTANTS=0
SURVIVORS=()
REMAPPINGS=()

check_tools
check_source_file
check_output_directory
check_timeout
load_remappings
RESULTS_FILE="$OUTPUT_DIRECTORY/gambit_results.json"

trap restore_source_file EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

generate_mutants
run_baseline_tests
test_mutants
report_results
