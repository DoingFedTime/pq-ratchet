#!/usr/bin/env bash
# run_adversarial_tests.sh
#
# Builds and runs every test suite in the pq-ratchet adversarial test matrix.
# Prints a summary table and exits non-zero if any suite failed.
#
# Usage:
#   ./run_adversarial_tests.sh [--no-miri] [--no-docker]
#
# Flags:
#   --no-miri     Skip the Miri stage (slow; requires nightly).
#   --no-docker   Run cargo directly instead of via Docker (uses local toolchain).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ── Parse flags ───────────────────────────────────────────────────────────────
USE_MIRI=1
USE_DOCKER=1
for arg in "$@"; do
  case "$arg" in
    --no-miri)   USE_MIRI=0 ;;
    --no-docker) USE_DOCKER=0 ;;
    *) echo "Unknown flag: $arg"; exit 1 ;;
  esac
done

# ── Colour helpers ────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
RESET='\033[0m'

pass() { echo -e "${GREEN}PASS${RESET}"; }
fail() { echo -e "${RED}FAIL${RESET}"; }

# ── Suite registry ────────────────────────────────────────────────────────────
# Each entry: "label|docker-target|cargo-command"
SUITES=(
  "clippy|clippy-tests|cargo clippy --all-features -- -D warnings"
  "stable|stable-tests|cargo test --tests -- --test-threads=1"
  "adversarial|adversarial|cargo test --test adversarial -- --test-threads=1"
  "proptest-heavy|proptest-heavy|PROPTEST_CASES=5000 cargo test --test proptest"
)
if [ "$USE_MIRI" -eq 1 ]; then
  SUITES+=("miri|miri-tests|cargo miri test --lib")
fi

# ── Run suites ────────────────────────────────────────────────────────────────
declare -A RESULTS
declare -A DURATIONS

COMPOSE_FILE="$SCRIPT_DIR/docker-compose.adversarial.yml"

run_suite_docker() {
  local label="$1"
  local target="$2"
  echo -e "\n${BOLD}Building Docker target: ${target}${RESET}"
  # Tests execute during the build (via RUN instructions). A non-zero exit means
  # at least one test failed. We deliberately avoid set -e in this function so
  # we can capture the exit code and record it instead of aborting the script.
  if ! docker build \
      --file Dockerfile.test \
      --target "$target" \
      --tag "pq-ratchet-${label}:ci" \
      . 2>&1; then
    echo -e "${RED}Docker build FAILED for target: ${target}${RESET}"
    return 1
  fi
  echo -e "${GREEN}Docker build succeeded for: ${label}${RESET}"
}

run_suite_local() {
  local label="$1"
  local cmd="$2"
  echo -e "\n${BOLD}Running suite locally: ${label}${RESET}"
  eval "$cmd" 2>&1
}

echo -e "\n${BOLD}====== pq-ratchet Adversarial Test Matrix ======${RESET}"
echo "Mode: $([ "$USE_DOCKER" -eq 1 ] && echo 'Docker' || echo 'Local cargo')"
echo "Miri: $([ "$USE_MIRI" -eq 1 ] && echo 'enabled' || echo 'disabled')"
echo

OVERALL_PASS=1

for entry in "${SUITES[@]}"; do
  IFS='|' read -r label target cmd <<< "$entry"

  START_TS=$(date +%s)

  if [ "$USE_DOCKER" -eq 1 ]; then
    if run_suite_docker "$label" "$target"; then
      RESULTS[$label]="PASS"
    else
      RESULTS[$label]="FAIL"
      OVERALL_PASS=0
    fi
  else
    if run_suite_local "$label" "$cmd"; then
      RESULTS[$label]="PASS"
    else
      RESULTS[$label]="FAIL"
      OVERALL_PASS=0
    fi
  fi

  END_TS=$(date +%s)
  DURATIONS[$label]=$(( END_TS - START_TS ))
done

# ── Summary table ─────────────────────────────────────────────────────────────
echo
echo -e "${BOLD}====== Test Suite Summary ======${RESET}"
printf "%-20s %-8s %s\n" "Suite" "Result" "Duration"
printf "%-20s %-8s %s\n" "-----" "------" "--------"

for entry in "${SUITES[@]}"; do
  IFS='|' read -r label _ _ <<< "$entry"
  result="${RESULTS[$label]}"
  dur="${DURATIONS[$label]}s"
  if [ "$result" = "PASS" ]; then
    printf "%-20s " "$label"
    pass
    printf "  %s\n" "$dur"
  else
    printf "%-20s " "$label"
    fail
    printf "  %s\n" "$dur"
  fi
done

echo
if [ "$OVERALL_PASS" -eq 1 ]; then
  echo -e "${GREEN}${BOLD}All suites passed.${RESET}"
  exit 0
else
  echo -e "${RED}${BOLD}One or more suites FAILED.${RESET}"
  exit 1
fi
