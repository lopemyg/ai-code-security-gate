#!/usr/bin/env bash
# Runs the automated stages of the verification gate locally.
#   Stage I  - Scan:  Bandit and Semgrep on a target folder
#   Stage II - Test:  pytest security tests
# Stage III (human review) is manual; Stage IV (retest) is simply running
# this script again after fixes are applied.
#
# Usage: ./scripts/run_gate.sh fixed        -> should PASS
#        ./scripts/run_gate.sh vulnerable   -> should FAIL (merge blocked)

set -u
TARGET="${1:-fixed}"
cd "$(dirname "$0")/.."

echo "== Stage I: Scan ($TARGET) =="
bandit -r "$TARGET"
BANDIT=$?
semgrep scan --config .semgrep/rules.yml --error --metrics=off "$TARGET"
SEMGREP=$?
SCAN=0
if [ "$BANDIT" -ne 0 ] || [ "$SEMGREP" -ne 0 ]; then
  SCAN=1
fi

echo
echo "== Stage II: Test =="
python3 -m pytest -q tests
TEST=$?

echo
if [ "$SCAN" -ne 0 ] || [ "$TEST" -ne 0 ]; then
  echo "GATE RESULT: BLOCKED (scan exit $SCAN, tests exit $TEST)"
  exit 1
fi
echo "GATE RESULT: PASSED - ready for human review (Stage III)"
