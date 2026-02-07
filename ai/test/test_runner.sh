#!/bin/bash
#
# AI Security Scanner — Test Runner
# Orchestrates all test suites and reports overall results.
#

set -uo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

SUITES_RUN=0
SUITES_PASSED=0
SUITES_FAILED=0

run_suite() {
    local suite_name="$1"
    local suite_file="$2"

    ((SUITES_RUN++)) || true

    echo ""
    echo -e "${BLUE}━━━ Suite: $suite_name ━━━${NC}"
    echo ""

    if [[ ! -f "$suite_file" ]]; then
        echo -e "${RED}[FAIL]${NC} Test file not found: $suite_file"
        ((SUITES_FAILED++)) || true
        return
    fi

    if bash "$suite_file"; then
        echo ""
        echo -e "${GREEN}[SUITE PASS]${NC} $suite_name"
        ((SUITES_PASSED++)) || true
    else
        echo ""
        echo -e "${RED}[SUITE FAIL]${NC} $suite_name"
        ((SUITES_FAILED++)) || true
    fi
}

echo -e "${BLUE}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║${NC}       Starlings AI Security Scanner — Test Runner         ${BLUE}║${NC}"
echo -e "${BLUE}╚═══════════════════════════════════════════════════════════╝${NC}"

run_suite "Prerequisites" "$TEST_DIR/test_prerequisites.sh"
run_suite "Report Structure" "$TEST_DIR/test_report_structure.sh"

echo ""
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo "Test Runner Summary:"
echo "  Suites run:     $SUITES_RUN"
echo "  Suites passed:  $SUITES_PASSED"
echo "  Suites failed:  $SUITES_FAILED"
echo ""

if [[ "$SUITES_FAILED" -eq 0 ]]; then
    echo -e "${GREEN}All test suites passed.${NC}"
    exit 0
else
    echo -e "${RED}$SUITES_FAILED suite(s) failed.${NC}"
    exit 1
fi
