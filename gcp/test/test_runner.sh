#!/bin/bash

################################################################################
# GCP Scanner Test Runner
#
# Runs all test cases for starlings-gcp-scan.sh and reports pass/fail.
#
# Environment variables (optional):
#   GCP_TEST_PROJECT  - GCP project ID for integration tests
#
# Usage:
#   ./test_runner.sh              # Run all tests (connection tests skipped without credentials)
#   ./test_runner.sh --all        # Run all tests including integration
#   ./test_runner.sh --unit       # Run only unit/structure tests
################################################################################

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCANNER_DIR="$(dirname "$TEST_DIR")"

SUITES_RUN=0
SUITES_PASSED=0
SUITES_FAILED=0
SUITES_SKIPPED=0

RUN_MODE="${1:-auto}"

################################################################################
# Helpers
################################################################################

suite_pass() {
    local name="$1"
    local duration="$2"
    echo -e "${GREEN}[PASS]${NC} $name (${duration}s)"
    SUITES_PASSED=$((SUITES_PASSED + 1))
    SUITES_RUN=$((SUITES_RUN + 1))
}

suite_fail() {
    local name="$1"
    local duration="$2"
    echo -e "${RED}[FAIL]${NC} $name (${duration}s)"
    SUITES_FAILED=$((SUITES_FAILED + 1))
    SUITES_RUN=$((SUITES_RUN + 1))
}

suite_skip() {
    local name="$1"
    local reason="$2"
    echo -e "${YELLOW}[SKIP]${NC} $name - $reason"
    SUITES_SKIPPED=$((SUITES_SKIPPED + 1))
}

run_test_suite() {
    local name="$1"
    local script="$2"

    if [ ! -f "$script" ]; then
        suite_skip "$name" "Script not found: $script"
        return
    fi

    if [ ! -x "$script" ]; then
        chmod +x "$script"
    fi

    local start_time
    start_time=$(date +%s)

    echo ""
    echo -e "${BLUE}================================================================${NC}"
    echo -e "${BLUE} Running: $name${NC}"
    echo -e "${BLUE}================================================================${NC}"
    echo ""

    local exit_code=0
    bash "$script" || exit_code=$?

    local end_time
    end_time=$(date +%s)
    local duration=$((end_time - start_time))

    echo ""
    if [ "$exit_code" -eq 0 ]; then
        suite_pass "$name" "$duration"
    else
        suite_fail "$name" "$duration"
    fi
}

################################################################################
# Banner
################################################################################

echo ""
echo -e "${BLUE}================================================================${NC}"
echo -e "${BLUE}  Starlings GCP Security Scanner - Test Runner${NC}"
echo -e "${BLUE}================================================================${NC}"
echo ""
echo "  Scanner:  $SCANNER_DIR/starlings-gcp-scan.sh"
echo "  Tests:    $TEST_DIR/"
echo "  Mode:     $RUN_MODE"
echo ""

################################################################################
# Prerequisites
################################################################################

echo "Checking prerequisites..."

if ! command -v bash &> /dev/null; then
    echo -e "${RED}[FAIL]${NC} bash not found"
    exit 1
fi
echo -e "${GREEN}[OK]${NC}   bash"

if ! command -v jq &> /dev/null; then
    echo -e "${RED}[FAIL]${NC} jq not found (required for report structure tests)"
    exit 1
fi
echo -e "${GREEN}[OK]${NC}   jq"

if [ ! -f "$SCANNER_DIR/starlings-gcp-scan.sh" ]; then
    echo -e "${RED}[FAIL]${NC} Scanner script not found: $SCANNER_DIR/starlings-gcp-scan.sh"
    exit 1
fi
echo -e "${GREEN}[OK]${NC}   Scanner script found"

# Check if gcloud credentials are available for integration tests
HAS_GCLOUD=false
if command -v gcloud &> /dev/null; then
    ACTIVE_ACCOUNT=$(gcloud auth list --filter=status:ACTIVE --format="value(account)" 2>/dev/null | head -1 || echo "")
    if [ -n "$ACTIVE_ACCOUNT" ]; then
        HAS_GCLOUD=true
        echo -e "${GREEN}[OK]${NC}   gcloud authenticated: $ACTIVE_ACCOUNT"
    else
        echo -e "${YELLOW}[--]${NC}   gcloud installed but not authenticated"
    fi
else
    echo -e "${YELLOW}[--]${NC}   gcloud not installed"
fi

################################################################################
# Test Suite Execution
################################################################################

TOTAL_START=$(date +%s)

# --------------------------------------------------------------------------
# Suite 1: Report Structure Tests (no credentials needed)
# --------------------------------------------------------------------------
if [ "$RUN_MODE" != "--connection" ]; then
    run_test_suite "Report Structure Tests" "$TEST_DIR/test_report_structure.sh"
fi

# --------------------------------------------------------------------------
# Suite 2: gcloud Connection Tests (requires credentials)
# --------------------------------------------------------------------------
if [ "$RUN_MODE" = "--unit" ]; then
    suite_skip "gcloud Connection Tests" "Unit-only mode (use --all or --connection)"
elif [ "$RUN_MODE" = "--all" ] || [ "$RUN_MODE" = "--connection" ]; then
    if [ "$HAS_GCLOUD" = true ]; then
        run_test_suite "gcloud Connection Tests" "$TEST_DIR/test_gcloud_connection.sh"
    else
        suite_skip "gcloud Connection Tests" "gcloud not authenticated"
    fi
elif [ "$RUN_MODE" = "auto" ]; then
    if [ "$HAS_GCLOUD" = true ]; then
        run_test_suite "gcloud Connection Tests" "$TEST_DIR/test_gcloud_connection.sh"
    else
        suite_skip "gcloud Connection Tests" "gcloud not authenticated (use --all to force)"
    fi
fi

################################################################################
# Summary
################################################################################

TOTAL_END=$(date +%s)
TOTAL_DURATION=$((TOTAL_END - TOTAL_START))

echo ""
echo ""
echo -e "${BLUE}================================================================${NC}"
echo -e "${BLUE}  Test Summary${NC}"
echo -e "${BLUE}================================================================${NC}"
echo ""
echo "  Suites Run:     $SUITES_RUN"
echo -e "  Suites Passed:  ${GREEN}$SUITES_PASSED${NC}"
echo -e "  Suites Failed:  ${RED}$SUITES_FAILED${NC}"
echo -e "  Suites Skipped: ${YELLOW}$SUITES_SKIPPED${NC}"
echo ""
echo "  Total Duration: ${TOTAL_DURATION}s"
echo ""

if [ "$SUITES_FAILED" -eq 0 ]; then
    if [ "$SUITES_RUN" -eq 0 ]; then
        echo -e "${YELLOW}[--]${NC} No test suites were executed"
        exit 0
    else
        echo -e "${GREEN}[PASS]${NC} All test suites passed!"
        exit 0
    fi
else
    echo -e "${RED}[FAIL]${NC} $SUITES_FAILED test suite(s) failed"
    exit 1
fi
