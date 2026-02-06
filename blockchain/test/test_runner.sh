#!/bin/bash

################################################################################
# Blockchain Auditor Test Runner
#
# Runs all test suites for starlings-blockchain-audit.sh
# Set ETHERSCAN_API_KEY environment variable for live integration tests
################################################################################

set -uo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCANNER_DIR="$(dirname "$TEST_DIR")"

# Counters
SUITES_RUN=0
SUITES_PASSED=0
SUITES_FAILED=0
SUITES_SKIPPED=0

echo ""
echo -e "${BLUE}Starlings Blockchain Security Auditor - Test Runner${NC}"
echo "===================================================="
echo ""
echo "Scanner: $SCANNER_DIR/starlings-blockchain-audit.sh"
echo "Tests:   $TEST_DIR/"
echo ""

################################################################################
# Environment Check
################################################################################

echo "Environment:"
if [[ -n "${ETHERSCAN_API_KEY:-}" ]]; then
  echo -e "  ${GREEN}[SET]${NC} ETHERSCAN_API_KEY (live integration tests enabled)"
else
  echo -e "  ${YELLOW}[NOT SET]${NC} ETHERSCAN_API_KEY (report tests will use sample data)"
fi
echo ""

################################################################################
# Run a test suite
################################################################################

run_suite() {
  local suite_name="$1"
  local suite_file="$2"

  ((SUITES_RUN++)) || true

  echo -e "${BLUE}--- Suite: $suite_name ---${NC}"
  echo ""

  if [[ ! -f "$suite_file" ]]; then
    echo -e "${RED}[FAIL]${NC} Test file not found: $suite_file"
    ((SUITES_FAILED++)) || true
    echo ""
    return
  fi

  if [[ ! -x "$suite_file" ]]; then
    echo -e "${YELLOW}[WARN]${NC} Test file not executable, running with bash: $suite_file"
  fi

  # Run the suite and capture exit code
  if bash "$suite_file"; then
    echo ""
    echo -e "${GREEN}[SUITE PASS]${NC} $suite_name"
    ((SUITES_PASSED++)) || true
  else
    echo ""
    echo -e "${RED}[SUITE FAIL]${NC} $suite_name"
    ((SUITES_FAILED++)) || true
  fi

  echo ""
}

################################################################################
# Run All Suites
################################################################################

echo "Starting test suites..."
echo "===================================================="
echo ""

# Suite 1: Prerequisites
run_suite "Prerequisites" "$TEST_DIR/test_prerequisites.sh"

# Suite 2: Report Structure
run_suite "Report Structure" "$TEST_DIR/test_report_structure.sh"

################################################################################
# Summary
################################################################################

echo "===================================================="
echo ""
echo -e "${BLUE}Test Runner Summary${NC}"
echo ""
echo "  Suites run:     $SUITES_RUN"
echo "  Suites passed:  $SUITES_PASSED"
echo "  Suites failed:  $SUITES_FAILED"
echo ""

if [[ "$SUITES_FAILED" -eq 0 ]]; then
  echo -e "${GREEN}All test suites passed.${NC}"
  echo ""
  exit 0
else
  echo -e "${RED}$SUITES_FAILED test suite(s) failed.${NC}"
  echo ""
  exit 1
fi
