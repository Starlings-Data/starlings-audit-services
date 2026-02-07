#!/bin/bash
#
# Test Suite: Prerequisites
# Validates that required tools exist and the scanner script is well-formed.
#

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCANNER_DIR="$(dirname "$TEST_DIR")"
SCANNER="$SCANNER_DIR/starlings-ai-scan.sh"

test_start() {
    echo -e "${BLUE}[TEST]${NC} $1"
    ((TESTS_RUN++)) || true
}

test_pass() {
    echo -e "${GREEN}[PASS]${NC} $1"
    ((TESTS_PASSED++)) || true
}

test_fail() {
    echo -e "${RED}[FAIL]${NC} $1"
    ((TESTS_FAILED++)) || true
}

# -------------------------------------------------------
# Test 1: git is installed
# -------------------------------------------------------
test_start "git is installed"
if command -v git &> /dev/null; then
    GIT_VERSION=$(git --version)
    test_pass "git found: $GIT_VERSION"
else
    test_fail "git not found — required for cloning repos"
fi

# -------------------------------------------------------
# Test 2: grep is installed
# -------------------------------------------------------
test_start "grep is installed"
if command -v grep &> /dev/null; then
    test_pass "grep found"
else
    test_fail "grep not found — required for pattern scanning"
fi

# -------------------------------------------------------
# Test 3: jq is installed (optional but recommended)
# -------------------------------------------------------
test_start "jq is installed (recommended)"
if command -v jq &> /dev/null; then
    JQ_VERSION=$(jq --version 2>&1)
    test_pass "jq found: $JQ_VERSION"
else
    echo -e "${YELLOW}[WARN]${NC} jq not found — reports will not be pretty-printed"
    test_pass "jq is optional (warn only)"
fi

# -------------------------------------------------------
# Test 4: Scanner script exists
# -------------------------------------------------------
test_start "Scanner script exists"
if [[ -f "$SCANNER" ]]; then
    test_pass "Scanner found at: $SCANNER"
else
    test_fail "Scanner not found at: $SCANNER"
fi

# -------------------------------------------------------
# Test 5: Scanner script is executable
# -------------------------------------------------------
test_start "Scanner script is executable"
if [[ -x "$SCANNER" ]]; then
    test_pass "Scanner is executable"
else
    test_fail "Scanner is not executable (run: chmod +x $SCANNER)"
fi

# -------------------------------------------------------
# Test 6: Scanner has valid bash syntax
# -------------------------------------------------------
test_start "Scanner has valid bash syntax"
if bash -n "$SCANNER" 2>/dev/null; then
    test_pass "Script has valid bash syntax"
else
    test_fail "Script has syntax errors"
fi

# -------------------------------------------------------
# Test 7: --help flag works
# -------------------------------------------------------
test_start "--help flag works"
HELP_OUTPUT=$(bash "$SCANNER" --help 2>&1 || true)
if echo "$HELP_OUTPUT" | grep -q "repo"; then
    test_pass "--help shows usage with --repo option"
else
    test_fail "--help does not show expected usage info"
fi

# -------------------------------------------------------
# Test 8: Exits with error when no --repo given
# -------------------------------------------------------
test_start "Exits with error when no --repo given"
NO_REPO_OUTPUT=$(bash "$SCANNER" --output /dev/null 2>&1 | sed 's/\x1b\[[0-9;]*m//g' || true)
if echo "$NO_REPO_OUTPUT" | grep -qi "repo"; then
    test_pass "Correctly errors when --repo is missing"
else
    test_fail "Should error when --repo is not provided"
fi

# -------------------------------------------------------
# Test 9: Test fixtures directory exists
# -------------------------------------------------------
test_start "Test fixtures directory exists"
if [[ -d "$TEST_DIR/fixtures" ]]; then
    FIXTURE_COUNT=$(find "$TEST_DIR/fixtures" -type f | wc -l | tr -d ' ')
    test_pass "Fixtures directory found with $FIXTURE_COUNT files"
else
    test_fail "Fixtures directory not found at $TEST_DIR/fixtures"
fi

# -------------------------------------------------------
# Summary
# -------------------------------------------------------
echo ""
echo "Prerequisites Test Results:"
echo "  Total:  $TESTS_RUN"
echo "  Passed: $TESTS_PASSED"
echo "  Failed: $TESTS_FAILED"

if [[ "$TESTS_FAILED" -eq 0 ]]; then
    exit 0
else
    exit 1
fi
