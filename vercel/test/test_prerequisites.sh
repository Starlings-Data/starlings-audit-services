#!/bin/bash

################################################################################
# Test: Vercel Scanner Prerequisites
#
# Validates that required tools are installed, the scanner script exists and
# has valid syntax, and basic API connectivity works.
################################################################################

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

test_start() {
  local test_name="$1"
  echo -e "${BLUE}[TEST]${NC} $test_name"
  ((TESTS_RUN++)) || true
}

test_pass() {
  local message="$1"
  echo -e "${GREEN}[PASS]${NC} $message"
  ((TESTS_PASSED++)) || true
}

test_fail() {
  local message="$1"
  echo -e "${RED}[FAIL]${NC} $message"
  ((TESTS_FAILED++)) || true
}

echo ""
echo "Vercel Scanner - Prerequisites Tests"
echo "====================================="
echo ""

################################################################################
# Test 1: curl is installed
################################################################################

test_start "curl is installed"
if command -v curl &> /dev/null; then
  CURL_VERSION=$(curl --version | head -n 1)
  test_pass "curl found: $CURL_VERSION"
else
  test_fail "curl not found -- install with: brew install curl (macOS) or apt install curl (Linux)"
fi

################################################################################
# Test 2: jq is installed
################################################################################

test_start "jq is installed"
if command -v jq &> /dev/null; then
  JQ_VERSION=$(jq --version 2>&1)
  test_pass "jq found: $JQ_VERSION"
else
  test_fail "jq not found -- install with: brew install jq (macOS) or apt install jq (Linux)"
fi

################################################################################
# Test 3: Scanner script exists and is executable
################################################################################

test_start "Scanner script exists and is executable"
SCANNER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCANNER="$SCANNER_DIR/starlings-vercel-scan.sh"

if [[ -f "$SCANNER" ]]; then
  if [[ -x "$SCANNER" ]]; then
    test_pass "Scanner found and executable: $SCANNER"
  else
    test_fail "Scanner found but not executable: $SCANNER (run: chmod +x $SCANNER)"
  fi
else
  test_fail "Scanner not found at: $SCANNER"
fi

################################################################################
# Test 4: Scanner script has valid bash syntax
################################################################################

test_start "Scanner script has valid bash syntax"
if bash -n "$SCANNER" 2>/dev/null; then
  test_pass "Script has valid bash syntax"
else
  test_fail "Script has syntax errors"
fi

################################################################################
# Test 5: Scanner displays help without errors
################################################################################

test_start "Scanner --help exits cleanly"
if "$SCANNER" --help > /dev/null 2>&1; then
  test_pass "Scanner --help runs without error"
else
  test_fail "Scanner --help failed"
fi

################################################################################
# Test 6: Scanner fails gracefully without VERCEL_TOKEN
################################################################################

test_start "Scanner fails gracefully without VERCEL_TOKEN"
# Unset token temporarily and run -- should exit with error
SAVED_TOKEN="${VERCEL_TOKEN:-}"
unset VERCEL_TOKEN 2>/dev/null || true

OUTPUT=$("$SCANNER" 2>&1 || true)
if echo "$OUTPUT" | grep -qi "VERCEL_TOKEN"; then
  test_pass "Scanner reports missing VERCEL_TOKEN"
else
  test_fail "Scanner did not report missing VERCEL_TOKEN"
fi

# Restore token
if [[ -n "$SAVED_TOKEN" ]]; then
  export VERCEL_TOKEN="$SAVED_TOKEN"
fi

################################################################################
# Test 7: Vercel API is reachable
################################################################################

test_start "Vercel API is reachable"
API_RESPONSE=$(curl -s --max-time 10 -o /dev/null -w "%{http_code}" "https://api.vercel.com" 2>/dev/null || echo "000")

if [[ "$API_RESPONSE" != "000" ]]; then
  test_pass "Vercel API reachable (HTTP $API_RESPONSE)"
else
  test_fail "Could not connect to Vercel API at https://api.vercel.com"
fi

################################################################################
# Test 8: VERCEL_TOKEN validity (if set)
################################################################################

test_start "VERCEL_TOKEN validity check"
if [[ -n "${VERCEL_TOKEN:-}" ]]; then
  AUTH_RESPONSE=$(curl -s --max-time 10 -w "\n%{http_code}" \
    -H "Authorization: Bearer ${VERCEL_TOKEN}" \
    "https://api.vercel.com/v2/user" 2>/dev/null || echo -e "\n000")

  HTTP_CODE=$(echo "$AUTH_RESPONSE" | tail -n1)

  if [[ "$HTTP_CODE" == "200" ]]; then
    USER_NAME=$(echo "$AUTH_RESPONSE" | sed '$d' | jq -r '.user.name // .user.username // "unknown"' 2>/dev/null)
    test_pass "Token valid, authenticated as: $USER_NAME"
  elif [[ "$HTTP_CODE" == "403" || "$HTTP_CODE" == "401" ]]; then
    test_fail "Token rejected (HTTP $HTTP_CODE) -- check VERCEL_TOKEN"
  else
    test_fail "Unexpected response from Vercel API (HTTP $HTTP_CODE)"
  fi
else
  echo -e "  ${YELLOW}[SKIP]${NC} VERCEL_TOKEN not set (skipping auth check)"
  ((TESTS_RUN--)) || true
fi

################################################################################
# Summary
################################################################################

echo ""
echo "====================================="
echo ""
echo "Prerequisites Test Results:"
echo "  Total:  $TESTS_RUN"
echo "  Passed: $TESTS_PASSED"
echo "  Failed: $TESTS_FAILED"
echo ""

if [[ "$TESTS_FAILED" -eq 0 ]]; then
  echo -e "${GREEN}[PASS]${NC} All prerequisite tests passed"
  exit 0
else
  echo -e "${RED}[FAIL]${NC} Some prerequisite tests failed"
  exit 1
fi
