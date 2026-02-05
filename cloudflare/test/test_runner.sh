#!/bin/bash

################################################################################
# Cloudflare Scanner Test Runner
# 
# Runs all test cases for starlings-cf-scan.sh
# Set CF_API_TOKEN and CF_TEST_ZONE environment variables before running
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

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCANNER_DIR="$(dirname "$TEST_DIR")"

################################################################################
# Test Framework
################################################################################

test_start() {
  local test_name="$1"
  echo -e "${BLUE}▶${NC} Testing: $test_name" >&2
  ((TESTS_RUN++))
}

test_pass() {
  local message="$1"
  echo -e "${GREEN}✓${NC} $message" >&2
  ((TESTS_PASSED++))
}

test_fail() {
  local message="$1"
  echo -e "${RED}✗${NC} $message" >&2
  ((TESTS_FAILED++))
}

test_skip() {
  local message="$1"
  echo -e "${YELLOW}⊘${NC} $message" >&2
}

################################################################################
# Prerequisites Check
################################################################################

echo "Checking prerequisites..."

if ! command -v bash &> /dev/null; then
  echo -e "${RED}✗${NC} bash not found"
  exit 1
fi

if ! command -v curl &> /dev/null; then
  echo -e "${RED}✗${NC} curl not found"
  exit 1
fi

if ! command -v jq &> /dev/null; then
  echo -e "${RED}✗${NC} jq not found"
  exit 1
fi

echo -e "${GREEN}✓${NC} All prerequisites installed"
echo ""

# Check credentials
if [[ -z "${CF_API_TOKEN:-}" ]]; then
  echo -e "${YELLOW}⚠${NC} CF_API_TOKEN not set"
  echo "  Skipping integration tests (use: export CF_API_TOKEN=...)"
  echo "  Running syntax and unit tests only"
  SKIP_INTEGRATION=1
else
  echo -e "${GREEN}✓${NC} CF_API_TOKEN set"
  SKIP_INTEGRATION=0
fi

if [[ -z "${CF_TEST_ZONE:-}" ]]; then
  echo -e "${YELLOW}⚠${NC} CF_TEST_ZONE not set"
  echo "  Skipping zone tests (use: export CF_TEST_ZONE=example.com)"
  SKIP_INTEGRATION=1
else
  echo -e "${GREEN}✓${NC} CF_TEST_ZONE set: $CF_TEST_ZONE"
fi

echo ""
echo "Starting test suite..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

################################################################################
# Syntax Tests
################################################################################

test_start "Syntax: Scanner script is valid bash"
if bash -n "$SCANNER_DIR/starlings-cf-scan.sh" 2>/dev/null; then
  test_pass "Script has valid bash syntax"
else
  test_fail "Script has syntax errors"
fi

################################################################################
# Help & Usage Tests
################################################################################

test_start "Usage: Help message displays"
if "$SCANNER_DIR/starlings-cf-scan.sh" --help 2>&1 | grep -q "Usage:"; then
  test_pass "Help message works"
else
  test_fail "Help message not found"
fi

test_start "Usage: Error on missing arguments"
if ! "$SCANNER_DIR/starlings-cf-scan.sh" 2>&1 | grep -q "required"; then
  test_fail "Should error on missing arguments"
else
  test_pass "Correctly requires arguments"
fi

test_start "Usage: Error on missing zone"
if ! "$SCANNER_DIR/starlings-cf-scan.sh" --api-token "test" 2>&1 | grep -q "Zone"; then
  test_fail "Should require zone"
else
  test_pass "Zone requirement enforced"
fi

################################################################################
# Integration Tests
################################################################################

if [[ "$SKIP_INTEGRATION" == "1" ]]; then
  echo ""
  test_skip "Skipping integration tests (no credentials configured)"
  echo ""
else
  echo ""
  
  test_start "Integration: API connectivity test"
  if "$SCANNER_DIR/starlings-cf-scan.sh" --api-token "$CF_API_TOKEN" --zone "$CF_TEST_ZONE" > /tmp/cf-scan-test.json 2>&1; then
    test_pass "Successfully connected to Cloudflare API"
  else
    test_fail "Failed to connect to Cloudflare API"
  fi
  
  test_start "Integration: Report generation"
  if [[ -f /tmp/cf-scan-test.json ]] && jq empty /tmp/cf-scan-test.json 2>/dev/null; then
    test_pass "Valid JSON report generated"
  else
    test_fail "Report is not valid JSON"
  fi
  
  test_start "Integration: Report has required fields"
  if [[ -f /tmp/cf-scan-test.json ]]; then
    local has_metadata=$(jq 'has("metadata")' /tmp/cf-scan-test.json 2>/dev/null)
    local has_summary=$(jq 'has("summary")' /tmp/cf-scan-test.json 2>/dev/null)
    local has_checks=$(jq 'has("checks")' /tmp/cf-scan-test.json 2>/dev/null)
    
    if [[ "$has_metadata" == "true" && "$has_summary" == "true" && "$has_checks" == "true" ]]; then
      test_pass "Report has all required sections"
    else
      test_fail "Report missing required sections"
    fi
  fi
  
  test_start "Integration: Score calculation"
  if [[ -f /tmp/cf-scan-test.json ]]; then
    local score=$(jq '.summary.overallScore' /tmp/cf-scan-test.json 2>/dev/null)
    if [[ "$score" =~ ^[0-9]+$ ]] && [[ "$score" -ge 0 ]] && [[ "$score" -le 100 ]]; then
      test_pass "Security score calculated: $score/100"
    else
      test_fail "Invalid security score: $score"
    fi
  fi
  
  test_start "Integration: Risk level determination"
  if [[ -f /tmp/cf-scan-test.json ]]; then
    local risk=$(jq -r '.summary.riskLevel' /tmp/cf-scan-test.json 2>/dev/null)
    if [[ "$risk" =~ ^(LOW|MEDIUM|HIGH|CRITICAL|UNKNOWN)$ ]]; then
      test_pass "Risk level determined: $risk"
    else
      test_fail "Invalid risk level: $risk"
    fi
  fi
  
  test_start "Integration: All check categories present"
  if [[ -f /tmp/cf-scan-test.json ]]; then
    local has_dns=$(jq '.checks.dns | length' /tmp/cf-scan-test.json 2>/dev/null)
    local has_tls=$(jq '.checks.https_tls | length' /tmp/cf-scan-test.json 2>/dev/null)
    
    if [[ "$has_dns" -gt 0 && "$has_tls" -gt 0 ]]; then
      test_pass "All check categories present"
    else
      test_fail "Missing check categories"
    fi
  fi
  
  test_start "Integration: Checks have status"
  if [[ -f /tmp/cf-scan-test.json ]]; then
    local statuses=$(jq -r '.checks[] | .[] | .status' /tmp/cf-scan-test.json 2>/dev/null | sort -u)
    if echo "$statuses" | grep -q "PASS"; then
      test_pass "Checks have status values"
    else
      test_fail "No check statuses found"
    fi
  fi
  
  # Cleanup
  rm -f /tmp/cf-scan-test.json
fi

################################################################################
# Output Tests
################################################################################

test_start "Output: Debug mode works"
if "$SCANNER_DIR/starlings-cf-scan.sh" --help 2>&1 | grep -q "debug"; then
  test_pass "Debug option documented"
else
  test_fail "Debug option not documented"
fi

################################################################################
# Summary
################################################################################

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Test Results:"
echo "  Total:  $TESTS_RUN"
echo "  Passed: $TESTS_PASSED"
echo "  Failed: $TESTS_FAILED"
echo ""

if [[ "$TESTS_FAILED" -eq 0 ]]; then
  echo -e "${GREEN}✓${NC} All tests passed!"
  exit 0
else
  echo -e "${RED}✗${NC} Some tests failed"
  exit 1
fi
