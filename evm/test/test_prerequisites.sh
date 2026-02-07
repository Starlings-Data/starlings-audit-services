#!/bin/bash

################################################################################
# Test: Blockchain Auditor Prerequisites
#
# Validates that required tools are installed, address format validation works,
# and at least one chain RPC endpoint is reachable.
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
echo "Blockchain Auditor - Prerequisites Tests"
echo "========================================="
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
# Test 3: bash version supports associative arrays (4.0+)
################################################################################

test_start "bash version supports associative arrays"
BASH_MAJOR="${BASH_VERSINFO[0]}"
BASH_MINOR="${BASH_VERSINFO[1]}"
if [[ "$BASH_MAJOR" -ge 4 ]]; then
  test_pass "bash $BASH_MAJOR.$BASH_MINOR (associative arrays supported)"
else
  test_fail "bash $BASH_MAJOR.$BASH_MINOR -- version 4.0+ required for associative arrays"
fi

################################################################################
# Test 4: Valid Ethereum address format accepted
################################################################################

test_start "Valid address format accepted"
VALID_ADDRESS="0xdAC17F958D2ee523a2206206994597C13D831ec7"
if echo "$VALID_ADDRESS" | grep -qE '^0x[0-9a-fA-F]{40}$'; then
  test_pass "Address $VALID_ADDRESS matches expected format"
else
  test_fail "Valid address rejected by format check"
fi

################################################################################
# Test 5: Invalid addresses rejected
################################################################################

test_start "Invalid addresses rejected"
INVALID_ADDRESSES=(
  "not-an-address"
  "0x123"
  "0xZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"
  "dAC17F958D2ee523a2206206994597C13D831ec7"
  ""
)
ALL_REJECTED=true
for addr in "${INVALID_ADDRESSES[@]}"; do
  if echo "$addr" | grep -qE '^0x[0-9a-fA-F]{40}$'; then
    echo -e "  ${RED}Incorrectly accepted:${NC} '$addr'"
    ALL_REJECTED=false
  fi
done
if $ALL_REJECTED; then
  test_pass "All invalid addresses correctly rejected"
else
  test_fail "Some invalid addresses were incorrectly accepted"
fi

################################################################################
# Test 6: RPC connectivity (Ethereum public endpoint)
################################################################################

test_start "RPC connectivity to Ethereum"
RPC_URL="https://eth.llamarpc.com"
RPC_PAYLOAD='{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}'

RPC_RESPONSE=$(curl -s --max-time 10 -X POST "$RPC_URL" \
  -H "Content-Type: application/json" \
  -d "$RPC_PAYLOAD" 2>/dev/null || echo "")

if [[ -n "$RPC_RESPONSE" ]]; then
  CHAIN_ID=$(echo "$RPC_RESPONSE" | jq -r '.result // empty' 2>/dev/null || echo "")
  if [[ "$CHAIN_ID" == "0x1" ]]; then
    test_pass "Ethereum RPC reachable (chain ID: $CHAIN_ID)"
  elif [[ -n "$CHAIN_ID" ]]; then
    test_pass "Ethereum RPC reachable (chain ID: $CHAIN_ID -- expected 0x1)"
  else
    test_fail "Ethereum RPC responded but returned unexpected data"
  fi
else
  test_fail "Could not connect to Ethereum RPC at $RPC_URL"
fi

################################################################################
# Test 7: RPC connectivity (Polygon public endpoint)
################################################################################

test_start "RPC connectivity to Polygon"
RPC_URL="https://polygon-rpc.com"
RPC_PAYLOAD='{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}'

RPC_RESPONSE=$(curl -s --max-time 10 -X POST "$RPC_URL" \
  -H "Content-Type: application/json" \
  -d "$RPC_PAYLOAD" 2>/dev/null || echo "")

if [[ -n "$RPC_RESPONSE" ]]; then
  CHAIN_ID=$(echo "$RPC_RESPONSE" | jq -r '.result // empty' 2>/dev/null || echo "")
  if [[ "$CHAIN_ID" == "0x89" ]]; then
    test_pass "Polygon RPC reachable (chain ID: $CHAIN_ID)"
  elif [[ -n "$CHAIN_ID" ]]; then
    test_pass "Polygon RPC reachable (chain ID: $CHAIN_ID -- expected 0x89)"
  else
    test_fail "Polygon RPC responded but returned unexpected data"
  fi
else
  test_fail "Could not connect to Polygon RPC at $RPC_URL"
fi

################################################################################
# Test 8: Scanner script exists and is executable
################################################################################

test_start "Scanner script exists and is executable"
SCANNER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCANNER="$SCANNER_DIR/starlings-blockchain-audit.sh"

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
# Test 9: Scanner script has valid bash syntax
################################################################################

test_start "Scanner script has valid bash syntax"
if bash -n "$SCANNER" 2>/dev/null; then
  test_pass "Script has valid bash syntax"
else
  test_fail "Script has syntax errors"
fi

################################################################################
# Summary
################################################################################

echo ""
echo "========================================="
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
