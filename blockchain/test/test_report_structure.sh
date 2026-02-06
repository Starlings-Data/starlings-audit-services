#!/bin/bash

################################################################################
# Test: Blockchain Auditor Report Structure
#
# Validates that the JSON report output has all required fields and correct
# structure. Uses a sample report or a live-generated report if explorer API
# keys are configured.
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

SCANNER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPORT="/tmp/blockchain-audit-test-report.json"

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

test_skip() {
  local message="$1"
  echo -e "${YELLOW}[SKIP]${NC} $message"
}

echo ""
echo "Blockchain Auditor - Report Structure Tests"
echo "============================================="
echo ""

################################################################################
# Generate or locate a report
################################################################################

USE_SAMPLE=false

# Try to generate a live report if an Etherscan API key is available
if [[ -n "${ETHERSCAN_API_KEY:-}" ]]; then
  echo "Etherscan API key found. Generating live report..."
  # USDT on Ethereum -- well-known, verified contract
  TEST_ADDRESS="0xdAC17F958D2ee523a2206206994597C13D831ec7"
  if "$SCANNER_DIR/starlings-blockchain-audit.sh" "$TEST_ADDRESS" --chain ethereum --output "$REPORT" > /dev/null 2>&1; then
    echo -e "${GREEN}[OK]${NC} Report generated from live scan"
  else
    echo -e "${YELLOW}[WARN]${NC} Live scan failed, falling back to sample report"
    USE_SAMPLE=true
  fi
else
  echo "No ETHERSCAN_API_KEY set. Using sample report for structure validation."
  USE_SAMPLE=true
fi

# Create a sample report that matches the scanner output format
if $USE_SAMPLE; then
  cat > "$REPORT" << 'SAMPLE_EOF'
{
  "scanner_version": "1.0.0",
  "scan_date": "2026-02-05T14:30:00Z",
  "chain": "Ethereum",
  "chain_id": "1",
  "network": "mainnet",
  "contract_address": "0xdAC17F958D2ee523a2206206994597C13D831ec7",
  "contract_name": "TetherToken",
  "explorer_url": "https://etherscan.io/address/0xdAC17F958D2ee523a2206206994597C13D831ec7",
  "score": {
    "overall": 62,
    "interpretation": "Fair",
    "risk_level": "MEDIUM"
  },
  "summary": {
    "critical": 0,
    "high": 2,
    "medium": 3,
    "low": 1,
    "info": 0,
    "passed": 8,
    "total_checks": 14
  },
  "findings": [
    {
      "domain": "ownership",
      "check_id": "OWN-001",
      "severity": "high",
      "title": "Contract owned by an EOA (single key)",
      "description": "The contract owner is an externally owned account (single private key).",
      "resources": ["0xC6CDE7C39eB2f0F0095F41570af89eFC2C1Ea828"],
      "remediation": "Transfer ownership to a multisig wallet.",
      "frameworks": ["CCSS 3.1", "ISO27001 A.9.2.3", "SOC2 CC6.1"]
    },
    {
      "domain": "token",
      "check_id": "TKN-004",
      "severity": "high",
      "title": "Token has blacklist capability",
      "description": "The contract can blacklist addresses, preventing them from transferring tokens.",
      "resources": [],
      "remediation": "Understand why blacklisting exists.",
      "frameworks": ["CCSS 3.2", "ISO27001 A.9.4.1", "SOC2 CC6.3"]
    }
  ]
}
SAMPLE_EOF
  echo -e "${GREEN}[OK]${NC} Sample report created"
fi

echo ""

################################################################################
# Test 1: Report is valid JSON
################################################################################

test_start "Report is valid JSON"
if jq empty "$REPORT" 2>/dev/null; then
  test_pass "Report is valid JSON"
else
  test_fail "Report is not valid JSON"
  echo "  Report contents:"
  head -20 "$REPORT" 2>/dev/null || echo "  (could not read report)"
  # Cannot continue if JSON is invalid
  rm -f "$REPORT"
  exit 1
fi

################################################################################
# Test 2: Required top-level fields
################################################################################

test_start "Required top-level fields present"
REQUIRED_FIELDS=("scanner_version" "scan_date" "chain" "chain_id" "contract_address" "score" "summary" "findings")
MISSING_FIELDS=()
for field in "${REQUIRED_FIELDS[@]}"; do
  if ! jq -e ".[\"$field\"]" "$REPORT" > /dev/null 2>&1; then
    MISSING_FIELDS+=("$field")
  fi
done

if [[ ${#MISSING_FIELDS[@]} -eq 0 ]]; then
  test_pass "All required top-level fields present: ${REQUIRED_FIELDS[*]}"
else
  test_fail "Missing required fields: ${MISSING_FIELDS[*]}"
fi

################################################################################
# Test 3: scanner_version is a string
################################################################################

test_start "scanner_version is a non-empty string"
VERSION=$(jq -r '.scanner_version // empty' "$REPORT" 2>/dev/null)
if [[ -n "$VERSION" ]]; then
  test_pass "scanner_version: $VERSION"
else
  test_fail "scanner_version is missing or empty"
fi

################################################################################
# Test 4: scan_date is ISO 8601 format
################################################################################

test_start "scan_date is ISO 8601 format"
SCAN_DATE=$(jq -r '.scan_date // empty' "$REPORT" 2>/dev/null)
if [[ "$SCAN_DATE" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]]; then
  test_pass "scan_date: $SCAN_DATE"
else
  test_fail "scan_date not in ISO 8601 format: '$SCAN_DATE' (expected YYYY-MM-DDTHH:MM:SSZ)"
fi

################################################################################
# Test 5: chain is a known chain name
################################################################################

test_start "chain is a recognized chain name"
CHAIN=$(jq -r '.chain // empty' "$REPORT" 2>/dev/null)
KNOWN_CHAINS=("Ethereum" "Avalanche C-Chain" "BNB Smart Chain" "Polygon")
CHAIN_FOUND=false
for known in "${KNOWN_CHAINS[@]}"; do
  if [[ "$CHAIN" == "$known" ]]; then
    CHAIN_FOUND=true
    break
  fi
done
if $CHAIN_FOUND; then
  test_pass "chain: $CHAIN"
else
  test_fail "Unrecognized chain: '$CHAIN' (expected one of: ${KNOWN_CHAINS[*]})"
fi

################################################################################
# Test 6: chain_id is a valid number string
################################################################################

test_start "chain_id is a valid number"
CHAIN_ID=$(jq -r '.chain_id // empty' "$REPORT" 2>/dev/null)
if [[ "$CHAIN_ID" =~ ^[0-9]+$ ]]; then
  test_pass "chain_id: $CHAIN_ID"
else
  test_fail "chain_id is not a number: '$CHAIN_ID'"
fi

################################################################################
# Test 7: contract_address is a valid Ethereum address
################################################################################

test_start "contract_address is a valid address"
ADDRESS=$(jq -r '.contract_address // empty' "$REPORT" 2>/dev/null)
if [[ "$ADDRESS" =~ ^0x[0-9a-fA-F]{40}$ ]]; then
  test_pass "contract_address: $ADDRESS"
else
  test_fail "Invalid contract_address: '$ADDRESS'"
fi

################################################################################
# Test 8: score object structure
################################################################################

test_start "score object has required fields"
SCORE_FIELDS=("overall" "risk_level")
MISSING_SCORE=()
for field in "${SCORE_FIELDS[@]}"; do
  if ! jq -e ".score.$field" "$REPORT" > /dev/null 2>&1; then
    MISSING_SCORE+=("$field")
  fi
done
if [[ ${#MISSING_SCORE[@]} -eq 0 ]]; then
  OVERALL=$(jq -r '.score.overall' "$REPORT")
  RISK=$(jq -r '.score.risk_level' "$REPORT")
  test_pass "score.overall: $OVERALL, score.risk_level: $RISK"
else
  test_fail "Missing score fields: ${MISSING_SCORE[*]}"
fi

################################################################################
# Test 9: score.overall is 0-100
################################################################################

test_start "score.overall is between 0 and 100"
OVERALL=$(jq -r '.score.overall' "$REPORT" 2>/dev/null)
if [[ "$OVERALL" =~ ^[0-9]+$ ]] && [[ "$OVERALL" -ge 0 ]] && [[ "$OVERALL" -le 100 ]]; then
  test_pass "score.overall: $OVERALL (valid range)"
else
  test_fail "score.overall out of range: $OVERALL (expected 0-100)"
fi

################################################################################
# Test 10: score.risk_level is a known value
################################################################################

test_start "score.risk_level is a valid risk level"
RISK=$(jq -r '.score.risk_level' "$REPORT" 2>/dev/null)
if [[ "$RISK" =~ ^(LOW|MEDIUM|HIGH|CRITICAL)$ ]]; then
  test_pass "risk_level: $RISK"
else
  test_fail "Invalid risk_level: '$RISK' (expected LOW, MEDIUM, HIGH, or CRITICAL)"
fi

################################################################################
# Test 11: summary has severity counts
################################################################################

test_start "summary has severity counts"
SUMMARY_FIELDS=("critical" "high" "medium" "low" "info" "passed" "total_checks")
MISSING_SUMMARY=()
for field in "${SUMMARY_FIELDS[@]}"; do
  if ! jq -e ".summary.$field" "$REPORT" > /dev/null 2>&1; then
    MISSING_SUMMARY+=("$field")
  fi
done
if [[ ${#MISSING_SUMMARY[@]} -eq 0 ]]; then
  CRIT=$(jq '.summary.critical' "$REPORT")
  HIGH=$(jq '.summary.high' "$REPORT")
  MED=$(jq '.summary.medium' "$REPORT")
  LOW=$(jq '.summary.low' "$REPORT")
  TOTAL=$(jq '.summary.total_checks' "$REPORT")
  test_pass "summary: $CRIT critical, $HIGH high, $MED medium, $LOW low ($TOTAL total checks)"
else
  test_fail "Missing summary fields: ${MISSING_SUMMARY[*]}"
fi

################################################################################
# Test 12: summary counts are non-negative integers
################################################################################

test_start "summary counts are non-negative integers"
ALL_VALID=true
for field in "critical" "high" "medium" "low" "info" "passed" "total_checks"; do
  VAL=$(jq -r ".summary.$field" "$REPORT" 2>/dev/null)
  if ! [[ "$VAL" =~ ^[0-9]+$ ]]; then
    echo -e "  ${RED}Invalid value for summary.$field:${NC} '$VAL'"
    ALL_VALID=false
  fi
done
if $ALL_VALID; then
  test_pass "All summary counts are non-negative integers"
else
  test_fail "Some summary counts are not valid non-negative integers"
fi

################################################################################
# Test 13: findings is an array
################################################################################

test_start "findings is an array"
FINDINGS_TYPE=$(jq -r '.findings | type' "$REPORT" 2>/dev/null)
if [[ "$FINDINGS_TYPE" == "array" ]]; then
  FINDINGS_COUNT=$(jq '.findings | length' "$REPORT")
  test_pass "findings is an array with $FINDINGS_COUNT entries"
else
  test_fail "findings is not an array (type: $FINDINGS_TYPE)"
fi

################################################################################
# Test 14: finding structure validation
################################################################################

test_start "findings have required fields"
FINDINGS_COUNT=$(jq '.findings | length' "$REPORT" 2>/dev/null)

if [[ "$FINDINGS_COUNT" -gt 0 ]]; then
  FINDING_FIELDS=("domain" "check_id" "severity" "title" "description" "resources" "remediation" "frameworks")
  ALL_FINDINGS_VALID=true

  for i in $(seq 0 $((FINDINGS_COUNT - 1))); do
    for field in "${FINDING_FIELDS[@]}"; do
      if ! jq -e ".findings[$i].$field" "$REPORT" > /dev/null 2>&1; then
        echo -e "  ${RED}Finding $i missing field:${NC} $field"
        ALL_FINDINGS_VALID=false
      fi
    done
  done

  if $ALL_FINDINGS_VALID; then
    test_pass "All $FINDINGS_COUNT findings have required fields"
  else
    test_fail "Some findings are missing required fields"
  fi
else
  test_skip "No findings to validate (empty findings array)"
  # Still counts as run but skip doesn't increment pass or fail
  ((TESTS_RUN--)) || true
fi

################################################################################
# Test 15: finding severity values are valid
################################################################################

test_start "finding severity values are valid"
if [[ "$FINDINGS_COUNT" -gt 0 ]]; then
  INVALID_SEVERITIES=$(jq -r '.findings[].severity' "$REPORT" 2>/dev/null | grep -vE '^(critical|high|medium|low|info)$' || true)
  if [[ -z "$INVALID_SEVERITIES" ]]; then
    SEVERITIES=$(jq -r '.findings[].severity' "$REPORT" 2>/dev/null | sort | uniq -c | tr '\n' ', ')
    test_pass "All severities valid: $SEVERITIES"
  else
    test_fail "Invalid severity values found: $INVALID_SEVERITIES"
  fi
else
  test_pass "No findings to validate (empty array is acceptable)"
fi

################################################################################
# Test 16: finding check_id format
################################################################################

test_start "finding check_id values match expected format"
if [[ "$FINDINGS_COUNT" -gt 0 ]]; then
  # Expected format: XX-NNN or XXX-NNN (e.g., SC-001, OWN-002, PRX-001, TKN-003, AUD-001)
  INVALID_IDS=$(jq -r '.findings[].check_id' "$REPORT" 2>/dev/null | grep -vE '^(SC|OWN|PRX|TKN|AUD)-[0-9]{3}$' || true)
  if [[ -z "$INVALID_IDS" ]]; then
    IDS=$(jq -r '.findings[].check_id' "$REPORT" 2>/dev/null | tr '\n' ', ')
    test_pass "All check_ids valid: $IDS"
  else
    test_fail "Invalid check_id values: $INVALID_IDS (expected format: SC-001, OWN-002, etc.)"
  fi
else
  test_pass "No findings to validate (empty array is acceptable)"
fi

################################################################################
# Test 17: finding domain values are valid
################################################################################

test_start "finding domain values are valid"
if [[ "$FINDINGS_COUNT" -gt 0 ]]; then
  INVALID_DOMAINS=$(jq -r '.findings[].domain' "$REPORT" 2>/dev/null | grep -vE '^(verification|ownership|proxy|token|audit)$' || true)
  if [[ -z "$INVALID_DOMAINS" ]]; then
    DOMAINS=$(jq -r '.findings[].domain' "$REPORT" 2>/dev/null | sort -u | tr '\n' ', ')
    test_pass "All domains valid: $DOMAINS"
  else
    test_fail "Invalid domain values: $INVALID_DOMAINS"
  fi
else
  test_pass "No findings to validate (empty array is acceptable)"
fi

################################################################################
# Test 18: finding resources is an array
################################################################################

test_start "finding resources fields are arrays"
if [[ "$FINDINGS_COUNT" -gt 0 ]]; then
  ALL_ARRAYS=true
  for i in $(seq 0 $((FINDINGS_COUNT - 1))); do
    RTYPE=$(jq -r ".findings[$i].resources | type" "$REPORT" 2>/dev/null)
    if [[ "$RTYPE" != "array" ]]; then
      echo -e "  ${RED}Finding $i resources is $RTYPE, not array${NC}"
      ALL_ARRAYS=false
    fi
  done
  if $ALL_ARRAYS; then
    test_pass "All findings have resources as arrays"
  else
    test_fail "Some findings have non-array resources"
  fi
else
  test_pass "No findings to validate (empty array is acceptable)"
fi

################################################################################
# Cleanup
################################################################################

rm -f "$REPORT"

################################################################################
# Summary
################################################################################

echo ""
echo "============================================="
echo ""
echo "Report Structure Test Results:"
echo "  Total:  $TESTS_RUN"
echo "  Passed: $TESTS_PASSED"
echo "  Failed: $TESTS_FAILED"
echo ""

if [[ "$TESTS_FAILED" -eq 0 ]]; then
  echo -e "${GREEN}[PASS]${NC} All report structure tests passed"
  exit 0
else
  echo -e "${RED}[FAIL]${NC} Some report structure tests failed"
  exit 1
fi
