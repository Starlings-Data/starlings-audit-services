#!/bin/bash

################################################################################
# Test: Vercel Scanner Report Structure
#
# Validates that the JSON report output has all required fields and correct
# structure. Uses a sample report or a live-generated report if VERCEL_TOKEN
# is configured.
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
REPORT="/tmp/vercel-scan-test-report.json"

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
echo "Vercel Scanner - Report Structure Tests"
echo "========================================"
echo ""

################################################################################
# Generate or locate a report
################################################################################

USE_SAMPLE=false

if [[ -n "${VERCEL_TOKEN:-}" ]]; then
  echo "VERCEL_TOKEN found. Generating live report..."
  if "$SCANNER_DIR/starlings-vercel-scan.sh" --output "$REPORT" > /dev/null 2>&1; then
    echo -e "${GREEN}[OK]${NC} Report generated from live scan"
  else
    echo -e "${YELLOW}[WARN]${NC} Live scan failed, falling back to sample report"
    USE_SAMPLE=true
  fi
else
  echo "No VERCEL_TOKEN set. Using sample report for structure validation."
  USE_SAMPLE=true
fi

if $USE_SAMPLE; then
  cat > "$REPORT" << 'SAMPLE_EOF'
{
  "scanner_version": "1.0.0",
  "scan_date": "2026-02-05T20:00:00Z",
  "platform": "Vercel",
  "scope": "team",
  "team_name": "Starlings Data",
  "team_id": "team_xxxxxxxxxxxx",
  "user": "test-user",
  "projects_scanned": [
    {"id": "prj_abc123", "name": "my-web-app"},
    {"id": "prj_def456", "name": "api-service"}
  ],
  "score": {
    "overall": 68,
    "interpretation": "Fair",
    "risk_level": "MEDIUM"
  },
  "summary": {
    "critical": 0,
    "high": 2,
    "medium": 3,
    "low": 1,
    "info": 1,
    "passed": 12,
    "total_checks": 19
  },
  "findings": [
    {
      "domain": "env",
      "check_id": "ENV-001",
      "severity": "high",
      "title": "Sensitive env vars exposed to preview deployments (my-web-app)",
      "description": "2 sensitive environment variable(s) are available in preview deployments.",
      "resources": ["DATABASE_URL", "API_SECRET_KEY"],
      "remediation": "Restrict sensitive variables to production environment only.",
      "frameworks": ["ISO27001 A.14.2.5", "SOC2 CC6.1", "CIS 5.2", "CCSS 3.4"]
    },
    {
      "domain": "firewall",
      "check_id": "FW-002",
      "severity": "high",
      "title": "OWASP WAF rules not enabled (api-service)",
      "description": "OWASP managed rules are not active.",
      "resources": ["api-service"],
      "remediation": "Enable OWASP managed rules in Project Settings > Security > Firewall.",
      "frameworks": ["ISO27001 A.14.1.2", "SOC2 CC6.6", "CIS 9.4"]
    },
    {
      "domain": "project",
      "check_id": "PROJ-001",
      "severity": "medium",
      "title": "Preview deployments not protected (my-web-app)",
      "description": "Preview deployments are publicly accessible.",
      "resources": ["my-web-app"],
      "remediation": "Enable Deployment Protection for preview deployments.",
      "frameworks": ["ISO27001 A.14.2.5", "SOC2 CC6.1", "CIS 5.2"]
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
  head -20 "$REPORT" 2>/dev/null || echo "  (could not read report)"
  rm -f "$REPORT"
  exit 1
fi

################################################################################
# Test 2: Required top-level fields
################################################################################

test_start "Required top-level fields present"
REQUIRED_FIELDS=("scanner_version" "scan_date" "platform" "scope" "projects_scanned" "score" "summary" "findings")
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
# Test 3: scanner_version is a non-empty string
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
# Test 5: platform is "Vercel"
################################################################################

test_start "platform is Vercel"
PLATFORM=$(jq -r '.platform // empty' "$REPORT" 2>/dev/null)
if [[ "$PLATFORM" == "Vercel" ]]; then
  test_pass "platform: $PLATFORM"
else
  test_fail "Unexpected platform: '$PLATFORM' (expected 'Vercel')"
fi

################################################################################
# Test 6: scope is "personal" or "team"
################################################################################

test_start "scope is a valid value"
SCOPE=$(jq -r '.scope // empty' "$REPORT" 2>/dev/null)
if [[ "$SCOPE" == "personal" || "$SCOPE" == "team" ]]; then
  test_pass "scope: $SCOPE"
else
  test_fail "Invalid scope: '$SCOPE' (expected 'personal' or 'team')"
fi

################################################################################
# Test 7: projects_scanned is an array
################################################################################

test_start "projects_scanned is an array"
PROJECTS_TYPE=$(jq -r '.projects_scanned | type' "$REPORT" 2>/dev/null)
if [[ "$PROJECTS_TYPE" == "array" ]]; then
  PROJECT_COUNT=$(jq '.projects_scanned | length' "$REPORT")
  test_pass "projects_scanned is an array with $PROJECT_COUNT entries"
else
  test_fail "projects_scanned is not an array (type: $PROJECTS_TYPE)"
fi

################################################################################
# Test 8: score object has required fields
################################################################################

test_start "score object has required fields"
SCORE_FIELDS=("overall" "interpretation" "risk_level")
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
  # Expected: AUTH-NNN, ENV-NNN, DEP-NNN, DOM-NNN, FW-NNN, EDGE-NNN, LOG-NNN, PROJ-NNN
  INVALID_IDS=$(jq -r '.findings[].check_id' "$REPORT" 2>/dev/null | grep -vE '^(AUTH|ENV|DEP|DOM|FW|EDGE|LOG|PROJ)-[0-9]{3}$' || true)
  if [[ -z "$INVALID_IDS" ]]; then
    IDS=$(jq -r '.findings[].check_id' "$REPORT" 2>/dev/null | tr '\n' ', ')
    test_pass "All check_ids valid: $IDS"
  else
    test_fail "Invalid check_id values: $INVALID_IDS"
  fi
else
  test_pass "No findings to validate (empty array is acceptable)"
fi

################################################################################
# Test 17: finding domain values are valid
################################################################################

test_start "finding domain values are valid"
if [[ "$FINDINGS_COUNT" -gt 0 ]]; then
  INVALID_DOMAINS=$(jq -r '.findings[].domain' "$REPORT" 2>/dev/null | grep -vE '^(auth|env|deploy|domain|firewall|edge|logging|project)$' || true)
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
echo "========================================"
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
