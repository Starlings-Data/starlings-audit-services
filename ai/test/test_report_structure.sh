#!/bin/bash
#
# Test Suite: Report Structure
# Validates JSON report output from the scanner against the vulnerable fixtures.
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
FIXTURES="$TEST_DIR/fixtures"
REPORT="/tmp/ai-scan-test-report-$$.json"

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

test_skip() {
    echo -e "${YELLOW}[SKIP]${NC} $1"
}

cleanup() {
    rm -f "$REPORT"
}
trap cleanup EXIT

# -------------------------------------------------------
# Generate report from fixtures
# -------------------------------------------------------
echo -e "${BLUE}Generating report from test fixtures...${NC}"
echo ""

if ! bash "$SCANNER" --repo "$FIXTURES" --output "$REPORT" > /dev/null 2>&1; then
    echo -e "${RED}Scanner failed to run on fixtures${NC}"
    # Try to continue with whatever output exists
fi

if [[ ! -f "$REPORT" ]]; then
    echo -e "${RED}No report generated. Cannot continue.${NC}"
    exit 1
fi

# -------------------------------------------------------
# Test 1: Report is valid JSON
# -------------------------------------------------------
test_start "Report is valid JSON"
if jq empty "$REPORT" 2>/dev/null; then
    test_pass "Report is valid JSON"
else
    test_fail "Report is not valid JSON"
    echo "Report contents:"
    head -20 "$REPORT"
    exit 1
fi

# -------------------------------------------------------
# Test 2: Required top-level fields present
# -------------------------------------------------------
test_start "Required top-level fields present"
REQUIRED_FIELDS=("scanner_version" "scan_date" "platform" "repository" "files_scanned" "score" "summary" "findings")
MISSING_FIELDS=()
for field in "${REQUIRED_FIELDS[@]}"; do
    if ! jq -e ".[\"$field\"]" "$REPORT" > /dev/null 2>&1; then
        MISSING_FIELDS+=("$field")
    fi
done

if [[ ${#MISSING_FIELDS[@]} -eq 0 ]]; then
    test_pass "All required fields present: ${REQUIRED_FIELDS[*]}"
else
    test_fail "Missing fields: ${MISSING_FIELDS[*]}"
fi

# -------------------------------------------------------
# Test 3: scanner_version is non-empty
# -------------------------------------------------------
test_start "scanner_version is valid"
VERSION=$(jq -r '.scanner_version // empty' "$REPORT" 2>/dev/null)
if [[ -n "$VERSION" ]]; then
    test_pass "scanner_version: $VERSION"
else
    test_fail "scanner_version is empty"
fi

# -------------------------------------------------------
# Test 4: scan_date is ISO 8601
# -------------------------------------------------------
test_start "scan_date is ISO 8601 format"
SCAN_DATE=$(jq -r '.scan_date // empty' "$REPORT" 2>/dev/null)
if [[ "$SCAN_DATE" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]]; then
    test_pass "scan_date: $SCAN_DATE"
else
    test_fail "scan_date not ISO 8601: $SCAN_DATE"
fi

# -------------------------------------------------------
# Test 5: platform field
# -------------------------------------------------------
test_start "platform field is set"
PLATFORM=$(jq -r '.platform // empty' "$REPORT" 2>/dev/null)
if [[ -n "$PLATFORM" ]]; then
    test_pass "platform: $PLATFORM"
else
    test_fail "platform is empty"
fi

# -------------------------------------------------------
# Test 6: score.overall is 0-100
# -------------------------------------------------------
test_start "score.overall is between 0-100"
OVERALL=$(jq -r '.score.overall' "$REPORT" 2>/dev/null)
if [[ "$OVERALL" =~ ^[0-9]+$ ]] && [[ "$OVERALL" -ge 0 ]] && [[ "$OVERALL" -le 100 ]]; then
    test_pass "score.overall: $OVERALL"
else
    test_fail "score.overall out of range: $OVERALL"
fi

# -------------------------------------------------------
# Test 7: score.risk_level is valid
# -------------------------------------------------------
test_start "score.risk_level is valid"
RISK=$(jq -r '.score.risk_level' "$REPORT" 2>/dev/null)
if [[ "$RISK" =~ ^(LOW|MEDIUM|HIGH|CRITICAL)$ ]]; then
    test_pass "risk_level: $RISK"
else
    test_fail "Invalid risk_level: $RISK"
fi

# -------------------------------------------------------
# Test 8: score.interpretation is valid
# -------------------------------------------------------
test_start "score.interpretation is valid"
INTERP=$(jq -r '.score.interpretation' "$REPORT" 2>/dev/null)
if [[ "$INTERP" =~ ^(Excellent|Good|Fair|Poor|Critical)$ ]]; then
    test_pass "interpretation: $INTERP"
else
    test_fail "Invalid interpretation: $INTERP"
fi

# -------------------------------------------------------
# Test 9: summary has all severity counts
# -------------------------------------------------------
test_start "summary has all severity counts"
SUMMARY_FIELDS=("critical" "high" "medium" "low" "info" "passed" "total_checks")
MISSING_SUMMARY=()
for field in "${SUMMARY_FIELDS[@]}"; do
    if ! jq -e ".summary.$field" "$REPORT" > /dev/null 2>&1; then
        MISSING_SUMMARY+=("$field")
    fi
done

if [[ ${#MISSING_SUMMARY[@]} -eq 0 ]]; then
    test_pass "All summary fields present"
else
    test_fail "Missing summary fields: ${MISSING_SUMMARY[*]}"
fi

# -------------------------------------------------------
# Test 10: findings is an array
# -------------------------------------------------------
test_start "findings is an array"
FINDINGS_TYPE=$(jq -r '.findings | type' "$REPORT" 2>/dev/null)
if [[ "$FINDINGS_TYPE" == "array" ]]; then
    FINDINGS_COUNT=$(jq '.findings | length' "$REPORT")
    test_pass "findings array with $FINDINGS_COUNT entries"
else
    test_fail "findings is not an array (got: $FINDINGS_TYPE)"
fi

# -------------------------------------------------------
# Test 11: findings have required fields
# -------------------------------------------------------
test_start "findings have required fields"
FINDINGS_COUNT=$(jq '.findings | length' "$REPORT" 2>/dev/null)
if [[ "$FINDINGS_COUNT" -gt 0 ]]; then
    FINDING_FIELDS=("domain" "check_id" "severity" "title" "description" "resources" "remediation")
    ALL_VALID=true

    for i in $(seq 0 $((FINDINGS_COUNT - 1))); do
        for field in "${FINDING_FIELDS[@]}"; do
            if ! jq -e ".findings[$i].$field" "$REPORT" > /dev/null 2>&1; then
                ALL_VALID=false
                echo -e "    ${RED}Finding $i missing field: $field${NC}"
            fi
        done
    done

    if $ALL_VALID; then
        test_pass "All $FINDINGS_COUNT findings have required fields"
    else
        test_fail "Some findings missing required fields"
    fi
else
    test_skip "No findings to validate"
fi

# -------------------------------------------------------
# Test 12: check_id format matches PREFIX-NNN
# -------------------------------------------------------
test_start "check_id format is PREFIX-NNN"
if [[ "$FINDINGS_COUNT" -gt 0 ]]; then
    INVALID_IDS=$(jq -r '.findings[].check_id' "$REPORT" 2>/dev/null | grep -v -E '^(KEY|INJ|MOD|CFG)-[0-9]{3}$' || true)
    if [[ -z "$INVALID_IDS" ]]; then
        test_pass "All check_ids match PREFIX-NNN format"
    else
        test_fail "Invalid check_ids: $INVALID_IDS"
    fi
else
    test_skip "No findings to validate"
fi

# -------------------------------------------------------
# Test 13: severity values are valid
# -------------------------------------------------------
test_start "severity values are valid"
if [[ "$FINDINGS_COUNT" -gt 0 ]]; then
    INVALID_SEV=$(jq -r '.findings[].severity' "$REPORT" 2>/dev/null | grep -v -E '^(critical|high|medium|low|info)$' || true)
    if [[ -z "$INVALID_SEV" ]]; then
        test_pass "All severity values are valid"
    else
        test_fail "Invalid severity values: $INVALID_SEV"
    fi
else
    test_skip "No findings to validate"
fi

# -------------------------------------------------------
# Test 14: domain values are valid
# -------------------------------------------------------
test_start "domain values are valid"
if [[ "$FINDINGS_COUNT" -gt 0 ]]; then
    INVALID_DOM=$(jq -r '.findings[].domain' "$REPORT" 2>/dev/null | grep -v -E '^(secrets|injection|models|config)$' || true)
    if [[ -z "$INVALID_DOM" ]]; then
        test_pass "All domain values are valid"
    else
        test_fail "Invalid domain values: $INVALID_DOM"
    fi
else
    test_skip "No findings to validate"
fi

# -------------------------------------------------------
# Test 15: Vulnerable fixtures trigger findings
# -------------------------------------------------------
test_start "Vulnerable fixtures trigger expected findings"
# The fixtures contain: KEY-001, KEY-002, KEY-003, KEY-004, INJ-001, MOD-001
EXPECTED_CHECKS=("KEY-001" "KEY-002" "KEY-003" "KEY-004" "INJ-001" "MOD-001")
FOUND_CHECKS=$(jq -r '.findings[].check_id' "$REPORT" 2>/dev/null | sort -u)
MISSING_CHECKS=()

for check in "${EXPECTED_CHECKS[@]}"; do
    if ! echo "$FOUND_CHECKS" | grep -q "$check"; then
        MISSING_CHECKS+=("$check")
    fi
done

if [[ ${#MISSING_CHECKS[@]} -eq 0 ]]; then
    test_pass "All expected findings detected: ${EXPECTED_CHECKS[*]}"
else
    test_fail "Expected findings not detected: ${MISSING_CHECKS[*]}"
    echo "    Found: $FOUND_CHECKS"
fi

# -------------------------------------------------------
# Test 16: Score reflects findings (not 100 for vulnerable code)
# -------------------------------------------------------
test_start "Score reflects findings severity"
SCORE=$(jq -r '.score.overall' "$REPORT" 2>/dev/null)
if [[ "$SCORE" -lt 80 ]]; then
    test_pass "Score ($SCORE) correctly reflects vulnerabilities"
else
    test_fail "Score ($SCORE) seems too high for vulnerable fixtures"
fi

# -------------------------------------------------------
# Test 17: files_scanned is > 0
# -------------------------------------------------------
test_start "files_scanned is > 0"
FILES=$(jq -r '.files_scanned' "$REPORT" 2>/dev/null)
if [[ "$FILES" =~ ^[0-9]+$ ]] && [[ "$FILES" -gt 0 ]]; then
    test_pass "files_scanned: $FILES"
else
    test_fail "files_scanned invalid: $FILES"
fi

# -------------------------------------------------------
# Test 18: findings have frameworks array
# -------------------------------------------------------
test_start "findings have frameworks array"
if [[ "$FINDINGS_COUNT" -gt 0 ]]; then
    FRAMEWORKS_TYPE=$(jq -r '.findings[0].frameworks | type' "$REPORT" 2>/dev/null)
    if [[ "$FRAMEWORKS_TYPE" == "array" ]]; then
        test_pass "frameworks field is an array"
    else
        test_fail "frameworks field is not an array (got: $FRAMEWORKS_TYPE)"
    fi
else
    test_skip "No findings to validate"
fi

# -------------------------------------------------------
# Summary
# -------------------------------------------------------
echo ""
echo "Report Structure Test Results:"
echo "  Total:  $TESTS_RUN"
echo "  Passed: $TESTS_PASSED"
echo "  Failed: $TESTS_FAILED"

if [[ "$TESTS_FAILED" -eq 0 ]]; then
    exit 0
else
    exit 1
fi
