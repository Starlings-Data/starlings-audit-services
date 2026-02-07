#!/bin/bash

################################################################################
# DigitalOcean Scanner Test Runner
#
# Runs all test cases for starlings-do-scan.sh
# Ensure doctl is installed and authenticated before running.
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
TESTS_SKIPPED=0

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCANNER_DIR="$(dirname "$TEST_DIR")"

################################################################################
# Test Framework
################################################################################

test_start() {
    local test_name="$1"
    echo -e "${BLUE}>>>${NC} Testing: $test_name"
    ((TESTS_RUN++))
}

test_pass() {
    local message="$1"
    echo -e "    ${GREEN}PASS${NC} - $message"
    ((TESTS_PASSED++))
}

test_fail() {
    local message="$1"
    echo -e "    ${RED}FAIL${NC} - $message"
    ((TESTS_FAILED++))
}

test_skip() {
    local message="$1"
    echo -e "    ${YELLOW}SKIP${NC} - $message"
    ((TESTS_SKIPPED++))
}

################################################################################
# Prerequisites Check
################################################################################

echo ""
echo "========================================"
echo "  DigitalOcean Scanner Test Suite"
echo "========================================"
echo ""
echo "Checking test prerequisites..."
echo ""

# Check bash
if command -v bash &> /dev/null; then
    echo -e "${GREEN}OK${NC} - bash available"
else
    echo -e "${RED}MISSING${NC} - bash not found"
    exit 1
fi

# Check jq
JQ_AVAILABLE=false
if command -v jq &> /dev/null; then
    echo -e "${GREEN}OK${NC} - jq available"
    JQ_AVAILABLE=true
else
    echo -e "${YELLOW}WARN${NC} - jq not found (some tests will be skipped)"
fi

# Check doctl
DOCTL_AVAILABLE=false
if command -v doctl &> /dev/null; then
    echo -e "${GREEN}OK${NC} - doctl available"
    DOCTL_AVAILABLE=true
else
    echo -e "${YELLOW}WARN${NC} - doctl not found (integration tests will be skipped)"
fi

# Check doctl auth
DOCTL_AUTHED=false
if [ "$DOCTL_AVAILABLE" = true ]; then
    if doctl account get &> /dev/null; then
        echo -e "${GREEN}OK${NC} - doctl authenticated"
        DOCTL_AUTHED=true
    else
        echo -e "${YELLOW}WARN${NC} - doctl not authenticated (integration tests will be skipped)"
    fi
fi

# Check scanner exists
if [ -f "$SCANNER_DIR/starlings-do-scan.sh" ]; then
    echo -e "${GREEN}OK${NC} - Scanner script found"
else
    echo -e "${RED}MISSING${NC} - Scanner script not found at $SCANNER_DIR/starlings-do-scan.sh"
    exit 1
fi

echo ""
echo "Starting tests..."
echo "----------------------------------------"
echo ""

################################################################################
# 1. Syntax Tests
################################################################################

echo "=== Syntax Tests ==="
echo ""

test_start "Scanner script has valid bash syntax"
if bash -n "$SCANNER_DIR/starlings-do-scan.sh" 2>/dev/null; then
    test_pass "Script has valid bash syntax"
else
    test_fail "Script has syntax errors"
fi

test_start "Test scripts have valid bash syntax"
ALL_SYNTAX_OK=true
for test_file in "$TEST_DIR"/test_*.sh; do
    if [ -f "$test_file" ]; then
        if ! bash -n "$test_file" 2>/dev/null; then
            test_fail "Syntax error in $(basename "$test_file")"
            ALL_SYNTAX_OK=false
        fi
    fi
done
if [ "$ALL_SYNTAX_OK" = true ]; then
    test_pass "All test scripts have valid syntax"
fi

test_start "Scanner script is executable"
if [ -x "$SCANNER_DIR/starlings-do-scan.sh" ]; then
    test_pass "Scanner script is executable"
else
    test_fail "Scanner script is not executable (run: chmod +x starlings-do-scan.sh)"
fi

echo ""

################################################################################
# 2. Help and Usage Tests
################################################################################

echo "=== Help and Usage Tests ==="
echo ""

test_start "Help flag displays usage information"
HELP_OUTPUT=$("$SCANNER_DIR/starlings-do-scan.sh" --help 2>&1 || true)
if echo "$HELP_OUTPUT" | grep -qi "usage"; then
    test_pass "Help message displays usage"
else
    test_fail "Help message does not contain usage information"
fi

test_start "Help flag shows output option"
if echo "$HELP_OUTPUT" | grep -qi "\-\-output"; then
    test_pass "Help message documents --output flag"
else
    test_fail "Help message does not document --output flag"
fi

test_start "Help flag shows verbose option"
if echo "$HELP_OUTPUT" | grep -qi "\-\-verbose"; then
    test_pass "Help message documents --verbose flag"
else
    test_fail "Help message does not document --verbose flag"
fi

test_start "Scanner rejects unknown arguments"
if "$SCANNER_DIR/starlings-do-scan.sh" --invalid-flag 2>&1 | grep -qi "unknown\|error\|usage"; then
    test_pass "Unknown arguments are rejected"
else
    test_fail "Unknown arguments are not rejected"
fi

echo ""

################################################################################
# 3. Connection Tests
################################################################################

echo "=== Connection Tests ==="
echo ""

if [ "$DOCTL_AVAILABLE" = true ] && [ "$DOCTL_AUTHED" = true ]; then
    test_start "doctl connection test script"
    if bash "$TEST_DIR/test_doctl_connection.sh" > /dev/null 2>&1; then
        test_pass "Connection test passed"
    else
        test_fail "Connection test failed"
    fi
else
    test_start "doctl connection test script"
    test_skip "doctl not available or not authenticated"
fi

echo ""

################################################################################
# 4. Integration Tests (require doctl + auth)
################################################################################

echo "=== Integration Tests ==="
echo ""

if [ "$DOCTL_AVAILABLE" = true ] && [ "$DOCTL_AUTHED" = true ] && [ "$JQ_AVAILABLE" = true ]; then

    INTEGRATION_REPORT="/tmp/do-integration-test-report.json"

    test_start "Scanner runs and generates output"
    if "$SCANNER_DIR/starlings-do-scan.sh" --output "$INTEGRATION_REPORT" > /dev/null 2>&1; then
        test_pass "Scanner completed successfully"
    else
        test_fail "Scanner exited with error"
    fi

    test_start "Output file exists"
    if [ -f "$INTEGRATION_REPORT" ]; then
        test_pass "Report file created at $INTEGRATION_REPORT"
    else
        test_fail "Report file not created"
    fi

    test_start "Output is valid JSON"
    if [ -f "$INTEGRATION_REPORT" ] && jq empty "$INTEGRATION_REPORT" 2>/dev/null; then
        test_pass "Report is valid JSON"
    else
        test_fail "Report is not valid JSON"
    fi

    test_start "Report structure test script"
    if [ -f "$INTEGRATION_REPORT" ]; then
        if bash "$TEST_DIR/test_report_structure.sh" "$INTEGRATION_REPORT" > /dev/null 2>&1; then
            test_pass "Report structure validation passed"
        else
            test_fail "Report structure validation failed"
        fi
    else
        test_fail "No report to validate"
    fi

    test_start "Report contains scanner_version"
    if [ -f "$INTEGRATION_REPORT" ] && jq -e '.scanner_version' "$INTEGRATION_REPORT" > /dev/null 2>&1; then
        VERSION=$(jq -r '.scanner_version' "$INTEGRATION_REPORT")
        test_pass "scanner_version: $VERSION"
    else
        test_fail "Missing scanner_version"
    fi

    test_start "Report contains score"
    if [ -f "$INTEGRATION_REPORT" ] && jq -e '.score.overall' "$INTEGRATION_REPORT" > /dev/null 2>&1; then
        SCORE=$(jq -r '.score.overall' "$INTEGRATION_REPORT")
        INTERP=$(jq -r '.score.interpretation' "$INTEGRATION_REPORT")
        test_pass "Score: $SCORE/100 ($INTERP)"
    else
        test_fail "Missing score"
    fi

    test_start "Report contains summary counts"
    if [ -f "$INTEGRATION_REPORT" ] && jq -e '.summary.total_checks' "$INTEGRATION_REPORT" > /dev/null 2>&1; then
        TOTAL=$(jq -r '.summary.total_checks' "$INTEGRATION_REPORT")
        test_pass "Total checks: $TOTAL"
    else
        test_fail "Missing summary counts"
    fi

    test_start "Report has findings array"
    if [ -f "$INTEGRATION_REPORT" ] && jq -e '.findings | type == "array"' "$INTEGRATION_REPORT" > /dev/null 2>&1; then
        FCOUNT=$(jq '.findings | length' "$INTEGRATION_REPORT")
        test_pass "Findings array with $FCOUNT entries"
    else
        test_fail "Missing or malformed findings array"
    fi

    test_start "Email addresses are redacted"
    if [ -f "$INTEGRATION_REPORT" ]; then
        # Check that no raw email addresses remain (should be REDACTED_EMAIL)
        RAW_EMAILS=$(grep -cE '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' "$INTEGRATION_REPORT" 2>/dev/null || echo "0")
        REDACTED=$(grep -c 'REDACTED_EMAIL' "$INTEGRATION_REPORT" 2>/dev/null || echo "0")
        if [ "$RAW_EMAILS" -eq 0 ] || [ "$REDACTED" -gt 0 ]; then
            test_pass "Email addresses are redacted"
        else
            test_fail "Found $RAW_EMAILS unredacted email address(es)"
        fi
    else
        test_fail "No report to check"
    fi

    # Cleanup
    rm -f "$INTEGRATION_REPORT"

else
    test_start "Integration tests"
    if [ "$DOCTL_AVAILABLE" = false ]; then
        test_skip "doctl not installed (install doctl to run integration tests)"
    elif [ "$DOCTL_AUTHED" = false ]; then
        test_skip "doctl not authenticated (run: doctl auth init)"
    else
        test_skip "jq not installed (install jq to run integration tests)"
    fi
fi

echo ""

################################################################################
# 5. File Structure Tests
################################################################################

echo "=== File Structure Tests ==="
echo ""

test_start "README.md exists"
if [ -f "$SCANNER_DIR/README.md" ]; then
    test_pass "README.md found"
else
    test_fail "README.md not found"
fi

test_start "Test directory exists"
if [ -d "$TEST_DIR" ]; then
    test_pass "test/ directory found"
else
    test_fail "test/ directory not found"
fi

test_start "Test scripts are executable"
ALL_EXEC=true
for test_file in "$TEST_DIR"/test_*.sh; do
    if [ -f "$test_file" ] && [ ! -x "$test_file" ]; then
        test_fail "$(basename "$test_file") is not executable"
        ALL_EXEC=false
    fi
done
if [ "$ALL_EXEC" = true ]; then
    test_pass "All test scripts are executable"
fi

echo ""

################################################################################
# Summary
################################################################################

echo "========================================"
echo "  Test Results"
echo "========================================"
echo ""
echo -e "  Total:   $TESTS_RUN"
echo -e "  ${GREEN}Passed:  $TESTS_PASSED${NC}"
echo -e "  ${RED}Failed:  $TESTS_FAILED${NC}"
echo -e "  ${YELLOW}Skipped: $TESTS_SKIPPED${NC}"
echo ""

if [ "$TESTS_FAILED" -eq 0 ]; then
    echo -e "${GREEN}All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}$TESTS_FAILED test(s) failed.${NC} Review the output above for details."
    exit 1
fi
