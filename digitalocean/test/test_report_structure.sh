#!/bin/bash

################################################################################
# Test: DigitalOcean Scanner Report Structure
#
# Validates that the generated JSON report has the correct structure,
# required fields, and properly formatted findings.
#
# This test requires a report file. If one does not exist, it will attempt
# to run the scanner to generate one. You can also provide a report path:
#   ./test_report_structure.sh /path/to/existing-report.json
################################################################################

set -euo pipefail

SCANNER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPORT="${1:-/tmp/do-test-report.json}"
GENERATED=false
PASS=0
FAIL=0

echo "Testing DigitalOcean scanner report structure..."
echo ""

# Generate report if not provided or not found
if [ ! -f "$REPORT" ]; then
    echo "No report found at $REPORT. Generating one..."
    if "$SCANNER_DIR/starlings-do-scan.sh" --output "$REPORT" > /dev/null 2>&1; then
        echo "Report generated at $REPORT"
        GENERATED=true
    else
        echo "FAIL - Scanner failed to generate report"
        exit 1
    fi
fi

echo "Using report: $REPORT"
echo ""

# Test 1: JSON validity
echo "1. Checking JSON validity..."
if jq empty "$REPORT" 2>/dev/null; then
    echo "  PASS - Report is valid JSON"
    ((PASS++))
else
    echo "  FAIL - Report is not valid JSON"
    echo "  Content:"
    head -20 "$REPORT" 2>/dev/null || true
    ((FAIL++))
    echo ""
    echo "Results: $PASS passed, $FAIL failed"
    exit 1
fi

# Test 2: Required top-level fields
echo ""
echo "2. Checking required top-level fields..."
REQUIRED_FIELDS=("scanner_version" "scan_date" "account_email" "score" "summary" "findings")
for field in "${REQUIRED_FIELDS[@]}"; do
    if jq -e ".$field" "$REPORT" > /dev/null 2>&1; then
        VALUE=$(jq -r ".$field | if type == \"object\" or type == \"array\" then type else . end" "$REPORT" 2>/dev/null)
        echo "  PASS - Field present: $field ($VALUE)"
        ((PASS++))
    else
        echo "  FAIL - Missing required field: $field"
        ((FAIL++))
    fi
done

# Test 3: scanner_version format
echo ""
echo "3. Checking scanner_version format..."
VERSION=$(jq -r '.scanner_version' "$REPORT" 2>/dev/null || echo "")
if [[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "  PASS - Valid semver: $VERSION"
    ((PASS++))
else
    echo "  FAIL - Invalid version format: $VERSION (expected semver like 1.0.0)"
    ((FAIL++))
fi

# Test 4: scan_date format (ISO 8601)
echo ""
echo "4. Checking scan_date format..."
SCAN_DATE=$(jq -r '.scan_date' "$REPORT" 2>/dev/null || echo "")
if [[ "$SCAN_DATE" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]]; then
    echo "  PASS - Valid ISO 8601 date: $SCAN_DATE"
    ((PASS++))
else
    echo "  FAIL - Invalid date format: $SCAN_DATE (expected ISO 8601)"
    ((FAIL++))
fi

# Test 5: Score structure
echo ""
echo "5. Checking score structure..."
if jq -e '.score.overall' "$REPORT" > /dev/null 2>&1; then
    OVERALL=$(jq -r '.score.overall' "$REPORT")
    if [[ "$OVERALL" =~ ^[0-9]+$ ]] && [ "$OVERALL" -ge 0 ] && [ "$OVERALL" -le 100 ]; then
        echo "  PASS - Score.overall valid: $OVERALL/100"
        ((PASS++))
    else
        echo "  FAIL - Score.overall out of range: $OVERALL"
        ((FAIL++))
    fi
else
    echo "  FAIL - Missing score.overall"
    ((FAIL++))
fi

if jq -e '.score.interpretation' "$REPORT" > /dev/null 2>&1; then
    INTERP=$(jq -r '.score.interpretation' "$REPORT")
    if [[ "$INTERP" =~ ^(Excellent|Good|Fair|Needs\ Attention)$ ]]; then
        echo "  PASS - Score.interpretation valid: $INTERP"
        ((PASS++))
    else
        echo "  FAIL - Invalid interpretation: $INTERP"
        ((FAIL++))
    fi
else
    echo "  FAIL - Missing score.interpretation"
    ((FAIL++))
fi

# Test 6: Summary structure
echo ""
echo "6. Checking summary structure..."
SUMMARY_FIELDS=("critical" "high" "medium" "low" "passed" "total_checks")
for field in "${SUMMARY_FIELDS[@]}"; do
    if jq -e ".summary.$field" "$REPORT" > /dev/null 2>&1; then
        VALUE=$(jq -r ".summary.$field" "$REPORT")
        if [[ "$VALUE" =~ ^[0-9]+$ ]]; then
            echo "  PASS - summary.$field: $VALUE"
            ((PASS++))
        else
            echo "  FAIL - summary.$field is not a number: $VALUE"
            ((FAIL++))
        fi
    else
        echo "  FAIL - Missing summary.$field"
        ((FAIL++))
    fi
done

# Test 7: Summary total consistency
echo ""
echo "7. Checking summary total consistency..."
CRITICAL=$(jq -r '.summary.critical' "$REPORT" 2>/dev/null || echo "0")
HIGH=$(jq -r '.summary.high' "$REPORT" 2>/dev/null || echo "0")
MEDIUM=$(jq -r '.summary.medium' "$REPORT" 2>/dev/null || echo "0")
LOW=$(jq -r '.summary.low' "$REPORT" 2>/dev/null || echo "0")
PASSED=$(jq -r '.summary.passed' "$REPORT" 2>/dev/null || echo "0")
TOTAL=$(jq -r '.summary.total_checks' "$REPORT" 2>/dev/null || echo "0")
COMPUTED=$((CRITICAL + HIGH + MEDIUM + LOW + PASSED))

if [ "$COMPUTED" -eq "$TOTAL" ]; then
    echo "  PASS - Total checks is consistent: $COMPUTED = $TOTAL"
    ((PASS++))
else
    echo "  FAIL - Total checks mismatch: $CRITICAL + $HIGH + $MEDIUM + $LOW + $PASSED = $COMPUTED, but total_checks = $TOTAL"
    ((FAIL++))
fi

# Test 8: Findings array
echo ""
echo "8. Checking findings array..."
if jq -e '.findings | type == "array"' "$REPORT" > /dev/null 2>&1; then
    FINDINGS_COUNT=$(jq '.findings | length' "$REPORT")
    echo "  PASS - Findings is an array with $FINDINGS_COUNT entries"
    ((PASS++))
else
    echo "  FAIL - Findings is not an array"
    ((FAIL++))
fi

# Test 9: Finding structure (check first finding if any exist)
echo ""
echo "9. Checking finding structure..."
FINDINGS_COUNT=$(jq '.findings | length' "$REPORT" 2>/dev/null || echo "0")

if [ "$FINDINGS_COUNT" -gt 0 ]; then
    FINDING_FIELDS=("domain" "check_id" "severity" "title" "description" "resources" "remediation" "frameworks")
    SAMPLE=$(jq '.findings[0]' "$REPORT")

    for field in "${FINDING_FIELDS[@]}"; do
        if echo "$SAMPLE" | jq -e ".$field" > /dev/null 2>&1; then
            echo "  PASS - Finding has field: $field"
            ((PASS++))
        else
            echo "  FAIL - Finding missing field: $field"
            ((FAIL++))
        fi
    done

    # Validate severity values
    echo ""
    echo "  Checking severity values..."
    SEVERITIES=$(jq -r '.findings[].severity' "$REPORT" 2>/dev/null | sort -u)
    ALL_VALID=true
    for sev in $SEVERITIES; do
        if [[ "$sev" =~ ^(critical|high|medium|low)$ ]]; then
            echo "    PASS - Valid severity: $sev"
        else
            echo "    FAIL - Invalid severity: $sev"
            ALL_VALID=false
            ((FAIL++))
        fi
    done
    if [ "$ALL_VALID" = true ]; then
        ((PASS++))
    fi

    # Validate check_id format
    echo ""
    echo "  Checking check_id format..."
    INVALID_IDS=$(jq -r '.findings[].check_id' "$REPORT" 2>/dev/null | grep -cvE '^(APP|DB|NET|STO|DRP|DNS|ACL)-[0-9]{3}$' || true)
    if [ "$INVALID_IDS" -eq 0 ]; then
        echo "    PASS - All check_ids follow expected format"
        ((PASS++))
    else
        echo "    FAIL - $INVALID_IDS check_id(s) have unexpected format"
        ((FAIL++))
    fi

    # Validate resources is an array
    echo ""
    echo "  Checking resources field type..."
    RESOURCE_TYPES=$(jq '[.findings[].resources | type] | unique' "$REPORT" 2>/dev/null)
    if echo "$RESOURCE_TYPES" | jq -e '. == ["array"]' > /dev/null 2>&1; then
        echo "    PASS - All resources fields are arrays"
        ((PASS++))
    else
        echo "    FAIL - Some resources fields are not arrays: $RESOURCE_TYPES"
        ((FAIL++))
    fi

    # Validate frameworks is an array
    echo ""
    echo "  Checking frameworks field type..."
    FRAMEWORK_TYPES=$(jq '[.findings[].frameworks | type] | unique' "$REPORT" 2>/dev/null)
    if echo "$FRAMEWORK_TYPES" | jq -e '. == ["array"]' > /dev/null 2>&1; then
        echo "    PASS - All frameworks fields are arrays"
        ((PASS++))
    else
        echo "    FAIL - Some frameworks fields are not arrays: $FRAMEWORK_TYPES"
        ((FAIL++))
    fi
else
    echo "  SKIP - No findings to validate (all checks passed)"
fi

# Test 10: Platform field
echo ""
echo "10. Checking platform field..."
PLATFORM=$(jq -r '.platform // empty' "$REPORT" 2>/dev/null)
if [ "$PLATFORM" = "digitalocean" ]; then
    echo "   PASS - Platform: $PLATFORM"
    ((PASS++))
else
    echo "   FAIL - Expected platform 'digitalocean', got '$PLATFORM'"
    ((FAIL++))
fi

# Cleanup generated report
if [ "$GENERATED" = true ]; then
    rm -f "$REPORT"
    echo ""
    echo "(Cleaned up generated test report)"
fi

# Summary
echo ""
echo "========================================"
echo "Report Structure Test Results"
echo "========================================"
echo "  Passed: $PASS"
echo "  Failed: $FAIL"
echo ""

if [ "$FAIL" -eq 0 ]; then
    echo "All report structure tests passed!"
    exit 0
else
    echo "Some report structure tests failed. Review the output above."
    exit 1
fi
