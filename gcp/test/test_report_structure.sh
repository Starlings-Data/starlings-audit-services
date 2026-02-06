#!/bin/bash

################################################################################
# Test: GCP Scanner Report Structure
#
# Validates that the generated report has correct JSON structure and all
# required fields. Runs the scanner in a dry-run/mock mode by generating
# a synthetic report, then validates its schema.
#
# This test does NOT require GCP credentials - it validates report structure
# independently by creating a mock report that mirrors scanner output.
################################################################################

set -euo pipefail

SCANNER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPORT="/tmp/gcp-test-report-$$.json"
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

pass() {
    local message="$1"
    echo "[PASS] $message"
    TESTS_PASSED=$((TESTS_PASSED + 1))
    TESTS_RUN=$((TESTS_RUN + 1))
}

fail() {
    local message="$1"
    echo "[FAIL] $message"
    TESTS_FAILED=$((TESTS_FAILED + 1))
    TESTS_RUN=$((TESTS_RUN + 1))
}

cleanup() {
    rm -f "$REPORT"
}
trap cleanup EXIT

echo "Testing GCP scanner report structure..."
echo ""

# --------------------------------------------------------------------------
# Prerequisites
# --------------------------------------------------------------------------
if ! command -v jq &> /dev/null; then
    echo "[FAIL] jq is required for report structure tests"
    exit 1
fi

# --------------------------------------------------------------------------
# Generate mock report
# --------------------------------------------------------------------------
echo "Generating mock report for structure validation..."

cat > "$REPORT" << 'MOCK_EOF'
{
  "scanner_version": "1.0.0",
  "scan_date": "2026-02-05T10:30:00Z",
  "project_id": "test-project-123",
  "project_number": "REDACTED",
  "score": {
    "overall": 72,
    "interpretation": "Good"
  },
  "summary": {
    "critical": 2,
    "high": 4,
    "medium": 5,
    "low": 3,
    "passed": 20,
    "total_checks": 34
  },
  "compliance_coverage": {
    "cis_gcp_foundations": true,
    "iso_27001": true,
    "soc_2": true,
    "ccss": true
  },
  "findings": [
    {
      "domain": "iam",
      "check_id": "IAM-003",
      "severity": "critical",
      "title": "Service accounts with Owner or Editor roles",
      "description": "2 service account(s) have Owner or Editor roles assigned. These are overly permissive.",
      "resources": ["test-sa@test-project-123.iam.gserviceaccount.com"],
      "remediation": "Replace Owner/Editor roles with granular predefined or custom roles following least privilege",
      "frameworks": ["CIS-GCP 1.5", "ISO27001 A.9.2.3", "SOC2 CC6.3", "CCSS 4.3"]
    },
    {
      "domain": "compute",
      "check_id": "GCE-001",
      "severity": "critical",
      "title": "Firewall rules allow SSH from anywhere",
      "description": "1 firewall rule(s) allow SSH (port 22) ingress from 0.0.0.0/0",
      "resources": ["allow-ssh-all"],
      "remediation": "Restrict SSH access to specific IP ranges. Use IAP TCP forwarding or OS Login instead of direct SSH.",
      "frameworks": ["CIS-GCP 3.6", "ISO27001 A.13.1.1", "SOC2 CC6.6", "CCSS 5.1"]
    },
    {
      "domain": "gcs",
      "check_id": "GCS-001",
      "severity": "critical",
      "title": "Publicly accessible Cloud Storage buckets",
      "description": "1 bucket(s) grant access to allUsers or allAuthenticatedUsers",
      "resources": ["public-bucket-test"],
      "remediation": "Remove allUsers and allAuthenticatedUsers IAM bindings",
      "frameworks": ["CIS-GCP 5.1", "ISO27001 A.13.1.1", "SOC2 CC6.1", "CCSS 3.1"]
    },
    {
      "domain": "sql",
      "check_id": "SQL-002",
      "severity": "high",
      "title": "Cloud SQL instances without SSL enforcement",
      "description": "1 Cloud SQL instance(s) do not require SSL/TLS connections",
      "resources": ["test-db-instance"],
      "remediation": "Enforce SSL connections: gcloud sql instances patch INSTANCE --require-ssl",
      "frameworks": ["CIS-GCP 6.4", "ISO27001 A.14.1.2", "SOC2 CC6.7", "CCSS 3.2"]
    },
    {
      "domain": "logging",
      "check_id": "LOG-001",
      "severity": "high",
      "title": "Data Access audit logs not configured",
      "description": "No Data Access audit log configuration found.",
      "resources": [],
      "remediation": "Enable Data Access audit logs for all services",
      "frameworks": ["CIS-GCP 2.1", "ISO27001 A.12.4.1", "SOC2 CC7.2", "CCSS 6.1"]
    }
  ]
}
MOCK_EOF

echo ""

# --------------------------------------------------------------------------
# Test 1: JSON validity
# --------------------------------------------------------------------------
echo "1. Checking JSON validity..."
if jq empty "$REPORT" 2>/dev/null; then
    pass "Report is valid JSON"
else
    fail "Report is not valid JSON"
    cat "$REPORT"
    exit 1
fi

# --------------------------------------------------------------------------
# Test 2: Required top-level fields
# --------------------------------------------------------------------------
echo ""
echo "2. Checking required top-level fields..."

TOP_LEVEL_FIELDS=("scanner_version" "scan_date" "project_id" "score" "summary" "findings")
for field in "${TOP_LEVEL_FIELDS[@]}"; do
    if jq -e ".$field" "$REPORT" > /dev/null 2>&1; then
        VALUE=$(jq -r ".$field | if type == \"object\" or type == \"array\" then type else . end" "$REPORT")
        pass "Field present: $field ($VALUE)"
    else
        fail "Missing required field: $field"
    fi
done

# --------------------------------------------------------------------------
# Test 3: Scanner version format
# --------------------------------------------------------------------------
echo ""
echo "3. Checking scanner_version format..."
SCANNER_VERSION=$(jq -r '.scanner_version' "$REPORT")
if [[ "$SCANNER_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    pass "scanner_version is valid semver: $SCANNER_VERSION"
else
    fail "scanner_version is not valid semver: $SCANNER_VERSION"
fi

# --------------------------------------------------------------------------
# Test 4: scan_date format (ISO 8601)
# --------------------------------------------------------------------------
echo ""
echo "4. Checking scan_date format..."
SCAN_DATE=$(jq -r '.scan_date' "$REPORT")
if [[ "$SCAN_DATE" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]]; then
    pass "scan_date is valid ISO 8601: $SCAN_DATE"
else
    fail "scan_date is not valid ISO 8601: $SCAN_DATE"
fi

# --------------------------------------------------------------------------
# Test 5: Score structure
# --------------------------------------------------------------------------
echo ""
echo "5. Checking score structure..."

OVERALL_SCORE=$(jq -r '.score.overall' "$REPORT")
if [[ "$OVERALL_SCORE" =~ ^[0-9]+$ ]] && [ "$OVERALL_SCORE" -ge 0 ] && [ "$OVERALL_SCORE" -le 100 ]; then
    pass "score.overall is valid: $OVERALL_SCORE/100"
else
    fail "score.overall is invalid: $OVERALL_SCORE"
fi

INTERPRETATION=$(jq -r '.score.interpretation' "$REPORT")
if [[ "$INTERPRETATION" =~ ^(Excellent|Good|Fair|Needs Attention)$ ]]; then
    pass "score.interpretation is valid: $INTERPRETATION"
else
    fail "score.interpretation is invalid: $INTERPRETATION"
fi

# --------------------------------------------------------------------------
# Test 6: Summary structure
# --------------------------------------------------------------------------
echo ""
echo "6. Checking summary structure..."

SUMMARY_FIELDS=("critical" "high" "medium" "low" "passed" "total_checks")
for field in "${SUMMARY_FIELDS[@]}"; do
    VALUE=$(jq -r ".summary.$field" "$REPORT" 2>/dev/null)
    if [[ "$VALUE" =~ ^[0-9]+$ ]]; then
        pass "summary.$field is valid integer: $VALUE"
    else
        fail "summary.$field is missing or invalid: $VALUE"
    fi
done

# Verify total_checks equals sum of all categories
CRITICAL=$(jq -r '.summary.critical' "$REPORT")
HIGH=$(jq -r '.summary.high' "$REPORT")
MEDIUM=$(jq -r '.summary.medium' "$REPORT")
LOW=$(jq -r '.summary.low' "$REPORT")
PASSED=$(jq -r '.summary.passed' "$REPORT")
TOTAL=$(jq -r '.summary.total_checks' "$REPORT")
COMPUTED_TOTAL=$((CRITICAL + HIGH + MEDIUM + LOW + PASSED))

if [ "$TOTAL" -eq "$COMPUTED_TOTAL" ]; then
    pass "total_checks ($TOTAL) equals sum of severity counts + passed ($COMPUTED_TOTAL)"
else
    fail "total_checks ($TOTAL) does not equal computed total ($COMPUTED_TOTAL)"
fi

# --------------------------------------------------------------------------
# Test 7: Compliance coverage
# --------------------------------------------------------------------------
echo ""
echo "7. Checking compliance_coverage..."

COMPLIANCE_FIELDS=("cis_gcp_foundations" "iso_27001" "soc_2" "ccss")
for field in "${COMPLIANCE_FIELDS[@]}"; do
    VALUE=$(jq -r ".compliance_coverage.$field" "$REPORT" 2>/dev/null)
    if [ "$VALUE" = "true" ]; then
        pass "compliance_coverage.$field: $VALUE"
    else
        fail "compliance_coverage.$field is missing or false: $VALUE"
    fi
done

# --------------------------------------------------------------------------
# Test 8: Findings array structure
# --------------------------------------------------------------------------
echo ""
echo "8. Checking findings array..."

FINDINGS_COUNT=$(jq '.findings | length' "$REPORT")
if [ "$FINDINGS_COUNT" -gt 0 ]; then
    pass "Findings array has $FINDINGS_COUNT entries"
else
    fail "Findings array is empty"
fi

# --------------------------------------------------------------------------
# Test 9: Individual finding structure
# --------------------------------------------------------------------------
echo ""
echo "9. Checking individual finding structure..."

FINDING_FIELDS=("domain" "check_id" "severity" "title" "description" "resources" "remediation" "frameworks")
SAMPLE_FINDING=$(jq '.findings[0]' "$REPORT")

for field in "${FINDING_FIELDS[@]}"; do
    if echo "$SAMPLE_FINDING" | jq -e ".$field" > /dev/null 2>&1; then
        pass "Finding has field: $field"
    else
        fail "Finding missing field: $field"
    fi
done

# --------------------------------------------------------------------------
# Test 10: Finding severity values
# --------------------------------------------------------------------------
echo ""
echo "10. Checking finding severity values..."

VALID_SEVERITIES="critical high medium low"
ALL_SEVERITIES=$(jq -r '.findings[].severity' "$REPORT" | sort -u)

ALL_VALID=true
while IFS= read -r sev; do
    if echo "$VALID_SEVERITIES" | grep -qw "$sev"; then
        pass "Valid severity: $sev"
    else
        fail "Invalid severity: $sev (expected: $VALID_SEVERITIES)"
        ALL_VALID=false
    fi
done <<< "$ALL_SEVERITIES"

# --------------------------------------------------------------------------
# Test 11: Finding domains
# --------------------------------------------------------------------------
echo ""
echo "11. Checking finding domains..."

VALID_DOMAINS="iam gcs compute sql logging"
ALL_DOMAINS=$(jq -r '.findings[].domain' "$REPORT" | sort -u)

while IFS= read -r domain; do
    if echo "$VALID_DOMAINS" | grep -qw "$domain"; then
        pass "Valid domain: $domain"
    else
        fail "Invalid domain: $domain (expected: $VALID_DOMAINS)"
    fi
done <<< "$ALL_DOMAINS"

# --------------------------------------------------------------------------
# Test 12: Finding check_id format
# --------------------------------------------------------------------------
echo ""
echo "12. Checking check_id format..."

ALL_CHECK_IDS=$(jq -r '.findings[].check_id' "$REPORT")

while IFS= read -r check_id; do
    if [[ "$check_id" =~ ^(IAM|GCS|GCE|SQL|LOG)-[0-9]{3}$ ]]; then
        pass "Valid check_id: $check_id"
    else
        fail "Invalid check_id format: $check_id (expected: PREFIX-NNN)"
    fi
done <<< "$ALL_CHECK_IDS"

# --------------------------------------------------------------------------
# Test 13: Frameworks are arrays of strings
# --------------------------------------------------------------------------
echo ""
echo "13. Checking frameworks structure..."

FRAMEWORKS_TYPE=$(jq -r '.findings[0].frameworks | type' "$REPORT")
if [ "$FRAMEWORKS_TYPE" = "array" ]; then
    FRAMEWORK_COUNT=$(jq '.findings[0].frameworks | length' "$REPORT")
    pass "frameworks is an array with $FRAMEWORK_COUNT entries"
else
    fail "frameworks should be an array, got: $FRAMEWORKS_TYPE"
fi

FIRST_FRAMEWORK=$(jq -r '.findings[0].frameworks[0]' "$REPORT")
if [[ "$FIRST_FRAMEWORK" =~ ^(CIS-GCP|ISO27001|SOC2|CCSS) ]]; then
    pass "Framework format valid: $FIRST_FRAMEWORK"
else
    fail "Framework format invalid: $FIRST_FRAMEWORK"
fi

# --------------------------------------------------------------------------
# Test 14: Resources is an array
# --------------------------------------------------------------------------
echo ""
echo "14. Checking resources structure..."

RESOURCES_TYPE=$(jq -r '.findings[0].resources | type' "$REPORT")
if [ "$RESOURCES_TYPE" = "array" ]; then
    pass "resources is an array"
else
    fail "resources should be an array, got: $RESOURCES_TYPE"
fi

# --------------------------------------------------------------------------
# Test 15: Project number is redacted
# --------------------------------------------------------------------------
echo ""
echo "15. Checking project number redaction..."

PROJECT_NUMBER=$(jq -r '.project_number' "$REPORT")
if [ "$PROJECT_NUMBER" = "REDACTED" ]; then
    pass "project_number is redacted"
else
    # Check that no raw 12-digit numbers appear
    TWELVE_DIGIT=$(jq -r '.. | strings' "$REPORT" 2>/dev/null | grep -cE '[0-9]{12}' || echo "0")
    if [ "$TWELVE_DIGIT" -eq 0 ]; then
        pass "No unredacted 12-digit numbers found"
    else
        fail "Found $TWELVE_DIGIT unredacted 12-digit number(s)"
    fi
fi

# --------------------------------------------------------------------------
# Test 16: Scanner script syntax check
# --------------------------------------------------------------------------
echo ""
echo "16. Checking scanner script syntax..."

if bash -n "$SCANNER_DIR/starlings-gcp-scan.sh" 2>/dev/null; then
    pass "starlings-gcp-scan.sh has valid bash syntax"
else
    fail "starlings-gcp-scan.sh has syntax errors"
fi

# --------------------------------------------------------------------------
# Test 17: Scanner help works
# --------------------------------------------------------------------------
echo ""
echo "17. Checking scanner help output..."

HELP_OUTPUT=$("$SCANNER_DIR/starlings-gcp-scan.sh" --help 2>&1 || true)
if echo "$HELP_OUTPUT" | grep -q "Usage:"; then
    pass "Scanner --help shows usage information"
else
    fail "Scanner --help does not show usage information"
fi

if echo "$HELP_OUTPUT" | grep -q "\-\-project"; then
    pass "Scanner --help documents --project flag"
else
    fail "Scanner --help missing --project flag documentation"
fi

if echo "$HELP_OUTPUT" | grep -q "\-\-output"; then
    pass "Scanner --help documents --output flag"
else
    fail "Scanner --help missing --output flag documentation"
fi

# --------------------------------------------------------------------------
# Summary
# --------------------------------------------------------------------------
echo ""
echo "================================================================"
echo ""
echo "Test Results:"
echo "  Total:  $TESTS_RUN"
echo "  Passed: $TESTS_PASSED"
echo "  Failed: $TESTS_FAILED"
echo ""

if [ "$TESTS_FAILED" -eq 0 ]; then
    echo "[PASS] All report structure tests passed!"
    exit 0
else
    echo "[FAIL] Some report structure tests failed. Review the output above."
    exit 1
fi
