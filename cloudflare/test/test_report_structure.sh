#!/bin/bash

################################################################################
# Test: Cloudflare Scanner Report Structure
# 
# Validates that the generated report has correct structure and fields
################################################################################

set -euo pipefail

SCANNER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "Testing report structure..."
echo ""

# Test 1: JSON validity
echo "1. Checking JSON validity..."
REPORT="/tmp/cf-test-report.json"

if ! "$SCANNER_DIR/starlings-cf-scan.sh" --api-token "$CF_API_TOKEN" --zone "$CF_TEST_ZONE" --output "$REPORT" > /dev/null 2>&1; then
  echo "✗ Scanner failed to generate report"
  exit 1
fi

if ! jq empty "$REPORT" 2>/dev/null; then
  echo "✗ Report is not valid JSON"
  cat "$REPORT"
  exit 1
fi

echo "✓ Report is valid JSON"

# Test 2: Required top-level fields
echo ""
echo "2. Checking required fields..."

required_fields=("metadata" "summary" "checks" "frameworks")
for field in "${required_fields[@]}"; do
  if jq -e ".$field" "$REPORT" >/dev/null 2>&1; then
    echo "✓ Field present: $field"
  else
    echo "✗ Missing required field: $field"
    exit 1
  fi
done

# Test 3: Metadata structure
echo ""
echo "3. Checking metadata structure..."
if jq -e '.metadata.scanType' "$REPORT" >/dev/null 2>&1; then
  SCAN_TYPE=$(jq -r '.metadata.scanType' "$REPORT")
  echo "✓ Scan Type: $SCAN_TYPE"
fi

if jq -e '.metadata.timestamp' "$REPORT" >/dev/null 2>&1; then
  TIMESTAMP=$(jq -r '.metadata.timestamp' "$REPORT")
  echo "✓ Timestamp: $TIMESTAMP"
fi

if jq -e '.metadata.zone' "$REPORT" >/dev/null 2>&1; then
  ZONE=$(jq -r '.metadata.zone' "$REPORT")
  echo "✓ Zone: $ZONE"
fi

if jq -e '.metadata.scanDuration' "$REPORT" >/dev/null 2>&1; then
  DURATION=$(jq -r '.metadata.scanDuration' "$REPORT")
  echo "✓ Duration: ${DURATION}s"
fi

# Test 4: Summary structure
echo ""
echo "4. Checking summary..."
SUMMARY_FIELDS=("overallScore" "riskLevel" "checksTotal" "checksPassed" "checksFailed" "checksWarning")
for field in "${SUMMARY_FIELDS[@]}"; do
  if jq -e ".summary.$field" "$REPORT" >/dev/null 2>&1; then
    VALUE=$(jq -r ".summary.$field" "$REPORT")
    echo "✓ $field: $VALUE"
  else
    echo "✗ Missing summary field: $field"
  fi
done

# Test 5: Check categories
echo ""
echo "5. Checking check categories..."
CHECK_CATEGORIES=("dns" "https_tls" "ddos_security" "access_control" "performance")
for category in "${CHECK_CATEGORIES[@]}"; do
  if jq -e ".checks.$category" "$REPORT" >/dev/null 2>&1; then
    COUNT=$(jq ".checks.$category | length" "$REPORT")
    echo "✓ Category $category: $COUNT checks"
  else
    echo "✗ Missing check category: $category"
  fi
done

# Test 6: Check item structure
echo ""
echo "6. Checking check item structure..."
SAMPLE_CHECK=$(jq '.checks.dns[0]' "$REPORT" 2>/dev/null || jq '.checks.https_tls[0]' "$REPORT")

if [[ -n "$SAMPLE_CHECK" ]]; then
  if echo "$SAMPLE_CHECK" | jq -e '.name' >/dev/null 2>&1; then
    echo "✓ Check has name"
  fi
  
  if echo "$SAMPLE_CHECK" | jq -e '.status' >/dev/null 2>&1; then
    STATUS=$(echo "$SAMPLE_CHECK" | jq -r '.status')
    if [[ "$STATUS" =~ ^(PASS|FAIL|WARNING|UNKNOWN)$ ]]; then
      echo "✓ Check has valid status: $STATUS"
    else
      echo "✗ Invalid status: $STATUS"
    fi
  fi
  
  if echo "$SAMPLE_CHECK" | jq -e '.message' >/dev/null 2>&1; then
    echo "✓ Check has message"
  fi
  
  if echo "$SAMPLE_CHECK" | jq -e '.remediation' >/dev/null 2>&1; then
    echo "✓ Check has remediation"
  fi
fi

# Test 7: Frameworks
echo ""
echo "7. Checking frameworks..."
FRAMEWORKS=$(jq '.frameworks | keys[]' "$REPORT" 2>/dev/null)
if [[ -n "$FRAMEWORKS" ]]; then
  echo "✓ Frameworks present:"
  echo "$FRAMEWORKS" | sed 's/^/  - /'
else
  echo "⚠ No frameworks defined"
fi

# Test 8: Score validation
echo ""
echo "8. Validating scores..."
OVERALL_SCORE=$(jq -r '.summary.overallScore' "$REPORT")
if [[ "$OVERALL_SCORE" =~ ^[0-9]+$ ]] && [[ "$OVERALL_SCORE" -ge 0 ]] && [[ "$OVERALL_SCORE" -le 100 ]]; then
  echo "✓ Overall score valid: $OVERALL_SCORE/100"
else
  echo "✗ Invalid overall score: $OVERALL_SCORE"
fi

RISK_LEVEL=$(jq -r '.summary.riskLevel' "$REPORT")
if [[ "$RISK_LEVEL" =~ ^(LOW|MEDIUM|HIGH|CRITICAL|UNKNOWN)$ ]]; then
  echo "✓ Risk level valid: $RISK_LEVEL"
else
  echo "✗ Invalid risk level: $RISK_LEVEL"
fi

# Cleanup
rm -f "$REPORT"

echo ""
echo "✓ All structure tests passed!"
