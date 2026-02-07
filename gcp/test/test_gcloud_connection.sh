#!/bin/bash

################################################################################
# Test: GCP gcloud Connection
#
# Validates that gcloud CLI is installed, authenticated, and has access to the
# target project with required APIs enabled.
#
# Environment variables:
#   GCP_TEST_PROJECT  - GCP project ID to test against (optional, uses gcloud default)
################################################################################

set -euo pipefail

TEST_PROJECT="${GCP_TEST_PROJECT:-}"
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

skip() {
    local message="$1"
    echo "[SKIP] $message"
}

echo "Testing GCP gcloud connection..."
echo ""

# --------------------------------------------------------------------------
# Test 1: gcloud CLI installed
# --------------------------------------------------------------------------
echo "1. Checking gcloud CLI installation..."
if command -v gcloud &> /dev/null; then
    GCLOUD_VERSION=$(gcloud version 2>/dev/null | head -1 || echo "unknown")
    pass "gcloud CLI found: $GCLOUD_VERSION"
else
    fail "gcloud CLI not found. Install from https://cloud.google.com/sdk/docs/install"
    echo ""
    echo "Cannot continue without gcloud CLI."
    exit 1
fi

# --------------------------------------------------------------------------
# Test 2: gsutil installed (bundled with gcloud SDK)
# --------------------------------------------------------------------------
echo ""
echo "2. Checking gsutil installation..."
if command -v gsutil &> /dev/null; then
    pass "gsutil found"
else
    fail "gsutil not found. It should be included with the gcloud SDK."
fi

# --------------------------------------------------------------------------
# Test 3: jq installed (optional but recommended)
# --------------------------------------------------------------------------
echo ""
echo "3. Checking jq installation..."
if command -v jq &> /dev/null; then
    JQ_VERSION=$(jq --version 2>/dev/null || echo "unknown")
    pass "jq found: $JQ_VERSION"
else
    skip "jq not found (optional, but recommended for formatted output)"
fi

# --------------------------------------------------------------------------
# Test 4: gcloud authentication
# --------------------------------------------------------------------------
echo ""
echo "4. Checking gcloud authentication..."
ACTIVE_ACCOUNT=$(gcloud auth list --filter=status:ACTIVE --format="value(account)" 2>/dev/null | head -1 || echo "")

if [ -n "$ACTIVE_ACCOUNT" ]; then
    pass "Authenticated as: $ACTIVE_ACCOUNT"
else
    fail "gcloud not authenticated. Run: gcloud auth login"
    echo ""
    echo "Cannot continue without authentication."
    exit 1
fi

# --------------------------------------------------------------------------
# Test 5: Project access
# --------------------------------------------------------------------------
echo ""
echo "5. Checking project access..."

if [ -z "$TEST_PROJECT" ]; then
    TEST_PROJECT=$(gcloud config get-value project 2>/dev/null || echo "")
fi

if [ -z "$TEST_PROJECT" ]; then
    fail "No GCP project configured. Set GCP_TEST_PROJECT or run: gcloud config set project PROJECT_ID"
    echo ""
    echo "Cannot continue without a project."
    exit 1
fi

echo "   Project: $TEST_PROJECT"

if gcloud projects describe "$TEST_PROJECT" &> /dev/null; then
    PROJECT_NAME=$(gcloud projects describe "$TEST_PROJECT" --format="value(name)" 2>/dev/null || echo "unknown")
    pass "Project accessible: $PROJECT_NAME ($TEST_PROJECT)"
else
    fail "Cannot access project '$TEST_PROJECT'. Check permissions."
    echo ""
    echo "Cannot continue without project access."
    exit 1
fi

# --------------------------------------------------------------------------
# Test 6: Required APIs enabled
# --------------------------------------------------------------------------
echo ""
echo "6. Checking required APIs..."

REQUIRED_APIS=(
    "compute.googleapis.com"
    "iam.googleapis.com"
    "sqladmin.googleapis.com"
    "logging.googleapis.com"
    "monitoring.googleapis.com"
    "cloudresourcemanager.googleapis.com"
    "storage-api.googleapis.com"
)

OPTIONAL_APIS=(
    "cloudasset.googleapis.com"
    "binaryauthorization.googleapis.com"
    "securitycenter.googleapis.com"
    "accesscontextmanager.googleapis.com"
    "apikeys.googleapis.com"
)

ENABLED_APIS=$(gcloud services list --project="$TEST_PROJECT" --format="value(name)" 2>/dev/null || echo "")

for api in "${REQUIRED_APIS[@]}"; do
    if echo "$ENABLED_APIS" | grep -q "$api"; then
        pass "API enabled: $api"
    else
        fail "API not enabled: $api (run: gcloud services enable $api --project=$TEST_PROJECT)"
    fi
done

echo ""
echo "   Checking optional APIs..."

for api in "${OPTIONAL_APIS[@]}"; do
    if echo "$ENABLED_APIS" | grep -q "$api"; then
        pass "API enabled: $api"
    else
        skip "API not enabled: $api (optional, some checks will be skipped)"
    fi
done

# --------------------------------------------------------------------------
# Test 7: IAM permissions (basic read check)
# --------------------------------------------------------------------------
echo ""
echo "7. Checking IAM read permissions..."

if gcloud projects get-iam-policy "$TEST_PROJECT" --format="value(bindings)" &> /dev/null; then
    pass "Can read project IAM policy"
else
    fail "Cannot read project IAM policy. Ensure the scanner role is assigned."
fi

# --------------------------------------------------------------------------
# Test 8: Compute API access
# --------------------------------------------------------------------------
echo ""
echo "8. Checking Compute Engine access..."

if gcloud compute firewall-rules list --project="$TEST_PROJECT" --format="value(name)" --limit=1 &> /dev/null; then
    pass "Can list compute firewall rules"
else
    fail "Cannot list compute firewall rules. Check compute.firewalls.list permission."
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
    echo "[PASS] All connection tests passed!"
    exit 0
else
    echo "[FAIL] Some connection tests failed. Review the output above."
    exit 1
fi
