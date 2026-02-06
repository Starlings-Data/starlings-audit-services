#!/bin/bash

################################################################################
# Test: DigitalOcean doctl Connection
#
# Validates that doctl is installed, authenticated, and has account access.
################################################################################

set -euo pipefail

PASS=0
FAIL=0

echo "Testing DigitalOcean doctl connection..."
echo ""

# Test 1: doctl CLI installed
echo "1. Checking doctl CLI is installed..."
if command -v doctl &> /dev/null; then
    DOCTL_VERSION=$(doctl version 2>/dev/null | head -n 1)
    echo "  PASS - doctl found: $DOCTL_VERSION"
    ((PASS++))
else
    echo "  FAIL - doctl CLI not found"
    echo "  Install: brew install doctl (macOS) or see https://docs.digitalocean.com/reference/doctl/how-to/install/"
    ((FAIL++))
    echo ""
    echo "Results: $PASS passed, $FAIL failed"
    exit 1
fi

# Test 2: doctl authentication
echo ""
echo "2. Checking doctl authentication..."
if doctl account get &> /dev/null; then
    echo "  PASS - doctl is authenticated"
    ((PASS++))
else
    echo "  FAIL - doctl is not authenticated or token is invalid"
    echo "  Run: doctl auth init"
    ((FAIL++))
    echo ""
    echo "Results: $PASS passed, $FAIL failed"
    exit 1
fi

# Test 3: Account access and info
echo ""
echo "3. Checking account access..."
ACCOUNT_EMAIL=$(doctl account get --format Email --no-header 2>/dev/null || echo "")
ACCOUNT_STATUS=$(doctl account get --format Status --no-header 2>/dev/null || echo "")
ACCOUNT_UUID=$(doctl account get --format UUID --no-header 2>/dev/null || echo "")

if [ -n "$ACCOUNT_EMAIL" ] && [ -n "$ACCOUNT_STATUS" ]; then
    echo "  PASS - Account accessible"
    echo "    Email:  $ACCOUNT_EMAIL"
    echo "    Status: $ACCOUNT_STATUS"
    echo "    UUID:   $ACCOUNT_UUID"
    ((PASS++))
else
    echo "  FAIL - Unable to retrieve account information"
    ((FAIL++))
fi

# Test 4: API read access - list Droplets
echo ""
echo "4. Checking API read access (listing Droplets)..."
if doctl compute droplet list --output json &> /dev/null; then
    DROPLET_COUNT=$(doctl compute droplet list --output json 2>/dev/null | jq 'length' 2>/dev/null || echo "unknown")
    echo "  PASS - Droplet list accessible ($DROPLET_COUNT Droplets)"
    ((PASS++))
else
    echo "  FAIL - Unable to list Droplets (check token permissions)"
    ((FAIL++))
fi

# Test 5: API read access - list databases
echo ""
echo "5. Checking API read access (listing databases)..."
if doctl databases list --output json &> /dev/null; then
    DB_COUNT=$(doctl databases list --output json 2>/dev/null | jq 'length' 2>/dev/null || echo "unknown")
    echo "  PASS - Database list accessible ($DB_COUNT databases)"
    ((PASS++))
else
    echo "  FAIL - Unable to list databases (check token permissions)"
    ((FAIL++))
fi

# Test 6: jq availability
echo ""
echo "6. Checking jq availability..."
if command -v jq &> /dev/null; then
    JQ_VERSION=$(jq --version 2>/dev/null || echo "unknown")
    echo "  PASS - jq found: $JQ_VERSION"
    ((PASS++))
else
    echo "  WARN - jq not found (optional but recommended)"
    echo "  Install: brew install jq (macOS) or apt-get install jq (Linux)"
fi

# Summary
echo ""
echo "========================================"
echo "Connection Test Results"
echo "========================================"
echo "  Passed: $PASS"
echo "  Failed: $FAIL"
echo ""

if [ "$FAIL" -eq 0 ]; then
    echo "All connection tests passed!"
    exit 0
else
    echo "Some connection tests failed. Review the output above."
    exit 1
fi
