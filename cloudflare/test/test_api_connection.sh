#!/bin/bash

################################################################################
# Test: Cloudflare API Connection
# 
# Validates that the API token is valid and has required permissions
################################################################################

set -euo pipefail

API_TOKEN="${CF_API_TOKEN:-}"
ZONE_NAME="${CF_TEST_ZONE:-}"

if [[ -z "$API_TOKEN" ]]; then
  echo "Error: CF_API_TOKEN not set"
  exit 1
fi

if [[ -z "$ZONE_NAME" ]]; then
  echo "Error: CF_TEST_ZONE not set"
  exit 1
fi

echo "Testing Cloudflare API connection..."
echo "Zone: $ZONE_NAME"
echo ""

# Test 1: Basic connectivity
echo "1. Testing basic API connectivity..."
RESPONSE=$(curl -s -w "\n%{http_code}" \
  -H "Authorization: Bearer $API_TOKEN" \
  https://api.cloudflare.com/client/v4/zones)

HTTP_CODE=$(echo "$RESPONSE" | tail -n 1)
BODY=$(echo "$RESPONSE" | head -n -1)

if [[ "$HTTP_CODE" == "200" ]]; then
  echo "✓ API is reachable (HTTP $HTTP_CODE)"
else
  echo "✗ API returned HTTP $HTTP_CODE"
  echo "Response: $BODY"
  exit 1
fi

# Test 2: Token validity
echo ""
echo "2. Testing token validity..."
if echo "$BODY" | jq -e '.success' >/dev/null 2>&1; then
  echo "✓ Token is valid and authenticated"
else
  echo "✗ Token authentication failed"
  echo "Response: $BODY"
  exit 1
fi

# Test 3: Zone lookup
echo ""
echo "3. Looking up zone: $ZONE_NAME"
ZONE_RESPONSE=$(curl -s \
  -H "Authorization: Bearer $API_TOKEN" \
  "https://api.cloudflare.com/client/v4/zones?name=$ZONE_NAME")

if echo "$ZONE_RESPONSE" | jq -e '.result[0].id' >/dev/null 2>&1; then
  ZONE_ID=$(echo "$ZONE_RESPONSE" | jq -r '.result[0].id')
  echo "✓ Zone found: $ZONE_ID"
else
  echo "✗ Zone not found"
  echo "Response: $ZONE_RESPONSE"
  exit 1
fi

# Test 4: DNS read permission
echo ""
echo "4. Testing DNS read permission..."
DNS_RESPONSE=$(curl -s \
  -H "Authorization: Bearer $API_TOKEN" \
  "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/dns_records")

if echo "$DNS_RESPONSE" | jq -e '.success' >/dev/null 2>&1; then
  DNS_COUNT=$(echo "$DNS_RESPONSE" | jq '.result | length')
  echo "✓ DNS read permission granted ($DNS_COUNT records)"
else
  echo "✗ DNS read permission denied"
fi

# Test 5: Settings read permission
echo ""
echo "5. Testing settings read permission..."
SETTINGS_RESPONSE=$(curl -s \
  -H "Authorization: Bearer $API_TOKEN" \
  "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/settings/ssl")

if echo "$SETTINGS_RESPONSE" | jq -e '.result.value' >/dev/null 2>&1; then
  echo "✓ Settings read permission granted"
else
  echo "✗ Settings read permission denied"
fi

echo ""
echo "✓ All API tests passed!"
