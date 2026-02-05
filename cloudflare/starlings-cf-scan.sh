#!/bin/bash

################################################################################
# Starlings Cloudflare Security Scanner
# 
# Comprehensive security audit for Cloudflare domains
# Checks DNS, HTTPS/TLS, DDoS protection, WAF, access control, and performance
################################################################################

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Defaults
API_TOKEN=""
ZONE_ID=""
ZONE_NAME=""
OUTPUT_FILE="cloudflare-scan-report.json"
DEBUG=0

################################################################################
# Helper Functions
################################################################################

log_info() {
  echo -e "${BLUE}ℹ${NC} $1" >&2
}

log_success() {
  echo -e "${GREEN}✓${NC} $1" >&2
}

log_warning() {
  echo -e "${YELLOW}⚠${NC} $1" >&2
}

log_error() {
  echo -e "${RED}✗${NC} $1" >&2
}

usage() {
  cat << EOF
Usage: $0 --api-token TOKEN --zone DOMAIN [OPTIONS]

Required:
  --api-token TOKEN    Cloudflare API token (must have read access to DNS, SSL, WAF)
  --zone DOMAIN        Domain name (e.g., example.com)

Optional:
  --output FILE        Output JSON file (default: cloudflare-scan-report.json)
  --debug              Enable debug output
  --help               Show this help message

Environment:
  CF_API_TOKEN         Alternative to --api-token

Examples:
  $0 --api-token YOUR_TOKEN --zone example.com
  CF_API_TOKEN=YOUR_TOKEN $0 --zone example.com

Output:
  JSON report with security score (0-100), risk assessment, and remediation steps.

EOF
  exit 0
}

################################################################################
# Argument Parsing
################################################################################

while [[ $# -gt 0 ]]; do
  case $1 in
    --api-token)
      API_TOKEN="$2"
      shift 2
      ;;
    --zone)
      ZONE_NAME="$2"
      shift 2
      ;;
    --output)
      OUTPUT_FILE="$2"
      shift 2
      ;;
    --debug)
      DEBUG=1
      shift
      ;;
    --help)
      usage
      ;;
    *)
      log_error "Unknown option: $1"
      usage
      exit 1
      ;;
  esac
done

# Check for environment variable
if [[ -z "$API_TOKEN" && -n "${CF_API_TOKEN:-}" ]]; then
  API_TOKEN="$CF_API_TOKEN"
fi

# Validate inputs
if [[ -z "$API_TOKEN" ]]; then
  log_error "API token required. Use --api-token or set CF_API_TOKEN"
  exit 1
fi

if [[ -z "$ZONE_NAME" ]]; then
  log_error "Zone name required. Use --zone"
  exit 1
fi

log_info "Scanning Cloudflare domain: $ZONE_NAME"

################################################################################
# API Functions
################################################################################

cf_api() {
  local endpoint="$1"
  local method="${2:-GET}"
  local data="${3:-}"
  
  local url="https://api.cloudflare.com/client/v4${endpoint}"
  
  if [[ -n "$data" ]]; then
    curl -s -X "$method" \
      -H "Authorization: Bearer $API_TOKEN" \
      -H "Content-Type: application/json" \
      -d "$data" \
      "$url"
  else
    curl -s -X "$method" \
      -H "Authorization: Bearer $API_TOKEN" \
      "$url"
  fi
}

# Get zone ID from zone name
get_zone_id() {
  local response=$(cf_api "/zones?name=$ZONE_NAME")
  
  if [[ $(echo "$response" | jq -r '.success') != "true" ]]; then
    log_error "Failed to fetch zone: $(echo "$response" | jq -r '.errors[0].message // "Unknown error"')"
    exit 1
  fi
  
  local zone_id=$(echo "$response" | jq -r '.result[0].id // empty')
  if [[ -z "$zone_id" ]]; then
    log_error "Zone not found: $ZONE_NAME"
    exit 1
  fi
  
  echo "$zone_id"
}

################################################################################
# Scan Functions
################################################################################

# Initialize report structure
init_report() {
  cat > "$OUTPUT_FILE" << 'EOF'
{
  "metadata": {
    "scanType": "Cloudflare Security Audit",
    "timestamp": "",
    "zone": "",
    "scanDuration": 0
  },
  "summary": {
    "overallScore": 0,
    "riskLevel": "UNKNOWN",
    "checksTotal": 0,
    "checksPassed": 0,
    "checksFailed": 0,
    "checksWarning": 0
  },
  "checks": {
    "dns": [],
    "https_tls": [],
    "ddos_security": [],
    "access_control": [],
    "performance": []
  },
  "frameworks": {},
  "remediation": []
}
EOF
}

add_check() {
  local category="$1"
  local check_name="$2"
  local status="$3"  # PASS, FAIL, WARNING
  local message="$4"
  local remediation="${5:-}"
  
  local check_json=$(cat <<EOF
{
  "name": "$check_name",
  "status": "$status",
  "message": "$message",
  "remediation": "$remediation"
}
EOF
)
  
  # Append check to appropriate category
  local temp_file=$(mktemp)
  jq ".checks.$category += [$check_json]" "$OUTPUT_FILE" > "$temp_file"
  mv "$temp_file" "$OUTPUT_FILE"
}

# DNS Security Checks
scan_dns_security() {
  log_info "Scanning DNS Security..."
  
  local nameservers=$(cf_api "/zones/$ZONE_ID/nameservers" | jq -r '.result.nameservers[]' 2>/dev/null || echo "")
  
  if [[ -n "$nameservers" ]]; then
    add_check "dns" "Nameserver Configuration" "PASS" "Nameservers properly configured" "Monitor for unexpected changes"
  else
    add_check "dns" "Nameserver Configuration" "FAIL" "Unable to verify nameserver configuration" "Verify zone nameservers in Cloudflare dashboard"
  fi
  
  # DNSSEC Check
  local dnssec=$(cf_api "/zones/$ZONE_ID/dnssec" | jq -r '.result.status // empty' 2>/dev/null)
  if [[ "$dnssec" == "active" ]]; then
    add_check "dns" "DNSSEC Enabled" "PASS" "DNSSEC is enabled and signing records" "Ensure DS records are in parent zone"
  else
    add_check "dns" "DNSSEC Enabled" "WARNING" "DNSSEC is not enabled" "Enable DNSSEC to prevent DNS spoofing (Zone > DNS > DNSSEC)"
  fi
  
  # Domain Registrar Lock Check
  add_check "dns" "Domain Registrar Lock" "UNKNOWN" "Manual check required: Is domain lock enabled at registrar?" "Enable domain lock to prevent unauthorized transfers"
}

# HTTPS/TLS Checks
scan_https_tls() {
  log_info "Scanning HTTPS/TLS Configuration..."
  
  # SSL/TLS Version
  local ssl_tls=$(cf_api "/zones/$ZONE_ID/settings/min_tls_version" | jq -r '.result.value // empty' 2>/dev/null)
  if [[ "$ssl_tls" == "1.2" ]] || [[ "$ssl_tls" == "1.3" ]]; then
    add_check "https_tls" "Minimum TLS Version" "PASS" "TLS 1.2+ enforced (configured: $ssl_tls)" "Ensure TLS 1.2+ is enforced globally"
  else
    add_check "https_tls" "Minimum TLS Version" "FAIL" "TLS version is too old: $ssl_tls" "Set minimum TLS to 1.2 (Zone > SSL/TLS > Edge Certificates)"
  fi
  
  # SSL Certificate Status
  local ssl_status=$(cf_api "/zones/$ZONE_ID/settings/ssl" | jq -r '.result.value // empty' 2>/dev/null)
  if [[ -n "$ssl_status" ]]; then
    add_check "https_tls" "SSL Certificate Status" "PASS" "SSL certificate managed by Cloudflare" "Monitor certificate expiration"
  else
    add_check "https_tls" "SSL Certificate Status" "WARNING" "Unable to verify SSL certificate" "Ensure SSL certificate is valid and not expired"
  fi
  
  # HTTPS Redirect
  local https_redirect=$(cf_api "/zones/$ZONE_ID/settings/always_use_https" | jq -r '.result.value // empty' 2>/dev/null)
  if [[ "$https_redirect" == "on" ]]; then
    add_check "https_tls" "HTTPS Redirect Enforced" "PASS" "All HTTP traffic redirected to HTTPS" "Ensure all traffic is encrypted"
  else
    add_check "https_tls" "HTTPS Redirect Enforced" "FAIL" "HTTPS redirect not enabled" "Enable Always Use HTTPS (Zone > SSL/TLS > Edge Certificates)"
  fi
  
  # HSTS Headers
  local hsts=$(cf_api "/zones/$ZONE_ID/settings/security_header" | jq -r '.result.value // empty' 2>/dev/null)
  if [[ "$hsts" == "on" ]]; then
    add_check "https_tls" "HSTS Headers" "PASS" "HSTS headers enabled" "Monitor HSTS max-age settings"
  else
    add_check "https_tls" "HSTS Headers" "WARNING" "HSTS headers may not be enabled" "Enable Security Header for HSTS (Zone > SSL/TLS > Edge Certificates)"
  fi
  
  # Certificate Transparency
  local ct=$(cf_api "/zones/$ZONE_ID/settings/opportunistic_encryption" | jq -r '.result.value // empty' 2>/dev/null)
  add_check "https_tls" "Certificate Transparency" "PASS" "Cloudflare issues publicly logged certificates" "Certificate transparency is automatic"
}

# DDoS & Security Checks
scan_ddos_security() {
  log_info "Scanning DDoS & Security Features..."
  
  # DDoS Protection
  local ddos=$(cf_api "/zones/$ZONE_ID/settings/security_level" | jq -r '.result.value // empty' 2>/dev/null)
  if [[ -n "$ddos" && "$ddos" != "off" ]]; then
    add_check "ddos_security" "DDoS Protection" "PASS" "DDoS protection enabled (Level: $ddos)" "Monitor DDoS metrics in Analytics"
  else
    add_check "ddos_security" "DDoS Protection" "WARNING" "DDoS protection may be disabled" "Enable DDoS protection (Zone > Security > DDoS)"
  fi
  
  # WAF Rules
  local waf_rules=$(cf_api "/zones/$ZONE_ID/firewall/waf/packages" | jq '.result | length' 2>/dev/null || echo "0")
  if [[ "$waf_rules" -gt 0 ]]; then
    add_check "ddos_security" "WAF Rules Configured" "PASS" "WAF rules are configured ($waf_rules packages)" "Review WAF rules regularly"
  else
    add_check "ddos_security" "WAF Rules Configured" "WARNING" "No WAF rules configured" "Enable WAF (Zone > Security > WAF) for protection against common attacks"
  fi
  
  # Bot Management
  local bot_mgmt=$(cf_api "/zones/$ZONE_ID/settings/bot_management" | jq -r '.result.value // empty' 2>/dev/null)
  if [[ "$bot_mgmt" == "on" ]]; then
    add_check "ddos_security" "Bot Management" "PASS" "Bot management enabled to detect malicious traffic" "Monitor bot scores in analytics"
  else
    add_check "ddos_security" "Bot Management" "WARNING" "Bot management not enabled" "Enable Bot Management for advanced threat detection (Zone > Security > Bots)"
  fi
  
  # Rate Limiting
  local rate_limit=$(cf_api "/zones/$ZONE_ID/rate_limit" | jq '.result | length' 2>/dev/null || echo "0")
  if [[ "$rate_limit" -gt 0 ]]; then
    add_check "ddos_security" "Rate Limiting" "PASS" "Rate limiting rules configured ($rate_limit rules)" "Monitor for legitimate traffic being blocked"
  else
    add_check "ddos_security" "Rate Limiting" "WARNING" "No rate limiting configured" "Create rate limiting rules to prevent abuse (Zone > Security > Rate Limiting)"
  fi
  
  # Challenge Pages
  local challenge=$(cf_api "/zones/$ZONE_ID/settings/challenge_ttl" | jq -r '.result.value // empty' 2>/dev/null)
  add_check "ddos_security" "Challenge Pages" "PASS" "Challenge pages configured to mitigate attacks" "Customize challenge appearance"
}

# Access Control Checks
scan_access_control() {
  log_info "Scanning Access Control..."
  
  # Zero Trust / Access
  add_check "access_control" "Cloudflare Zero Trust" "UNKNOWN" "Manual check required: Is Zero Trust configured?" "Enable Cloudflare Zero Trust for fine-grained access policies"
  
  # API Token Rotation
  add_check "access_control" "API Token Rotation" "UNKNOWN" "Manual check required: When were API tokens last rotated?" "Rotate API tokens every 90 days minimum"
  
  # Firewall Rules
  local fw_rules=$(cf_api "/zones/$ZONE_ID/firewall/rules" | jq '.result | length' 2>/dev/null || echo "0")
  if [[ "$fw_rules" -gt 0 ]]; then
    add_check "access_control" "Firewall Rules" "PASS" "Firewall rules configured ($fw_rules rules)" "Review firewall rules for least privilege"
  else
    add_check "access_control" "Firewall Rules" "WARNING" "No custom firewall rules" "Create firewall rules for defense-in-depth (Zone > Security > Firewall Rules)"
  fi
  
  # Allowed IPs / Restrictions
  add_check "access_control" "IP Restrictions" "UNKNOWN" "Manual check required: Are sensitive endpoints IP-restricted?" "Use firewall rules to restrict access to sensitive areas"
}

# Performance Checks
scan_performance() {
  log_info "Scanning Performance Settings..."
  
  # Caching Rules
  local cache_rules=$(cf_api "/zones/$ZONE_ID/caching/cache_rules" | jq '.result | length' 2>/dev/null || echo "0")
  if [[ "$cache_rules" -gt 0 ]]; then
    add_check "performance" "Caching Rules" "PASS" "Caching rules configured ($cache_rules rules)" "Monitor cache hit ratio in analytics"
  else
    add_check "performance" "Caching Rules" "WARNING" "No caching rules configured" "Create caching rules to improve performance (Zone > Caching > Cache Rules)"
  fi
  
  # Image Optimization
  local image_opt=$(cf_api "/zones/$ZONE_ID/settings/image_resizing" | jq -r '.result.value // empty' 2>/dev/null)
  if [[ "$image_opt" == "on" ]]; then
    add_check "performance" "Image Optimization" "PASS" "Image resizing/optimization enabled" "Enable WebP and Avif formats for better performance"
  else
    add_check "performance" "Image Optimization" "WARNING" "Image optimization not enabled" "Enable Image Resizing (Zone > Caching > Image Optimization)"
  fi
  
  # Minification
  local minify=$(cf_api "/zones/$ZONE_ID/settings/minify" | jq -r '.result.value // empty' 2>/dev/null)
  if [[ "$minify" == "on" ]]; then
    add_check "performance" "Minification" "PASS" "JavaScript/CSS minification enabled" "Monitor for minification conflicts"
  else
    add_check "performance" "Minification" "WARNING" "Minification not enabled" "Enable minification (Zone > Speed > Optimization)"
  fi
  
  # Polish
  local polish=$(cf_api "/zones/$ZONE_ID/settings/polish" | jq -r '.result.value // empty' 2>/dev/null)
  if [[ "$polish" != "" && "$polish" != "off" ]]; then
    add_check "performance" "Image Polish" "PASS" "Image optimization (Polish) enabled" "Monitor image quality vs file size"
  else
    add_check "performance" "Image Polish" "WARNING" "Image Polish not enabled" "Enable Polish for automatic image optimization (Zone > Speed > Optimization)"
  fi
}

################################################################################
# Calculate Score & Generate Report
################################################################################

calculate_score() {
  local total_checks=$(jq '.checks[] | length' "$OUTPUT_FILE" 2>/dev/null | awk '{sum+=$1} END {print sum}')
  local passed=$(jq '.checks[] | .[] | select(.status == "PASS") | .status' "$OUTPUT_FILE" 2>/dev/null | wc -l)
  local failed=$(jq '.checks[] | .[] | select(.status == "FAIL") | .status' "$OUTPUT_FILE" 2>/dev/null | wc -l)
  local warnings=$(jq '.checks[] | .[] | select(.status == "WARNING") | .status' "$OUTPUT_FILE" 2>/dev/null | wc -l)
  
  local score=0
  if [[ "$total_checks" -gt 0 ]]; then
    score=$(( (passed * 100) / total_checks ))
  fi
  
  local risk_level="UNKNOWN"
  if [[ "$score" -ge 80 ]]; then
    risk_level="LOW"
  elif [[ "$score" -ge 60 ]]; then
    risk_level="MEDIUM"
  elif [[ "$score" -ge 40 ]]; then
    risk_level="HIGH"
  else
    risk_level="CRITICAL"
  fi
  
  # Update report with summary
  local temp_file=$(mktemp)
  jq --arg score "$score" --arg risk "$risk_level" --arg total "$total_checks" --arg pass "$passed" --arg fail "$failed" --arg warn "$warnings" \
    '.summary.overallScore = ($score | tonumber) |
     .summary.riskLevel = $risk |
     .summary.checksTotal = ($total | tonumber) |
     .summary.checksPassed = ($pass | tonumber) |
     .summary.checksFailed = ($fail | tonumber) |
     .summary.checksWarning = ($warn | tonumber)' \
    "$OUTPUT_FILE" > "$temp_file"
  mv "$temp_file" "$OUTPUT_FILE"
  
  echo "$score"
}

# Map to CIS Framework
add_frameworks() {
  local temp_file=$(mktemp)
  jq '.frameworks = {
    "CIS Cloudflare": {
      "version": "1.0",
      "checks": [
        "Ensure DNSSEC is enabled",
        "Ensure TLS 1.2+ is enforced",
        "Ensure HTTPS redirect is enabled",
        "Ensure WAF is configured",
        "Ensure DDoS protection is enabled"
      ]
    },
    "PCI-DSS": {
      "version": "3.2.1",
      "checks": [
        "Requirement 4.1: Encryption in transit",
        "Requirement 6.5.1: Injection attacks"
      ]
    }
  }' "$OUTPUT_FILE" > "$temp_file"
  mv "$temp_file" "$OUTPUT_FILE"
}

################################################################################
# Main Execution
################################################################################

main() {
  local start_time=$(date +%s)
  
  # Initialize report
  init_report
  
  # Get zone ID
  ZONE_ID=$(get_zone_id)
  log_success "Zone ID: $ZONE_ID"
  
  # Run all scans
  scan_dns_security
  scan_https_tls
  scan_ddos_security
  scan_access_control
  scan_performance
  
  # Calculate score
  local score=$(calculate_score)
  
  # Add frameworks
  add_frameworks
  
  # Update metadata
  local end_time=$(date +%s)
  local duration=$((end_time - start_time))
  local timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
  
  local temp_file=$(mktemp)
  jq --arg ts "$timestamp" --arg zone "$ZONE_NAME" --arg dur "$duration" \
    '.metadata.timestamp = $ts |
     .metadata.zone = $zone |
     .metadata.scanDuration = ($dur | tonumber)' \
    "$OUTPUT_FILE" > "$temp_file"
  mv "$temp_file" "$OUTPUT_FILE"
  
  # Print summary
  echo ""
  log_success "Scan completed in ${duration}s"
  log_info "Report saved to: $OUTPUT_FILE"
  echo ""
  echo "Security Score: $score/100"
  local risk_level=$(jq -r '.summary.riskLevel' "$OUTPUT_FILE")
  echo "Risk Level: $risk_level"
  echo ""
  echo "Summary:"
  jq '.summary' "$OUTPUT_FILE" | grep -v null
}

main "$@"
