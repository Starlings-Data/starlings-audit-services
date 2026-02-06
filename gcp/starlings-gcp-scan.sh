#!/bin/bash
#
# Starlings GCP Security Scanner v1.0.0
# ======================================
#
# This script runs locally in YOUR environment.
# Your GCP credentials NEVER leave your machine.
#
# What it does:
#   - Runs read-only checks against your GCP project
#   - Identifies security misconfigurations
#   - Maps findings to compliance frameworks (CIS GCP Foundations, ISO 27001, SOC 2, CCSS)
#   - Outputs a JSON report you can review before sharing
#
# Requirements:
#   - gcloud CLI installed and authenticated
#   - Read-only permissions (see gcp-scan-policy.yaml for minimal IAM role)
#
# Usage:
#   ./starlings-gcp-scan.sh [--project PROJECT_ID] [--output FILE] [--verbose]
#
# Source: https://github.com/Starlings-Data/gcp-scanner
# License: MIT
#

set -e

# ============================================================================
# Configuration
# ============================================================================

SCANNER_VERSION="1.0.0"
DEFAULT_OUTPUT="gcp-security-report.json"
PROJECT_ID=""
OUTPUT_FILE=""
VERBOSE=false

# Colors for terminal output
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# ============================================================================
# Helper Functions
# ============================================================================

print_banner() {
    echo ""
    echo -e "${BLUE}╔═══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║${NC}     Starlings GCP Security Scanner v${SCANNER_VERSION}            ${BLUE}║${NC}"
    echo -e "${BLUE}╚═══════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo "  Your credentials never leave your machine."
    echo "  Review the output before sharing."
    echo ""
}

print_status() {
    echo -e "${BLUE}[*]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

print_finding() {
    local severity=$1
    local message=$2
    case $severity in
        critical) echo -e "  ${RED}[CRITICAL]${NC} $message" ;;
        high)     echo -e "  ${RED}[HIGH]${NC} $message" ;;
        medium)   echo -e "  ${YELLOW}[MEDIUM]${NC} $message" ;;
        low)      echo -e "  ${GREEN}[LOW]${NC} $message" ;;
        pass)     echo -e "  ${GREEN}[PASS]${NC} $message" ;;
    esac
}

usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -p, --project PROJECT  GCP project ID to scan (default: from gcloud config)"
    echo "  -o, --output FILE      Output file (default: ${DEFAULT_OUTPUT})"
    echo "  -v, --verbose          Verbose output"
    echo "  -h, --help             Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                                 # Scan default project"
    echo "  $0 --project my-project-123        # Scan specific project"
    echo "  $0 --output my-report.json         # Custom output file"
    echo "  $0 --project my-proj --verbose     # Verbose scan"
    echo ""
}

check_prerequisites() {
    print_status "Checking prerequisites..."

    # Check gcloud CLI
    if ! command -v gcloud &> /dev/null; then
        print_error "gcloud CLI not found. Please install it first."
        echo "  See: https://cloud.google.com/sdk/docs/install"
        exit 1
    fi
    print_success "gcloud CLI found"

    # Check gcloud authentication
    if ! gcloud auth list --filter=status:ACTIVE --format="value(account)" 2>/dev/null | head -1 | grep -q '.'; then
        print_error "gcloud not authenticated. Please authenticate first."
        echo "  Run: gcloud auth login"
        exit 1
    fi
    print_success "gcloud authenticated"

    # Get project ID
    if [ -z "$PROJECT_ID" ]; then
        PROJECT_ID=$(gcloud config get-value project 2>/dev/null || echo "")
    fi

    if [ -z "$PROJECT_ID" ]; then
        print_error "No GCP project configured. Set one with --project or 'gcloud config set project PROJECT_ID'"
        exit 1
    fi
    print_status "Project ID: $PROJECT_ID"

    # Verify project access
    if ! gcloud projects describe "$PROJECT_ID" &> /dev/null; then
        print_error "Cannot access project '$PROJECT_ID'. Check permissions."
        exit 1
    fi
    print_success "Project access verified"

    # Get project number for reference
    PROJECT_NUMBER=$(gcloud projects describe "$PROJECT_ID" --format="value(projectNumber)" 2>/dev/null || echo "unknown")

    # Check jq
    if ! command -v jq &> /dev/null; then
        print_warning "jq not found. Output will be less formatted."
        JQ_AVAILABLE=false
    else
        JQ_AVAILABLE=true
        print_success "jq found"
    fi
}

# ============================================================================
# Findings Storage
# ============================================================================

declare -a FINDINGS=()
declare -i CRITICAL_COUNT=0
declare -i HIGH_COUNT=0
declare -i MEDIUM_COUNT=0
declare -i LOW_COUNT=0
declare -i PASS_COUNT=0

add_finding() {
    local domain=$1
    local check_id=$2
    local severity=$3
    local title=$4
    local description=$5
    local resources=$6
    local remediation=$7
    local frameworks=$8

    case $severity in
        critical) ((CRITICAL_COUNT++)) ;;
        high)     ((HIGH_COUNT++)) ;;
        medium)   ((MEDIUM_COUNT++)) ;;
        low)      ((LOW_COUNT++)) ;;
    esac

    # Escape quotes in strings for JSON
    description=$(echo "$description" | sed 's/"/\\"/g')
    remediation=$(echo "$remediation" | sed 's/"/\\"/g')

    # Add frameworks if provided, otherwise use empty array
    if [ -z "$frameworks" ]; then
        frameworks="[]"
    fi

    FINDINGS+=("{\"domain\":\"$domain\",\"check_id\":\"$check_id\",\"severity\":\"$severity\",\"title\":\"$title\",\"description\":\"$description\",\"resources\":$resources,\"remediation\":\"$remediation\",\"frameworks\":$frameworks}")
}

add_pass() {
    ((PASS_COUNT++))
}

# ============================================================================
# IAM Checks (IAM-001 through IAM-008)
# ============================================================================

check_iam() {
    print_status "Checking IAM & Access Management..."

    # IAM-001: Default service accounts with editor role
    print_status "  Checking default service account usage..."
    local default_sa="${PROJECT_NUMBER}-compute@developer.gserviceaccount.com"
    local default_sa_bindings=$(gcloud projects get-iam-policy "$PROJECT_ID" \
        --format=json 2>/dev/null | \
        grep -c "$default_sa" 2>/dev/null || echo "0")

    if [ "$default_sa_bindings" -gt 0 ]; then
        add_finding "iam" "IAM-001" "high" \
            "Default compute service account has IAM bindings" \
            "The default Compute Engine service account ($default_sa) has explicit IAM role bindings. Default service accounts should not be used." \
            "[\"$default_sa\"]" \
            "Create dedicated service accounts with least-privilege roles instead of using the default compute service account" \
            "[\"CIS-GCP 1.1\",\"ISO27001 A.9.2.3\",\"SOC2 CC6.3\",\"CCSS 4.3\"]"
        print_finding "high" "Default compute service account has IAM bindings"
    else
        add_pass
        print_finding "pass" "Default compute service account has no extra bindings"
    fi

    # IAM-002: User-managed service account keys
    print_status "  Checking user-managed service account keys..."
    local service_accounts=$(gcloud iam service-accounts list \
        --project="$PROJECT_ID" --format="value(email)" 2>/dev/null || echo "")
    local sas_with_keys=()

    for sa in $service_accounts; do
        local keys=$(gcloud iam service-accounts keys list \
            --iam-account="$sa" \
            --managed-by=user \
            --format="value(name)" 2>/dev/null || echo "")
        if [ -n "$keys" ]; then
            sas_with_keys+=("$sa")
        fi
    done

    if [ ${#sas_with_keys[@]} -gt 0 ]; then
        local sa_list=$(printf '"%s",' "${sas_with_keys[@]}" | sed 's/,$//')
        add_finding "iam" "IAM-002" "high" \
            "Service accounts with user-managed keys" \
            "${#sas_with_keys[@]} service account(s) have user-managed keys. These keys are long-lived credentials and a security risk." \
            "[$sa_list]" \
            "Use Workload Identity Federation or GCP-managed keys instead of user-managed service account keys. Delete unused keys." \
            "[\"CIS-GCP 1.4\",\"ISO27001 A.9.2.5\",\"SOC2 CC6.1\",\"CCSS 4.1\"]"
        print_finding "high" "${#sas_with_keys[@]} service account(s) with user-managed keys"
    else
        add_pass
        print_finding "pass" "No service accounts with user-managed keys"
    fi

    # IAM-003: Over-privileged service accounts (roles/owner or roles/editor)
    print_status "  Checking for over-privileged service accounts..."
    local iam_policy=$(gcloud projects get-iam-policy "$PROJECT_ID" --format=json 2>/dev/null || echo "{}")
    local overprivileged_sas=()

    for sa in $service_accounts; do
        local has_owner=$(echo "$iam_policy" | grep -B5 "$sa" | grep -c "roles/owner" 2>/dev/null || echo "0")
        local has_editor=$(echo "$iam_policy" | grep -B5 "$sa" | grep -c "roles/editor" 2>/dev/null || echo "0")
        if [ "$has_owner" -gt 0 ] || [ "$has_editor" -gt 0 ]; then
            overprivileged_sas+=("$sa")
        fi
    done

    if [ ${#overprivileged_sas[@]} -gt 0 ]; then
        local sa_list=$(printf '"%s",' "${overprivileged_sas[@]}" | sed 's/,$//')
        add_finding "iam" "IAM-003" "critical" \
            "Service accounts with Owner or Editor roles" \
            "${#overprivileged_sas[@]} service account(s) have Owner or Editor roles assigned. These are overly permissive." \
            "[$sa_list]" \
            "Replace Owner/Editor roles with granular predefined or custom roles following least privilege" \
            "[\"CIS-GCP 1.5\",\"ISO27001 A.9.2.3\",\"SOC2 CC6.3\",\"CCSS 4.3\"]"
        print_finding "critical" "${#overprivileged_sas[@]} over-privileged service account(s)"
    else
        add_pass
        print_finding "pass" "No service accounts with Owner/Editor roles"
    fi

    # IAM-004: Service account key rotation (keys older than 90 days)
    print_status "  Checking service account key age..."
    local old_keys_sas=()
    local ninety_days_ago
    if [[ "$OSTYPE" == "darwin"* ]]; then
        ninety_days_ago=$(date -v-90d +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo "")
    else
        ninety_days_ago=$(date -d "90 days ago" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo "")
    fi

    if [ -n "$ninety_days_ago" ]; then
        for sa in $service_accounts; do
            local old_keys=$(gcloud iam service-accounts keys list \
                --iam-account="$sa" \
                --managed-by=user \
                --format="value(validAfterTime)" \
                --filter="validAfterTime<$ninety_days_ago" 2>/dev/null || echo "")
            if [ -n "$old_keys" ]; then
                old_keys_sas+=("$sa")
            fi
        done

        if [ ${#old_keys_sas[@]} -gt 0 ]; then
            local sa_list=$(printf '"%s",' "${old_keys_sas[@]}" | sed 's/,$//')
            add_finding "iam" "IAM-004" "medium" \
                "Service account keys older than 90 days" \
                "${#old_keys_sas[@]} service account(s) have keys older than 90 days that should be rotated" \
                "[$sa_list]" \
                "Rotate service account keys at least every 90 days. Consider using Workload Identity Federation to eliminate keys entirely." \
                "[\"CIS-GCP 1.7\",\"ISO27001 A.9.2.5\",\"SOC2 CC6.1\"]"
            print_finding "medium" "${#old_keys_sas[@]} service account(s) with old keys"
        else
            add_pass
            print_finding "pass" "No service account keys older than 90 days"
        fi
    fi

    # IAM-005: Members with primitive roles (owner/editor on users)
    print_status "  Checking for users with primitive roles..."
    local primitive_users=()
    local owner_members=$(echo "$iam_policy" | \
        jq -r '.bindings[] | select(.role=="roles/owner" or .role=="roles/editor") | .members[]' 2>/dev/null | \
        grep "^user:" || echo "")

    for member in $owner_members; do
        primitive_users+=("$member")
    done

    if [ ${#primitive_users[@]} -gt 0 ]; then
        local user_list=$(printf '"%s",' "${primitive_users[@]}" | sed 's/,$//')
        add_finding "iam" "IAM-005" "high" \
            "Users with primitive Owner/Editor roles" \
            "${#primitive_users[@]} user(s) have primitive Owner or Editor roles. Use predefined roles instead." \
            "[$user_list]" \
            "Replace primitive roles (Owner/Editor) with specific predefined roles for each user" \
            "[\"CIS-GCP 1.3\",\"ISO27001 A.9.2.3\",\"SOC2 CC6.3\",\"CCSS 4.3\"]"
        print_finding "high" "${#primitive_users[@]} user(s) with primitive roles"
    else
        add_pass
        print_finding "pass" "No users with primitive Owner/Editor roles"
    fi

    # IAM-006: Domain-restricted sharing org policy
    print_status "  Checking domain-restricted sharing..."
    local domain_policy=$(gcloud resource-manager org-policies describe \
        constraints/iam.allowedPolicyMemberDomains \
        --project="$PROJECT_ID" --format=json 2>/dev/null || echo "")

    if [ -z "$domain_policy" ] || echo "$domain_policy" | grep -q '"listPolicy": {}' 2>/dev/null; then
        add_finding "iam" "IAM-006" "medium" \
            "Domain-restricted sharing not configured" \
            "The iam.allowedPolicyMemberDomains organization policy is not configured. Any Google account can be granted access." \
            "[]" \
            "Configure the iam.allowedPolicyMemberDomains org policy to restrict IAM policy members to your domain" \
            "[\"CIS-GCP 1.1\",\"ISO27001 A.9.2.3\",\"SOC2 CC6.1\"]"
        print_finding "medium" "Domain-restricted sharing not configured"
    else
        add_pass
        print_finding "pass" "Domain-restricted sharing is configured"
    fi

    # IAM-007: Service account impersonation permissions
    print_status "  Checking service account impersonation..."
    local impersonation_members=$(echo "$iam_policy" | \
        jq -r '.bindings[] | select(.role=="roles/iam.serviceAccountTokenCreator" or .role=="roles/iam.serviceAccountUser") | .members[]' 2>/dev/null | \
        grep "^user:" || echo "")
    local impersonation_count=$(echo "$impersonation_members" | grep -c "^user:" 2>/dev/null || echo "0")

    if [ "$impersonation_count" -gt 0 ]; then
        add_finding "iam" "IAM-007" "medium" \
            "Users with service account impersonation rights" \
            "$impersonation_count user(s) can impersonate service accounts via Token Creator or Service Account User roles" \
            "[]" \
            "Review and restrict service account impersonation permissions. Use conditional IAM bindings where possible." \
            "[\"CIS-GCP 1.6\",\"ISO27001 A.9.2.3\",\"SOC2 CC6.3\"]"
        print_finding "medium" "$impersonation_count user(s) with impersonation rights"
    else
        add_pass
        print_finding "pass" "No users with broad service account impersonation"
    fi

    # IAM-008: Ensure API keys are restricted
    print_status "  Checking API key restrictions..."
    local api_keys=$(gcloud services api-keys list \
        --project="$PROJECT_ID" --format="value(uid,restrictions.apiTargets)" 2>/dev/null || echo "")
    local unrestricted_keys=0

    if [ -n "$api_keys" ]; then
        while IFS=$'\t' read -r key_uid restrictions; do
            if [ -z "$restrictions" ] || [ "$restrictions" = "None" ]; then
                ((unrestricted_keys++))
            fi
        done <<< "$api_keys"
    fi

    if [ "$unrestricted_keys" -gt 0 ]; then
        add_finding "iam" "IAM-008" "high" \
            "Unrestricted API keys" \
            "$unrestricted_keys API key(s) have no API or application restrictions set" \
            "[]" \
            "Restrict API keys to specific APIs and applications (HTTP referrer, IP, or Android/iOS app)" \
            "[\"CIS-GCP 1.12\",\"ISO27001 A.9.4.1\",\"SOC2 CC6.1\",\"CCSS 4.2\"]"
        print_finding "high" "$unrestricted_keys unrestricted API key(s)"
    else
        add_pass
        print_finding "pass" "All API keys are restricted (or none exist)"
    fi
}

# ============================================================================
# Cloud Storage Checks (GCS-001 through GCS-005)
# ============================================================================

check_gcs() {
    print_status "Checking Cloud Storage Security..."

    # Get all buckets in the project
    local buckets=$(gsutil ls -p "$PROJECT_ID" 2>/dev/null | sed 's|gs://||;s|/||' || echo "")

    if [ -z "$buckets" ]; then
        print_warning "  No Cloud Storage buckets found or unable to list buckets"
        return
    fi

    local public_buckets=()
    local unencrypted_buckets=()
    local no_logging_buckets=()
    local no_versioning_buckets=()
    local no_uniform_access_buckets=()
    local bucket_count=0

    for bucket in $buckets; do
        ((bucket_count++))

        # GCS-001: Public access
        local iam_policy=$(gsutil iam get "gs://$bucket" 2>/dev/null || echo "")
        if echo "$iam_policy" | grep -q "allUsers\|allAuthenticatedUsers" 2>/dev/null; then
            public_buckets+=("$bucket")
        fi

        # GCS-002: Customer-managed encryption keys (CMEK)
        local encryption=$(gcloud storage buckets describe "gs://$bucket" \
            --format="value(default_kms_key)" 2>/dev/null || echo "")
        if [ -z "$encryption" ] || [ "$encryption" = "None" ]; then
            unencrypted_buckets+=("$bucket")
        fi

        # GCS-003: Access logging
        local logging=$(gsutil logging get "gs://$bucket" 2>/dev/null || echo "")
        if echo "$logging" | grep -q "has no logging" 2>/dev/null || [ -z "$logging" ]; then
            no_logging_buckets+=("$bucket")
        fi

        # GCS-004: Versioning
        local versioning=$(gsutil versioning get "gs://$bucket" 2>/dev/null || echo "")
        if echo "$versioning" | grep -q "Suspended" 2>/dev/null; then
            no_versioning_buckets+=("$bucket")
        fi

        # GCS-005: Uniform bucket-level access
        local uniform_access=$(gcloud storage buckets describe "gs://$bucket" \
            --format="value(uniform_bucket_level_access)" 2>/dev/null || echo "")
        if [ "$uniform_access" != "True" ] && ! echo "$uniform_access" | grep -q "enabled.*True" 2>/dev/null; then
            no_uniform_access_buckets+=("$bucket")
        fi
    done

    print_status "  Scanned $bucket_count bucket(s)"

    # Report findings
    if [ ${#public_buckets[@]} -gt 0 ]; then
        local bucket_list=$(printf '"%s",' "${public_buckets[@]}" | sed 's/,$//')
        add_finding "gcs" "GCS-001" "critical" \
            "Publicly accessible Cloud Storage buckets" \
            "${#public_buckets[@]} bucket(s) grant access to allUsers or allAuthenticatedUsers" \
            "[$bucket_list]" \
            "Remove allUsers and allAuthenticatedUsers IAM bindings. Enable org policy constraints/storage.publicAccessPrevention" \
            "[\"CIS-GCP 5.1\",\"ISO27001 A.13.1.1\",\"SOC2 CC6.1\",\"CCSS 3.1\"]"
        print_finding "critical" "${#public_buckets[@]} publicly accessible bucket(s)"
    else
        add_pass
        print_finding "pass" "No publicly accessible buckets found"
    fi

    if [ ${#unencrypted_buckets[@]} -gt 0 ]; then
        local bucket_list=$(printf '"%s",' "${unencrypted_buckets[@]}" | sed 's/,$//')
        add_finding "gcs" "GCS-002" "medium" \
            "Buckets without customer-managed encryption keys" \
            "${#unencrypted_buckets[@]} bucket(s) use Google-managed encryption instead of CMEK" \
            "[$bucket_list]" \
            "Configure Cloud KMS customer-managed encryption keys (CMEK) for sensitive buckets" \
            "[\"CIS-GCP 5.3\",\"ISO27001 A.10.1.1\",\"SOC2 CC6.1\",\"CCSS 3.2\"]"
        print_finding "medium" "${#unencrypted_buckets[@]} bucket(s) without CMEK"
    else
        add_pass
        print_finding "pass" "All buckets use customer-managed encryption"
    fi

    if [ ${#no_logging_buckets[@]} -gt 0 ]; then
        add_finding "gcs" "GCS-003" "medium" \
            "Cloud Storage buckets without access logging" \
            "${#no_logging_buckets[@]} bucket(s) do not have access logging enabled" \
            "[]" \
            "Enable access logging with gsutil logging set on <log-bucket> gs://<bucket>" \
            "[\"CIS-GCP 5.3\",\"ISO27001 A.12.4.1\",\"SOC2 CC7.2\"]"
        print_finding "medium" "${#no_logging_buckets[@]} bucket(s) without logging"
    else
        add_pass
        print_finding "pass" "All buckets have logging enabled"
    fi

    if [ ${#no_versioning_buckets[@]} -gt 0 ]; then
        add_finding "gcs" "GCS-004" "low" \
            "Cloud Storage buckets without versioning" \
            "${#no_versioning_buckets[@]} bucket(s) do not have object versioning enabled" \
            "[]" \
            "Enable versioning with gsutil versioning set on gs://<bucket> for data protection" \
            "[\"ISO27001 A.17.1.1\",\"SOC2 CC9.1\"]"
        print_finding "low" "${#no_versioning_buckets[@]} bucket(s) without versioning"
    else
        add_pass
        print_finding "pass" "All buckets have versioning enabled"
    fi

    if [ ${#no_uniform_access_buckets[@]} -gt 0 ]; then
        local bucket_list=$(printf '"%s",' "${no_uniform_access_buckets[@]}" | sed 's/,$//')
        add_finding "gcs" "GCS-005" "medium" \
            "Buckets without uniform bucket-level access" \
            "${#no_uniform_access_buckets[@]} bucket(s) do not have uniform bucket-level access enabled. ACLs may grant unintended permissions." \
            "[$bucket_list]" \
            "Enable uniform bucket-level access to use IAM exclusively and disable legacy ACLs" \
            "[\"CIS-GCP 5.2\",\"ISO27001 A.9.2.3\",\"SOC2 CC6.1\"]"
        print_finding "medium" "${#no_uniform_access_buckets[@]} bucket(s) without uniform access"
    else
        add_pass
        print_finding "pass" "All buckets use uniform bucket-level access"
    fi
}

# ============================================================================
# Compute & Network Checks (GCE-001 through GCE-009)
# ============================================================================

check_compute() {
    print_status "Checking Compute & Network Security..."

    # GCE-001: Firewall rules allowing 0.0.0.0/0 on SSH (22)
    print_status "  Checking firewall rules for open SSH..."
    local open_ssh_rules=$(gcloud compute firewall-rules list \
        --project="$PROJECT_ID" \
        --filter="sourceRanges=('0.0.0.0/0') AND allowed[].ports=('22') AND direction=INGRESS AND disabled=false" \
        --format="value(name)" 2>/dev/null || echo "")
    local open_ssh_count=$(echo "$open_ssh_rules" | grep -c '.' 2>/dev/null || echo "0")

    if [ "$open_ssh_count" -gt 0 ]; then
        local rules_list=$(echo "$open_ssh_rules" | while read -r rule; do printf '"%s",' "$rule"; done | sed 's/,$//')
        add_finding "compute" "GCE-001" "critical" \
            "Firewall rules allow SSH from anywhere" \
            "$open_ssh_count firewall rule(s) allow SSH (port 22) ingress from 0.0.0.0/0" \
            "[$rules_list]" \
            "Restrict SSH access to specific IP ranges. Use IAP TCP forwarding or OS Login instead of direct SSH." \
            "[\"CIS-GCP 3.6\",\"ISO27001 A.13.1.1\",\"SOC2 CC6.6\",\"CCSS 5.1\"]"
        print_finding "critical" "$open_ssh_count firewall rule(s) with SSH open to world"
    else
        add_pass
        print_finding "pass" "No firewall rules with SSH open to world"
    fi

    # GCE-002: Firewall rules allowing 0.0.0.0/0 on RDP (3389)
    print_status "  Checking firewall rules for open RDP..."
    local open_rdp_rules=$(gcloud compute firewall-rules list \
        --project="$PROJECT_ID" \
        --filter="sourceRanges=('0.0.0.0/0') AND allowed[].ports=('3389') AND direction=INGRESS AND disabled=false" \
        --format="value(name)" 2>/dev/null || echo "")
    local open_rdp_count=$(echo "$open_rdp_rules" | grep -c '.' 2>/dev/null || echo "0")

    if [ "$open_rdp_count" -gt 0 ]; then
        local rules_list=$(echo "$open_rdp_rules" | while read -r rule; do printf '"%s",' "$rule"; done | sed 's/,$//')
        add_finding "compute" "GCE-002" "critical" \
            "Firewall rules allow RDP from anywhere" \
            "$open_rdp_count firewall rule(s) allow RDP (port 3389) ingress from 0.0.0.0/0" \
            "[$rules_list]" \
            "Restrict RDP access to specific IP ranges. Use IAP TCP forwarding for remote access." \
            "[\"CIS-GCP 3.7\",\"ISO27001 A.13.1.1\",\"SOC2 CC6.6\",\"CCSS 5.1\"]"
        print_finding "critical" "$open_rdp_count firewall rule(s) with RDP open to world"
    else
        add_pass
        print_finding "pass" "No firewall rules with RDP open to world"
    fi

    # GCE-003: Instances with external/public IP addresses
    print_status "  Checking instances with public IPs..."
    local public_instances=$(gcloud compute instances list \
        --project="$PROJECT_ID" \
        --filter="networkInterfaces[].accessConfigs[].natIP:*" \
        --format="value(name)" 2>/dev/null || echo "")
    local public_count=$(echo "$public_instances" | grep -c '.' 2>/dev/null || echo "0")

    if [ "$public_count" -gt 0 ]; then
        local instance_list=$(echo "$public_instances" | while read -r inst; do printf '"%s",' "$inst"; done | sed 's/,$//')
        add_finding "compute" "GCE-003" "medium" \
            "Compute instances with external IP addresses" \
            "$public_count instance(s) have external IP addresses assigned" \
            "[$instance_list]" \
            "Remove external IPs where not required. Use Cloud NAT for outbound and IAP for inbound access." \
            "[\"CIS-GCP 4.9\",\"ISO27001 A.13.1.1\",\"SOC2 CC6.6\"]"
        print_finding "medium" "$public_count instance(s) with external IPs"
    else
        add_pass
        print_finding "pass" "No instances with external IPs"
    fi

    # GCE-004: OS Login disabled on instances
    print_status "  Checking OS Login configuration..."
    local project_metadata=$(gcloud compute project-info describe \
        --project="$PROJECT_ID" \
        --format="value(commonInstanceMetadata.items.filter(key:enable-oslogin).extract(value).flatten())" 2>/dev/null || echo "")

    if [ "$project_metadata" != "TRUE" ] && [ "$project_metadata" != "true" ]; then
        add_finding "compute" "GCE-004" "medium" \
            "OS Login not enabled at project level" \
            "OS Login is not enabled project-wide. Instances may use legacy SSH key management." \
            "[]" \
            "Enable OS Login project-wide: gcloud compute project-info add-metadata --metadata enable-oslogin=TRUE" \
            "[\"CIS-GCP 4.4\",\"ISO27001 A.9.2.1\",\"SOC2 CC6.1\",\"CCSS 4.1\"]"
        print_finding "medium" "OS Login not enabled at project level"
    else
        add_pass
        print_finding "pass" "OS Login enabled at project level"
    fi

    # GCE-005: Serial port access enabled
    print_status "  Checking serial port access..."
    local serial_port=$(gcloud compute project-info describe \
        --project="$PROJECT_ID" \
        --format="value(commonInstanceMetadata.items.filter(key:serial-port-enable).extract(value).flatten())" 2>/dev/null || echo "")

    if [ "$serial_port" = "TRUE" ] || [ "$serial_port" = "true" ] || [ "$serial_port" = "1" ]; then
        add_finding "compute" "GCE-005" "medium" \
            "Serial port access enabled at project level" \
            "Interactive serial port access is enabled project-wide. This can be used to bypass network security." \
            "[]" \
            "Disable serial port access: gcloud compute project-info add-metadata --metadata serial-port-enable=FALSE" \
            "[\"CIS-GCP 4.5\",\"ISO27001 A.13.1.1\",\"SOC2 CC6.6\"]"
        print_finding "medium" "Serial port access enabled"
    else
        add_pass
        print_finding "pass" "Serial port access disabled"
    fi

    # GCE-006: IP forwarding enabled on instances
    print_status "  Checking IP forwarding..."
    local ip_fwd_instances=$(gcloud compute instances list \
        --project="$PROJECT_ID" \
        --filter="canIpForward=true" \
        --format="value(name)" 2>/dev/null || echo "")
    local ip_fwd_count=$(echo "$ip_fwd_instances" | grep -c '.' 2>/dev/null || echo "0")

    if [ "$ip_fwd_count" -gt 0 ]; then
        add_finding "compute" "GCE-006" "low" \
            "Instances with IP forwarding enabled" \
            "$ip_fwd_count instance(s) have IP forwarding enabled. Unless acting as a router or NAT, this should be disabled." \
            "[]" \
            "Disable IP forwarding on instances that do not require it" \
            "[\"CIS-GCP 4.6\",\"ISO27001 A.13.1.1\",\"SOC2 CC6.6\"]"
        print_finding "low" "$ip_fwd_count instance(s) with IP forwarding"
    else
        add_pass
        print_finding "pass" "No instances with IP forwarding enabled"
    fi

    # GCE-007: VPC Flow Logs disabled on subnets
    print_status "  Checking VPC Flow Logs..."
    local subnets_no_flowlogs=$(gcloud compute networks subnets list \
        --project="$PROJECT_ID" \
        --filter="enableFlowLogs=false OR enableFlowLogs=null" \
        --format="value(name)" 2>/dev/null || echo "")
    local no_flowlogs_count=$(echo "$subnets_no_flowlogs" | grep -c '.' 2>/dev/null || echo "0")

    if [ "$no_flowlogs_count" -gt 0 ]; then
        add_finding "compute" "GCE-007" "medium" \
            "VPC subnets without Flow Logs" \
            "$no_flowlogs_count subnet(s) do not have VPC Flow Logs enabled" \
            "[]" \
            "Enable VPC Flow Logs on all subnets for network traffic visibility and forensic analysis" \
            "[\"CIS-GCP 3.8\",\"ISO27001 A.12.4.1\",\"SOC2 CC7.2\",\"CCSS 6.1\"]"
        print_finding "medium" "$no_flowlogs_count subnet(s) without Flow Logs"
    else
        add_pass
        print_finding "pass" "All subnets have VPC Flow Logs enabled"
    fi

    # GCE-008: SSL policies with weak cipher suites
    print_status "  Checking SSL policies..."
    local ssl_policies=$(gcloud compute ssl-policies list \
        --project="$PROJECT_ID" \
        --format="value(name,profile,minTlsVersion)" 2>/dev/null || echo "")
    local weak_ssl=0

    if [ -n "$ssl_policies" ]; then
        while IFS=$'\t' read -r name profile min_tls; do
            if [ "$min_tls" != "TLS_1_2" ] && [ "$min_tls" != "TLS_1_3" ]; then
                ((weak_ssl++))
            fi
            if [ "$profile" = "COMPATIBLE" ]; then
                ((weak_ssl++))
            fi
        done <<< "$ssl_policies"
    fi

    if [ "$weak_ssl" -gt 0 ]; then
        add_finding "compute" "GCE-008" "high" \
            "SSL policies with weak configuration" \
            "$weak_ssl SSL policy(ies) use weak TLS versions or cipher profiles" \
            "[]" \
            "Update SSL policies to use minimum TLS 1.2 with MODERN or RESTRICTED profile" \
            "[\"CIS-GCP 3.9\",\"ISO27001 A.14.1.2\",\"SOC2 CC6.7\",\"CCSS 3.2\"]"
        print_finding "high" "$weak_ssl weak SSL policy(ies)"
    else
        add_pass
        print_finding "pass" "SSL policies use strong configuration (or none exist)"
    fi

    # GCE-009: Cloud Armor (WAF) and Private Google Access
    print_status "  Checking Cloud Armor and Private Google Access..."
    local security_policies=$(gcloud compute security-policies list \
        --project="$PROJECT_ID" --format="value(name)" 2>/dev/null || echo "")

    if [ -z "$security_policies" ]; then
        add_finding "compute" "GCE-009" "low" \
            "No Cloud Armor security policies configured" \
            "No Cloud Armor (WAF) security policies are defined. Web-facing applications lack DDoS and WAF protection." \
            "[]" \
            "Create Cloud Armor security policies for web-facing load balancers to protect against DDoS and OWASP Top 10 attacks" \
            "[\"ISO27001 A.13.1.1\",\"SOC2 CC6.6\",\"CCSS 5.2\"]"
        print_finding "low" "No Cloud Armor security policies"
    else
        add_pass
        print_finding "pass" "Cloud Armor security policies configured"
    fi

    # Also check Private Google Access on subnets
    local subnets_no_pga=$(gcloud compute networks subnets list \
        --project="$PROJECT_ID" \
        --filter="privateIpGoogleAccess=false" \
        --format="value(name)" 2>/dev/null || echo "")
    local no_pga_count=$(echo "$subnets_no_pga" | grep -c '.' 2>/dev/null || echo "0")

    if [ "$no_pga_count" -gt 0 ]; then
        if [ "$VERBOSE" = true ]; then
            print_finding "low" "$no_pga_count subnet(s) without Private Google Access (informational)"
        fi
    fi
}

# ============================================================================
# Cloud SQL & Database Checks (SQL-001 through SQL-004)
# ============================================================================

check_sql() {
    print_status "Checking Cloud SQL & Database Security..."

    # Get all Cloud SQL instances
    local instances=$(gcloud sql instances list \
        --project="$PROJECT_ID" \
        --format="value(name)" 2>/dev/null || echo "")

    if [ -z "$instances" ]; then
        print_status "  No Cloud SQL instances found"
        return
    fi

    local public_ip_instances=()
    local no_ssl_instances=()
    local no_backup_instances=()
    local wide_network_instances=()

    for instance in $instances; do
        local details=$(gcloud sql instances describe "$instance" \
            --project="$PROJECT_ID" --format=json 2>/dev/null || echo "{}")

        # SQL-001: Public IP enabled
        local has_public_ip=$(echo "$details" | \
            jq -r '.ipAddresses[]? | select(.type=="PRIMARY") | .ipAddress' 2>/dev/null || echo "")
        if [ -n "$has_public_ip" ]; then
            public_ip_instances+=("$instance")
        fi

        # SQL-002: SSL/TLS enforcement
        local require_ssl=$(echo "$details" | \
            jq -r '.settings.ipConfiguration.requireSsl // false' 2>/dev/null || echo "false")
        if [ "$require_ssl" != "true" ]; then
            no_ssl_instances+=("$instance")
        fi

        # SQL-003: Automated backups
        local backup_enabled=$(echo "$details" | \
            jq -r '.settings.backupConfiguration.enabled // false' 2>/dev/null || echo "false")
        if [ "$backup_enabled" != "true" ]; then
            no_backup_instances+=("$instance")
        fi

        # SQL-004: Authorized networks (check for 0.0.0.0/0)
        local wide_network=$(echo "$details" | \
            jq -r '.settings.ipConfiguration.authorizedNetworks[]? | select(.value=="0.0.0.0/0") | .value' 2>/dev/null || echo "")
        if [ -n "$wide_network" ]; then
            wide_network_instances+=("$instance")
        fi
    done

    # Report findings
    if [ ${#public_ip_instances[@]} -gt 0 ]; then
        local instance_list=$(printf '"%s",' "${public_ip_instances[@]}" | sed 's/,$//')
        add_finding "sql" "SQL-001" "high" \
            "Cloud SQL instances with public IP" \
            "${#public_ip_instances[@]} Cloud SQL instance(s) have public IP addresses assigned" \
            "[$instance_list]" \
            "Use private IP connectivity only. Configure Private Service Connect or VPC peering for Cloud SQL access." \
            "[\"CIS-GCP 6.5\",\"ISO27001 A.13.1.1\",\"SOC2 CC6.6\",\"CCSS 3.1\"]"
        print_finding "high" "${#public_ip_instances[@]} Cloud SQL instance(s) with public IP"
    else
        add_pass
        print_finding "pass" "No Cloud SQL instances with public IP"
    fi

    if [ ${#no_ssl_instances[@]} -gt 0 ]; then
        local instance_list=$(printf '"%s",' "${no_ssl_instances[@]}" | sed 's/,$//')
        add_finding "sql" "SQL-002" "high" \
            "Cloud SQL instances without SSL enforcement" \
            "${#no_ssl_instances[@]} Cloud SQL instance(s) do not require SSL/TLS connections" \
            "[$instance_list]" \
            "Enforce SSL connections: gcloud sql instances patch INSTANCE --require-ssl" \
            "[\"CIS-GCP 6.4\",\"ISO27001 A.14.1.2\",\"SOC2 CC6.7\",\"CCSS 3.2\"]"
        print_finding "high" "${#no_ssl_instances[@]} Cloud SQL instance(s) without SSL"
    else
        add_pass
        print_finding "pass" "All Cloud SQL instances enforce SSL"
    fi

    if [ ${#no_backup_instances[@]} -gt 0 ]; then
        local instance_list=$(printf '"%s",' "${no_backup_instances[@]}" | sed 's/,$//')
        add_finding "sql" "SQL-003" "high" \
            "Cloud SQL instances without automated backups" \
            "${#no_backup_instances[@]} Cloud SQL instance(s) do not have automated backups enabled" \
            "[$instance_list]" \
            "Enable automated backups with point-in-time recovery for all production databases" \
            "[\"CIS-GCP 6.7\",\"ISO27001 A.17.1.1\",\"SOC2 CC9.1\",\"CCSS 7.1\"]"
        print_finding "high" "${#no_backup_instances[@]} Cloud SQL instance(s) without backups"
    else
        add_pass
        print_finding "pass" "All Cloud SQL instances have backups enabled"
    fi

    if [ ${#wide_network_instances[@]} -gt 0 ]; then
        local instance_list=$(printf '"%s",' "${wide_network_instances[@]}" | sed 's/,$//')
        add_finding "sql" "SQL-004" "critical" \
            "Cloud SQL instances allowing connections from any IP" \
            "${#wide_network_instances[@]} Cloud SQL instance(s) have 0.0.0.0/0 in authorized networks" \
            "[$instance_list]" \
            "Remove 0.0.0.0/0 from authorized networks. Restrict to specific IP ranges or use private IP only." \
            "[\"CIS-GCP 6.5\",\"ISO27001 A.13.1.1\",\"SOC2 CC6.6\",\"CCSS 5.1\"]"
        print_finding "critical" "${#wide_network_instances[@]} Cloud SQL instance(s) open to all IPs"
    else
        add_pass
        print_finding "pass" "No Cloud SQL instances with unrestricted network access"
    fi
}

# ============================================================================
# Logging & Monitoring Checks (LOG-001 through LOG-008)
# ============================================================================

check_logging() {
    print_status "Checking Logging & Monitoring..."

    # LOG-001: Audit logging configuration
    print_status "  Checking audit log configuration..."
    local audit_config=$(gcloud projects get-iam-policy "$PROJECT_ID" \
        --format="json" 2>/dev/null | jq '.auditConfigs // []' 2>/dev/null || echo "[]")
    local audit_config_count=$(echo "$audit_config" | jq 'length' 2>/dev/null || echo "0")

    if [ "$audit_config_count" = "0" ] || [ "$audit_config" = "[]" ]; then
        add_finding "logging" "LOG-001" "high" \
            "Data Access audit logs not configured" \
            "No Data Access audit log configuration found. Admin Activity logs are always on, but Data Access logs must be explicitly enabled." \
            "[]" \
            "Enable Data Access audit logs for all services: gcloud projects set-iam-policy with auditConfigs" \
            "[\"CIS-GCP 2.1\",\"ISO27001 A.12.4.1\",\"SOC2 CC7.2\",\"CCSS 6.1\"]"
        print_finding "high" "Data Access audit logs not configured"
    else
        add_pass
        print_finding "pass" "Data Access audit logs configured"
    fi

    # LOG-002: Log sinks (exports) configured
    print_status "  Checking log sinks..."
    local sinks=$(gcloud logging sinks list \
        --project="$PROJECT_ID" --format="value(name)" 2>/dev/null || echo "")

    if [ -z "$sinks" ]; then
        add_finding "logging" "LOG-002" "high" \
            "No log sinks configured" \
            "No log sinks (exports) are configured. Logs should be exported to a separate destination for long-term retention." \
            "[]" \
            "Create log sinks to export logs to Cloud Storage, BigQuery, or Pub/Sub for long-term retention" \
            "[\"CIS-GCP 2.2\",\"ISO27001 A.12.4.1\",\"SOC2 CC7.2\",\"CCSS 6.1\"]"
        print_finding "high" "No log sinks configured"
    else
        add_pass
        print_finding "pass" "Log sinks configured"
    fi

    # LOG-003: Alerting policies
    print_status "  Checking alerting policies..."
    local alerts=$(gcloud alpha monitoring policies list \
        --project="$PROJECT_ID" --format="value(name)" 2>/dev/null || echo "")

    if [ -z "$alerts" ]; then
        add_finding "logging" "LOG-003" "medium" \
            "No alerting policies configured" \
            "No Cloud Monitoring alerting policies are defined. Critical events may go unnoticed." \
            "[]" \
            "Create alerting policies for key metrics: IAM changes, firewall rule changes, and audit log anomalies" \
            "[\"CIS-GCP 2.4\",\"ISO27001 A.16.1.2\",\"SOC2 CC7.3\",\"CCSS 6.2\"]"
        print_finding "medium" "No alerting policies configured"
    else
        add_pass
        print_finding "pass" "Alerting policies configured"
    fi

    # LOG-004: Uptime checks
    print_status "  Checking uptime checks..."
    local uptime_checks=$(gcloud monitoring uptime list-configs \
        --project="$PROJECT_ID" --format="value(name)" 2>/dev/null || echo "")

    if [ -z "$uptime_checks" ]; then
        add_finding "logging" "LOG-004" "low" \
            "No uptime checks configured" \
            "No Cloud Monitoring uptime checks are defined. Service availability issues may go undetected." \
            "[]" \
            "Create uptime checks for critical service endpoints" \
            "[\"ISO27001 A.17.1.1\",\"SOC2 CC7.1\"]"
        print_finding "low" "No uptime checks configured"
    else
        add_pass
        print_finding "pass" "Uptime checks configured"
    fi

    # LOG-005: Security Command Center enabled
    print_status "  Checking Security Command Center..."
    local scc_enabled=$(gcloud scc settings describe \
        --project="$PROJECT_ID" --format="value(name)" 2>/dev/null || echo "")

    if [ -z "$scc_enabled" ]; then
        add_finding "logging" "LOG-005" "medium" \
            "Security Command Center not enabled" \
            "Security Command Center (SCC) is not enabled or accessible. SCC provides centralized security findings." \
            "[]" \
            "Enable Security Command Center Standard (free) or Premium tier for advanced threat detection" \
            "[\"CIS-GCP 2.12\",\"ISO27001 A.12.6.1\",\"SOC2 CC7.1\",\"CCSS 6.2\"]"
        print_finding "medium" "Security Command Center not enabled"
    else
        add_pass
        print_finding "pass" "Security Command Center is enabled"
    fi

    # LOG-006: Cloud Asset Inventory
    print_status "  Checking Cloud Asset Inventory..."
    local asset_api=$(gcloud services list --project="$PROJECT_ID" \
        --filter="name:cloudasset.googleapis.com" \
        --format="value(name)" 2>/dev/null || echo "")

    if [ -z "$asset_api" ]; then
        add_finding "logging" "LOG-006" "low" \
            "Cloud Asset Inventory API not enabled" \
            "The Cloud Asset Inventory API is not enabled. This service provides resource and policy inventory." \
            "[]" \
            "Enable Cloud Asset Inventory API: gcloud services enable cloudasset.googleapis.com" \
            "[\"ISO27001 A.8.1.1\",\"SOC2 CC6.1\"]"
        print_finding "low" "Cloud Asset Inventory API not enabled"
    else
        add_pass
        print_finding "pass" "Cloud Asset Inventory API is enabled"
    fi

    # LOG-007: VPC Service Controls
    print_status "  Checking VPC Service Controls..."
    local access_policies=$(gcloud access-context-manager policies list \
        --format="value(name)" 2>/dev/null || echo "")

    if [ -z "$access_policies" ]; then
        add_finding "logging" "LOG-007" "medium" \
            "VPC Service Controls not configured" \
            "No VPC Service Controls access policies found. VPC SC helps prevent data exfiltration from GCP services." \
            "[]" \
            "Configure VPC Service Controls with access policies and service perimeters for sensitive projects" \
            "[\"CIS-GCP 3.10\",\"ISO27001 A.13.1.3\",\"SOC2 CC6.1\",\"CCSS 3.1\"]"
        print_finding "medium" "VPC Service Controls not configured"
    else
        add_pass
        print_finding "pass" "VPC Service Controls configured"
    fi

    # LOG-008: Binary Authorization
    print_status "  Checking Binary Authorization..."
    local binauthz_api=$(gcloud services list --project="$PROJECT_ID" \
        --filter="name:binaryauthorization.googleapis.com" \
        --format="value(name)" 2>/dev/null || echo "")

    if [ -z "$binauthz_api" ]; then
        add_finding "logging" "LOG-008" "low" \
            "Binary Authorization not enabled" \
            "Binary Authorization API is not enabled. This service ensures only trusted container images are deployed to GKE." \
            "[]" \
            "Enable Binary Authorization for GKE deployments: gcloud services enable binaryauthorization.googleapis.com" \
            "[\"ISO27001 A.14.2.7\",\"SOC2 CC7.1\",\"CCSS 2.1\"]"
        print_finding "low" "Binary Authorization not enabled"
    else
        add_pass
        print_finding "pass" "Binary Authorization is enabled"
    fi
}

# ============================================================================
# Report Generation
# ============================================================================

calculate_score() {
    local max_checks=$((CRITICAL_COUNT + HIGH_COUNT + MEDIUM_COUNT + LOW_COUNT + PASS_COUNT))

    if [ "$max_checks" -eq 0 ]; then
        echo "0"
        return
    fi

    # Weighted deductions
    local deductions=$((CRITICAL_COUNT * 15 + HIGH_COUNT * 8 + MEDIUM_COUNT * 3 + LOW_COUNT * 1))
    local max_score=$((max_checks * 10))
    local raw_score=$((max_score - deductions))

    if [ "$raw_score" -lt 0 ]; then
        raw_score=0
    fi

    local percentage=$((raw_score * 100 / max_score))
    echo "$percentage"
}

get_interpretation() {
    local score=$1
    if [ "$score" -ge 90 ]; then
        echo "Excellent"
    elif [ "$score" -ge 70 ]; then
        echo "Good"
    elif [ "$score" -ge 50 ]; then
        echo "Fair"
    else
        echo "Needs Attention"
    fi
}

generate_report() {
    local score=$(calculate_score)
    local interpretation=$(get_interpretation "$score")
    local scan_date=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

    # Build findings JSON array
    local findings_json=""
    for finding in "${FINDINGS[@]}"; do
        if [ -n "$findings_json" ]; then
            findings_json="$findings_json,"
        fi
        findings_json="$findings_json$finding"
    done

    # Generate report
    cat > "$OUTPUT_FILE" << EOF
{
  "scanner_version": "$SCANNER_VERSION",
  "scan_date": "$scan_date",
  "project_id": "$PROJECT_ID",
  "project_number": "$PROJECT_NUMBER",
  "score": {
    "overall": $score,
    "interpretation": "$interpretation"
  },
  "summary": {
    "critical": $CRITICAL_COUNT,
    "high": $HIGH_COUNT,
    "medium": $MEDIUM_COUNT,
    "low": $LOW_COUNT,
    "passed": $PASS_COUNT,
    "total_checks": $((CRITICAL_COUNT + HIGH_COUNT + MEDIUM_COUNT + LOW_COUNT + PASS_COUNT))
  },
  "compliance_coverage": {
    "cis_gcp_foundations": true,
    "iso_27001": true,
    "soc_2": true,
    "ccss": true
  },
  "findings": [$findings_json]
}
EOF

    # Redact project numbers (12-digit numbers) for safety
    if [[ "$OSTYPE" == "darwin"* ]]; then
        sed -i '' 's/[0-9]\{12\}/REDACTED/g' "$OUTPUT_FILE"
    else
        sed -i 's/[0-9]\{12\}/REDACTED/g' "$OUTPUT_FILE"
    fi

    # Pretty print if jq available
    if [ "$JQ_AVAILABLE" = true ]; then
        local temp_file=$(mktemp)
        jq '.' "$OUTPUT_FILE" > "$temp_file" && mv "$temp_file" "$OUTPUT_FILE"
    fi
}

print_summary() {
    local score=$(calculate_score)
    local interpretation=$(get_interpretation "$score")
    local total=$((CRITICAL_COUNT + HIGH_COUNT + MEDIUM_COUNT + LOW_COUNT + PASS_COUNT))

    echo ""
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  Security Score: ${BLUE}$score/100${NC} ($interpretation)"
    echo ""
    echo "  Summary:"
    echo -e "    ${RED}Critical:${NC} $CRITICAL_COUNT"
    echo -e "    ${RED}High:${NC}     $HIGH_COUNT"
    echo -e "    ${YELLOW}Medium:${NC}   $MEDIUM_COUNT"
    echo -e "    ${GREEN}Low:${NC}      $LOW_COUNT"
    echo -e "    ${GREEN}Passed:${NC}   $PASS_COUNT"
    echo ""
    echo "  Total checks: $total"
    echo ""
    echo -e "  Compliance frameworks covered:"
    echo "    - CIS GCP Foundations Benchmark"
    echo "    - ISO 27001"
    echo "    - SOC 2"
    echo "    - CCSS (Cryptocurrency Security Standard)"
    echo ""
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  Report saved to: ${GREEN}$OUTPUT_FILE${NC}"
    echo ""
    echo "  Next steps:"
    echo "    1. Review the report for sensitive information"
    echo "    2. Share it at: https://scamshield.app/audit"
    echo "    3. Get your personalized remediation plan"
    echo ""
}

# ============================================================================
# Main
# ============================================================================

main() {
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -p|--project)
                PROJECT_ID="$2"
                shift 2
                ;;
            -o|--output)
                OUTPUT_FILE="$2"
                shift 2
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                echo "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
    done

    # Set default output file
    if [ -z "$OUTPUT_FILE" ]; then
        OUTPUT_FILE="$DEFAULT_OUTPUT"
    fi

    print_banner
    check_prerequisites

    echo ""
    echo -e "${BLUE}Starting security scan...${NC}"
    echo ""

    # Run all checks
    check_iam
    echo ""
    check_gcs
    echo ""
    check_compute
    echo ""
    check_sql
    echo ""
    check_logging

    # Generate report
    generate_report

    # Print summary
    print_summary
}

main "$@"
