#!/bin/bash
#
# Starlings DigitalOcean Security Scanner v1.0.0
# ===============================================
#
# This script runs locally in YOUR environment.
# Your DigitalOcean credentials NEVER leave your machine.
#
# What it does:
#   - Runs read-only checks against your DigitalOcean account
#   - Identifies security misconfigurations
#   - Maps findings to compliance frameworks (ISO 27001, SOC 2, CIS, CCSS)
#   - Outputs a JSON report you can review before sharing
#
# Requirements:
#   - doctl CLI installed and authenticated
#   - Read-only API token recommended (see README.md)
#
# Usage:
#   ./starlings-do-scan.sh [--output FILE] [--verbose] [--help]
#
# Source: https://github.com/Starlings-Data/digitalocean-scanner
# License: MIT
#

set -e

# ============================================================================
# Configuration
# ============================================================================

SCANNER_VERSION="1.0.0"
DEFAULT_OUTPUT="do-security-report.json"
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
    echo -e "${BLUE}║${NC}     Starlings DigitalOcean Security Scanner v${SCANNER_VERSION}      ${BLUE}║${NC}"
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
    echo -e "${GREEN}[+]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_error() {
    echo -e "${RED}[x]${NC} $1"
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
    echo "  -o, --output FILE      Output file (default: ${DEFAULT_OUTPUT})"
    echo "  -v, --verbose          Verbose output"
    echo "  -h, --help             Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                           # Run full scan"
    echo "  $0 --output my-report.json   # Custom output file"
    echo "  $0 --verbose                 # Show detailed output"
    echo ""
}

check_prerequisites() {
    print_status "Checking prerequisites..."

    # Check doctl CLI
    if ! command -v doctl &> /dev/null; then
        print_error "doctl CLI not found. Please install it first."
        echo "  See: https://docs.digitalocean.com/reference/doctl/how-to/install/"
        exit 1
    fi
    print_success "doctl CLI found"

    # Check doctl authentication
    if ! doctl account get &> /dev/null; then
        print_error "doctl not authenticated or token invalid."
        echo "  Run: doctl auth init"
        exit 1
    fi
    print_success "doctl authenticated"

    # Get account info
    ACCOUNT_EMAIL=$(doctl account get --format Email --no-header 2>/dev/null || echo "unknown")
    ACCOUNT_UUID=$(doctl account get --format UUID --no-header 2>/dev/null || echo "unknown")
    ACCOUNT_STATUS=$(doctl account get --format Status --no-header 2>/dev/null || echo "unknown")
    ACCOUNT_DROPLET_LIMIT=$(doctl account get --format DropletLimit --no-header 2>/dev/null || echo "unknown")
    print_status "Account: $ACCOUNT_EMAIL (Status: $ACCOUNT_STATUS)"

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
# App Platform Checks
# ============================================================================

check_app_platform() {
    print_status "Checking App Platform Security..."

    # Get all apps
    local apps_json=$(doctl apps list --output json 2>/dev/null || echo "[]")
    local app_count=$(echo "$apps_json" | jq 'length' 2>/dev/null || echo "0")

    if [ "$app_count" = "0" ] || [ "$app_count" = "" ]; then
        print_status "  No App Platform apps found"
        return
    fi

    print_status "  Found $app_count app(s)"

    # APP-001: Check for environment variables that may contain secrets in plaintext
    print_status "  Checking environment variable exposure..."
    local apps_with_plaintext_secrets=()

    for i in $(seq 0 $((app_count - 1))); do
        local app_id=$(echo "$apps_json" | jq -r ".[$i].id" 2>/dev/null)
        local app_name=$(echo "$apps_json" | jq -r ".[$i].spec.name" 2>/dev/null)

        # Get app spec to check env vars
        local app_spec=$(doctl apps get "$app_id" --output json 2>/dev/null || echo "{}")

        # Check all service components for plaintext env vars with suspicious names
        local has_plaintext_secrets=$(echo "$app_spec" | jq -r '
            .. | objects | select(.envs?) | .envs[]? |
            select(.type != "SECRET" and .type != "secret") |
            select(.key | test("(?i)(password|secret|token|key|api_key|apikey|private|credential)")) |
            .key' 2>/dev/null || echo "")

        if [ -n "$has_plaintext_secrets" ]; then
            apps_with_plaintext_secrets+=("$app_name")
        fi
    done

    if [ ${#apps_with_plaintext_secrets[@]} -gt 0 ]; then
        local app_list=$(printf '"%s",' "${apps_with_plaintext_secrets[@]}" | sed 's/,$//')
        add_finding "app_platform" "APP-001" "critical" \
            "Plaintext secrets in App Platform environment variables" \
            "${#apps_with_plaintext_secrets[@]} app(s) have environment variables with secret-like names not marked as SECRET type" \
            "[$app_list]" \
            "Mark sensitive environment variables as SECRET type in app spec to encrypt them at rest" \
            "[\"ISO27001 A.10.1.1\",\"SOC2 CC6.1\",\"CCSS 3.2\"]"
        print_finding "critical" "${#apps_with_plaintext_secrets[@]} app(s) with plaintext secrets in env vars"
    else
        add_pass
        print_finding "pass" "No plaintext secrets detected in environment variables"
    fi

    # APP-002: Check deployment settings - auto deploy from branch
    print_status "  Checking deployment settings..."
    local apps_with_auto_deploy=()

    for i in $(seq 0 $((app_count - 1))); do
        local app_name=$(echo "$apps_json" | jq -r ".[$i].spec.name" 2>/dev/null)

        # Check if any component has auto-deploy from a non-main branch
        local has_risky_auto_deploy=$(echo "$apps_json" | jq -r "
            .[$i].spec | .. | objects | select(.github?) |
            select(.deploy_on_push == true) |
            .github.branch" 2>/dev/null || echo "")

        if [ -n "$has_risky_auto_deploy" ]; then
            apps_with_auto_deploy+=("$app_name")
        fi
    done

    if [ ${#apps_with_auto_deploy[@]} -gt 0 ]; then
        local app_list=$(printf '"%s",' "${apps_with_auto_deploy[@]}" | sed 's/,$//')
        add_finding "app_platform" "APP-002" "medium" \
            "App Platform auto-deploy on push enabled" \
            "${#apps_with_auto_deploy[@]} app(s) have auto-deploy on push enabled. Ensure branch protection is configured." \
            "[$app_list]" \
            "Review deploy-on-push settings. Use branch protection rules on source repos and restrict deploy branches to main/production only." \
            "[\"ISO27001 A.14.2.2\",\"SOC2 CC8.1\"]"
        print_finding "medium" "${#apps_with_auto_deploy[@]} app(s) with auto-deploy on push"
    else
        add_pass
        print_finding "pass" "No unrestricted auto-deploy configurations found"
    fi

    # APP-003: Check trusted sources configuration
    print_status "  Checking trusted sources..."
    local apps_without_trusted_sources=()

    for i in $(seq 0 $((app_count - 1))); do
        local app_name=$(echo "$apps_json" | jq -r ".[$i].spec.name" 2>/dev/null)
        local app_id=$(echo "$apps_json" | jq -r ".[$i].id" 2>/dev/null)

        # Check if app uses Docker Hub images without trusted sources pinning
        local uses_unpinned_images=$(echo "$apps_json" | jq -r "
            .[$i].spec | .. | objects | select(.image?) |
            select(.image.registry_type == \"DOCKER_HUB\") |
            select(.image.tag == \"latest\" or .image.tag == null) |
            .image.repository" 2>/dev/null || echo "")

        if [ -n "$uses_unpinned_images" ]; then
            apps_without_trusted_sources+=("$app_name")
        fi
    done

    if [ ${#apps_without_trusted_sources[@]} -gt 0 ]; then
        local app_list=$(printf '"%s",' "${apps_without_trusted_sources[@]}" | sed 's/,$//')
        add_finding "app_platform" "APP-003" "high" \
            "App Platform using unpinned container images" \
            "${#apps_without_trusted_sources[@]} app(s) use unpinned (latest) Docker Hub images" \
            "[$app_list]" \
            "Pin container images to specific tags or SHA digests. Use DigitalOcean Container Registry for trusted sources." \
            "[\"ISO27001 A.14.2.5\",\"SOC2 CC7.1\",\"CCSS 2.1\"]"
        print_finding "high" "${#apps_without_trusted_sources[@]} app(s) with unpinned container images"
    else
        add_pass
        print_finding "pass" "All app container images are pinned to specific versions"
    fi

    # APP-004: Check if apps have HTTP->HTTPS redirect
    print_status "  Checking HTTPS enforcement..."
    local apps_json_detail=""
    local apps_without_https=()

    for i in $(seq 0 $((app_count - 1))); do
        local app_name=$(echo "$apps_json" | jq -r ".[$i].spec.name" 2>/dev/null)
        local app_id=$(echo "$apps_json" | jq -r ".[$i].id" 2>/dev/null)

        # Check if any service/route doesn't enforce HTTPS
        local has_http_route=$(echo "$apps_json" | jq -r "
            .[$i].spec | .. | objects | select(.routes?) |
            .routes[]? | select(.preserve_path_prefix? == true) |
            .path" 2>/dev/null || echo "")

        # App Platform enforces HTTPS by default, but check the live URL
        local live_url=$(echo "$apps_json" | jq -r ".[$i].live_url // empty" 2>/dev/null)
        if [ -n "$live_url" ] && echo "$live_url" | grep -q "^http://"; then
            apps_without_https+=("$app_name")
        fi
    done

    if [ ${#apps_without_https[@]} -gt 0 ]; then
        local app_list=$(printf '"%s",' "${apps_without_https[@]}" | sed 's/,$//')
        add_finding "app_platform" "APP-004" "high" \
            "Apps not enforcing HTTPS" \
            "${#apps_without_https[@]} app(s) may not be enforcing HTTPS" \
            "[$app_list]" \
            "Ensure all apps use HTTPS. Configure custom domains with SSL certificates." \
            "[\"ISO27001 A.14.1.2\",\"SOC2 CC6.7\",\"CCSS 5.2\"]"
        print_finding "high" "${#apps_without_https[@]} app(s) not enforcing HTTPS"
    else
        add_pass
        print_finding "pass" "All apps enforce HTTPS"
    fi
}

# ============================================================================
# Database Checks (DBaaS)
# ============================================================================

check_databases() {
    print_status "Checking Database Security (DBaaS)..."

    # Get all databases
    local dbs_json=$(doctl databases list --output json 2>/dev/null || echo "[]")
    local db_count=$(echo "$dbs_json" | jq 'length' 2>/dev/null || echo "0")

    if [ "$db_count" = "0" ] || [ "$db_count" = "" ]; then
        print_status "  No managed databases found"
        return
    fi

    print_status "  Found $db_count database cluster(s)"

    # DB-001: Public access enabled
    print_status "  Checking public access settings..."
    local public_dbs=()

    for i in $(seq 0 $((db_count - 1))); do
        local db_id=$(echo "$dbs_json" | jq -r ".[$i].id" 2>/dev/null)
        local db_name=$(echo "$dbs_json" | jq -r ".[$i].name" 2>/dev/null)

        # Check if database has public network access
        local private_net=$(echo "$dbs_json" | jq -r ".[$i].private_network_uuid // empty" 2>/dev/null)
        local connection_host=$(echo "$dbs_json" | jq -r ".[$i].connection.host // empty" 2>/dev/null)
        local private_host=$(echo "$dbs_json" | jq -r ".[$i].private_connection.host // empty" 2>/dev/null)

        # If the public connection host exists and no firewall rules restrict it
        local firewall_rules=$(doctl databases firewalls list "$db_id" --output json 2>/dev/null || echo "[]")
        local has_open_firewall=$(echo "$firewall_rules" | jq '[.[] | select(.type == "ip_addr" and .value == "0.0.0.0/0")] | length' 2>/dev/null || echo "0")

        if [ "$has_open_firewall" != "0" ]; then
            public_dbs+=("$db_name")
        fi
    done

    if [ ${#public_dbs[@]} -gt 0 ]; then
        local db_list=$(printf '"%s",' "${public_dbs[@]}" | sed 's/,$//')
        add_finding "database" "DB-001" "critical" \
            "Databases with unrestricted public access" \
            "${#public_dbs[@]} database cluster(s) allow connections from any IP (0.0.0.0/0)" \
            "[$db_list]" \
            "Configure database firewall rules to restrict access to specific IPs, Droplets, Kubernetes clusters, or App Platform apps. Use: doctl databases firewalls replace <db-id> --rules" \
            "[\"CIS 4.1\",\"ISO27001 A.13.1.1\",\"SOC2 CC6.6\",\"CCSS 5.1\"]"
        print_finding "critical" "${#public_dbs[@]} database(s) with unrestricted public access"
    else
        add_pass
        print_finding "pass" "No databases with unrestricted public access"
    fi

    # DB-002: SSL enforcement
    print_status "  Checking SSL enforcement..."
    local no_ssl_dbs=()

    for i in $(seq 0 $((db_count - 1))); do
        local db_id=$(echo "$dbs_json" | jq -r ".[$i].id" 2>/dev/null)
        local db_name=$(echo "$dbs_json" | jq -r ".[$i].name" 2>/dev/null)
        local db_engine=$(echo "$dbs_json" | jq -r ".[$i].engine" 2>/dev/null)

        local connection_ssl=$(echo "$dbs_json" | jq -r ".[$i].connection.ssl // false" 2>/dev/null)
        if [ "$connection_ssl" = "false" ]; then
            no_ssl_dbs+=("$db_name ($db_engine)")
        fi
    done

    if [ ${#no_ssl_dbs[@]} -gt 0 ]; then
        local db_list=$(printf '"%s",' "${no_ssl_dbs[@]}" | sed 's/,$//')
        add_finding "database" "DB-002" "high" \
            "Databases without SSL enforcement" \
            "${#no_ssl_dbs[@]} database cluster(s) do not enforce SSL connections" \
            "[$db_list]" \
            "Enable SSL mode for all database connections. For PostgreSQL set ssl_mode=require, for MySQL set ssl=true. DigitalOcean managed databases support SSL by default." \
            "[\"CIS 4.2\",\"ISO27001 A.14.1.2\",\"SOC2 CC6.7\",\"CCSS 5.2\"]"
        print_finding "high" "${#no_ssl_dbs[@]} database(s) without SSL enforcement"
    else
        add_pass
        print_finding "pass" "All databases enforce SSL connections"
    fi

    # DB-003: Trusted sources / firewall rules
    print_status "  Checking database firewall rules..."
    local no_firewall_dbs=()

    for i in $(seq 0 $((db_count - 1))); do
        local db_id=$(echo "$dbs_json" | jq -r ".[$i].id" 2>/dev/null)
        local db_name=$(echo "$dbs_json" | jq -r ".[$i].name" 2>/dev/null)

        local firewall_rules=$(doctl databases firewalls list "$db_id" --output json 2>/dev/null || echo "[]")
        local rule_count=$(echo "$firewall_rules" | jq 'length' 2>/dev/null || echo "0")

        if [ "$rule_count" = "0" ]; then
            no_firewall_dbs+=("$db_name")
        fi
    done

    if [ ${#no_firewall_dbs[@]} -gt 0 ]; then
        local db_list=$(printf '"%s",' "${no_firewall_dbs[@]}" | sed 's/,$//')
        add_finding "database" "DB-003" "high" \
            "Databases without firewall rules (trusted sources)" \
            "${#no_firewall_dbs[@]} database cluster(s) have no firewall rules configured" \
            "[$db_list]" \
            "Add trusted sources using doctl databases firewalls replace <db-id> --rules type:droplet,value:<droplet-id>. Restrict to specific Droplets, K8s clusters, or apps." \
            "[\"CIS 4.1\",\"ISO27001 A.13.1.1\",\"SOC2 CC6.6\",\"CCSS 5.1\"]"
        print_finding "high" "${#no_firewall_dbs[@]} database(s) without firewall rules"
    else
        add_pass
        print_finding "pass" "All databases have firewall rules configured"
    fi

    # DB-004: Backup configuration
    print_status "  Checking backup configuration..."
    local no_backup_dbs=()

    for i in $(seq 0 $((db_count - 1))); do
        local db_id=$(echo "$dbs_json" | jq -r ".[$i].id" 2>/dev/null)
        local db_name=$(echo "$dbs_json" | jq -r ".[$i].name" 2>/dev/null)

        # Check for recent backups
        local backups=$(doctl databases backups list "$db_id" --output json 2>/dev/null || echo "[]")
        local backup_count=$(echo "$backups" | jq 'length' 2>/dev/null || echo "0")

        if [ "$backup_count" = "0" ]; then
            no_backup_dbs+=("$db_name")
        fi
    done

    if [ ${#no_backup_dbs[@]} -gt 0 ]; then
        local db_list=$(printf '"%s",' "${no_backup_dbs[@]}" | sed 's/,$//')
        add_finding "database" "DB-004" "high" \
            "Databases without recent backups" \
            "${#no_backup_dbs[@]} database cluster(s) have no backups available" \
            "[$db_list]" \
            "DigitalOcean managed databases include automatic daily backups. Verify backups are functioning and consider additional backup strategies for critical data." \
            "[\"ISO27001 A.17.1.1\",\"SOC2 CC9.1\",\"CCSS 7.1\"]"
        print_finding "high" "${#no_backup_dbs[@]} database(s) without recent backups"
    else
        add_pass
        print_finding "pass" "All databases have backups available"
    fi

    # DB-005: Version currency
    print_status "  Checking database version currency..."
    local outdated_dbs=()

    for i in $(seq 0 $((db_count - 1))); do
        local db_name=$(echo "$dbs_json" | jq -r ".[$i].name" 2>/dev/null)
        local db_engine=$(echo "$dbs_json" | jq -r ".[$i].engine" 2>/dev/null)
        local db_version=$(echo "$dbs_json" | jq -r ".[$i].version" 2>/dev/null)

        # Check for significantly outdated versions
        local is_outdated=false
        case "$db_engine" in
            pg)
                # PostgreSQL: flag versions older than 14
                if [ -n "$db_version" ] && [ "$db_version" -lt 14 ] 2>/dev/null; then
                    is_outdated=true
                fi
                ;;
            mysql)
                # MySQL: flag version 8.0.x that is early patch
                if [ -n "$db_version" ] && echo "$db_version" | grep -qE "^5\."; then
                    is_outdated=true
                fi
                ;;
            redis)
                # Redis: flag versions older than 7
                if [ -n "$db_version" ] && [ "$db_version" -lt 7 ] 2>/dev/null; then
                    is_outdated=true
                fi
                ;;
            mongodb)
                # MongoDB: flag versions older than 6
                if [ -n "$db_version" ] && [ "$db_version" -lt 6 ] 2>/dev/null; then
                    is_outdated=true
                fi
                ;;
        esac

        if [ "$is_outdated" = true ]; then
            outdated_dbs+=("$db_name ($db_engine $db_version)")
        fi
    done

    if [ ${#outdated_dbs[@]} -gt 0 ]; then
        local db_list=$(printf '"%s",' "${outdated_dbs[@]}" | sed 's/,$//')
        add_finding "database" "DB-005" "medium" \
            "Outdated database engine versions" \
            "${#outdated_dbs[@]} database cluster(s) are running outdated engine versions" \
            "[$db_list]" \
            "Upgrade database clusters to the latest supported major version. Use doctl databases migrate <db-id> --version <version> after testing compatibility." \
            "[\"ISO27001 A.14.2.2\",\"SOC2 CC7.1\",\"CCSS 2.2\"]"
        print_finding "medium" "${#outdated_dbs[@]} database(s) with outdated versions"
    else
        add_pass
        print_finding "pass" "All databases are running current versions"
    fi

    # DB-006: Eviction policy for Redis
    print_status "  Checking Redis eviction policies..."
    local redis_no_eviction=()

    for i in $(seq 0 $((db_count - 1))); do
        local db_name=$(echo "$dbs_json" | jq -r ".[$i].name" 2>/dev/null)
        local db_engine=$(echo "$dbs_json" | jq -r ".[$i].engine" 2>/dev/null)
        local db_id=$(echo "$dbs_json" | jq -r ".[$i].id" 2>/dev/null)

        if [ "$db_engine" = "redis" ]; then
            local eviction_policy=$(doctl databases configuration get "$db_id" --output json 2>/dev/null | jq -r '.config.redis_maxmemory_policy // "noeviction"' 2>/dev/null || echo "noeviction")
            if [ "$eviction_policy" = "noeviction" ]; then
                redis_no_eviction+=("$db_name")
            fi
        fi
    done

    if [ ${#redis_no_eviction[@]} -gt 0 ]; then
        local db_list=$(printf '"%s",' "${redis_no_eviction[@]}" | sed 's/,$//')
        add_finding "database" "DB-006" "low" \
            "Redis clusters with noeviction policy" \
            "${#redis_no_eviction[@]} Redis cluster(s) use noeviction policy which may cause write failures when memory is full" \
            "[$db_list]" \
            "Review and set an appropriate eviction policy (e.g., allkeys-lru) for cache workloads to prevent outages when memory is exhausted." \
            "[\"ISO27001 A.17.1.1\",\"SOC2 CC9.1\"]"
        print_finding "low" "${#redis_no_eviction[@]} Redis cluster(s) with noeviction policy"
    else
        add_pass
        print_finding "pass" "Redis eviction policies are configured appropriately"
    fi
}

# ============================================================================
# Networking Checks
# ============================================================================

check_networking() {
    print_status "Checking Networking Security..."

    # NET-001: Cloud Firewalls
    print_status "  Checking Cloud Firewalls..."
    local firewalls_json=$(doctl compute firewall list --output json 2>/dev/null || echo "[]")
    local firewall_count=$(echo "$firewalls_json" | jq 'length' 2>/dev/null || echo "0")

    # Get all droplets to check if any lack firewall coverage
    local droplets_json=$(doctl compute droplet list --output json 2>/dev/null || echo "[]")
    local droplet_count=$(echo "$droplets_json" | jq 'length' 2>/dev/null || echo "0")

    if [ "$droplet_count" != "0" ] && [ "$droplet_count" != "" ]; then
        local droplets_without_firewall=()

        for i in $(seq 0 $((droplet_count - 1))); do
            local droplet_id=$(echo "$droplets_json" | jq -r ".[$i].id" 2>/dev/null)
            local droplet_name=$(echo "$droplets_json" | jq -r ".[$i].name" 2>/dev/null)

            # Check if this droplet is in any firewall's droplet_ids
            local in_firewall=false
            if [ "$firewall_count" != "0" ]; then
                local is_covered=$(echo "$firewalls_json" | jq --arg did "$droplet_id" '[.[] | select(.droplet_ids[]? == ($did | tonumber))] | length' 2>/dev/null || echo "0")
                # Also check tag-based assignment
                local droplet_tags=$(echo "$droplets_json" | jq -r ".[$i].tags[]?" 2>/dev/null || echo "")
                local tag_covered=false
                for tag in $droplet_tags; do
                    local tag_match=$(echo "$firewalls_json" | jq --arg t "$tag" '[.[] | select(.tags[]? == $t)] | length' 2>/dev/null || echo "0")
                    if [ "$tag_match" != "0" ]; then
                        tag_covered=true
                        break
                    fi
                done

                if [ "$is_covered" != "0" ] || [ "$tag_covered" = true ]; then
                    in_firewall=true
                fi
            fi

            if [ "$in_firewall" = false ]; then
                droplets_without_firewall+=("$droplet_name")
            fi
        done

        if [ ${#droplets_without_firewall[@]} -gt 0 ]; then
            local dl_list=$(printf '"%s",' "${droplets_without_firewall[@]}" | sed 's/,$//')
            add_finding "networking" "NET-001" "critical" \
                "Droplets without Cloud Firewall protection" \
                "${#droplets_without_firewall[@]} Droplet(s) are not protected by any Cloud Firewall" \
                "[$dl_list]" \
                "Create and assign Cloud Firewalls to all Droplets. Use doctl compute firewall create with appropriate inbound/outbound rules." \
                "[\"CIS 5.1\",\"ISO27001 A.13.1.1\",\"SOC2 CC6.6\",\"CCSS 5.1\"]"
            print_finding "critical" "${#droplets_without_firewall[@]} Droplet(s) without firewall protection"
        else
            add_pass
            print_finding "pass" "All Droplets are protected by Cloud Firewalls"
        fi
    fi

    # NET-002: Overly permissive firewall rules
    print_status "  Checking firewall rule permissiveness..."
    local overly_permissive_firewalls=()

    if [ "$firewall_count" != "0" ] && [ "$firewall_count" != "" ]; then
        for i in $(seq 0 $((firewall_count - 1))); do
            local fw_name=$(echo "$firewalls_json" | jq -r ".[$i].name" 2>/dev/null)

            # Check for inbound rules allowing all TCP from 0.0.0.0/0
            local has_open_all=$(echo "$firewalls_json" | jq -r "
                .[$i].inbound_rules[]? |
                select(.protocol == \"tcp\" and .ports == \"all\" and
                    (.sources.addresses[]? == \"0.0.0.0/0\" or .sources.addresses[]? == \"::/0\")
                ) | .protocol" 2>/dev/null || echo "")

            if [ -n "$has_open_all" ]; then
                overly_permissive_firewalls+=("$fw_name")
            fi
        done

        if [ ${#overly_permissive_firewalls[@]} -gt 0 ]; then
            local fw_list=$(printf '"%s",' "${overly_permissive_firewalls[@]}" | sed 's/,$//')
            add_finding "networking" "NET-002" "critical" \
                "Cloud Firewalls with overly permissive rules" \
                "${#overly_permissive_firewalls[@]} firewall(s) allow all TCP traffic from anywhere" \
                "[$fw_list]" \
                "Restrict inbound rules to only required ports and source IPs. Apply principle of least privilege." \
                "[\"CIS 5.2\",\"ISO27001 A.13.1.1\",\"SOC2 CC6.6\",\"CCSS 5.1\"]"
            print_finding "critical" "${#overly_permissive_firewalls[@]} firewall(s) with overly permissive rules"
        else
            add_pass
            print_finding "pass" "No overly permissive firewall rules found"
        fi
    fi

    # NET-003: SSH open to world in firewalls
    print_status "  Checking SSH access restrictions..."
    local ssh_open_firewalls=()

    if [ "$firewall_count" != "0" ] && [ "$firewall_count" != "" ]; then
        for i in $(seq 0 $((firewall_count - 1))); do
            local fw_name=$(echo "$firewalls_json" | jq -r ".[$i].name" 2>/dev/null)

            local has_open_ssh=$(echo "$firewalls_json" | jq -r "
                .[$i].inbound_rules[]? |
                select(.protocol == \"tcp\" and .ports == \"22\" and
                    (.sources.addresses[]? == \"0.0.0.0/0\" or .sources.addresses[]? == \"::/0\")
                ) | .protocol" 2>/dev/null || echo "")

            if [ -n "$has_open_ssh" ]; then
                ssh_open_firewalls+=("$fw_name")
            fi
        done

        if [ ${#ssh_open_firewalls[@]} -gt 0 ]; then
            local fw_list=$(printf '"%s",' "${ssh_open_firewalls[@]}" | sed 's/,$//')
            add_finding "networking" "NET-003" "high" \
                "Cloud Firewalls with SSH open to the world" \
                "${#ssh_open_firewalls[@]} firewall(s) allow SSH (port 22) from 0.0.0.0/0" \
                "[$fw_list]" \
                "Restrict SSH access to specific IP addresses or CIDR ranges. Consider using a VPN or bastion host." \
                "[\"CIS 5.2\",\"ISO27001 A.13.1.1\",\"SOC2 CC6.6\",\"CCSS 5.1\"]"
            print_finding "high" "${#ssh_open_firewalls[@]} firewall(s) with SSH open to world"
        else
            add_pass
            print_finding "pass" "No firewalls with SSH open to the world"
        fi
    fi

    # NET-004: Load balancer configuration
    print_status "  Checking load balancer security..."
    local lbs_json=$(doctl compute load-balancer list --output json 2>/dev/null || echo "[]")
    local lb_count=$(echo "$lbs_json" | jq 'length' 2>/dev/null || echo "0")

    if [ "$lb_count" != "0" ] && [ "$lb_count" != "" ]; then
        local lbs_without_ssl=()
        local lbs_without_proxy_protocol=()
        local lbs_without_redirect=()

        for i in $(seq 0 $((lb_count - 1))); do
            local lb_name=$(echo "$lbs_json" | jq -r ".[$i].name" 2>/dev/null)

            # Check for HTTPS forwarding rules
            local has_https=$(echo "$lbs_json" | jq -r ".[$i].forwarding_rules[]? | select(.entry_protocol == \"https\" or .entry_protocol == \"http2\") | .entry_protocol" 2>/dev/null || echo "")
            if [ -z "$has_https" ]; then
                lbs_without_ssl+=("$lb_name")
            fi

            # Check redirect HTTP to HTTPS
            local has_redirect=$(echo "$lbs_json" | jq -r ".[$i].redirect_http_to_https // false" 2>/dev/null)
            if [ "$has_redirect" = "false" ]; then
                local has_http=$(echo "$lbs_json" | jq -r ".[$i].forwarding_rules[]? | select(.entry_protocol == \"http\") | .entry_protocol" 2>/dev/null || echo "")
                if [ -n "$has_http" ]; then
                    lbs_without_redirect+=("$lb_name")
                fi
            fi

            # Check proxy protocol
            local proxy_protocol=$(echo "$lbs_json" | jq -r ".[$i].enable_proxy_protocol // false" 2>/dev/null)
            if [ "$proxy_protocol" = "false" ]; then
                lbs_without_proxy_protocol+=("$lb_name")
            fi
        done

        if [ ${#lbs_without_ssl[@]} -gt 0 ]; then
            local lb_list=$(printf '"%s",' "${lbs_without_ssl[@]}" | sed 's/,$//')
            add_finding "networking" "NET-004" "high" \
                "Load balancers without HTTPS" \
                "${#lbs_without_ssl[@]} load balancer(s) do not have HTTPS forwarding rules" \
                "[$lb_list]" \
                "Add HTTPS forwarding rules with SSL certificates to all load balancers handling web traffic." \
                "[\"ISO27001 A.14.1.2\",\"SOC2 CC6.7\",\"CCSS 5.2\"]"
            print_finding "high" "${#lbs_without_ssl[@]} load balancer(s) without HTTPS"
        else
            add_pass
            print_finding "pass" "All load balancers have HTTPS configured"
        fi

        if [ ${#lbs_without_redirect[@]} -gt 0 ]; then
            local lb_list=$(printf '"%s",' "${lbs_without_redirect[@]}" | sed 's/,$//')
            add_finding "networking" "NET-005" "medium" \
                "Load balancers without HTTP to HTTPS redirect" \
                "${#lbs_without_redirect[@]} load balancer(s) do not redirect HTTP to HTTPS" \
                "[$lb_list]" \
                "Enable redirect_http_to_https on load balancers to enforce encrypted connections." \
                "[\"ISO27001 A.14.1.2\",\"SOC2 CC6.7\"]"
            print_finding "medium" "${#lbs_without_redirect[@]} load balancer(s) without HTTP->HTTPS redirect"
        else
            add_pass
            print_finding "pass" "All load balancers redirect HTTP to HTTPS"
        fi
    else
        print_status "  No load balancers found"
    fi

    # NET-006: VPC configuration
    print_status "  Checking VPC configuration..."
    local vpcs_json=$(doctl vpcs list --output json 2>/dev/null || echo "[]")
    local vpc_count=$(echo "$vpcs_json" | jq 'length' 2>/dev/null || echo "0")

    if [ "$vpc_count" = "0" ] || [ "$vpc_count" = "1" ]; then
        # Only default VPC or none - check if droplets exist that should be segmented
        if [ "$droplet_count" != "0" ] && [ "$droplet_count" != "" ] && [ "$droplet_count" -gt 5 ] 2>/dev/null; then
            add_finding "networking" "NET-006" "medium" \
                "No custom VPC network segmentation" \
                "Account has $droplet_count Droplets but only uses the default VPC. Consider network segmentation." \
                "[]" \
                "Create custom VPCs to segment workloads (e.g., production, staging, databases). Use doctl vpcs create." \
                "[\"ISO27001 A.13.1.3\",\"SOC2 CC6.6\",\"CCSS 5.3\"]"
            print_finding "medium" "No custom VPC network segmentation with $droplet_count Droplets"
        else
            add_pass
            print_finding "pass" "VPC configuration appropriate for current workload"
        fi
    else
        add_pass
        print_finding "pass" "Custom VPCs configured for network segmentation ($vpc_count VPCs)"
    fi
}

# ============================================================================
# Storage Checks (Spaces)
# ============================================================================

check_storage() {
    print_status "Checking Storage Security (Spaces)..."

    # Get Spaces buckets - doctl does not have a direct spaces list, use s3cmd-compatible API via doctl
    # Spaces are accessed via: doctl compute cdn list (for CDN) and the Spaces API
    # We check via regions where Spaces are available

    local spaces_regions=("nyc3" "sfo3" "ams3" "sgp1" "fra1" "syd1")
    local all_spaces=()

    # Try to list Spaces - doctl doesn't have native spaces list, checking CDN endpoints
    # and using the registry/monitoring endpoints as proxies
    # Note: For Spaces, we check CDN and CORS configs

    # STO-001: Check CDN-connected Spaces
    print_status "  Checking Spaces CDN configuration..."
    local cdns_json=$(doctl compute cdn list --output json 2>/dev/null || echo "[]")
    local cdn_count=$(echo "$cdns_json" | jq 'length' 2>/dev/null || echo "0")

    if [ "$cdn_count" != "0" ] && [ "$cdn_count" != "" ]; then
        local cdns_without_custom_domain=()
        local cdns_without_ttl=()

        for i in $(seq 0 $((cdn_count - 1))); do
            local cdn_id=$(echo "$cdns_json" | jq -r ".[$i].id" 2>/dev/null)
            local cdn_origin=$(echo "$cdns_json" | jq -r ".[$i].origin" 2>/dev/null)
            local cdn_domain=$(echo "$cdns_json" | jq -r ".[$i].custom_domain // empty" 2>/dev/null)
            local cdn_ttl=$(echo "$cdns_json" | jq -r ".[$i].ttl // 0" 2>/dev/null)

            if [ -z "$cdn_domain" ]; then
                cdns_without_custom_domain+=("$cdn_origin")
            fi

            if [ "$cdn_ttl" = "0" ]; then
                cdns_without_ttl+=("$cdn_origin")
            fi
        done

        if [ ${#cdns_without_custom_domain[@]} -gt 0 ]; then
            local cdn_list=$(printf '"%s",' "${cdns_without_custom_domain[@]}" | sed 's/,$//')
            add_finding "storage" "STO-001" "low" \
                "CDN endpoints without custom domain" \
                "${#cdns_without_custom_domain[@]} CDN endpoint(s) use default DigitalOcean domain instead of custom domain" \
                "[$cdn_list]" \
                "Configure custom domains with SSL certificates for CDN endpoints to maintain brand consistency and enable custom SSL." \
                "[\"ISO27001 A.14.1.2\",\"SOC2 CC6.7\"]"
            print_finding "low" "${#cdns_without_custom_domain[@]} CDN endpoint(s) without custom domain"
        else
            add_pass
            print_finding "pass" "All CDN endpoints have custom domains"
        fi
    else
        print_status "  No CDN endpoints found"
    fi

    # STO-002: Check for public Spaces access via CORS
    # Since doctl doesn't have direct Spaces CORS check, we check if Spaces have CDN (publicly intended)
    # vs those without CDN that might be unintentionally public
    print_status "  Checking Spaces access patterns..."

    # Use doctl to check for any publicly accessible Spaces by examining CDN origins
    if [ "$cdn_count" != "0" ] && [ "$cdn_count" != "" ]; then
        local public_spaces=()
        for i in $(seq 0 $((cdn_count - 1))); do
            local cdn_origin=$(echo "$cdns_json" | jq -r ".[$i].origin" 2>/dev/null)
            local cdn_cert=$(echo "$cdns_json" | jq -r ".[$i].certificate_id // empty" 2>/dev/null)
            if [ -z "$cdn_cert" ] && [ -n "$cdn_origin" ]; then
                public_spaces+=("$cdn_origin")
            fi
        done

        if [ ${#public_spaces[@]} -gt 0 ]; then
            local space_list=$(printf '"%s",' "${public_spaces[@]}" | sed 's/,$//')
            add_finding "storage" "STO-002" "medium" \
                "CDN Spaces endpoints without SSL certificate" \
                "${#public_spaces[@]} Spaces CDN endpoint(s) do not have a custom SSL certificate configured" \
                "[$space_list]" \
                "Upload or provision an SSL certificate and attach it to the CDN endpoint for secure content delivery." \
                "[\"ISO27001 A.14.1.2\",\"SOC2 CC6.7\",\"CCSS 5.2\"]"
            print_finding "medium" "${#public_spaces[@]} CDN Spaces without SSL certificate"
        else
            add_pass
            print_finding "pass" "All CDN Spaces have SSL certificates configured"
        fi
    fi

    # STO-003: Container Registry security
    print_status "  Checking Container Registry..."
    local registry_json=$(doctl registry get --output json 2>/dev/null || echo "")

    if [ -n "$registry_json" ] && [ "$registry_json" != "" ] && [ "$registry_json" != "null" ]; then
        local registry_name=$(echo "$registry_json" | jq -r '.name // empty' 2>/dev/null)

        if [ -n "$registry_name" ]; then
            # Check garbage collection status
            local gc_json=$(doctl registry garbage-collection get-active --output json 2>/dev/null || echo "")
            local repos_json=$(doctl registry repository list-v2 --output json 2>/dev/null || echo "[]")
            local repo_count=$(echo "$repos_json" | jq 'length' 2>/dev/null || echo "0")

            if [ "$repo_count" != "0" ]; then
                # Check for images without tags (dangling)
                local untagged_count=0
                for j in $(seq 0 $((repo_count - 1))); do
                    local manifests=$(echo "$repos_json" | jq -r ".[$j].tag_count // 0" 2>/dev/null)
                done

                add_pass
                print_finding "pass" "Container Registry found: $registry_name ($repo_count repositories)"
            else
                add_pass
                print_finding "pass" "Container Registry configured (no repositories yet)"
            fi
        fi
    else
        print_status "  No Container Registry configured"
    fi
}

# ============================================================================
# Droplet Checks
# ============================================================================

check_droplets() {
    print_status "Checking Droplet Security..."

    local droplets_json=$(doctl compute droplet list --output json 2>/dev/null || echo "[]")
    local droplet_count=$(echo "$droplets_json" | jq 'length' 2>/dev/null || echo "0")

    if [ "$droplet_count" = "0" ] || [ "$droplet_count" = "" ]; then
        print_status "  No Droplets found"
        return
    fi

    print_status "  Found $droplet_count Droplet(s)"

    # DRP-001: Droplets without SSH keys (password auth)
    print_status "  Checking SSH key authentication..."
    local password_auth_droplets=()

    # Get all SSH keys on the account
    local ssh_keys_json=$(doctl compute ssh-key list --output json 2>/dev/null || echo "[]")
    local ssh_key_count=$(echo "$ssh_keys_json" | jq 'length' 2>/dev/null || echo "0")

    if [ "$ssh_key_count" = "0" ]; then
        add_finding "droplets" "DRP-001" "critical" \
            "No SSH keys configured on account" \
            "No SSH keys are registered with the DigitalOcean account. Droplets may be using password authentication only." \
            "[]" \
            "Add SSH keys to your account using doctl compute ssh-key create. Recreate Droplets with SSH key authentication." \
            "[\"CIS 5.3\",\"ISO27001 A.9.4.2\",\"SOC2 CC6.1\",\"CCSS 4.1\"]"
        print_finding "critical" "No SSH keys configured on account"
    else
        add_pass
        print_finding "pass" "SSH keys configured on account ($ssh_key_count key(s))"
    fi

    # DRP-002: Droplets without backups enabled
    print_status "  Checking Droplet backups..."
    local no_backup_droplets=()

    for i in $(seq 0 $((droplet_count - 1))); do
        local d_name=$(echo "$droplets_json" | jq -r ".[$i].name" 2>/dev/null)
        local d_backups=$(echo "$droplets_json" | jq -r ".[$i].features[]?" 2>/dev/null | grep -c "backups" || echo "0")

        if [ "$d_backups" = "0" ]; then
            no_backup_droplets+=("$d_name")
        fi
    done

    if [ ${#no_backup_droplets[@]} -gt 0 ]; then
        local d_list=$(printf '"%s",' "${no_backup_droplets[@]}" | sed 's/,$//')
        add_finding "droplets" "DRP-002" "high" \
            "Droplets without automated backups" \
            "${#no_backup_droplets[@]} Droplet(s) do not have automated backups enabled" \
            "[$d_list]" \
            "Enable automated backups for all production Droplets. Cost is 20% of Droplet price. Use doctl compute droplet-action enable-backups <droplet-id>." \
            "[\"ISO27001 A.17.1.1\",\"SOC2 CC9.1\",\"CCSS 7.1\"]"
        print_finding "high" "${#no_backup_droplets[@]} Droplet(s) without backups"
    else
        add_pass
        print_finding "pass" "All Droplets have automated backups enabled"
    fi

    # DRP-003: Droplets without monitoring
    print_status "  Checking Droplet monitoring..."
    local no_monitoring_droplets=()

    for i in $(seq 0 $((droplet_count - 1))); do
        local d_name=$(echo "$droplets_json" | jq -r ".[$i].name" 2>/dev/null)
        local d_monitoring=$(echo "$droplets_json" | jq -r ".[$i].features[]?" 2>/dev/null | grep -c "monitoring" || echo "0")

        if [ "$d_monitoring" = "0" ]; then
            no_monitoring_droplets+=("$d_name")
        fi
    done

    if [ ${#no_monitoring_droplets[@]} -gt 0 ]; then
        local d_list=$(printf '"%s",' "${no_monitoring_droplets[@]}" | sed 's/,$//')
        add_finding "droplets" "DRP-003" "medium" \
            "Droplets without monitoring agent" \
            "${#no_monitoring_droplets[@]} Droplet(s) do not have the monitoring agent enabled" \
            "[$d_list]" \
            "Enable monitoring on Droplets for visibility into CPU, memory, disk, and network usage. Install the DigitalOcean monitoring agent." \
            "[\"ISO27001 A.12.4.1\",\"SOC2 CC7.2\",\"CCSS 6.1\"]"
        print_finding "medium" "${#no_monitoring_droplets[@]} Droplet(s) without monitoring"
    else
        add_pass
        print_finding "pass" "All Droplets have monitoring enabled"
    fi

    # DRP-004: Droplets not in a VPC (or in default VPC only)
    print_status "  Checking Droplet VPC placement..."
    local default_vpc_only_droplets=()
    local vpcs_json=$(doctl vpcs list --output json 2>/dev/null || echo "[]")
    local default_vpc_uuid=""

    # Find the default VPC
    local vpc_count=$(echo "$vpcs_json" | jq 'length' 2>/dev/null || echo "0")
    for v in $(seq 0 $((vpc_count - 1))); do
        local is_default=$(echo "$vpcs_json" | jq -r ".[$v].default" 2>/dev/null)
        if [ "$is_default" = "true" ]; then
            default_vpc_uuid=$(echo "$vpcs_json" | jq -r ".[$v].id" 2>/dev/null)
            break
        fi
    done

    if [ -n "$default_vpc_uuid" ] && [ "$vpc_count" -gt 1 ] 2>/dev/null; then
        for i in $(seq 0 $((droplet_count - 1))); do
            local d_name=$(echo "$droplets_json" | jq -r ".[$i].name" 2>/dev/null)
            local d_vpc=$(echo "$droplets_json" | jq -r ".[$i].vpc_uuid" 2>/dev/null)

            if [ "$d_vpc" = "$default_vpc_uuid" ]; then
                default_vpc_only_droplets+=("$d_name")
            fi
        done

        if [ ${#default_vpc_only_droplets[@]} -gt 0 ]; then
            local d_list=$(printf '"%s",' "${default_vpc_only_droplets[@]}" | sed 's/,$//')
            add_finding "droplets" "DRP-004" "low" \
                "Droplets in default VPC despite custom VPCs existing" \
                "${#default_vpc_only_droplets[@]} Droplet(s) are in the default VPC. Consider placing them in purpose-specific VPCs for segmentation." \
                "[$d_list]" \
                "Migrate Droplets to custom VPCs for better network segmentation. Droplets must be rebuilt to change VPC." \
                "[\"ISO27001 A.13.1.3\",\"SOC2 CC6.6\",\"CCSS 5.3\"]"
            print_finding "low" "${#default_vpc_only_droplets[@]} Droplet(s) in default VPC"
        else
            add_pass
            print_finding "pass" "All Droplets are placed in custom VPCs"
        fi
    else
        add_pass
        print_finding "pass" "Droplet VPC placement is appropriate"
    fi

    # DRP-005: Droplet public IPv4 exposure
    print_status "  Checking public IP exposure..."
    local public_droplets=()

    for i in $(seq 0 $((droplet_count - 1))); do
        local d_name=$(echo "$droplets_json" | jq -r ".[$i].name" 2>/dev/null)
        local has_public_ipv4=$(echo "$droplets_json" | jq -r ".[$i].networks.v4[]? | select(.type == \"public\") | .ip_address" 2>/dev/null || echo "")

        if [ -n "$has_public_ipv4" ]; then
            public_droplets+=("$d_name")
        fi
    done

    if [ ${#public_droplets[@]} -gt 0 ]; then
        local d_list=$(printf '"%s",' "${public_droplets[@]}" | sed 's/,$//')
        add_finding "droplets" "DRP-005" "medium" \
            "Droplets with public IPv4 addresses" \
            "${#public_droplets[@]} Droplet(s) have public IPv4 addresses. Review if public exposure is necessary." \
            "[$d_list]" \
            "Where possible, place Droplets behind a load balancer or use a VPN. Remove public IPs from backend services that do not need direct internet access." \
            "[\"ISO27001 A.13.1.1\",\"SOC2 CC6.6\"]"
        print_finding "medium" "${#public_droplets[@]} Droplet(s) with public IPs"
    else
        add_pass
        print_finding "pass" "No Droplets with unnecessary public IPs"
    fi

    # DRP-006: Droplet user data / cloud-init check
    print_status "  Checking Droplet user data..."
    local droplets_with_user_data_secrets=()

    for i in $(seq 0 $((droplet_count - 1))); do
        local d_name=$(echo "$droplets_json" | jq -r ".[$i].name" 2>/dev/null)
        local d_id=$(echo "$droplets_json" | jq -r ".[$i].id" 2>/dev/null)

        # Note: user_data is only available at creation time and stored in metadata
        # We can check via the metadata endpoint concept but doctl doesn't expose user_data directly
        # Instead we flag if droplets were created with user_data enabled (a best-effort check)
        # The image slug can give hints about custom images vs standard
        local d_image=$(echo "$droplets_json" | jq -r ".[$i].image.slug // .[$i].image.name // empty" 2>/dev/null)
        # This is informational - user_data review must be done at creation time
    done

    # Informational pass - can't inspect user_data post-creation via doctl
    add_pass
    print_finding "pass" "Droplet user data review (manual inspection recommended at creation time)"

    # DRP-007: Outdated Droplet images
    print_status "  Checking Droplet image currency..."
    local outdated_image_droplets=()

    for i in $(seq 0 $((droplet_count - 1))); do
        local d_name=$(echo "$droplets_json" | jq -r ".[$i].name" 2>/dev/null)
        local d_image_slug=$(echo "$droplets_json" | jq -r ".[$i].image.slug // empty" 2>/dev/null)
        local d_image_name=$(echo "$droplets_json" | jq -r ".[$i].image.name // empty" 2>/dev/null)
        local d_image_distro=$(echo "$droplets_json" | jq -r ".[$i].image.distribution // empty" 2>/dev/null)

        # Check for known EOL distributions
        local is_outdated=false
        case "$d_image_slug" in
            ubuntu-16*|ubuntu-18*|debian-9*|debian-10*|centos-7*|centos-8*|fedora-3[0-6]*)
                is_outdated=true
                ;;
        esac
        # Also check by name if slug is empty
        if [ -z "$d_image_slug" ]; then
            case "$d_image_name" in
                *"Ubuntu 16"*|*"Ubuntu 18"*|*"Debian 9"*|*"Debian 10"*|*"CentOS 7"*|*"CentOS 8"*)
                    is_outdated=true
                    ;;
            esac
        fi

        if [ "$is_outdated" = true ]; then
            outdated_image_droplets+=("$d_name ($d_image_slug$d_image_name)")
        fi
    done

    if [ ${#outdated_image_droplets[@]} -gt 0 ]; then
        local d_list=$(printf '"%s",' "${outdated_image_droplets[@]}" | sed 's/,$//')
        add_finding "droplets" "DRP-007" "high" \
            "Droplets running end-of-life OS images" \
            "${#outdated_image_droplets[@]} Droplet(s) are running end-of-life or outdated operating system images" \
            "[$d_list]" \
            "Rebuild Droplets using current LTS or supported OS images to ensure security patches are available." \
            "[\"ISO27001 A.14.2.2\",\"SOC2 CC7.1\",\"CCSS 2.2\"]"
        print_finding "high" "${#outdated_image_droplets[@]} Droplet(s) with outdated OS images"
    else
        add_pass
        print_finding "pass" "All Droplets are running supported OS images"
    fi
}

# ============================================================================
# DNS / Domain Checks
# ============================================================================

check_dns() {
    print_status "Checking DNS & Domain Security..."

    # Get all domains
    local domains_json=$(doctl compute domain list --output json 2>/dev/null || echo "[]")
    local domain_count=$(echo "$domains_json" | jq 'length' 2>/dev/null || echo "0")

    if [ "$domain_count" = "0" ] || [ "$domain_count" = "" ]; then
        print_status "  No domains found"
        return
    fi

    print_status "  Found $domain_count domain(s)"

    # DNS-001: Check for DNSSEC (informational - DO manages DNS but DNSSEC may not be available)
    print_status "  Checking DNSSEC status..."
    # DigitalOcean DNS does not support DNSSEC natively
    # Flag this as informational if domains are hosted on DO DNS
    local do_hosted_domains=()

    for i in $(seq 0 $((domain_count - 1))); do
        local domain_name=$(echo "$domains_json" | jq -r ".[$i].name" 2>/dev/null)
        do_hosted_domains+=("$domain_name")
    done

    if [ ${#do_hosted_domains[@]} -gt 0 ]; then
        local domain_list=$(printf '"%s",' "${do_hosted_domains[@]}" | sed 's/,$//')
        add_finding "dns" "DNS-001" "low" \
            "Domains on DigitalOcean DNS without DNSSEC" \
            "${#do_hosted_domains[@]} domain(s) are hosted on DigitalOcean DNS which does not support DNSSEC natively" \
            "[$domain_list]" \
            "Consider using a DNS provider that supports DNSSEC (e.g., Cloudflare, AWS Route53) for domains requiring DNSSEC. Alternatively, use DNSSEC at the registrar level." \
            "[\"ISO27001 A.13.1.1\",\"SOC2 CC6.7\",\"CCSS 5.2\"]"
        print_finding "low" "${#do_hosted_domains[@]} domain(s) without DNSSEC (DO DNS limitation)"
    fi

    # DNS-002: Check for SPF/DKIM/DMARC records
    print_status "  Checking email security records..."
    local domains_without_spf=()
    local domains_without_dmarc=()

    for i in $(seq 0 $((domain_count - 1))); do
        local domain_name=$(echo "$domains_json" | jq -r ".[$i].name" 2>/dev/null)

        # Get DNS records for domain
        local records_json=$(doctl compute domain records list "$domain_name" --output json 2>/dev/null || echo "[]")

        # Check for SPF record
        local has_spf=$(echo "$records_json" | jq '[.[] | select(.type == "TXT" and (.data | test("v=spf1")))] | length' 2>/dev/null || echo "0")
        if [ "$has_spf" = "0" ]; then
            domains_without_spf+=("$domain_name")
        fi

        # Check for DMARC record
        local has_dmarc=$(echo "$records_json" | jq '[.[] | select(.type == "TXT" and (.name | test("_dmarc")) and (.data | test("v=DMARC1")))] | length' 2>/dev/null || echo "0")
        if [ "$has_dmarc" = "0" ]; then
            domains_without_dmarc+=("$domain_name")
        fi
    done

    if [ ${#domains_without_spf[@]} -gt 0 ]; then
        local domain_list=$(printf '"%s",' "${domains_without_spf[@]}" | sed 's/,$//')
        add_finding "dns" "DNS-002" "medium" \
            "Domains without SPF records" \
            "${#domains_without_spf[@]} domain(s) do not have SPF records configured" \
            "[$domain_list]" \
            "Add SPF TXT records to prevent email spoofing. Example: v=spf1 include:_spf.google.com ~all" \
            "[\"ISO27001 A.13.2.1\",\"SOC2 CC6.7\"]"
        print_finding "medium" "${#domains_without_spf[@]} domain(s) without SPF records"
    else
        add_pass
        print_finding "pass" "All domains have SPF records"
    fi

    if [ ${#domains_without_dmarc[@]} -gt 0 ]; then
        local domain_list=$(printf '"%s",' "${domains_without_dmarc[@]}" | sed 's/,$//')
        add_finding "dns" "DNS-003" "medium" \
            "Domains without DMARC records" \
            "${#domains_without_dmarc[@]} domain(s) do not have DMARC records configured" \
            "[$domain_list]" \
            "Add DMARC TXT records at _dmarc.<domain>. Example: v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com" \
            "[\"ISO27001 A.13.2.1\",\"SOC2 CC6.7\"]"
        print_finding "medium" "${#domains_without_dmarc[@]} domain(s) without DMARC records"
    else
        add_pass
        print_finding "pass" "All domains have DMARC records"
    fi

    # DNS-004: SSL Certificates
    print_status "  Checking SSL certificates..."
    local certs_json=$(doctl compute certificate list --output json 2>/dev/null || echo "[]")
    local cert_count=$(echo "$certs_json" | jq 'length' 2>/dev/null || echo "0")

    if [ "$cert_count" != "0" ] && [ "$cert_count" != "" ]; then
        local expiring_certs=()
        local current_epoch=$(date +%s)
        local thirty_days=$((30 * 24 * 60 * 60))

        for i in $(seq 0 $((cert_count - 1))); do
            local cert_name=$(echo "$certs_json" | jq -r ".[$i].name" 2>/dev/null)
            local cert_expiry=$(echo "$certs_json" | jq -r ".[$i].not_after // empty" 2>/dev/null)
            local cert_state=$(echo "$certs_json" | jq -r ".[$i].state // empty" 2>/dev/null)

            if [ -n "$cert_expiry" ]; then
                local expiry_epoch=$(date -j -f "%Y-%m-%dT%H:%M:%SZ" "$cert_expiry" +%s 2>/dev/null || date -d "$cert_expiry" +%s 2>/dev/null || echo "0")
                local time_left=$((expiry_epoch - current_epoch))

                if [ "$time_left" -lt "$thirty_days" ] && [ "$time_left" -gt 0 ]; then
                    expiring_certs+=("$cert_name (expires: $cert_expiry)")
                elif [ "$time_left" -le 0 ]; then
                    expiring_certs+=("$cert_name (EXPIRED: $cert_expiry)")
                fi
            fi
        done

        if [ ${#expiring_certs[@]} -gt 0 ]; then
            local cert_list=$(printf '"%s",' "${expiring_certs[@]}" | sed 's/,$//')
            add_finding "dns" "DNS-004" "high" \
                "SSL certificates expiring soon or expired" \
                "${#expiring_certs[@]} SSL certificate(s) are expiring within 30 days or already expired" \
                "[$cert_list]" \
                "Renew SSL certificates before expiry. Use Let's Encrypt auto-renewing certificates where possible." \
                "[\"ISO27001 A.14.1.2\",\"SOC2 CC6.7\",\"CCSS 5.2\"]"
            print_finding "high" "${#expiring_certs[@]} certificate(s) expiring soon or expired"
        else
            add_pass
            print_finding "pass" "All SSL certificates are valid with sufficient time remaining"
        fi
    else
        print_status "  No SSL certificates managed in DigitalOcean"
    fi
}

# ============================================================================
# Access Control Checks
# ============================================================================

check_access_control() {
    print_status "Checking Access Control..."

    # ACL-001: Account 2FA enforcement
    print_status "  Checking account two-factor authentication..."
    local account_json=$(doctl account get --output json 2>/dev/null || echo "{}")

    # doctl account get returns team info if available
    # Check if 2FA is mentioned in the account status
    local account_status=$(echo "$account_json" | jq -r '.status // empty' 2>/dev/null)
    # Note: doctl doesn't directly expose 2FA status, but we can check via API
    # For now we check what's available

    # Try to get team member information (requires team access)
    local team_json=$(doctl account get --output json 2>/dev/null || echo "{}")
    local email_verified=$(echo "$team_json" | jq -r '.email_verified // false' 2>/dev/null)

    # Informational check - recommend 2FA
    add_finding "access_control" "ACL-001" "high" \
        "Verify two-factor authentication is enabled" \
        "Ensure 2FA is enabled for all team members with access to the DigitalOcean account. This cannot be fully verified via API." \
        "[]" \
        "Enable 2FA for all team members in DigitalOcean account settings. Enforce 2FA at the team/organization level. Visit: https://cloud.digitalocean.com/account/security" \
        "[\"CIS 1.5\",\"ISO27001 A.9.4.2\",\"SOC2 CC6.1\",\"CCSS 4.1\"]"
    print_finding "high" "Verify 2FA is enabled for all team members (manual check)"

    # ACL-002: API token audit
    print_status "  Checking API token security..."
    # doctl doesn't expose token listing (security by design)
    # We can check if the current token has write access by attempting to detect scope

    # Check if token has write access (if it can list SSH keys and potentially create, it's read-write)
    local can_write=false
    # We test by checking account info scope indicators
    local droplet_limit=$(echo "$account_json" | jq -r '.droplet_limit // 0' 2>/dev/null)

    # Best practice recommendation
    add_finding "access_control" "ACL-002" "medium" \
        "Review API token scopes and rotation" \
        "Ensure API tokens follow least privilege. Use read-only tokens for monitoring and auditing. Rotate tokens regularly." \
        "[]" \
        "Review all API tokens at https://cloud.digitalocean.com/account/api/tokens. Delete unused tokens. Use scoped tokens (read-only where possible). Rotate tokens every 90 days." \
        "[\"CIS 1.14\",\"ISO27001 A.9.2.5\",\"SOC2 CC6.1\",\"CCSS 4.2\"]"
    print_finding "medium" "Review API token scopes and rotation (manual check recommended)"

    # ACL-003: SSH key audit
    print_status "  Checking SSH key hygiene..."
    local ssh_keys_json=$(doctl compute ssh-key list --output json 2>/dev/null || echo "[]")
    local key_count=$(echo "$ssh_keys_json" | jq 'length' 2>/dev/null || echo "0")

    if [ "$key_count" != "0" ] && [ "$key_count" != "" ]; then
        local weak_keys=()

        for i in $(seq 0 $((key_count - 1))); do
            local key_name=$(echo "$ssh_keys_json" | jq -r ".[$i].name" 2>/dev/null)
            local key_fingerprint=$(echo "$ssh_keys_json" | jq -r ".[$i].fingerprint" 2>/dev/null)
            local public_key=$(echo "$ssh_keys_json" | jq -r ".[$i].public_key" 2>/dev/null)

            # Check key type and size
            local key_type=$(echo "$public_key" | awk '{print $1}')
            case "$key_type" in
                ssh-dss|ssh-dsa)
                    weak_keys+=("$key_name (DSA - deprecated)")
                    ;;
                ssh-rsa)
                    # RSA keys should be at least 3072 bits for current security
                    # We can approximate by checking key length
                    local key_length=${#public_key}
                    if [ "$key_length" -lt 400 ]; then
                        weak_keys+=("$key_name (RSA - potentially weak)")
                    fi
                    ;;
            esac
        done

        if [ ${#weak_keys[@]} -gt 0 ]; then
            local key_list=$(printf '"%s",' "${weak_keys[@]}" | sed 's/,$//')
            add_finding "access_control" "ACL-003" "medium" \
                "Weak SSH key algorithms detected" \
                "${#weak_keys[@]} SSH key(s) use weak or deprecated algorithms" \
                "[$key_list]" \
                "Replace DSA and short RSA keys with Ed25519 or RSA 4096-bit keys. Generate with: ssh-keygen -t ed25519" \
                "[\"CIS 5.3\",\"ISO27001 A.10.1.1\",\"SOC2 CC6.1\",\"CCSS 4.1\"]"
            print_finding "medium" "${#weak_keys[@]} SSH key(s) with weak algorithms"
        else
            add_pass
            print_finding "pass" "All SSH keys use strong algorithms"
        fi
    fi

    # ACL-004: Team access review
    print_status "  Checking team access..."
    # DigitalOcean Teams API is limited via doctl, recommend manual review
    add_finding "access_control" "ACL-004" "low" \
        "Review team member access" \
        "Periodically review team member access and roles. Remove access for departed team members. This requires manual review." \
        "[]" \
        "Review team access at https://cloud.digitalocean.com/account/team. Remove inactive members. Apply least-privilege roles." \
        "[\"CIS 1.16\",\"ISO27001 A.9.2.6\",\"SOC2 CC6.2\",\"CCSS 4.3\"]"
    print_finding "low" "Review team member access (manual review recommended)"

    # ACL-005: Project organization
    print_status "  Checking project organization..."
    local projects_json=$(doctl projects list --output json 2>/dev/null || echo "[]")
    local project_count=$(echo "$projects_json" | jq 'length' 2>/dev/null || echo "0")

    if [ "$project_count" -le 1 ] 2>/dev/null; then
        local total_resources=$(doctl compute droplet list --output json 2>/dev/null | jq 'length' 2>/dev/null || echo "0")
        local total_dbs=$(doctl databases list --output json 2>/dev/null | jq 'length' 2>/dev/null || echo "0")
        local total_count=$((total_resources + total_dbs))

        if [ "$total_count" -gt 5 ]; then
            add_finding "access_control" "ACL-005" "low" \
                "Resources not organized into projects" \
                "Account has $total_count resources but only $project_count project(s). Use projects to organize and control access." \
                "[]" \
                "Create projects to organize resources by environment (prod, staging) or team. Use doctl projects create." \
                "[\"ISO27001 A.8.1.1\",\"SOC2 CC6.3\"]"
            print_finding "low" "Resources not organized into projects ($total_count resources, $project_count project(s))"
        else
            add_pass
            print_finding "pass" "Project organization is appropriate"
        fi
    else
        add_pass
        print_finding "pass" "Resources organized into $project_count projects"
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
  "platform": "digitalocean",
  "account_email": "$ACCOUNT_EMAIL",
  "account_uuid": "$ACCOUNT_UUID",
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
    "cis_benchmarks": true,
    "iso_27001": true,
    "soc_2": true,
    "ccss": true
  },
  "findings": [$findings_json]
}
EOF

    # Redact email addresses in report
    if [[ "$OSTYPE" == "darwin"* ]]; then
        sed -i '' 's/[a-zA-Z0-9._%+-]*@[a-zA-Z0-9.-]*\.[a-zA-Z]*/<REDACTED_EMAIL>/g' "$OUTPUT_FILE"
    else
        sed -i 's/[a-zA-Z0-9._%+-]*@[a-zA-Z0-9.-]*\.[a-zA-Z]*/<REDACTED_EMAIL>/g' "$OUTPUT_FILE"
    fi

    # Pretty print if jq available
    if [ "$JQ_AVAILABLE" = true ]; then
        local temp_file=$(mktemp)
        jq '.' "$OUTPUT_FILE" > "$temp_file" 2>/dev/null && mv "$temp_file" "$OUTPUT_FILE"
    fi
}

print_summary() {
    local score=$(calculate_score)
    local interpretation=$(get_interpretation "$score")
    local total=$((CRITICAL_COUNT + HIGH_COUNT + MEDIUM_COUNT + LOW_COUNT + PASS_COUNT))

    echo ""
    echo -e "${BLUE}════════════════════════════════════════════════════════════${NC}"
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
    echo "    - CIS Benchmarks"
    echo "    - ISO 27001"
    echo "    - SOC 2"
    echo "    - CCSS (Cryptocurrency Security Standard)"
    echo ""
    echo -e "${BLUE}════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  Report saved to: ${GREEN}$OUTPUT_FILE${NC}"
    echo ""
    echo "  Next steps:"
    echo "    1. Review the report for sensitive information"
    echo "    2. Share it at: https://scamshield.app/audit"
    echo "    3. Get your personalized remediation plan"
    echo ""
    echo -e "  Need help? Contact us at ${CYAN}https://scamshield.app/audit${NC}"
    echo ""
}

# ============================================================================
# Main
# ============================================================================

main() {
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
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
    check_app_platform
    echo ""
    check_databases
    echo ""
    check_networking
    echo ""
    check_storage
    echo ""
    check_droplets
    echo ""
    check_dns
    echo ""
    check_access_control

    # Generate report
    generate_report

    # Print summary
    print_summary
}

main "$@"
