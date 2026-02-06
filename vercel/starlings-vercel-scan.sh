#!/bin/bash
#
# Starlings Vercel Security Scanner v1.0.0
# =========================================
#
# This script runs locally in YOUR environment.
# Your Vercel API token NEVER leaves your machine.
#
# What it does:
#   - Runs read-only checks against your Vercel projects and team
#   - Identifies security misconfigurations
#   - Maps findings to compliance frameworks (ISO 27001, SOC 2, CIS, CCSS)
#   - Outputs a JSON report you can review before sharing
#
# Requirements:
#   - curl and jq installed
#   - VERCEL_TOKEN environment variable (personal access token or OAuth token)
#   - Optional: VERCEL_TEAM_ID for team-scoped scans
#
# Usage:
#   ./starlings-vercel-scan.sh [--project PROJECT] [--output FILE] [--verbose]
#
# Source: https://github.com/Starlings-Data/starlings-audit-services
# License: MIT
#

set -euo pipefail

# ============================================================================
# Configuration
# ============================================================================

SCANNER_VERSION="1.0.0"
DEFAULT_OUTPUT="vercel-security-report.json"
PROJECT_FILTER=""
OUTPUT_FILE=""
VERBOSE=false
API_BASE="https://api.vercel.com"

# Colors for terminal output
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# ============================================================================
# Helper Functions
# ============================================================================

print_banner() {
    echo ""
    echo -e "${BLUE}╔═══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║${NC}     Starlings Vercel Security Scanner v${SCANNER_VERSION}             ${BLUE}║${NC}"
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
    echo -e "${RED}[-]${NC} $1"
}

print_finding() {
    local severity=$1
    local message=$2
    case $severity in
        critical) echo -e "  ${RED}[CRITICAL]${NC} $message" ;;
        high)     echo -e "  ${RED}[HIGH]${NC} $message" ;;
        medium)   echo -e "  ${YELLOW}[MEDIUM]${NC} $message" ;;
        low)      echo -e "  ${GREEN}[LOW]${NC} $message" ;;
        info)     echo -e "  ${CYAN}[INFO]${NC} $message" ;;
        pass)     echo -e "  ${GREEN}[PASS]${NC} $message" ;;
    esac
}

print_verbose() {
    if $VERBOSE; then
        echo -e "  ${CYAN}[DEBUG]${NC} $1"
    fi
}

usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -p, --project NAME     Scan a specific project (default: all projects)"
    echo "  -o, --output FILE      Output file (default: ${DEFAULT_OUTPUT})"
    echo "  -v, --verbose          Verbose output"
    echo "  -h, --help             Show this help message"
    echo ""
    echo "Environment Variables:"
    echo "  VERCEL_TOKEN           Vercel API token (required)"
    echo "  VERCEL_TEAM_ID         Team ID for team-scoped scans (optional)"
    echo ""
    echo "Examples:"
    echo "  $0                                  # Scan all projects"
    echo "  $0 --project my-app                 # Scan specific project"
    echo "  $0 --output my-report.json          # Custom output file"
    echo "  $0 --verbose                        # Verbose output"
    echo ""
    echo "Getting a Vercel Token:"
    echo "  1. Go to https://vercel.com/account/tokens"
    echo "  2. Create a new token with read-only scope"
    echo "  3. export VERCEL_TOKEN=\"your-token-here\""
    echo ""
}

# ============================================================================
# API Helper
# ============================================================================

vercel_api() {
    local endpoint="$1"
    local query_params=""

    # Append team ID if set
    if [[ -n "${VERCEL_TEAM_ID:-}" ]]; then
        if [[ "$endpoint" == *"?"* ]]; then
            query_params="&teamId=${VERCEL_TEAM_ID}"
        else
            query_params="?teamId=${VERCEL_TEAM_ID}"
        fi
    fi

    local url="${API_BASE}${endpoint}${query_params}"
    print_verbose "GET $url"

    local response
    response=$(curl -s --max-time 30 -w "\n%{http_code}" \
        -H "Authorization: Bearer ${VERCEL_TOKEN}" \
        -H "Content-Type: application/json" \
        "$url" 2>/dev/null) || { echo ""; return 1; }

    local http_code
    http_code=$(echo "$response" | tail -n1)
    local body
    body=$(echo "$response" | sed '$d')

    if [[ "$http_code" == "200" ]]; then
        echo "$body"
        return 0
    elif [[ "$http_code" == "403" ]]; then
        print_verbose "403 Forbidden for $endpoint (insufficient permissions)"
        echo ""
        return 1
    elif [[ "$http_code" == "404" ]]; then
        print_verbose "404 Not Found for $endpoint"
        echo ""
        return 1
    else
        print_verbose "HTTP $http_code for $endpoint"
        echo ""
        return 1
    fi
}

# ============================================================================
# Prerequisites
# ============================================================================

check_prerequisites() {
    print_status "Checking prerequisites..."

    # Check curl
    if ! command -v curl &> /dev/null; then
        print_error "curl not found. Install with: brew install curl (macOS) or apt install curl (Linux)"
        exit 1
    fi
    print_success "curl found"

    # Check jq
    if ! command -v jq &> /dev/null; then
        print_error "jq not found. Install with: brew install jq (macOS) or apt install jq (Linux)"
        exit 1
    fi
    print_success "jq found"

    # Check VERCEL_TOKEN
    if [[ -z "${VERCEL_TOKEN:-}" ]]; then
        print_error "VERCEL_TOKEN environment variable is not set."
        echo ""
        echo "  To create a token:"
        echo "    1. Go to https://vercel.com/account/tokens"
        echo "    2. Create a new token"
        echo "    3. export VERCEL_TOKEN=\"your-token-here\""
        echo ""
        exit 1
    fi
    print_success "VERCEL_TOKEN is set"

    # Validate token by calling /v2/user
    print_status "Validating API token..."
    local user_response
    user_response=$(vercel_api "/v2/user") || true

    if [[ -z "$user_response" ]]; then
        print_error "Failed to authenticate with Vercel API. Check your VERCEL_TOKEN."
        exit 1
    fi

    USER_NAME=$(echo "$user_response" | jq -r '.user.name // .user.username // "unknown"')
    USER_ID=$(echo "$user_response" | jq -r '.user.id // "unknown"')
    print_success "Authenticated as: $USER_NAME ($USER_ID)"

    # Check team context
    if [[ -n "${VERCEL_TEAM_ID:-}" ]]; then
        print_status "Team ID: $VERCEL_TEAM_ID"
        local team_response
        team_response=$(vercel_api "/v2/teams/${VERCEL_TEAM_ID}") || true
        if [[ -n "$team_response" ]]; then
            TEAM_NAME=$(echo "$team_response" | jq -r '.name // "unknown"')
            TEAM_SLUG=$(echo "$team_response" | jq -r '.slug // "unknown"')
            print_success "Team: $TEAM_NAME ($TEAM_SLUG)"
        else
            print_warning "Could not retrieve team details"
            TEAM_NAME="unknown"
            TEAM_SLUG=""
        fi
    else
        print_status "No VERCEL_TEAM_ID set (scanning personal account)"
        TEAM_NAME=""
        TEAM_SLUG=""
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
declare -i INFO_COUNT=0
declare -i PASS_COUNT=0
declare -i TOTAL_CHECKS=0

add_finding() {
    local domain=$1
    local check_id=$2
    local severity=$3
    local title=$4
    local description=$5
    local resources=$6
    local remediation=$7
    local frameworks=$8

    ((TOTAL_CHECKS++))

    case $severity in
        critical) ((CRITICAL_COUNT++)) ;;
        high)     ((HIGH_COUNT++)) ;;
        medium)   ((MEDIUM_COUNT++)) ;;
        low)      ((LOW_COUNT++)) ;;
        info)     ((INFO_COUNT++)) ;;
    esac

    # Escape quotes in strings for JSON
    description=$(echo "$description" | sed 's/"/\\"/g')
    remediation=$(echo "$remediation" | sed 's/"/\\"/g')
    title=$(echo "$title" | sed 's/"/\\"/g')

    if [[ -z "$frameworks" ]]; then
        frameworks="[]"
    fi

    FINDINGS+=("{\"domain\":\"$domain\",\"check_id\":\"$check_id\",\"severity\":\"$severity\",\"title\":\"$title\",\"description\":\"$description\",\"resources\":$resources,\"remediation\":\"$remediation\",\"frameworks\":$frameworks}")
}

add_pass() {
    ((PASS_COUNT++))
    ((TOTAL_CHECKS++))
}

# ============================================================================
# Project Discovery
# ============================================================================

declare -a PROJECT_IDS=()
declare -a PROJECT_NAMES=()

discover_projects() {
    print_status "Discovering projects..."

    if [[ -n "$PROJECT_FILTER" ]]; then
        # Scan a specific project
        local proj_response
        proj_response=$(vercel_api "/v9/projects/${PROJECT_FILTER}") || true
        if [[ -n "$proj_response" ]]; then
            local proj_id
            proj_id=$(echo "$proj_response" | jq -r '.id // empty')
            local proj_name
            proj_name=$(echo "$proj_response" | jq -r '.name // empty')
            if [[ -n "$proj_id" ]]; then
                PROJECT_IDS+=("$proj_id")
                PROJECT_NAMES+=("$proj_name")
                print_success "Found project: $proj_name ($proj_id)"
            else
                print_error "Project not found: $PROJECT_FILTER"
                exit 1
            fi
        else
            print_error "Could not retrieve project: $PROJECT_FILTER"
            exit 1
        fi
    else
        # List all projects (paginated)
        local has_next=true
        local until_param=""
        local page=0

        while $has_next; do
            local list_endpoint="/v9/projects?limit=100"
            if [[ -n "$until_param" ]]; then
                list_endpoint="${list_endpoint}&until=${until_param}"
            fi

            local list_response
            list_response=$(vercel_api "$list_endpoint") || true

            if [[ -z "$list_response" ]]; then
                break
            fi

            local count
            count=$(echo "$list_response" | jq '.projects | length' 2>/dev/null || echo "0")

            if [[ "$count" == "0" ]]; then
                break
            fi

            for i in $(seq 0 $((count - 1))); do
                local pid pname
                pid=$(echo "$list_response" | jq -r ".projects[$i].id // empty")
                pname=$(echo "$list_response" | jq -r ".projects[$i].name // empty")
                if [[ -n "$pid" ]]; then
                    PROJECT_IDS+=("$pid")
                    PROJECT_NAMES+=("$pname")
                fi
            done

            # Check pagination
            local next_cursor
            next_cursor=$(echo "$list_response" | jq -r '.pagination.next // empty' 2>/dev/null)
            if [[ -n "$next_cursor" && "$next_cursor" != "null" ]]; then
                until_param="$next_cursor"
                ((page++))
            else
                has_next=false
            fi

            # Safety: max 10 pages (1000 projects)
            if [[ $page -ge 10 ]]; then
                has_next=false
            fi
        done

        print_success "Found ${#PROJECT_IDS[@]} project(s)"
    fi

    if [[ ${#PROJECT_IDS[@]} -eq 0 ]]; then
        print_warning "No projects found. Nothing to scan."
        exit 0
    fi
}

# ============================================================================
# Domain 1: Authentication & Access Control (AUTH)
# ============================================================================

check_auth() {
    print_status "Checking Authentication & Access Control..."

    # AUTH-001: Team-level 2FA / SSO enforcement
    print_status "  Checking team authentication settings..."
    if [[ -n "${VERCEL_TEAM_ID:-}" ]]; then
        local team_response
        team_response=$(vercel_api "/v2/teams/${VERCEL_TEAM_ID}") || true

        if [[ -n "$team_response" ]]; then
            # Check SAML SSO
            local saml_enabled
            saml_enabled=$(echo "$team_response" | jq -r '.saml.enforced // false' 2>/dev/null)
            local sso_connection
            sso_connection=$(echo "$team_response" | jq -r '.saml.connection // empty' 2>/dev/null)

            if [[ "$saml_enabled" == "true" ]]; then
                add_pass
                print_finding "pass" "SAML SSO is enforced for team"
            elif [[ -n "$sso_connection" && "$sso_connection" != "null" ]]; then
                add_finding "auth" "AUTH-001" "medium" \
                    "SSO configured but not enforced" \
                    "SAML SSO is configured but not enforced. Team members can still log in with email/password." \
                    "[]" \
                    "Enforce SAML SSO in Team Settings > Authentication to require SSO for all members." \
                    "[\"ISO27001 A.9.2.1\",\"SOC2 CC6.1\",\"CIS 1.1\"]"
                print_finding "medium" "SSO configured but not enforced"
            else
                add_finding "auth" "AUTH-001" "high" \
                    "No SSO/SAML configured for team" \
                    "The team does not have SAML SSO configured. Members authenticate with individual credentials only." \
                    "[]" \
                    "Configure SAML SSO in Team Settings > Authentication. Vercel supports Okta, Azure AD, Google Workspace, and generic SAML." \
                    "[\"ISO27001 A.9.2.1\",\"SOC2 CC6.1\",\"CIS 1.1\"]"
                print_finding "high" "No SSO/SAML configured for team"
            fi
        else
            add_finding "auth" "AUTH-001" "low" \
                "Could not retrieve team authentication settings" \
                "Unable to check team SSO/SAML configuration. Ensure your token has team read permissions." \
                "[]" \
                "Verify your API token has sufficient permissions to read team settings." \
                "[]"
            print_finding "low" "Could not check team auth settings"
        fi
    else
        add_finding "auth" "AUTH-001" "info" \
            "Personal account (no team SSO)" \
            "Scanning a personal account. SSO/SAML is only available for team accounts." \
            "[]" \
            "Consider using a Vercel Team for shared projects to enable SSO and team-level access controls." \
            "[\"ISO27001 A.9.2.1\"]"
        print_finding "info" "Personal account -- SSO not applicable"
    fi

    # AUTH-002: Team member count and roles
    print_status "  Checking team member access..."
    if [[ -n "${VERCEL_TEAM_ID:-}" ]]; then
        local members_response
        members_response=$(vercel_api "/v2/teams/${VERCEL_TEAM_ID}/members?limit=100") || true

        if [[ -n "$members_response" ]]; then
            local total_members
            total_members=$(echo "$members_response" | jq '.members | length' 2>/dev/null || echo "0")
            local owner_count
            owner_count=$(echo "$members_response" | jq '[.members[] | select(.role == "OWNER")] | length' 2>/dev/null || echo "0")
            local admin_count
            admin_count=$(echo "$members_response" | jq '[.members[] | select(.role == "ADMIN" or .role == "OWNER")] | length' 2>/dev/null || echo "0")

            if [[ "$owner_count" -gt 3 ]]; then
                local owner_names
                owner_names=$(echo "$members_response" | jq -r '[.members[] | select(.role == "OWNER") | .name // .email] | join(", ")' 2>/dev/null)
                add_finding "auth" "AUTH-002" "medium" \
                    "Excessive team owners ($owner_count)" \
                    "The team has $owner_count owners. Excessive owner accounts increase the attack surface." \
                    "[\"$owner_names\"]" \
                    "Reduce owner count to 2-3 trusted administrators. Use ADMIN or MEMBER roles for others." \
                    "[\"ISO27001 A.9.2.3\",\"SOC2 CC6.3\",\"CIS 1.16\"]"
                print_finding "medium" "$owner_count team owners (recommend max 3)"
            else
                add_pass
                print_finding "pass" "Team owner count ($owner_count) is reasonable"
            fi

            print_verbose "Team members: $total_members (owners: $owner_count, admins+owners: $admin_count)"
        else
            print_verbose "Could not retrieve team members"
        fi
    fi

    # AUTH-003: Access groups configured
    print_status "  Checking access groups..."
    if [[ -n "${VERCEL_TEAM_ID:-}" ]]; then
        local access_groups
        access_groups=$(vercel_api "/v1/access-groups") || true

        if [[ -n "$access_groups" ]]; then
            local ag_count
            ag_count=$(echo "$access_groups" | jq '.accessGroups | length' 2>/dev/null || echo "0")

            if [[ "$ag_count" -gt 0 ]]; then
                add_pass
                print_finding "pass" "$ag_count access group(s) configured"
            else
                add_finding "auth" "AUTH-003" "low" \
                    "No access groups configured" \
                    "No access groups found. Access groups provide fine-grained project-level permissions for team members." \
                    "[]" \
                    "Create access groups in Team Settings > Members > Access Groups to restrict project access by role." \
                    "[\"ISO27001 A.9.1.2\",\"SOC2 CC6.3\"]"
                print_finding "low" "No access groups configured"
            fi
        fi
    fi
}

# ============================================================================
# Domain 2: Environment Variables & Secrets (ENV)
# ============================================================================

check_environment() {
    print_status "Checking Environment Variables & Secrets..."

    for idx in "${!PROJECT_IDS[@]}"; do
        local project_id="${PROJECT_IDS[$idx]}"
        local project_name="${PROJECT_NAMES[$idx]}"

        print_status "  Checking env vars for project: $project_name"

        local env_response
        env_response=$(vercel_api "/v9/projects/${project_id}/env") || true

        if [[ -z "$env_response" ]]; then
            print_verbose "Could not retrieve env vars for $project_name"
            continue
        fi

        local env_vars
        env_vars=$(echo "$env_response" | jq '.envs // []')
        local env_count
        env_count=$(echo "$env_vars" | jq 'length' 2>/dev/null || echo "0")

        if [[ "$env_count" -eq 0 ]]; then
            print_verbose "No environment variables for $project_name"
            continue
        fi

        # ENV-001: Secrets exposed to preview/development
        local sensitive_in_preview=()
        local sensitive_patterns='(SECRET|KEY|TOKEN|PASSWORD|CREDENTIAL|PRIVATE|API_KEY|DATABASE_URL|MONGODB_URI|REDIS_URL|JWT_SECRET|AUTH|STRIPE|TWILIO|SENDGRID|AWS_ACCESS|AWS_SECRET)'

        for i in $(seq 0 $((env_count - 1))); do
            local key target_type env_type
            key=$(echo "$env_vars" | jq -r ".[$i].key // empty")
            env_type=$(echo "$env_vars" | jq -r ".[$i].type // empty")

            # Check if the var is available in preview or development
            local targets
            targets=$(echo "$env_vars" | jq -r ".[$i].target[]? // empty" 2>/dev/null)

            if echo "$key" | grep -qiE "$sensitive_patterns"; then
                if echo "$targets" | grep -q "preview"; then
                    sensitive_in_preview+=("$key")
                fi
            fi
        done

        if [[ ${#sensitive_in_preview[@]} -gt 0 ]]; then
            local var_list
            var_list=$(printf '"%s",' "${sensitive_in_preview[@]}" | sed 's/,$//')
            add_finding "env" "ENV-001" "high" \
                "Sensitive env vars exposed to preview deployments ($project_name)" \
                "${#sensitive_in_preview[@]} sensitive environment variable(s) are available in preview deployments. Preview deployments may be triggered by external contributors via pull requests." \
                "[$var_list]" \
                "Restrict sensitive variables to production environment only. Use separate, lower-privilege values for preview." \
                "[\"ISO27001 A.14.2.5\",\"SOC2 CC6.1\",\"CIS 5.2\",\"CCSS 3.4\"]"
            print_finding "high" "${#sensitive_in_preview[@]} sensitive vars exposed to preview ($project_name)"
        else
            add_pass
            print_finding "pass" "No sensitive vars exposed to preview ($project_name)"
        fi

        # ENV-002: Plaintext secrets (type != "secret" and type != "encrypted")
        local plaintext_secrets=()
        for i in $(seq 0 $((env_count - 1))); do
            local key env_type
            key=$(echo "$env_vars" | jq -r ".[$i].key // empty")
            env_type=$(echo "$env_vars" | jq -r ".[$i].type // empty")

            if echo "$key" | grep -qiE "$sensitive_patterns"; then
                if [[ "$env_type" == "plain" ]] || [[ "$env_type" == "system" ]]; then
                    plaintext_secrets+=("$key")
                fi
            fi
        done

        if [[ ${#plaintext_secrets[@]} -gt 0 ]]; then
            local var_list
            var_list=$(printf '"%s",' "${plaintext_secrets[@]}" | sed 's/,$//')
            add_finding "env" "ENV-002" "medium" \
                "Sensitive env vars stored as plaintext ($project_name)" \
                "${#plaintext_secrets[@]} sensitive variable(s) are stored as plaintext instead of encrypted secrets." \
                "[$var_list]" \
                "Use the 'Sensitive' type when creating environment variables that contain secrets. This encrypts the value at rest." \
                "[\"ISO27001 A.10.1.1\",\"SOC2 CC6.1\",\"CCSS 3.4\"]"
            print_finding "medium" "${#plaintext_secrets[@]} plaintext secrets ($project_name)"
        else
            add_pass
            print_finding "pass" "Sensitive vars use encrypted storage ($project_name)"
        fi

        # ENV-003: Environment variables with overly broad targets
        local broad_vars=0
        for i in $(seq 0 $((env_count - 1))); do
            local target_count
            target_count=$(echo "$env_vars" | jq ".[$i].target | length" 2>/dev/null || echo "0")
            if [[ "$target_count" -ge 3 ]]; then
                ((broad_vars++))
            fi
        done

        if [[ "$broad_vars" -gt 5 ]]; then
            add_finding "env" "ENV-003" "low" \
                "Many env vars available across all environments ($project_name)" \
                "$broad_vars environment variables are available across all environments (production, preview, development). Consider scoping variables to specific environments." \
                "[\"$project_name\"]" \
                "Review environment variables and restrict each to the minimum necessary environments." \
                "[\"ISO27001 A.9.4.1\",\"SOC2 CC6.3\"]"
            print_finding "low" "$broad_vars vars across all environments ($project_name)"
        else
            add_pass
            print_finding "pass" "Environment variable scoping looks reasonable ($project_name)"
        fi
    done
}

# ============================================================================
# Domain 3: Deployment Security (DEP)
# ============================================================================

check_deployments() {
    print_status "Checking Deployment Security..."

    for idx in "${!PROJECT_IDS[@]}"; do
        local project_id="${PROJECT_IDS[$idx]}"
        local project_name="${PROJECT_NAMES[$idx]}"

        print_status "  Checking deployments for project: $project_name"

        # Get project details
        local proj_response
        proj_response=$(vercel_api "/v9/projects/${project_id}") || true

        if [[ -z "$proj_response" ]]; then
            print_verbose "Could not retrieve project details for $project_name"
            continue
        fi

        # DEP-001: Git integration and branch protection
        local git_repo
        git_repo=$(echo "$proj_response" | jq -r '.link.type // empty' 2>/dev/null)
        local git_repo_name
        git_repo_name=$(echo "$proj_response" | jq -r '.link.repo // empty' 2>/dev/null)

        if [[ -z "$git_repo" || "$git_repo" == "null" ]]; then
            add_finding "deploy" "DEP-001" "medium" \
                "No Git integration configured ($project_name)" \
                "Project is not connected to a Git repository. Deployments may be manual or via CLI, lacking code review controls." \
                "[\"$project_name\"]" \
                "Connect the project to a Git repository (GitHub, GitLab, or Bitbucket) to enable code review before deployment." \
                "[\"ISO27001 A.14.2.2\",\"SOC2 CC8.1\",\"CIS 6.1\"]"
            print_finding "medium" "No Git integration ($project_name)"
        else
            add_pass
            print_finding "pass" "Git integration: $git_repo ($git_repo_name) for $project_name"
        fi

        # DEP-002: Preview deployment comments (PR safety)
        local preview_comments
        preview_comments=$(echo "$proj_response" | jq -r '.autoAssignCustomDomains // true' 2>/dev/null)

        # DEP-003: Build command injection potential (check for custom build commands)
        local build_command
        build_command=$(echo "$proj_response" | jq -r '.buildCommand // empty' 2>/dev/null)
        local install_command
        install_command=$(echo "$proj_response" | jq -r '.installCommand // empty' 2>/dev/null)

        if [[ -n "$build_command" ]]; then
            # Check for potentially risky patterns in build commands
            if echo "$build_command" | grep -qiE '(curl|wget|eval|exec|\$\(|`|\.sh|bash|sh -c)'; then
                add_finding "deploy" "DEP-003" "high" \
                    "Build command contains risky patterns ($project_name)" \
                    "The custom build command contains patterns that could indicate command injection risk: $build_command" \
                    "[\"$project_name\"]" \
                    "Review the build command for security. Avoid using curl/wget, eval, or shell execution in build commands." \
                    "[\"ISO27001 A.14.2.7\",\"SOC2 CC8.1\",\"CIS 6.3\"]"
                print_finding "high" "Risky build command patterns ($project_name)"
            else
                add_pass
                print_finding "pass" "Build command looks safe ($project_name)"
            fi
        fi

        # DEP-004: Framework detection (outdated or risky frameworks)
        local framework
        framework=$(echo "$proj_response" | jq -r '.framework // empty' 2>/dev/null)
        if [[ -n "$framework" ]]; then
            print_verbose "Framework: $framework for $project_name"
        fi

        # DEP-005: Skew protection (atomic deployments)
        local skew_protection
        skew_protection=$(echo "$proj_response" | jq -r '.skewProtection // empty' 2>/dev/null)
        # This is informational -- not a security finding per se

        # Get recent deployments to check for useful patterns
        local deploys_response
        deploys_response=$(vercel_api "/v6/deployments?projectId=${project_id}&limit=5") || true

        if [[ -n "$deploys_response" ]]; then
            local deploy_count
            deploy_count=$(echo "$deploys_response" | jq '.deployments | length' 2>/dev/null || echo "0")

            if [[ "$deploy_count" -gt 0 ]]; then
                # DEP-006: Check for deployments without source (manual/CLI)
                local manual_deploys=0
                for i in $(seq 0 $((deploy_count - 1))); do
                    local source
                    source=$(echo "$deploys_response" | jq -r ".deployments[$i].source // empty")
                    if [[ "$source" == "cli" || -z "$source" ]]; then
                        ((manual_deploys++))
                    fi
                done

                if [[ "$manual_deploys" -gt 0 ]]; then
                    add_finding "deploy" "DEP-006" "low" \
                        "Recent CLI/manual deployments detected ($project_name)" \
                        "$manual_deploys of the last $deploy_count deployments were made via CLI or manual trigger, bypassing Git-based code review." \
                        "[\"$project_name\"]" \
                        "Use Git-based deployments to ensure all changes go through code review before production." \
                        "[\"ISO27001 A.14.2.2\",\"SOC2 CC8.1\"]"
                    print_finding "low" "$manual_deploys manual deployments ($project_name)"
                else
                    add_pass
                    print_finding "pass" "All recent deployments are Git-based ($project_name)"
                fi
            fi
        fi
    done
}

# ============================================================================
# Domain 4: Domain & TLS Security (DOM)
# ============================================================================

check_domains() {
    print_status "Checking Domain & TLS Security..."

    for idx in "${!PROJECT_IDS[@]}"; do
        local project_id="${PROJECT_IDS[$idx]}"
        local project_name="${PROJECT_NAMES[$idx]}"

        print_status "  Checking domains for project: $project_name"

        local domains_response
        domains_response=$(vercel_api "/v9/projects/${project_id}/domains") || true

        if [[ -z "$domains_response" ]]; then
            print_verbose "Could not retrieve domains for $project_name"
            continue
        fi

        local domains
        domains=$(echo "$domains_response" | jq '.domains // []')
        local domain_count
        domain_count=$(echo "$domains" | jq 'length' 2>/dev/null || echo "0")

        if [[ "$domain_count" -eq 0 ]]; then
            print_verbose "No custom domains for $project_name"
            continue
        fi

        for i in $(seq 0 $((domain_count - 1))); do
            local domain_name verified redirect
            domain_name=$(echo "$domains" | jq -r ".[$i].name // empty")
            verified=$(echo "$domains" | jq -r ".[$i].verified // false")
            redirect=$(echo "$domains" | jq -r ".[$i].redirect // empty")

            # DOM-001: Unverified domains
            if [[ "$verified" != "true" ]]; then
                add_finding "domain" "DOM-001" "high" \
                    "Unverified domain: $domain_name ($project_name)" \
                    "Domain $domain_name is configured but not verified. Unverified domains may not resolve correctly and could be claimed by others." \
                    "[\"$domain_name\"]" \
                    "Verify domain ownership by adding the required DNS records. Check Vercel dashboard for verification instructions." \
                    "[\"ISO27001 A.13.1.1\",\"SOC2 CC6.6\"]"
                print_finding "high" "Unverified domain: $domain_name ($project_name)"
            else
                add_pass
                print_finding "pass" "Domain verified: $domain_name ($project_name)"
            fi
        done

        # DOM-002: Check domain TLS configuration
        for i in $(seq 0 $((domain_count - 1))); do
            local domain_name
            domain_name=$(echo "$domains" | jq -r ".[$i].name // empty")

            if [[ -z "$domain_name" ]]; then
                continue
            fi

            # Check domain config via API
            local domain_config
            domain_config=$(vercel_api "/v6/domains/${domain_name}/config") || true

            if [[ -n "$domain_config" ]]; then
                local ssl_ready
                ssl_ready=$(echo "$domain_config" | jq -r '.misconfigured // true' 2>/dev/null)

                if [[ "$ssl_ready" == "true" ]]; then
                    add_finding "domain" "DOM-002" "high" \
                        "Domain misconfigured: $domain_name ($project_name)" \
                        "The domain $domain_name has a DNS misconfiguration. This may result in SSL errors or service interruption." \
                        "[\"$domain_name\"]" \
                        "Check DNS configuration in Vercel dashboard. Ensure CNAME or A records point to Vercel correctly." \
                        "[\"ISO27001 A.13.1.1\",\"SOC2 CC6.6\"]"
                    print_finding "high" "Domain misconfigured: $domain_name"
                else
                    add_pass
                    print_finding "pass" "Domain configured correctly: $domain_name"
                fi
            fi
        done
    done

    # DOM-003: Check team-level domains
    if [[ -n "${VERCEL_TEAM_ID:-}" ]]; then
        local team_domains
        team_domains=$(vercel_api "/v5/domains?limit=100") || true

        if [[ -n "$team_domains" ]]; then
            local td_count
            td_count=$(echo "$team_domains" | jq '.domains | length' 2>/dev/null || echo "0")

            local expired_domains=0
            local now_epoch
            now_epoch=$(date +%s)

            for i in $(seq 0 $((td_count - 1))); do
                local expires_at
                expires_at=$(echo "$team_domains" | jq -r ".domains[$i].expiresAt // empty" 2>/dev/null)
                if [[ -n "$expires_at" && "$expires_at" != "null" ]]; then
                    local exp_epoch
                    exp_epoch=$((expires_at / 1000))
                    local days_until=$(( (exp_epoch - now_epoch) / 86400 ))
                    if [[ $days_until -lt 30 ]]; then
                        ((expired_domains++))
                    fi
                fi
            done

            if [[ "$expired_domains" -gt 0 ]]; then
                add_finding "domain" "DOM-003" "medium" \
                    "$expired_domains domain(s) expiring within 30 days" \
                    "Some team domains are expiring soon. Expired domains can be registered by attackers for phishing." \
                    "[]" \
                    "Renew expiring domains or enable auto-renewal. Review domains in Vercel dashboard > Domains." \
                    "[\"ISO27001 A.13.1.1\",\"SOC2 CC6.6\"]"
                print_finding "medium" "$expired_domains domain(s) expiring soon"
            else
                add_pass
                print_finding "pass" "No domains expiring within 30 days"
            fi
        fi
    fi
}

# ============================================================================
# Domain 5: Firewall & WAF (FW)
# ============================================================================

check_firewall() {
    print_status "Checking Firewall & WAF Configuration..."

    for idx in "${!PROJECT_IDS[@]}"; do
        local project_id="${PROJECT_IDS[$idx]}"
        local project_name="${PROJECT_NAMES[$idx]}"

        print_status "  Checking firewall for project: $project_name"

        local fw_response
        fw_response=$(vercel_api "/v1/security/firewall/config/active?projectId=${project_id}") || true

        if [[ -z "$fw_response" ]]; then
            # Firewall may not be available on free plans
            add_finding "firewall" "FW-001" "medium" \
                "Firewall not configured or not accessible ($project_name)" \
                "Could not retrieve firewall configuration. The Vercel Firewall may not be enabled or the plan may not include it." \
                "[\"$project_name\"]" \
                "Enable Vercel Firewall in Project Settings > Security. Available on Pro and Enterprise plans." \
                "[\"ISO27001 A.13.1.3\",\"SOC2 CC6.6\",\"CIS 9.2\"]"
            print_finding "medium" "Firewall not configured ($project_name)"
            continue
        fi

        # FW-001: Firewall enabled
        local fw_enabled
        fw_enabled=$(echo "$fw_response" | jq -r '.firewallEnabled // false' 2>/dev/null)

        if [[ "$fw_enabled" == "true" ]]; then
            add_pass
            print_finding "pass" "Firewall enabled ($project_name)"
        else
            add_finding "firewall" "FW-001" "high" \
                "Firewall disabled ($project_name)" \
                "The Vercel Firewall is configured but not enabled for this project." \
                "[\"$project_name\"]" \
                "Enable the firewall in Project Settings > Security > Firewall." \
                "[\"ISO27001 A.13.1.3\",\"SOC2 CC6.6\",\"CIS 9.2\"]"
            print_finding "high" "Firewall disabled ($project_name)"
            continue
        fi

        # FW-002: WAF managed rules (OWASP, bot protection)
        local managed_rules
        managed_rules=$(echo "$fw_response" | jq '.managedRules // {}' 2>/dev/null)

        local owasp_enabled
        owasp_enabled=$(echo "$managed_rules" | jq -r '.owasp.active // false' 2>/dev/null)
        local bot_protection
        bot_protection=$(echo "$managed_rules" | jq -r '.bot_protection.active // false' 2>/dev/null)

        if [[ "$owasp_enabled" != "true" ]]; then
            add_finding "firewall" "FW-002" "high" \
                "OWASP WAF rules not enabled ($project_name)" \
                "OWASP managed rules are not active. This leaves the application vulnerable to common web attacks (XSS, SQLi, etc.)." \
                "[\"$project_name\"]" \
                "Enable OWASP managed rules in Project Settings > Security > Firewall > Managed Rules." \
                "[\"ISO27001 A.14.1.2\",\"SOC2 CC6.6\",\"CIS 9.4\"]"
            print_finding "high" "OWASP WAF rules not active ($project_name)"
        else
            add_pass
            print_finding "pass" "OWASP WAF rules active ($project_name)"
        fi

        if [[ "$bot_protection" != "true" ]]; then
            add_finding "firewall" "FW-003" "medium" \
                "Bot protection not enabled ($project_name)" \
                "Bot protection managed rules are not active. Automated attacks and scraping may not be blocked." \
                "[\"$project_name\"]" \
                "Enable bot protection in Project Settings > Security > Firewall > Managed Rules." \
                "[\"ISO27001 A.13.1.3\",\"SOC2 CC6.6\"]"
            print_finding "medium" "Bot protection not active ($project_name)"
        else
            add_pass
            print_finding "pass" "Bot protection active ($project_name)"
        fi

        # FW-004: IP allowlist/denylist rules
        local ip_rules
        ip_rules=$(echo "$fw_response" | jq '.ips // []' 2>/dev/null)
        local ip_rule_count
        ip_rule_count=$(echo "$ip_rules" | jq 'length' 2>/dev/null || echo "0")

        if [[ "$ip_rule_count" -eq 0 ]]; then
            add_finding "firewall" "FW-004" "info" \
                "No IP-based firewall rules ($project_name)" \
                "No IP allow/deny rules are configured. Consider IP restrictions for admin endpoints or staging environments." \
                "[\"$project_name\"]" \
                "Add IP restrictions for sensitive paths (admin panels, API endpoints) in Firewall > IP Rules." \
                "[\"ISO27001 A.13.1.3\",\"SOC2 CC6.6\"]"
            print_finding "info" "No IP-based rules ($project_name)"
        else
            add_pass
            print_finding "pass" "$ip_rule_count IP-based firewall rule(s) configured ($project_name)"
        fi

        # FW-005: Custom WAF rules
        local custom_rules
        custom_rules=$(echo "$fw_response" | jq '.rules // []' 2>/dev/null)
        local custom_rule_count
        custom_rule_count=$(echo "$custom_rules" | jq 'length' 2>/dev/null || echo "0")

        if [[ "$custom_rule_count" -eq 0 ]]; then
            add_finding "firewall" "FW-005" "low" \
                "No custom firewall rules ($project_name)" \
                "No custom WAF rules are configured. Custom rules can block specific attack patterns relevant to your application." \
                "[\"$project_name\"]" \
                "Add custom firewall rules for application-specific protections (rate limiting, geo-blocking, path restrictions)." \
                "[\"ISO27001 A.13.1.3\"]"
            print_finding "low" "No custom firewall rules ($project_name)"
        else
            add_pass
            print_finding "pass" "$custom_rule_count custom firewall rule(s) configured ($project_name)"
        fi
    done
}

# ============================================================================
# Domain 6: Edge Config & Serverless Security (EDGE)
# ============================================================================

check_edge_config() {
    print_status "Checking Edge Config & Serverless Security..."

    # EDGE-001: Edge Config stores audit
    local edge_configs
    edge_configs=$(vercel_api "/v1/edge-config") || true

    if [[ -n "$edge_configs" ]]; then
        local ec_items
        ec_items=$(echo "$edge_configs" | jq 'if type == "array" then . else [.] end' 2>/dev/null || echo "[]")
        local ec_count
        ec_count=$(echo "$ec_items" | jq 'length' 2>/dev/null || echo "0")

        if [[ "$ec_count" -gt 0 ]]; then
            print_status "  Found $ec_count edge config store(s)"

            for i in $(seq 0 $((ec_count - 1))); do
                local ec_id ec_slug
                ec_id=$(echo "$ec_items" | jq -r ".[$i].id // empty")
                ec_slug=$(echo "$ec_items" | jq -r ".[$i].slug // empty")

                if [[ -z "$ec_id" ]]; then
                    continue
                fi

                # Check edge config tokens (access control)
                local ec_tokens
                ec_tokens=$(vercel_api "/v1/edge-config/${ec_id}/tokens") || true

                if [[ -n "$ec_tokens" ]]; then
                    local token_count
                    token_count=$(echo "$ec_tokens" | jq '.tokens | length' 2>/dev/null || echo "0")

                    if [[ "$token_count" -gt 5 ]]; then
                        add_finding "edge" "EDGE-001" "low" \
                            "Edge Config has many access tokens ($ec_slug)" \
                            "Edge Config store '$ec_slug' has $token_count access tokens. Excessive tokens increase the attack surface." \
                            "[\"$ec_slug\"]" \
                            "Review and revoke unused Edge Config tokens. Rotate tokens periodically." \
                            "[\"ISO27001 A.9.4.2\",\"SOC2 CC6.1\"]"
                        print_finding "low" "$token_count tokens for edge config ($ec_slug)"
                    else
                        add_pass
                        print_finding "pass" "Edge Config token count reasonable ($ec_slug)"
                    fi
                fi
            done
        else
            print_verbose "No edge config stores found"
        fi
    fi

    # EDGE-002: Check serverless function configuration per project
    for idx in "${!PROJECT_IDS[@]}"; do
        local project_id="${PROJECT_IDS[$idx]}"
        local project_name="${PROJECT_NAMES[$idx]}"

        local proj_response
        proj_response=$(vercel_api "/v9/projects/${project_id}") || true

        if [[ -z "$proj_response" ]]; then
            continue
        fi

        # Check serverless function region configuration
        local fn_region
        fn_region=$(echo "$proj_response" | jq -r '.serverlessFunctionRegion // empty' 2>/dev/null)

        if [[ -z "$fn_region" || "$fn_region" == "null" ]]; then
            add_finding "edge" "EDGE-002" "info" \
                "Default serverless function region ($project_name)" \
                "No specific serverless function region configured. Functions will deploy to the default region (iad1). Consider setting a region closer to your users for data residency compliance." \
                "[\"$project_name\"]" \
                "Set serverless function region in Project Settings > Functions to comply with data residency requirements." \
                "[\"ISO27001 A.18.1.4\",\"SOC2 CC6.1\"]"
            print_finding "info" "Default serverless region ($project_name)"
        else
            add_pass
            print_finding "pass" "Serverless region configured: $fn_region ($project_name)"
        fi

        # EDGE-003: Check function timeout (long timeouts = potential abuse)
        local fn_max_duration
        fn_max_duration=$(echo "$proj_response" | jq -r '.serverlessFunctionMaxDuration // empty' 2>/dev/null)

        # Not a critical finding, just informational
    done
}

# ============================================================================
# Domain 7: Logging & Monitoring (LOG)
# ============================================================================

check_logging() {
    print_status "Checking Logging & Monitoring..."

    # LOG-001: Log drains configured
    local log_drains
    log_drains=$(vercel_api "/v1/log-drains") || true

    if [[ -n "$log_drains" ]]; then
        local drain_count
        drain_count=$(echo "$log_drains" | jq 'if type == "array" then length else 0 end' 2>/dev/null || echo "0")

        if [[ "$drain_count" -gt 0 ]]; then
            add_pass
            print_finding "pass" "$drain_count log drain(s) configured"

            # LOG-002: Check log drain destinations
            for i in $(seq 0 $((drain_count - 1))); do
                local drain_type drain_name drain_url
                drain_type=$(echo "$log_drains" | jq -r ".[$i].deliveryFormat // .[$i].type // empty")
                drain_name=$(echo "$log_drains" | jq -r ".[$i].name // empty")
                drain_url=$(echo "$log_drains" | jq -r ".[$i].url // empty")

                # Check if log drain URL uses HTTPS
                if [[ -n "$drain_url" && "$drain_url" != https://* ]]; then
                    add_finding "logging" "LOG-002" "high" \
                        "Log drain uses non-HTTPS endpoint" \
                        "Log drain '$drain_name' sends logs to a non-HTTPS endpoint. Logs may contain sensitive data and should be encrypted in transit." \
                        "[\"$drain_name\"]" \
                        "Update the log drain to use an HTTPS endpoint." \
                        "[\"ISO27001 A.10.1.1\",\"SOC2 CC6.1\"]"
                    print_finding "high" "Non-HTTPS log drain: $drain_name"
                else
                    add_pass
                    print_finding "pass" "Log drain uses HTTPS: $drain_name"
                fi
            done
        else
            add_finding "logging" "LOG-001" "medium" \
                "No log drains configured" \
                "No log drains are configured. Deployment and runtime logs are only available in the Vercel dashboard with limited retention." \
                "[]" \
                "Configure log drains to export logs to a SIEM or log aggregation service (Datadog, Splunk, etc.) for long-term retention and monitoring." \
                "[\"ISO27001 A.12.4.1\",\"SOC2 CC7.2\",\"CIS 8.1\"]"
            print_finding "medium" "No log drains configured"
        fi
    else
        add_finding "logging" "LOG-001" "medium" \
            "Could not check log drain configuration" \
            "Unable to retrieve log drain configuration. Ensure your token has read permissions for log drains." \
            "[]" \
            "Configure log drains for centralized logging and monitoring." \
            "[\"ISO27001 A.12.4.1\",\"SOC2 CC7.2\"]"
        print_finding "medium" "Could not check log drains"
    fi

    # LOG-003: Webhooks for deployment events
    for idx in "${!PROJECT_IDS[@]}"; do
        local project_id="${PROJECT_IDS[$idx]}"
        local project_name="${PROJECT_NAMES[$idx]}"

        local webhooks
        webhooks=$(vercel_api "/v1/webhooks") || true

        if [[ -n "$webhooks" ]]; then
            local wh_count
            wh_count=$(echo "$webhooks" | jq 'if type == "array" then length else 0 end' 2>/dev/null || echo "0")

            if [[ "$wh_count" -gt 0 ]]; then
                add_pass
                print_finding "pass" "$wh_count webhook(s) configured for deployment notifications"

                # Check webhook security (HTTPS endpoints)
                for i in $(seq 0 $((wh_count - 1))); do
                    local wh_url
                    wh_url=$(echo "$webhooks" | jq -r ".[$i].url // empty")
                    if [[ -n "$wh_url" && "$wh_url" != https://* ]]; then
                        add_finding "logging" "LOG-003" "medium" \
                            "Webhook uses non-HTTPS endpoint" \
                            "A deployment webhook sends to a non-HTTPS URL. Webhook payloads may contain deployment metadata." \
                            "[\"$wh_url\"]" \
                            "Update webhook to use HTTPS endpoint and verify webhook signatures." \
                            "[\"ISO27001 A.10.1.1\",\"SOC2 CC6.1\"]"
                        print_finding "medium" "Non-HTTPS webhook detected"
                    fi
                done
            fi
            break  # Webhooks are team/account level, check once
        fi
    done
}

# ============================================================================
# Domain 8: Project Configuration Security (PROJ)
# ============================================================================

check_project_config() {
    print_status "Checking Project Configuration..."

    for idx in "${!PROJECT_IDS[@]}"; do
        local project_id="${PROJECT_IDS[$idx]}"
        local project_name="${PROJECT_NAMES[$idx]}"

        print_status "  Checking config for project: $project_name"

        local proj_response
        proj_response=$(vercel_api "/v9/projects/${project_id}") || true

        if [[ -z "$proj_response" ]]; then
            continue
        fi

        # PROJ-001: Password protection for preview deployments
        local password_protection
        password_protection=$(echo "$proj_response" | jq -r '.passwordProtection // empty' 2>/dev/null)

        local preview_protected=false
        if [[ -n "$password_protection" && "$password_protection" != "null" ]]; then
            local pp_deployment
            pp_deployment=$(echo "$proj_response" | jq -r '.passwordProtection.deploymentType // empty' 2>/dev/null)
            if [[ "$pp_deployment" == "preview" || "$pp_deployment" == "all" ]]; then
                preview_protected=true
            fi
        fi

        # Also check Vercel Authentication (Deployment Protection)
        local deployment_protection
        deployment_protection=$(echo "$proj_response" | jq -r '.protection // empty' 2>/dev/null)

        if $preview_protected; then
            add_pass
            print_finding "pass" "Preview deployments are password protected ($project_name)"
        else
            add_finding "project" "PROJ-001" "medium" \
                "Preview deployments not protected ($project_name)" \
                "Preview deployments are publicly accessible. They may expose in-development features or staging data." \
                "[\"$project_name\"]" \
                "Enable Deployment Protection (Vercel Authentication or password) for preview deployments in Project Settings > Deployment Protection." \
                "[\"ISO27001 A.14.2.5\",\"SOC2 CC6.1\",\"CIS 5.2\"]"
            print_finding "medium" "Preview deployments not protected ($project_name)"
        fi

        # PROJ-002: Auto-assign custom domains to production
        local auto_expose
        auto_expose=$(echo "$proj_response" | jq -r '.autoExposeSystemEnvs // false' 2>/dev/null)

        # PROJ-003: Secure headers (check via deployment response headers)
        # We'll check common security headers on the latest production deployment
        local prod_domain=""
        local domains_response
        domains_response=$(vercel_api "/v9/projects/${project_id}/domains") || true

        if [[ -n "$domains_response" ]]; then
            prod_domain=$(echo "$domains_response" | jq -r '.domains[0].name // empty' 2>/dev/null)
        fi

        if [[ -n "$prod_domain" && "$prod_domain" != "null" ]]; then
            print_status "  Checking security headers for: $prod_domain"

            local headers
            headers=$(curl -sI --max-time 10 "https://${prod_domain}" 2>/dev/null || echo "")

            if [[ -n "$headers" ]]; then
                local missing_headers=()

                if ! echo "$headers" | grep -qi "strict-transport-security"; then
                    missing_headers+=("Strict-Transport-Security (HSTS)")
                fi
                if ! echo "$headers" | grep -qi "x-content-type-options"; then
                    missing_headers+=("X-Content-Type-Options")
                fi
                if ! echo "$headers" | grep -qi "x-frame-options"; then
                    missing_headers+=("X-Frame-Options")
                fi
                if ! echo "$headers" | grep -qi "content-security-policy"; then
                    missing_headers+=("Content-Security-Policy")
                fi

                if [[ ${#missing_headers[@]} -gt 0 ]]; then
                    local header_list
                    header_list=$(printf '"%s",' "${missing_headers[@]}" | sed 's/,$//')
                    add_finding "project" "PROJ-003" "medium" \
                        "Missing security headers ($project_name)" \
                        "${#missing_headers[@]} security header(s) missing on $prod_domain: $(IFS=', '; echo "${missing_headers[*]}")" \
                        "[$header_list]" \
                        "Add security headers via vercel.json headers configuration or middleware. HSTS, CSP, X-Frame-Options, and X-Content-Type-Options are recommended." \
                        "[\"ISO27001 A.14.1.2\",\"SOC2 CC6.6\",\"CIS 9.3\"]"
                    print_finding "medium" "${#missing_headers[@]} missing security headers ($project_name)"
                else
                    add_pass
                    print_finding "pass" "All key security headers present ($project_name)"
                fi
            fi
        fi

        # PROJ-004: Directory listing / source map exposure
        local output_dir
        output_dir=$(echo "$proj_response" | jq -r '.outputDirectory // empty' 2>/dev/null)

        # Check for source maps on production
        if [[ -n "$prod_domain" && "$prod_domain" != "null" ]]; then
            local sourcemap_check
            sourcemap_check=$(curl -sI --max-time 10 "https://${prod_domain}/" 2>/dev/null | grep -i "sourcemap" || true)

            if [[ -n "$sourcemap_check" ]]; then
                add_finding "project" "PROJ-004" "low" \
                    "Source maps may be exposed ($project_name)" \
                    "The production deployment includes SourceMap headers. Source maps can expose application source code." \
                    "[\"$prod_domain\"]" \
                    "Disable source maps in production. In Next.js, set productionBrowserSourceMaps: false in next.config.js." \
                    "[\"ISO27001 A.14.2.5\",\"SOC2 CC6.1\"]"
                print_finding "low" "Source maps may be exposed ($project_name)"
            fi
        fi

        # PROJ-005: Node.js version (check for outdated runtime)
        local node_version
        node_version=$(echo "$proj_response" | jq -r '.nodeVersion // empty' 2>/dev/null)

        if [[ -n "$node_version" && "$node_version" != "null" ]]; then
            local major_version
            major_version=$(echo "$node_version" | grep -oE '^[0-9]+' || echo "0")
            if [[ "$major_version" -lt 18 ]]; then
                add_finding "project" "PROJ-005" "medium" \
                    "Outdated Node.js version: $node_version ($project_name)" \
                    "The project uses Node.js $node_version which may be past end-of-life. Outdated runtimes miss security patches." \
                    "[\"$project_name\"]" \
                    "Update Node.js version to 18.x or 20.x LTS in Project Settings > General > Node.js Version." \
                    "[\"ISO27001 A.14.2.2\",\"SOC2 CC7.1\",\"CIS 6.2\"]"
                print_finding "medium" "Outdated Node.js: $node_version ($project_name)"
            else
                add_pass
                print_finding "pass" "Node.js version $node_version ($project_name)"
            fi
        fi
    done
}

# ============================================================================
# Scoring
# ============================================================================

calculate_score() {
    local max_score=100
    local deductions=0

    deductions=$(( (CRITICAL_COUNT * 15) + (HIGH_COUNT * 8) + (MEDIUM_COUNT * 3) + (LOW_COUNT * 1) ))

    local score=$((max_score - deductions))
    if [[ $score -lt 0 ]]; then
        score=0
    fi

    echo "$score"
}

get_risk_level() {
    local score=$1
    if [[ $score -ge 90 ]]; then
        echo "LOW"
    elif [[ $score -ge 70 ]]; then
        echo "LOW"
    elif [[ $score -ge 60 ]]; then
        echo "MEDIUM"
    elif [[ $score -ge 40 ]]; then
        echo "HIGH"
    else
        echo "CRITICAL"
    fi
}

get_interpretation() {
    local score=$1
    if [[ $score -ge 90 ]]; then
        echo "Excellent"
    elif [[ $score -ge 70 ]]; then
        echo "Good"
    elif [[ $score -ge 60 ]]; then
        echo "Fair"
    elif [[ $score -ge 40 ]]; then
        echo "Poor"
    else
        echo "Critical"
    fi
}

# ============================================================================
# Report Generation
# ============================================================================

generate_report() {
    local score
    score=$(calculate_score)
    local risk_level
    risk_level=$(get_risk_level "$score")
    local interpretation
    interpretation=$(get_interpretation "$score")
    local scan_date
    scan_date=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

    local output_file="${OUTPUT_FILE:-$DEFAULT_OUTPUT}"

    # Build findings JSON array
    local findings_json=""
    for i in "${!FINDINGS[@]}"; do
        if [[ $i -gt 0 ]]; then
            findings_json="${findings_json},"
        fi
        findings_json="${findings_json}${FINDINGS[$i]}"
    done

    # Build project list
    local projects_json=""
    for i in "${!PROJECT_IDS[@]}"; do
        if [[ $i -gt 0 ]]; then
            projects_json="${projects_json},"
        fi
        projects_json="${projects_json}{\"id\":\"${PROJECT_IDS[$i]}\",\"name\":\"${PROJECT_NAMES[$i]}\"}"
    done

    # Determine scope
    local scope="personal"
    if [[ -n "${VERCEL_TEAM_ID:-}" ]]; then
        scope="team"
    fi

    cat > "$output_file" << EOF
{
  "scanner_version": "$SCANNER_VERSION",
  "scan_date": "$scan_date",
  "platform": "Vercel",
  "scope": "$scope",
  "team_name": "${TEAM_NAME:-}",
  "team_id": "${VERCEL_TEAM_ID:-}",
  "user": "${USER_NAME:-unknown}",
  "projects_scanned": [$projects_json],
  "score": {
    "overall": $score,
    "interpretation": "$interpretation",
    "risk_level": "$risk_level"
  },
  "summary": {
    "critical": $CRITICAL_COUNT,
    "high": $HIGH_COUNT,
    "medium": $MEDIUM_COUNT,
    "low": $LOW_COUNT,
    "info": $INFO_COUNT,
    "passed": $PASS_COUNT,
    "total_checks": $TOTAL_CHECKS
  },
  "findings": [$findings_json]
}
EOF

    # Format with jq if available
    if command -v jq &> /dev/null; then
        local tmp_file="${output_file}.tmp"
        if jq '.' "$output_file" > "$tmp_file" 2>/dev/null; then
            mv "$tmp_file" "$output_file"
        else
            rm -f "$tmp_file"
        fi
    fi

    echo ""
    echo -e "${BLUE}╔═══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║${NC}                    Scan Complete                          ${BLUE}║${NC}"
    echo -e "${BLUE}╚═══════════════════════════════════════════════════════════╝${NC}"
    echo ""

    # Score color
    local score_color="$GREEN"
    if [[ $score -lt 60 ]]; then
        score_color="$RED"
    elif [[ $score -lt 80 ]]; then
        score_color="$YELLOW"
    fi

    echo -e "  Score:       ${score_color}${score}/100 ($interpretation)${NC}"
    echo -e "  Risk Level:  ${score_color}${risk_level}${NC}"
    echo ""
    echo "  Findings:"
    if [[ $CRITICAL_COUNT -gt 0 ]]; then echo -e "    ${RED}Critical: $CRITICAL_COUNT${NC}"; fi
    if [[ $HIGH_COUNT -gt 0 ]]; then echo -e "    ${RED}High:     $HIGH_COUNT${NC}"; fi
    if [[ $MEDIUM_COUNT -gt 0 ]]; then echo -e "    ${YELLOW}Medium:   $MEDIUM_COUNT${NC}"; fi
    if [[ $LOW_COUNT -gt 0 ]]; then echo -e "    ${GREEN}Low:      $LOW_COUNT${NC}"; fi
    if [[ $INFO_COUNT -gt 0 ]]; then echo -e "    ${CYAN}Info:     $INFO_COUNT${NC}"; fi
    echo -e "    ${GREEN}Passed:   $PASS_COUNT${NC}"
    echo ""
    echo "  Projects scanned: ${#PROJECT_IDS[@]}"
    echo "  Total checks:     $TOTAL_CHECKS"
    echo ""
    echo "  Report saved to: $output_file"
    echo ""
    echo -e "${CYAN}  Need help? Contact Starlings Security for a deep-dive audit.${NC}"
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
                PROJECT_FILTER="$2"
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
                print_error "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
    done

    print_banner
    check_prerequisites
    discover_projects

    echo ""
    echo -e "${BLUE}Starting security scan...${NC}"
    echo "========================================================"
    echo ""

    check_auth
    check_environment
    check_deployments
    check_domains
    check_firewall
    check_edge_config
    check_logging
    check_project_config

    echo ""
    echo "========================================================"

    generate_report
}

main "$@"
