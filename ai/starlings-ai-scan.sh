#!/bin/bash
#
# Starlings AI Security Scanner v1.0.0
# =====================================
#
# Static analysis scanner for AI/LLM security risks in GitHub repositories.
# Detects hardcoded API keys, prompt injection vulnerabilities, deprecated
# model usage, and insecure LLM integration patterns.
#
# This is a code-level scanner — it clones a repository and analyzes source
# files for security anti-patterns. No API keys or cloud credentials required
# to run the scanner itself.
#
# Usage:
#   ./starlings-ai-scan.sh --repo <github-url-or-local-path> [OPTIONS]
#
# Options:
#   --repo URL/PATH       GitHub URL or local directory to scan (required)
#   --branch BRANCH       Branch to scan (default: default branch)
#   --output FILE         Output JSON file (default: ai-security-report.json)
#   --verbose / -v        Verbose output
#   --help / -h           Show this help message
#
# Examples:
#   ./starlings-ai-scan.sh --repo https://github.com/org/my-ai-app
#   ./starlings-ai-scan.sh --repo ./my-local-project -v
#   ./starlings-ai-scan.sh --repo https://github.com/org/chatbot --branch dev -o report.json
#

set -euo pipefail

# ============================================================================
# Configuration
# ============================================================================

SCANNER_VERSION="1.0.0"
DEFAULT_OUTPUT="ai-security-report.json"
OUTPUT_FILE=""
VERBOSE=false
REPO_URL=""
BRANCH=""
SCAN_DIR=""
CLONED=false

# File extensions to scan
SCAN_EXTENSIONS="py,js,ts,jsx,tsx,rb,go,java,yaml,yml,json,toml,cfg,ini,ipynb,env,sh,md"

# Colors
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
    echo -e "${BLUE}║${NC}       Starlings AI Security Scanner v${SCANNER_VERSION}              ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}       GitHub Repository Static Analysis                  ${BLUE}║${NC}"
    echo -e "${BLUE}╚═══════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo "  Scans source code for AI/LLM security anti-patterns."
    echo "  No API keys required to run this scanner."
    echo ""
}

print_status()  { echo -e "${BLUE}[*]${NC} $1"; }
print_success() { echo -e "${GREEN}[+]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[!]${NC} $1"; }
print_error()   { echo -e "${RED}[-]${NC} $1"; }

print_verbose() {
    if $VERBOSE; then
        echo -e "  ${CYAN}[DEBUG]${NC} $1"
    fi
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

usage() {
    echo "Usage: $0 --repo <github-url-or-local-path> [OPTIONS]"
    echo ""
    echo "Required:"
    echo "  --repo URL/PATH       GitHub URL or local directory to scan"
    echo ""
    echo "Options:"
    echo "  --branch BRANCH       Branch to scan (default: default branch)"
    echo "  -o, --output FILE     Output JSON file (default: ${DEFAULT_OUTPUT})"
    echo "  -v, --verbose         Verbose output"
    echo "  -h, --help            Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 --repo https://github.com/org/my-ai-app"
    echo "  $0 --repo ./my-local-project -v"
    echo "  $0 --repo https://github.com/org/chatbot --branch dev -o report.json"
    echo ""
}

cleanup() {
    if $CLONED && [[ -n "$SCAN_DIR" && -d "$SCAN_DIR" ]]; then
        print_verbose "Cleaning up temp directory: $SCAN_DIR"
        rm -rf "$SCAN_DIR"
    fi
}

trap cleanup EXIT

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
    local frameworks=${8:-"[]"}

    ((TOTAL_CHECKS++)) || true

    case $severity in
        critical) ((CRITICAL_COUNT++)) || true ;;
        high)     ((HIGH_COUNT++)) || true ;;
        medium)   ((MEDIUM_COUNT++)) || true ;;
        low)      ((LOW_COUNT++)) || true ;;
        info)     ((INFO_COUNT++)) || true ;;
    esac

    # Escape double quotes and backslashes in strings for JSON
    title=$(printf '%s' "$title" | sed 's/\\/\\\\/g; s/"/\\"/g')
    description=$(printf '%s' "$description" | sed 's/\\/\\\\/g; s/"/\\"/g')
    remediation=$(printf '%s' "$remediation" | sed 's/\\/\\\\/g; s/"/\\"/g')

    FINDINGS+=("{\"domain\":\"$domain\",\"check_id\":\"$check_id\",\"severity\":\"$severity\",\"title\":\"$title\",\"description\":\"$description\",\"resources\":$resources,\"remediation\":\"$remediation\",\"frameworks\":$frameworks}")

    print_finding "$severity" "$title"
}

add_pass() {
    local message=$1
    ((PASS_COUNT++)) || true
    ((TOTAL_CHECKS++)) || true
    print_finding "pass" "$message"
}

# ============================================================================
# File Discovery
# ============================================================================

# Build list of files to scan (respects extensions, skips binary/vendored)
discover_files() {
    local dir="$1"
    local file_list

    # Build find command for relevant extensions
    local find_args=()
    IFS=',' read -ra EXTS <<< "$SCAN_EXTENSIONS"
    for i in "${!EXTS[@]}"; do
        if [[ $i -gt 0 ]]; then
            find_args+=("-o")
        fi
        find_args+=("-name" "*.${EXTS[$i]}")
    done

    # Find files, excluding common vendored/generated directories
    find "$dir" \
        -type d \( \
            -name node_modules -o \
            -name vendor -o \
            -name .git -o \
            -name __pycache__ -o \
            -name .venv -o \
            -name venv -o \
            -name dist -o \
            -name build -o \
            -name .next -o \
            -name .nuxt -o \
            -name coverage \
        \) -prune -o \
        -type f \( "${find_args[@]}" \) -print 2>/dev/null | sort
}

# ============================================================================
# Scanning Helpers
# ============================================================================

# Search files for a pattern, return matches as "file:line:content" lines
scan_pattern() {
    local dir="$1"
    local pattern="$2"
    local include_pattern="${3:-}"

    local grep_args=(-rn -E --include="*.py" --include="*.js" --include="*.ts"
        --include="*.jsx" --include="*.tsx" --include="*.rb" --include="*.go"
        --include="*.java" --include="*.yaml" --include="*.yml" --include="*.json"
        --include="*.toml" --include="*.cfg" --include="*.ini" --include="*.env"
        --include="*.sh" --include="*.ipynb" --include="*.md")

    if [[ -n "$include_pattern" ]]; then
        grep_args=(--include="$include_pattern" -rn -E)
    fi

    grep "${grep_args[@]}" "$pattern" "$dir" 2>/dev/null || true
}

# Count unique files from grep output
count_files() {
    local matches="$1"
    if [[ -z "$matches" ]]; then
        echo 0
        return
    fi
    echo "$matches" | cut -d: -f1 | sort -u | wc -l | tr -d ' '
}

# Get file list from grep output (relative paths)
file_list_json() {
    local matches="$1"
    local base_dir="$2"

    if [[ -z "$matches" ]]; then
        echo "[]"
        return
    fi

    local files
    files=$(echo "$matches" | cut -d: -f1 | sort -u | while read -r f; do
        # Make path relative to scan dir
        local rel="${f#$base_dir/}"
        printf '"%s",' "$rel"
    done)

    # Remove trailing comma, wrap in array
    files="${files%,}"
    echo "[$files]"
}

# Get sample matches (file:line) for reporting, limit to N
sample_matches() {
    local matches="$1"
    local base_dir="$2"
    local limit="${3:-5}"

    if [[ -z "$matches" ]]; then
        echo "[]"
        return
    fi

    local samples
    samples=$(echo "$matches" | head -n "$limit" | while read -r line; do
        local file
        file=$(echo "$line" | cut -d: -f1)
        local lineno
        lineno=$(echo "$line" | cut -d: -f2)
        local rel="${file#$base_dir/}"
        printf '"%s:%s",' "$rel" "$lineno"
    done)

    samples="${samples%,}"
    echo "[$samples]"
}

# Check if a match is in a comment or docstring (basic heuristic)
is_likely_comment() {
    local line="$1"
    # Strip leading whitespace
    local trimmed
    trimmed=$(echo "$line" | sed 's/^[[:space:]]*//')
    # Common comment prefixes
    if [[ "$trimmed" == "#"* ]] || [[ "$trimmed" == "//"* ]] || \
       [[ "$trimmed" == "*"* ]] || [[ "$trimmed" == "/*"* ]] || \
       [[ "$trimmed" == "<!--"* ]]; then
        return 0
    fi
    return 1
}

# Filter grep matches, removing likely comments and docs
filter_non_comments() {
    local matches="$1"
    if [[ -z "$matches" ]]; then
        echo ""
        return
    fi

    echo "$matches" | while IFS= read -r line; do
        local content
        content=$(echo "$line" | cut -d: -f3-)
        if ! is_likely_comment "$content"; then
            echo "$line"
        fi
    done
}

# ============================================================================
# Security Checks
# ============================================================================

# ---------------------------------------------------------------------------
# KEY-001: Hardcoded OpenAI API Keys
# ---------------------------------------------------------------------------
check_openai_keys() {
    print_status "KEY-001: Checking for hardcoded OpenAI API keys..."

    # Pattern: sk- followed by 20+ alphanumeric chars (OpenAI key format)
    # Also check for sk-proj- (project-scoped keys)
    local matches
    matches=$(scan_pattern "$SCAN_DIR" 'sk-(proj-)?[a-zA-Z0-9]{20,}')
    matches=$(filter_non_comments "$matches")

    # Filter out false positives: SSH keys (ssh-), Stripe keys (sk_test_, sk_live_)
    if [[ -n "$matches" ]]; then
        matches=$(echo "$matches" | grep -v -E '(sk_test_|sk_live_|sk_rsa|ssh-|skey-|\.sklearn)' || true)
    fi

    local file_count
    file_count=$(count_files "$matches")

    if [[ "$file_count" -gt 0 ]]; then
        local resources
        resources=$(sample_matches "$matches" "$SCAN_DIR")
        add_finding "secrets" "KEY-001" "critical" \
            "Hardcoded OpenAI API key(s) found in $file_count file(s)" \
            "OpenAI API keys matching sk-... pattern found committed to the repository. These keys grant access to OpenAI API and can incur charges or leak proprietary prompts." \
            "$resources" \
            "Remove keys from source code immediately. Rotate compromised keys at platform.openai.com. Use environment variables or a secrets manager (e.g., AWS Secrets Manager, HashiCorp Vault). Add key patterns to .gitignore and consider git-secrets or pre-commit hooks." \
            '["OWASP A07:2021","CIS 14.1","ISO27001 A.9.4.3","SOC2 CC6.1"]'
    else
        add_pass "No hardcoded OpenAI API keys found"
    fi
}

# ---------------------------------------------------------------------------
# KEY-002: Hardcoded Anthropic API Keys
# ---------------------------------------------------------------------------
check_anthropic_keys() {
    print_status "KEY-002: Checking for hardcoded Anthropic API keys..."

    local matches
    matches=$(scan_pattern "$SCAN_DIR" 'sk-ant-[a-zA-Z0-9_-]{20,}')
    matches=$(filter_non_comments "$matches")

    local file_count
    file_count=$(count_files "$matches")

    if [[ "$file_count" -gt 0 ]]; then
        local resources
        resources=$(sample_matches "$matches" "$SCAN_DIR")
        add_finding "secrets" "KEY-002" "critical" \
            "Hardcoded Anthropic API key(s) found in $file_count file(s)" \
            "Anthropic API keys matching sk-ant-... pattern found committed to the repository. These keys grant access to Claude models and can incur charges." \
            "$resources" \
            "Remove keys from source code immediately. Rotate compromised keys at console.anthropic.com. Use environment variables or a secrets manager." \
            '["OWASP A07:2021","CIS 14.1","ISO27001 A.9.4.3","SOC2 CC6.1"]'
    else
        add_pass "No hardcoded Anthropic API keys found"
    fi
}

# ---------------------------------------------------------------------------
# KEY-003: Generic Hardcoded Secrets (API keys, tokens, passwords)
# ---------------------------------------------------------------------------
check_generic_secrets() {
    print_status "KEY-003: Checking for generic hardcoded secrets..."

    # Look for assignments with actual values (not placeholders)
    local matches
    matches=$(scan_pattern "$SCAN_DIR" \
        '(API_KEY|API_SECRET|SECRET_KEY|ACCESS_TOKEN|AUTH_TOKEN|PRIVATE_KEY|DATABASE_URL|DB_PASSWORD|REDIS_URL|MONGODB_URI)\s*[=:]\s*["'"'"'][a-zA-Z0-9/+=_.:-]{16,}')
    matches=$(filter_non_comments "$matches")

    # Filter out common placeholders and examples
    if [[ -n "$matches" ]]; then
        matches=$(echo "$matches" | grep -v -iE '(your[-_]?(key|token|secret)|example|placeholder|xxx|TODO|CHANGEME|replace[-_]?me|<.*>|\.\.\.|sk-\.\.\.|\*{3,})' || true)
        # Filter out .env.example and .env.sample files
        matches=$(echo "$matches" | grep -v -E '\.(example|sample|template)' || true)
    fi

    local file_count
    file_count=$(count_files "$matches")

    if [[ "$file_count" -gt 0 ]]; then
        local resources
        resources=$(sample_matches "$matches" "$SCAN_DIR")
        add_finding "secrets" "KEY-003" "critical" \
            "Generic hardcoded secret(s) found in $file_count file(s)" \
            "API keys, tokens, or passwords appear to be hardcoded in source files. Committed secrets are accessible to anyone with repository access and persist in git history." \
            "$resources" \
            "Move all secrets to environment variables. Use .env files locally (excluded via .gitignore). Use a secrets manager in production. Run 'git filter-branch' or BFG Repo Cleaner to remove secrets from git history." \
            '["OWASP A07:2021","CIS 14.1","ISO27001 A.9.4.3","SOC2 CC6.1"]'
    else
        add_pass "No generic hardcoded secrets detected"
    fi
}

# ---------------------------------------------------------------------------
# KEY-004: .env Files Committed to Repository
# ---------------------------------------------------------------------------
check_env_files() {
    print_status "KEY-004: Checking for committed .env files..."

    local env_files
    env_files=$(find "$SCAN_DIR" -type f -name ".env" -o -name ".env.local" \
        -o -name ".env.production" -o -name ".env.development" 2>/dev/null \
        | grep -v node_modules | grep -v .git | grep -v vendor || true)

    # Exclude .env.example, .env.sample, .env.template
    if [[ -n "$env_files" ]]; then
        env_files=$(echo "$env_files" | grep -v -E '\.(example|sample|template)$' || true)
    fi

    local file_count=0
    if [[ -n "$env_files" ]]; then
        file_count=$(echo "$env_files" | wc -l | tr -d ' ')
    fi

    if [[ "$file_count" -gt 0 ]]; then
        local resources
        resources=$(echo "$env_files" | head -5 | while read -r f; do
            local rel="${f#$SCAN_DIR/}"
            printf '"%s",' "$rel"
        done)
        resources="[${resources%,}]"

        add_finding "secrets" "KEY-004" "high" \
            "$file_count .env file(s) committed to repository" \
            "Environment files containing secrets should never be committed. These files typically contain database URLs, API keys, and other sensitive configuration." \
            "$resources" \
            "Add .env* to .gitignore (keep .env.example with placeholder values). Remove .env files from git history using BFG Repo Cleaner. Rotate any secrets that were exposed." \
            '["OWASP A07:2021","CIS 14.1","ISO27001 A.9.4.3"]'
    else
        add_pass "No .env files committed to repository"
    fi
}

# ---------------------------------------------------------------------------
# KEY-005: Secrets in Jupyter Notebooks
# ---------------------------------------------------------------------------
check_notebook_secrets() {
    print_status "KEY-005: Checking for secrets in Jupyter notebooks..."

    local notebooks
    notebooks=$(find "$SCAN_DIR" -type f -name "*.ipynb" \
        ! -path "*/node_modules/*" ! -path "*/.git/*" 2>/dev/null || true)

    if [[ -z "$notebooks" ]]; then
        add_pass "No Jupyter notebooks found"
        return
    fi

    local matches
    matches=$(scan_pattern "$SCAN_DIR" \
        '(sk-[a-zA-Z0-9]{20,}|sk-ant-[a-zA-Z0-9_-]{20,}|API_KEY\s*=\s*["'"'"'][a-zA-Z0-9]{16,})' \
        "*.ipynb")

    local file_count
    file_count=$(count_files "$matches")

    if [[ "$file_count" -gt 0 ]]; then
        local resources
        resources=$(sample_matches "$matches" "$SCAN_DIR")
        add_finding "secrets" "KEY-005" "critical" \
            "API key(s) found in $file_count Jupyter notebook(s)" \
            "Jupyter notebooks with embedded API keys are especially dangerous — notebook outputs and cell history can contain keys even after cells are re-run with different values." \
            "$resources" \
            "Remove API keys from notebooks. Use environment variables (os.environ.get) or python-dotenv. Run 'jupyter nbconvert --clear-output' before committing. Consider nbstripout as a pre-commit hook." \
            '["OWASP A07:2021","CIS 14.1","ISO27001 A.9.4.3"]'
    else
        add_pass "No secrets found in Jupyter notebooks"
    fi
}

# ---------------------------------------------------------------------------
# INJ-001: f-string / Template Literal Prompt Injection
# ---------------------------------------------------------------------------
check_fstring_injection() {
    print_status "INJ-001: Checking for f-string prompt injection patterns..."

    # Python f-strings with user/input/query/message variables in prompt-like contexts
    local py_matches
    py_matches=$(scan_pattern "$SCAN_DIR" \
        '(prompt|system_prompt|user_prompt|messages?|instruction)\s*=\s*f["\x27].*\{.*(user|input|query|message|request|data|text|content|question)' \
        "*.py")
    py_matches=$(filter_non_comments "$py_matches")

    # JavaScript/TypeScript template literals in prompt contexts
    local js_matches
    js_matches=$(scan_pattern "$SCAN_DIR" \
        '(prompt|systemPrompt|userPrompt|messages?|instruction)\s*=\s*`.*\$\{.*(user|input|query|message|request|data|text|content|question)')
    js_matches=$(echo "$js_matches" | grep -E '\.(js|ts|jsx|tsx):' || true)
    js_matches=$(filter_non_comments "$js_matches")

    local all_matches=""
    [[ -n "$py_matches" ]] && all_matches+="$py_matches"
    [[ -n "$py_matches" && -n "$js_matches" ]] && all_matches+=$'\n'
    [[ -n "$js_matches" ]] && all_matches+="$js_matches"

    local file_count
    file_count=$(count_files "$all_matches")

    if [[ "$file_count" -gt 0 ]]; then
        local resources
        resources=$(sample_matches "$all_matches" "$SCAN_DIR")
        add_finding "injection" "INJ-001" "critical" \
            "Prompt injection via string interpolation in $file_count file(s)" \
            "User-controlled input is directly interpolated into LLM prompts using f-strings or template literals. An attacker can inject instructions that override the system prompt, exfiltrate data, or manipulate model behavior." \
            "$resources" \
            "Never interpolate user input directly into prompts. Use parameterized prompt templates (e.g., LangChain PromptTemplate, Anthropic message format). Validate and sanitize user input before including in any prompt context. Implement input length limits." \
            '["OWASP LLM01:2025","CIS 14.2","ISO27001 A.14.2.5"]'
    else
        add_pass "No f-string/template literal prompt injection patterns found"
    fi
}

# ---------------------------------------------------------------------------
# INJ-002: String Concatenation in Prompts
# ---------------------------------------------------------------------------
check_concat_injection() {
    print_status "INJ-002: Checking for string concatenation in prompts..."

    # prompt = "..." + user_input or prompt += user_input
    local matches
    matches=$(scan_pattern "$SCAN_DIR" \
        '(prompt|system_prompt|instruction|messages?)\s*(\+|\.concat|\.format|\.join|%\s)\s*.*(user|input|query|request|data|text)')
    matches=$(filter_non_comments "$matches")

    # Also catch prompt.format(user_input=...) style
    local format_matches
    format_matches=$(scan_pattern "$SCAN_DIR" \
        '\.(format|replace)\(.*\b(user|input|query|message|request)\b')
    format_matches=$(filter_non_comments "$format_matches")

    local all_matches=""
    [[ -n "$matches" ]] && all_matches+="$matches"
    [[ -n "$matches" && -n "$format_matches" ]] && all_matches+=$'\n'
    [[ -n "$format_matches" ]] && all_matches+="$format_matches"

    local file_count
    file_count=$(count_files "$all_matches")

    if [[ "$file_count" -gt 0 ]]; then
        local resources
        resources=$(sample_matches "$all_matches" "$SCAN_DIR")
        add_finding "injection" "INJ-002" "high" \
            "String concatenation in prompt construction in $file_count file(s)" \
            "User input is concatenated into LLM prompts via string operations (+, .format(), .concat()). This enables prompt injection attacks where malicious input alters model behavior." \
            "$resources" \
            "Use structured prompt templates that separate system instructions from user content. For OpenAI/Anthropic APIs, use the messages array with distinct system/user roles rather than concatenating into a single string." \
            '["OWASP LLM01:2025","CIS 14.2","ISO27001 A.14.2.5"]'
    else
        add_pass "No string concatenation prompt injection patterns found"
    fi
}

# ---------------------------------------------------------------------------
# INJ-003: Missing Input Validation Before LLM Calls
# ---------------------------------------------------------------------------
check_input_validation() {
    print_status "INJ-003: Checking for unvalidated input to LLM APIs..."

    # Look for direct user input → API call patterns without validation
    # Python: openai.ChatCompletion.create or client.chat.completions.create
    # with user_input or request.body directly in content
    local matches
    matches=$(scan_pattern "$SCAN_DIR" \
        '(completions?\.create|messages\.create|generate|invoke)\(.*\b(request\.(body|json|form|data|query)|user_input|raw_input|input\(\)|sys\.argv)' \
        "*.py")
    matches=$(filter_non_comments "$matches")

    # JS/TS: req.body directly in API call
    local js_matches
    js_matches=$(scan_pattern "$SCAN_DIR" \
        '(completions?\.create|messages\.create|generateText|streamText)\(.*\b(req\.body|req\.query|req\.params|request\.body)')
    js_matches=$(echo "$js_matches" | grep -E '\.(js|ts|jsx|tsx):' || true)
    js_matches=$(filter_non_comments "$js_matches")

    local all_matches=""
    [[ -n "$matches" ]] && all_matches+="$matches"
    [[ -n "$matches" && -n "$js_matches" ]] && all_matches+=$'\n'
    [[ -n "$js_matches" ]] && all_matches+="$js_matches"

    local file_count
    file_count=$(count_files "$all_matches")

    if [[ "$file_count" -gt 0 ]]; then
        local resources
        resources=$(sample_matches "$all_matches" "$SCAN_DIR")
        add_finding "injection" "INJ-003" "high" \
            "Unvalidated user input passed directly to LLM API in $file_count file(s)" \
            "User input from HTTP requests or stdin is passed directly to LLM API calls without visible validation or sanitization. This is the primary vector for prompt injection attacks." \
            "$resources" \
            "Add input validation: enforce length limits, strip control characters, reject known injection patterns. Use a validation layer between user input and LLM calls. Consider output validation as well (verify model responses before acting on them)." \
            '["OWASP LLM01:2025","OWASP LLM02:2025","ISO27001 A.14.2.5"]'
    else
        add_pass "No unvalidated direct input to LLM APIs detected"
    fi
}

# ---------------------------------------------------------------------------
# MOD-001: Deprecated or Insecure Model Versions
# ---------------------------------------------------------------------------
check_deprecated_models() {
    print_status "MOD-001: Checking for deprecated model versions..."

    local deprecated_models=(
        "gpt-3.5-turbo-0301"
        "gpt-3.5-turbo-0613"
        "gpt-4-0314"
        "gpt-4-0613"
        "text-davinci-003"
        "text-davinci-002"
        "text-davinci-001"
        "code-davinci-002"
        "code-davinci-001"
        "text-curie-001"
        "text-babbage-001"
        "text-ada-001"
        "claude-instant-1.0"
        "claude-instant-1.1"
        "claude-1.3"
        "claude-2.0"
    )

    # Build regex pattern
    local pattern
    pattern=$(printf '%s|' "${deprecated_models[@]}")
    pattern="${pattern%|}"

    local matches
    matches=$(scan_pattern "$SCAN_DIR" "$pattern")
    matches=$(filter_non_comments "$matches")

    local file_count
    file_count=$(count_files "$matches")

    if [[ "$file_count" -gt 0 ]]; then
        local resources
        resources=$(sample_matches "$matches" "$SCAN_DIR")
        add_finding "models" "MOD-001" "high" \
            "Deprecated model version(s) referenced in $file_count file(s)" \
            "References to deprecated or sunset model versions found. Deprecated models may have known vulnerabilities, reduced safety guardrails, or may stop working without notice." \
            "$resources" \
            "Update to current model versions. For OpenAI: use gpt-4o, gpt-4-turbo, or gpt-3.5-turbo (without date suffix). For Anthropic: use claude-sonnet-4-5-20250929 or claude-haiku-4-5-20251001. Pin to specific versions in production but maintain an update schedule." \
            '["OWASP LLM06:2025","ISO27001 A.12.6.1"]'
    else
        add_pass "No deprecated model versions found"
    fi
}

# ---------------------------------------------------------------------------
# CFG-001: Missing Rate Limiting on LLM Endpoints
# ---------------------------------------------------------------------------
check_rate_limiting() {
    print_status "CFG-001: Checking for rate limiting on LLM-backed endpoints..."

    # Look for API route handlers that call LLM APIs
    local llm_endpoints
    llm_endpoints=$(scan_pattern "$SCAN_DIR" \
        '(app\.(post|get|put)|router\.(post|get|put)|@app\.route|@router|def (chat|complete|generate|ask|query|prompt))')
    llm_endpoints=$(filter_non_comments "$llm_endpoints")

    if [[ -z "$llm_endpoints" ]]; then
        add_pass "No LLM-backed API endpoints detected (or not a web app)"
        return
    fi

    # Check if rate limiting libraries/middleware are present
    local rate_limit_present=false
    local rl_imports
    rl_imports=$(scan_pattern "$SCAN_DIR" \
        '(ratelimit|slowapi|flask.limiter|express-rate-limit|rate.limit|throttle|RateLimiter|Throttle|@ratelimit|limiter\.limit|rateLimiter)' || true)

    if [[ -n "$rl_imports" ]]; then
        rate_limit_present=true
    fi

    if ! $rate_limit_present; then
        local resources
        resources=$(sample_matches "$llm_endpoints" "$SCAN_DIR")
        add_finding "config" "CFG-001" "medium" \
            "No rate limiting detected on LLM-backed endpoints" \
            "API endpoints that call LLM services were found, but no rate limiting middleware or decorators were detected. Without rate limiting, a single user can generate excessive API costs or exhaust quotas." \
            "$resources" \
            "Add rate limiting middleware. Python: use slowapi or flask-limiter. Node.js: use express-rate-limit. Set per-user and global limits. Consider token-based rate limiting (limit total tokens/minute, not just requests)." \
            '["OWASP LLM10:2025","ISO27001 A.14.1.1"]'
    else
        add_pass "Rate limiting detected on LLM-backed endpoints"
    fi
}

# ---------------------------------------------------------------------------
# CFG-002: No Cost Controls / Token Limits
# ---------------------------------------------------------------------------
check_cost_controls() {
    print_status "CFG-002: Checking for cost controls and token limits..."

    # Look for LLM API calls
    local llm_calls
    llm_calls=$(scan_pattern "$SCAN_DIR" \
        '(completions?\.create|messages\.create|ChatCompletion|openai\.chat|anthropic\.messages|generateText|streamText)')
    llm_calls=$(filter_non_comments "$llm_calls")

    if [[ -z "$llm_calls" ]]; then
        add_pass "No LLM API calls detected"
        return
    fi

    # Check if max_tokens is set in API calls
    local has_max_tokens
    has_max_tokens=$(scan_pattern "$SCAN_DIR" '(max_tokens|maxTokens|max_completion_tokens)\s*[=:]' || true)

    if [[ -z "$has_max_tokens" ]]; then
        local resources
        resources=$(sample_matches "$llm_calls" "$SCAN_DIR")
        add_finding "config" "CFG-002" "medium" \
            "No token limits (max_tokens) set on LLM API calls" \
            "LLM API calls were found without max_tokens parameters. Without token limits, a single request could generate an unexpectedly long response, leading to high costs." \
            "$resources" \
            "Set max_tokens on all LLM API calls. Define per-request and per-user token budgets. Implement usage tracking and alerts. Consider setting up billing alerts on your OpenAI/Anthropic dashboard." \
            '["OWASP LLM10:2025","ISO27001 A.14.1.1"]'
    else
        add_pass "Token limits (max_tokens) detected in LLM API calls"
    fi
}

# ---------------------------------------------------------------------------
# CFG-003: Insecure API Communication
# ---------------------------------------------------------------------------
check_api_communication() {
    print_status "CFG-003: Checking for insecure API communication patterns..."

    # Check for HTTP (not HTTPS) calls to AI API endpoints
    local matches
    matches=$(scan_pattern "$SCAN_DIR" \
        'http://(api\.openai\.com|api\.anthropic\.com|api\.cohere\.ai|generativelanguage\.googleapis\.com|api\.mistral\.ai)')
    matches=$(filter_non_comments "$matches")

    # Also check for SSL verification disabled
    local ssl_disabled
    ssl_disabled=$(scan_pattern "$SCAN_DIR" '(verify\s*=\s*False|SSL_VERIFY\s*=\s*False|rejectUnauthorized\s*:\s*false|VERIFY_SSL\s*=\s*(0|false|False))')
    ssl_disabled=$(filter_non_comments "$ssl_disabled")

    local all_matches=""
    [[ -n "$matches" ]] && all_matches+="$matches"
    [[ -n "$matches" && -n "$ssl_disabled" ]] && all_matches+=$'\n'
    [[ -n "$ssl_disabled" ]] && all_matches+="$ssl_disabled"

    local file_count
    file_count=$(count_files "$all_matches")

    if [[ "$file_count" -gt 0 ]]; then
        local resources
        resources=$(sample_matches "$all_matches" "$SCAN_DIR")
        add_finding "config" "CFG-003" "medium" \
            "Insecure API communication patterns in $file_count file(s)" \
            "HTTP (non-TLS) calls to AI API endpoints or disabled SSL verification detected. API keys and prompts sent over unencrypted connections can be intercepted." \
            "$resources" \
            "Always use HTTPS for AI API calls (all major providers support it). Never disable SSL verification in production. Remove verify=False or rejectUnauthorized:false settings." \
            '["OWASP A02:2021","CIS 14.4","ISO27001 A.13.1.1","SOC2 CC6.7"]'
    else
        add_pass "No insecure API communication patterns found"
    fi
}

# ---------------------------------------------------------------------------
# CFG-004: System Prompt Exposed in Client Code
# ---------------------------------------------------------------------------
check_system_prompt_exposure() {
    print_status "CFG-004: Checking for system prompts in client-side code..."

    # Look for system prompts in JS/TS files that might be client-side
    local matches
    matches=$(scan_pattern "$SCAN_DIR" \
        '(system_prompt|systemPrompt|system_message|SYSTEM_PROMPT)\s*=\s*["'"'"'`]' \
        "*.js")
    matches=$(filter_non_comments "$matches")

    local ts_matches
    ts_matches=$(scan_pattern "$SCAN_DIR" \
        '(system_prompt|systemPrompt|system_message|SYSTEM_PROMPT)\s*=\s*["'"'"'`]' \
        "*.ts")
    ts_matches=$(filter_non_comments "$ts_matches")

    local tsx_matches
    tsx_matches=$(scan_pattern "$SCAN_DIR" \
        '(system_prompt|systemPrompt|system_message|SYSTEM_PROMPT)\s*=\s*["'"'"'`]' \
        "*.tsx")
    tsx_matches=$(filter_non_comments "$tsx_matches")

    local all_matches=""
    [[ -n "$matches" ]] && all_matches+="$matches"
    [[ -n "$matches" && -n "$ts_matches" ]] && all_matches+=$'\n'
    [[ -n "$ts_matches" ]] && all_matches+="$ts_matches"
    [[ -n "${all_matches}${tsx_matches}" && -n "$tsx_matches" ]] && all_matches+=$'\n'
    [[ -n "$tsx_matches" ]] && all_matches+="$tsx_matches"

    # Filter: only flag files in client-side paths
    if [[ -n "$all_matches" ]]; then
        local client_matches
        client_matches=$(echo "$all_matches" | grep -E '(src/|app/|pages/|components/|public/|client/|frontend/)' || true)
        # Also flag if no clear server directory
        if [[ -z "$client_matches" ]]; then
            client_matches="$all_matches"
        fi
        all_matches="$client_matches"
    fi

    local file_count
    file_count=$(count_files "$all_matches")

    if [[ "$file_count" -gt 0 ]]; then
        local resources
        resources=$(sample_matches "$all_matches" "$SCAN_DIR")
        add_finding "injection" "CFG-004" "medium" \
            "System prompt hardcoded in potentially client-side code ($file_count file(s))" \
            "System prompts found in JavaScript/TypeScript files that may be served to the client. Exposed system prompts reveal your application logic and make prompt injection easier to craft." \
            "$resources" \
            "Move system prompts to server-side code or environment variables. Never include system prompts in client-side bundles. Use a server API to proxy LLM calls so prompts stay server-side." \
            '["OWASP LLM07:2025","ISO27001 A.14.2.5"]'
    else
        add_pass "No system prompts exposed in client-side code"
    fi
}

# ---------------------------------------------------------------------------
# CFG-005: Missing .gitignore for AI-Related Secrets
# ---------------------------------------------------------------------------
check_gitignore() {
    print_status "CFG-005: Checking .gitignore for AI-related patterns..."

    local gitignore="$SCAN_DIR/.gitignore"

    if [[ ! -f "$gitignore" ]]; then
        add_finding "config" "CFG-005" "medium" \
            "No .gitignore file found" \
            "Repository has no .gitignore file. This increases the risk of accidentally committing .env files, API keys, model weights, or other sensitive artifacts." \
            '["(repository root)"]' \
            "Create a .gitignore file. At minimum, include: .env*, *.pem, *.key, *.model, *.pkl, *.h5, *.pt, __pycache__/, node_modules/, .ipynb_checkpoints/." \
            '["CIS 14.1","ISO27001 A.9.4.3"]'
        return
    fi

    local missing_patterns=()

    if ! grep -q '\.env' "$gitignore" 2>/dev/null; then
        missing_patterns+=(".env files")
    fi

    # Check for common AI artifact patterns
    local has_model_ignore=false
    if grep -qE '\.(model|pkl|h5|pt|pth|onnx|safetensors|gguf)' "$gitignore" 2>/dev/null; then
        has_model_ignore=true
    fi

    if [[ ${#missing_patterns[@]} -gt 0 ]] || ! $has_model_ignore; then
        local desc="The .gitignore file is missing patterns for:"
        if [[ ${#missing_patterns[@]} -gt 0 ]]; then
            desc="$desc ${missing_patterns[*]}."
        fi
        if ! $has_model_ignore; then
            desc="$desc Model weight files (.pt, .h5, .pkl, .onnx, .safetensors)."
        fi

        add_finding "config" "CFG-005" "low" \
            ".gitignore missing AI-related patterns" \
            "$desc Model weights can be hundreds of megabytes and may contain embedded training data." \
            '["(.gitignore)"]' \
            "Add to .gitignore: .env*, *.model, *.pkl, *.h5, *.pt, *.pth, *.onnx, *.safetensors, *.gguf. Consider using github/gitignore templates." \
            '["CIS 14.1","ISO27001 A.9.4.3"]'
    else
        add_pass ".gitignore includes AI-related patterns"
    fi
}

# ============================================================================
# Scoring
# ============================================================================

calculate_score() {
    local max_score=100
    local deductions=$(( (CRITICAL_COUNT * 15) + (HIGH_COUNT * 8) + (MEDIUM_COUNT * 3) + (LOW_COUNT * 1) ))
    local score=$((max_score - deductions))
    if [[ $score -lt 0 ]]; then
        score=0
    fi
    echo "$score"
}

get_risk_level() {
    local score=$1
    if [[ $score -ge 90 ]]; then   echo "LOW"
    elif [[ $score -ge 70 ]]; then echo "LOW"
    elif [[ $score -ge 60 ]]; then echo "MEDIUM"
    elif [[ $score -ge 40 ]]; then echo "HIGH"
    else                           echo "CRITICAL"
    fi
}

get_interpretation() {
    local score=$1
    if [[ $score -ge 90 ]]; then   echo "Excellent"
    elif [[ $score -ge 70 ]]; then echo "Good"
    elif [[ $score -ge 60 ]]; then echo "Fair"
    elif [[ $score -ge 40 ]]; then echo "Poor"
    else                           echo "Critical"
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

    # Count files scanned
    local files_scanned=0
    if [[ -d "$SCAN_DIR" ]]; then
        files_scanned=$(discover_files "$SCAN_DIR" | wc -l | tr -d ' ')
    fi

    # Build findings JSON array
    local findings_json=""
    for i in "${!FINDINGS[@]}"; do
        if [[ $i -gt 0 ]]; then
            findings_json="${findings_json},"
        fi
        findings_json="${findings_json}${FINDINGS[$i]}"
    done

    cat > "$output_file" << EOF
{
  "scanner_version": "$SCANNER_VERSION",
  "scan_date": "$scan_date",
  "platform": "AI/LLM Code Analysis",
  "repository": "$REPO_URL",
  "files_scanned": $files_scanned,
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

    # Print summary
    print_summary "$score" "$interpretation" "$risk_level" "$output_file" "$files_scanned"
}

print_summary() {
    local score=$1
    local interpretation=$2
    local risk_level=$3
    local output_file=$4
    local files_scanned=$5

    echo ""
    echo -e "${BLUE}╔═══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║${NC}                     Scan Complete                         ${BLUE}║${NC}"
    echo -e "${BLUE}╚═══════════════════════════════════════════════════════════╝${NC}"
    echo ""

    local score_color="$GREEN"
    if [[ $score -lt 60 ]]; then
        score_color="$RED"
    elif [[ $score -lt 80 ]]; then
        score_color="$YELLOW"
    fi

    echo -e "  Repository:    $REPO_URL"
    echo -e "  Files scanned: $files_scanned"
    echo -e "  Score:         ${score_color}${score}/100 ($interpretation)${NC}"
    echo -e "  Risk Level:    ${score_color}${risk_level}${NC}"
    echo ""
    echo "  Findings:"
    if [[ $CRITICAL_COUNT -gt 0 ]]; then echo -e "    ${RED}Critical: $CRITICAL_COUNT${NC}"; fi
    if [[ $HIGH_COUNT -gt 0 ]];     then echo -e "    ${RED}High:     $HIGH_COUNT${NC}"; fi
    if [[ $MEDIUM_COUNT -gt 0 ]];   then echo -e "    ${YELLOW}Medium:   $MEDIUM_COUNT${NC}"; fi
    if [[ $LOW_COUNT -gt 0 ]];      then echo -e "    ${GREEN}Low:      $LOW_COUNT${NC}"; fi
    if [[ $INFO_COUNT -gt 0 ]];     then echo -e "    ${CYAN}Info:     $INFO_COUNT${NC}"; fi
    echo -e "    ${GREEN}Passed:   $PASS_COUNT${NC}"
    echo ""
    echo "  Total checks:     $TOTAL_CHECKS"
    echo "  Report saved to:  $output_file"
    echo ""
    echo -e "  ${CYAN}Need a deeper audit? Contact us at starlings.ai${NC}"
    echo ""
}

# ============================================================================
# Repository Setup
# ============================================================================

setup_repo() {
    if [[ -z "$REPO_URL" ]]; then
        print_error "No repository specified. Use --repo <url-or-path>"
        usage
        exit 1
    fi

    # Check if it's a local directory
    if [[ -d "$REPO_URL" ]]; then
        SCAN_DIR="$(cd "$REPO_URL" && pwd)"
        print_success "Using local directory: $SCAN_DIR"
        return
    fi

    # Validate URL format
    if [[ ! "$REPO_URL" =~ ^https?:// ]]; then
        print_error "Invalid repository: '$REPO_URL' is not a URL or existing directory"
        exit 1
    fi

    # Clone to temp directory
    SCAN_DIR=$(mktemp -d "${TMPDIR:-/tmp}/starlings-ai-scan-XXXXXX")
    CLONED=true

    print_status "Cloning repository..."
    local clone_args=("--depth" "1")
    if [[ -n "$BRANCH" ]]; then
        clone_args+=("--branch" "$BRANCH")
    fi

    if git clone "${clone_args[@]}" "$REPO_URL" "$SCAN_DIR" 2>/dev/null; then
        print_success "Repository cloned successfully"
    else
        print_error "Failed to clone repository: $REPO_URL"
        exit 1
    fi
}

# ============================================================================
# Prerequisites
# ============================================================================

check_prerequisites() {
    print_status "Checking prerequisites..."

    if ! command -v git &> /dev/null; then
        print_error "git is required but not found"
        exit 1
    fi
    print_verbose "git found: $(git --version)"

    if ! command -v grep &> /dev/null; then
        print_error "grep is required but not found"
        exit 1
    fi
    print_verbose "grep found"

    if ! command -v jq &> /dev/null; then
        print_warning "jq not found — report will not be pretty-printed"
    else
        print_verbose "jq found: $(jq --version 2>&1)"
    fi

    print_success "Prerequisites satisfied"
}

# ============================================================================
# Main
# ============================================================================

main() {
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --repo)
                REPO_URL="$2"
                shift 2
                ;;
            --branch)
                BRANCH="$2"
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
    setup_repo

    # Count files
    local file_count
    file_count=$(discover_files "$SCAN_DIR" | wc -l | tr -d ' ')
    print_status "Found $file_count files to scan"

    echo ""
    echo -e "${BLUE}Starting AI security scan...${NC}"
    echo "========================================================"
    echo ""

    # --- Secrets Domain ---
    print_status "Scanning for hardcoded secrets..."
    echo ""
    check_openai_keys
    check_anthropic_keys
    check_generic_secrets
    check_env_files
    check_notebook_secrets

    echo ""
    echo "--------------------------------------------------------"
    echo ""

    # --- Prompt Injection Domain ---
    print_status "Scanning for prompt injection vulnerabilities..."
    echo ""
    check_fstring_injection
    check_concat_injection
    check_input_validation

    echo ""
    echo "--------------------------------------------------------"
    echo ""

    # --- Model & Configuration Domain ---
    print_status "Scanning for model and configuration issues..."
    echo ""
    check_deprecated_models
    check_rate_limiting
    check_cost_controls
    check_api_communication
    check_system_prompt_exposure
    check_gitignore

    echo ""
    echo "========================================================"

    generate_report
}

main "$@"
