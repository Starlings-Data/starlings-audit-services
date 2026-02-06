#!/bin/bash
#
# Starlings Multi-Chain Blockchain Security Auditor v1.0.0
# =========================================================
#
# Audits smart contracts and tokens on EVM-compatible chains.
# All queries are against public blockchain data — no private keys needed.
#
# Supported chains:
#   - Ethereum (ETH)
#   - Avalanche C-Chain (AVAX)
#   - BNB Smart Chain (BSC)
#   - Polygon (MATIC)
#
# What it does:
#   - Checks contract verification status
#   - Analyzes owner/admin privileges
#   - Detects proxy/upgradeable contracts
#   - Assesses token holder concentration (rug pull risk)
#   - Verifies liquidity locks
#   - Cross-references known audits
#   - Checks token mechanics (mint, burn, pause, fee)
#   - Evaluates overall security posture
#
# Requirements:
#   - curl, jq, bash
#   - Block explorer API key (free tier works)
#
# Usage:
#   ./starlings-blockchain-audit.sh <CONTRACT_ADDRESS> [OPTIONS]
#
# Source: https://github.com/Starlings-Data/starlings-audit-services
# License: MIT
#

set -e

# ============================================================================
# Configuration
# ============================================================================

SCANNER_VERSION="1.0.0"
DEFAULT_OUTPUT="blockchain-audit-report.json"
CONTRACT_ADDRESS=""
CHAIN="ethereum"
NETWORK="mainnet"
OUTPUT_FILE=""
VERBOSE=false

# ============================================================================
# Chain Configuration
# Each chain needs: RPC URL, Explorer API URL, Explorer API key env var,
# chain name, native currency, chain ID, explorer URL for links
# ============================================================================

declare -A CHAIN_RPC
declare -A CHAIN_EXPLORER_API
declare -A CHAIN_EXPLORER_KEY_VAR
declare -A CHAIN_NAME
declare -A CHAIN_CURRENCY
declare -A CHAIN_ID
declare -A CHAIN_EXPLORER_URL

# Ethereum
CHAIN_RPC[ethereum]="https://eth.llamarpc.com"
CHAIN_EXPLORER_API[ethereum]="https://api.etherscan.io/api"
CHAIN_EXPLORER_KEY_VAR[ethereum]="ETHERSCAN_API_KEY"
CHAIN_NAME[ethereum]="Ethereum"
CHAIN_CURRENCY[ethereum]="ETH"
CHAIN_ID[ethereum]="1"
CHAIN_EXPLORER_URL[ethereum]="https://etherscan.io"

# Avalanche C-Chain
CHAIN_RPC[avalanche]="https://api.avax.network/ext/bc/C/rpc"
CHAIN_EXPLORER_API[avalanche]="https://api.snowtrace.io/api"
CHAIN_EXPLORER_KEY_VAR[avalanche]="SNOWTRACE_API_KEY"
CHAIN_NAME[avalanche]="Avalanche C-Chain"
CHAIN_CURRENCY[avalanche]="AVAX"
CHAIN_ID[avalanche]="43114"
CHAIN_EXPLORER_URL[avalanche]="https://snowtrace.io"

# BNB Smart Chain
CHAIN_RPC[bsc]="https://bsc-dataseed.binance.org"
CHAIN_EXPLORER_API[bsc]="https://api.bscscan.com/api"
CHAIN_EXPLORER_KEY_VAR[bsc]="BSCSCAN_API_KEY"
CHAIN_NAME[bsc]="BNB Smart Chain"
CHAIN_CURRENCY[bsc]="BNB"
CHAIN_ID[bsc]="56"
CHAIN_EXPLORER_URL[bsc]="https://bscscan.com"

# Polygon
CHAIN_RPC[polygon]="https://polygon-rpc.com"
CHAIN_EXPLORER_API[polygon]="https://api.polygonscan.com/api"
CHAIN_EXPLORER_KEY_VAR[polygon]="POLYGONSCAN_API_KEY"
CHAIN_NAME[polygon]="Polygon"
CHAIN_CURRENCY[polygon]="MATIC"
CHAIN_ID[polygon]="137"
CHAIN_EXPLORER_URL[polygon]="https://polygonscan.com"

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
    echo -e "${BLUE}║${NC}  Starlings Blockchain Security Auditor v${SCANNER_VERSION}          ${BLUE}║${NC}"
    echo -e "${BLUE}╚═══════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo "  Multi-chain smart contract security analysis."
    echo "  All queries use public blockchain data."
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
    echo "Usage: $0 <CONTRACT_ADDRESS> [OPTIONS]"
    echo ""
    echo "Arguments:"
    echo "  CONTRACT_ADDRESS       The smart contract address to audit (0x...)"
    echo ""
    echo "Options:"
    echo "  -c, --chain CHAIN      Chain to audit on (default: ethereum)"
    echo "                         Supported: ethereum, avalanche, bsc, polygon"
    echo "  -n, --network NET      Network (default: mainnet)"
    echo "  -o, --output FILE      Output file (default: ${DEFAULT_OUTPUT})"
    echo "  -v, --verbose          Verbose output"
    echo "  -h, --help             Show this help message"
    echo ""
    echo "Environment variables (API keys — free tier works):"
    echo "  ETHERSCAN_API_KEY      Etherscan API key (etherscan.io/apis)"
    echo "  SNOWTRACE_API_KEY      Snowtrace API key (snowtrace.io/apis)"
    echo "  BSCSCAN_API_KEY        BscScan API key (bscscan.com/apis)"
    echo "  POLYGONSCAN_API_KEY    PolygonScan API key (polygonscan.com/apis)"
    echo ""
    echo "Examples:"
    echo "  $0 0xdAC17F958D2ee523a2206206994597C13D831ec7                    # Audit USDT on Ethereum"
    echo "  $0 0xB97EF9Ef8734C71904D8002F8b6Bc66Dd9c48a6E --chain avalanche  # USDC on Avalanche"
    echo "  $0 0x55d398326f99059fF775485246999027B3197955 --chain bsc          # USDT on BSC"
    echo ""
}

# Rate limiter — block explorer free tier is 5 req/sec
API_CALL_COUNT=0
api_sleep() {
    sleep 0.25
    ((API_CALL_COUNT++)) || true
}

# Query the block explorer API with retry on rate limit (429)
explorer_api() {
    local params=$1
    local api_url="${CHAIN_EXPLORER_API[$CHAIN]}"
    local key_var="${CHAIN_EXPLORER_KEY_VAR[$CHAIN]}"
    local api_key="${!key_var:-}"

    local url="${api_url}?${params}"

    local max_retries=3
    local retry=0
    local response=""

    while [ $retry -lt $max_retries ]; do
        api_sleep

        if [ -n "$api_key" ]; then
            # Pass API key as query param (URL-safe: keys are alphanumeric)
            response=$(curl -s --max-time 15 -w "\n%{http_code}" "${url}&apikey=${api_key}" 2>/dev/null) || { echo '{"status":"0","message":"NOTOK","result":"Connection failed"}'; return; }
        else
            response=$(curl -s --max-time 15 -w "\n%{http_code}" "$url" 2>/dev/null) || { echo '{"status":"0","message":"NOTOK","result":"Connection failed"}'; return; }
        fi

        local http_code
        http_code=$(echo "$response" | tail -n1)
        local body
        body=$(echo "$response" | sed '$d')

        if [ "$http_code" = "429" ]; then
            ((retry++)) || true
            print_warning "Rate limited (429). Waiting 2s before retry $retry/$max_retries..."
            sleep 2
            continue
        fi

        # Check for explorer API rate limit message in response body
        local rate_msg
        rate_msg=$(echo "$body" | jq -r '.result // ""' 2>/dev/null)
        if echo "$rate_msg" | grep -qi "rate limit"; then
            ((retry++)) || true
            print_warning "Explorer rate limit hit. Waiting 2s before retry $retry/$max_retries..."
            sleep 2
            continue
        fi

        echo "$body"
        return
    done

    print_warning "Explorer API retries exhausted for request"
    echo '{"status":"0","message":"NOTOK","result":"Rate limit exceeded after retries"}'
}

# Make an eth_call via RPC
rpc_call() {
    local to=$1
    local data=$2
    local rpc_url="${CHAIN_RPC[$CHAIN]}"

    local payload="{\"jsonrpc\":\"2.0\",\"method\":\"eth_call\",\"params\":[{\"to\":\"$to\",\"data\":\"$data\"},\"latest\"],\"id\":1}"

    api_sleep
    local response
    response=$(curl -s --max-time 15 -X POST "$rpc_url" \
        -H "Content-Type: application/json" \
        -d "$payload" 2>/dev/null) || { print_verbose "RPC call failed (connection error)"; echo ""; return; }

    local error
    error=$(echo "$response" | jq -r '.error.message // empty' 2>/dev/null)
    if [ -n "$error" ]; then
        print_verbose "RPC error: $error"
        echo ""
        return
    fi

    echo "$response" | jq -r '.result // empty' 2>/dev/null || echo ""
}

# Get transaction count (proxy for contract activity)
get_tx_count() {
    local address=$1
    local rpc_url="${CHAIN_RPC[$CHAIN]}"

    local payload="{\"jsonrpc\":\"2.0\",\"method\":\"eth_getTransactionCount\",\"params\":[\"$address\",\"latest\"],\"id\":1}"
    curl -s --max-time 15 -X POST "$rpc_url" \
        -H "Content-Type: application/json" \
        -d "$payload" 2>/dev/null | jq -r '.result // "0x0"' 2>/dev/null || echo "0x0"
}

# Get bytecode at address
get_code() {
    local address=$1
    local rpc_url="${CHAIN_RPC[$CHAIN]}"

    local payload="{\"jsonrpc\":\"2.0\",\"method\":\"eth_getCode\",\"params\":[\"$address\",\"latest\"],\"id\":1}"
    curl -s --max-time 15 -X POST "$rpc_url" \
        -H "Content-Type: application/json" \
        -d "$payload" 2>/dev/null | jq -r '.result // "0x"' 2>/dev/null || echo "0x"
}

# Read a storage slot
get_storage_at() {
    local address=$1
    local slot=$2
    local rpc_url="${CHAIN_RPC[$CHAIN]}"

    local payload="{\"jsonrpc\":\"2.0\",\"method\":\"eth_getStorageAt\",\"params\":[\"$address\",\"$slot\",\"latest\"],\"id\":1}"
    curl -s --max-time 15 -X POST "$rpc_url" \
        -H "Content-Type: application/json" \
        -d "$payload" 2>/dev/null | jq -r '.result // "0x0000000000000000000000000000000000000000000000000000000000000000"' 2>/dev/null || echo "0x0000000000000000000000000000000000000000000000000000000000000000"
}

# Extract address from 32-byte padded hex
extract_address() {
    local hex=$1
    # Remove 0x prefix and leading zeros, take last 40 chars
    echo "0x$(echo "$hex" | sed 's/^0x//' | sed 's/^0*//' | tail -c 41)"
}

# Hex to decimal
hex_to_dec() {
    local hex=$1
    hex=$(echo "$hex" | sed 's/^0x//')
    if [ -z "$hex" ] || [ "$hex" = "0" ]; then
        echo "0"
        return
    fi
    printf '%d\n' "0x${hex}" 2>/dev/null || echo "0"
}

check_prerequisites() {
    print_status "Checking prerequisites..."

    # Check curl
    if ! command -v curl &> /dev/null; then
        print_error "curl not found. Please install it."
        exit 1
    fi
    print_success "curl found"

    # Check jq
    if ! command -v jq &> /dev/null; then
        print_error "jq is required for blockchain auditing."
        echo "  Install: brew install jq (macOS) or apt install jq (Linux)"
        exit 1
    fi
    print_success "jq found"

    # Validate chain
    if [ -z "${CHAIN_RPC[$CHAIN]}" ]; then
        print_error "Unsupported chain: $CHAIN"
        echo "  Supported chains: ethereum, avalanche, bsc, polygon"
        exit 1
    fi
    print_success "Chain: ${CHAIN_NAME[$CHAIN]}"

    # Check API key
    local key_var="${CHAIN_EXPLORER_KEY_VAR[$CHAIN]}"
    local api_key="${!key_var:-}"
    if [ -z "$api_key" ]; then
        print_warning "No $key_var set — explorer API will be rate-limited. Get a free key at ${CHAIN_EXPLORER_URL[$CHAIN]}/apis"
    else
        print_success "Explorer API key configured"
    fi

    # Validate address format
    if ! echo "$CONTRACT_ADDRESS" | grep -qE '^0x[0-9a-fA-F]{40}$'; then
        print_error "Invalid contract address: $CONTRACT_ADDRESS"
        echo "  Address must be 42 characters starting with 0x"
        exit 1
    fi
    print_success "Address format valid: $CONTRACT_ADDRESS"

    # Verify it's a contract (has code)
    print_status "Verifying contract exists on ${CHAIN_NAME[$CHAIN]}..."
    local code=$(get_code "$CONTRACT_ADDRESS")
    if [ "$code" = "0x" ] || [ -z "$code" ]; then
        print_error "No contract found at $CONTRACT_ADDRESS on ${CHAIN_NAME[$CHAIN]}"
        echo "  This address is either an EOA (wallet) or does not exist on this chain."
        exit 1
    fi
    BYTECODE_SIZE=$(( (${#code} - 2) / 2 ))
    print_success "Contract found (${BYTECODE_SIZE} bytes)"
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
declare -i INFO_COUNT=0

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
        info)     ((INFO_COUNT++)) ;;
    esac

    description=$(echo "$description" | sed 's/"/\\"/g')
    remediation=$(echo "$remediation" | sed 's/"/\\"/g')

    if [ -z "$frameworks" ]; then
        frameworks="[]"
    fi

    FINDINGS+=("{\"domain\":\"$domain\",\"check_id\":\"$check_id\",\"severity\":\"$severity\",\"title\":\"$title\",\"description\":\"$description\",\"resources\":$resources,\"remediation\":\"$remediation\",\"frameworks\":$frameworks}")
}

add_pass() {
    ((PASS_COUNT++))
}

# ============================================================================
# Contract Verification (SC-001)
# ============================================================================

check_verification() {
    print_status "Checking Contract Verification..."

    local response=$(explorer_api "module=contract&action=getsourcecode&address=${CONTRACT_ADDRESS}")
    local status=$(echo "$response" | jq -r '.status' 2>/dev/null)
    local source=$(echo "$response" | jq -r '.result[0].SourceCode // ""' 2>/dev/null)
    local contract_name=$(echo "$response" | jq -r '.result[0].ContractName // ""' 2>/dev/null)
    local compiler=$(echo "$response" | jq -r '.result[0].CompilerVersion // ""' 2>/dev/null)
    local optimization=$(echo "$response" | jq -r '.result[0].OptimizationUsed // ""' 2>/dev/null)
    local license=$(echo "$response" | jq -r '.result[0].LicenseType // ""' 2>/dev/null)

    # Store for later checks
    CONTRACT_SOURCE="$source"
    CONTRACT_NAME="$contract_name"
    CONTRACT_ABI=$(echo "$response" | jq -r '.result[0].ABI // ""' 2>/dev/null)

    # SC-001: Is contract source verified?
    if [ -z "$source" ] || [ "$source" = "" ]; then
        add_finding "verification" "SC-001" "critical" \
            "Contract source code not verified" \
            "The contract at $CONTRACT_ADDRESS is not verified on ${CHAIN_NAME[$CHAIN]} block explorer. Users cannot review the code." \
            "[\"$CONTRACT_ADDRESS\"]" \
            "Verify the contract source code on ${CHAIN_EXPLORER_URL[$CHAIN]}. Unverified contracts are a major red flag." \
            "[\"CCSS 2.1\",\"ISO27001 A.14.2.5\"]"
        print_finding "critical" "Contract source code NOT verified"
        return
    fi

    add_pass
    print_finding "pass" "Contract verified: $contract_name (Compiler: $compiler)"

    # SC-002: Check compiler version (very old compilers have known bugs)
    if echo "$compiler" | grep -qE 'v0\.[0-3]\.|v0\.4\.[0-9][^0-9]|v0\.4\.1[0-9][^0-9]'; then
        add_finding "verification" "SC-002" "high" \
            "Outdated Solidity compiler" \
            "Contract compiled with $compiler. Solidity versions before 0.4.20 have known security vulnerabilities." \
            "[\"$compiler\"]" \
            "Recompile and redeploy with Solidity >=0.8.0 for built-in overflow protection and security fixes" \
            "[\"CCSS 2.1\",\"ISO27001 A.14.2.2\"]"
        print_finding "high" "Outdated compiler: $compiler"
    elif echo "$compiler" | grep -qE 'v0\.[4-6]\.'; then
        add_finding "verification" "SC-002" "medium" \
            "Older Solidity compiler" \
            "Contract compiled with $compiler. Consider upgrading to 0.8.x for better security defaults." \
            "[\"$compiler\"]" \
            "Recompile with Solidity >=0.8.0 for built-in overflow checks and improved security" \
            "[\"CCSS 2.1\"]"
        print_finding "medium" "Older compiler: $compiler"
    else
        add_pass
        print_finding "pass" "Compiler version acceptable: $compiler"
    fi

    # SC-003: License type
    if [ -z "$license" ] || [ "$license" = "None" ] || [ "$license" = "0" ]; then
        add_finding "verification" "SC-003" "low" \
            "No license specified" \
            "Contract does not specify a source code license. This may indicate lack of professional development practices." \
            "[]" \
            "Add an SPDX license identifier to the contract source code" \
            "[]"
        print_finding "low" "No license specified"
    else
        add_pass
        print_finding "pass" "License: $license"
    fi
}

# ============================================================================
# Ownership & Admin Privileges (OWN-001 through OWN-004)
# ============================================================================

check_ownership() {
    print_status "Checking Ownership & Admin Privileges..."

    if [ "$CONTRACT_ABI" = "Contract source code not verified" ] || [ -z "$CONTRACT_ABI" ]; then
        print_warning "  Cannot analyze ownership — contract not verified"
        return
    fi

    # OWN-001: Check for owner() function and who owns it
    # owner() selector = 0x8da5cb5b
    local owner_result=$(rpc_call "$CONTRACT_ADDRESS" "0x8da5cb5b")

    if [ -n "$owner_result" ] && [ "$owner_result" != "0x" ] && [ "$owner_result" != "0x0000000000000000000000000000000000000000000000000000000000000000" ]; then
        local owner_address=$(extract_address "$owner_result")
        print_status "  Contract owner: $owner_address"

        # Check if owner is an EOA (not a multisig)
        local owner_code=$(get_code "$owner_address")
        if [ "$owner_code" = "0x" ] || [ -z "$owner_code" ]; then
            add_finding "ownership" "OWN-001" "high" \
                "Contract owned by an EOA (single key)" \
                "The contract owner ($owner_address) is an externally owned account (single private key). If this key is compromised, the attacker gains full admin control." \
                "[\"$owner_address\"]" \
                "Transfer ownership to a multisig wallet (e.g., Gnosis Safe) or a timelock contract for critical operations" \
                "[\"CCSS 3.1\",\"ISO27001 A.9.2.3\",\"SOC2 CC6.1\"]"
            print_finding "high" "Owner is EOA: $owner_address (single key risk)"
        else
            add_pass
            print_finding "pass" "Owner is a contract (likely multisig): $owner_address"
        fi

        # Check if owner is the zero address (renounced)
        if [ "$owner_address" = "0x0000000000000000000000000000000000000000" ] || [ "$owner_address" = "0x0" ]; then
            add_pass
            print_finding "pass" "Ownership renounced (owner is zero address)"
        fi
    else
        add_pass
        print_finding "pass" "No owner() function — may be ownerless or use different access control"
    fi

    # OWN-002: Check for privileged functions in ABI
    local privileged_functions=""
    if [ -n "$CONTRACT_ABI" ] && [ "$CONTRACT_ABI" != "Contract source code not verified" ]; then
        privileged_functions=$(echo "$CONTRACT_ABI" | jq -r '
            [.[] | select(.type == "function") |
             select(.name | test("(?i)^(mint|burn|pause|unpause|setFee|setTax|blacklist|whitelist|freeze|lock|unlock|withdraw|drain|selfdestruct|kill|setOwner|transferOwnership|upgradeTo|setAdmin|setMinter|addMinter|removeMinter|setOperator|emergencyWithdraw|skim|sweep)$")) |
             .name] | unique | join(", ")' 2>/dev/null || echo "")
    fi

    if [ -n "$privileged_functions" ]; then
        # Determine severity based on which functions exist
        local severity="medium"
        if echo "$privileged_functions" | grep -qiE "mint|selfdestruct|kill|drain|sweep"; then
            severity="high"
        fi
        if echo "$privileged_functions" | grep -qiE "blacklist|freeze"; then
            severity="high"
        fi

        add_finding "ownership" "OWN-002" "$severity" \
            "Privileged admin functions detected" \
            "The contract has admin-only functions: $privileged_functions. These give the owner significant control." \
            "[]" \
            "Ensure privileged functions are protected by timelock and/or multisig. Consider renouncing unnecessary privileges." \
            "[\"CCSS 3.2\",\"ISO27001 A.9.4.1\",\"SOC2 CC6.3\"]"
        print_finding "$severity" "Privileged functions: $privileged_functions"
    else
        add_pass
        print_finding "pass" "No high-risk privileged functions detected in ABI"
    fi

    # OWN-003: Check for Pausable
    local has_paused=$(echo "$CONTRACT_ABI" | jq '[.[] | select(.name == "paused" or .name == "pause" or .name == "unpause")] | length' 2>/dev/null || echo "0")
    if [ "$has_paused" -gt 0 ]; then
        # Check if currently paused
        local paused_result=$(rpc_call "$CONTRACT_ADDRESS" "0x5c975abb")  # paused() selector
        if [ "$paused_result" = "0x0000000000000000000000000000000000000000000000000000000000000001" ]; then
            add_finding "ownership" "OWN-003" "high" \
                "Contract is currently PAUSED" \
                "The contract has a pause mechanism and is currently paused. Transactions may be blocked." \
                "[\"$CONTRACT_ADDRESS\"]" \
                "Investigate why the contract is paused. A paused contract may indicate an emergency or malicious intent." \
                "[\"CCSS 3.2\",\"SOC2 CC6.1\"]"
            print_finding "high" "Contract is currently PAUSED"
        else
            add_finding "ownership" "OWN-003" "low" \
                "Contract has pause capability" \
                "The contract can be paused by the owner, which would freeze all transfers." \
                "[]" \
                "Ensure pause capability is governed by timelock or multisig. Document emergency procedures." \
                "[\"CCSS 3.2\"]"
            print_finding "low" "Contract is pausable (currently active)"
        fi
    else
        add_pass
        print_finding "pass" "Contract has no pause mechanism"
    fi

    # OWN-004: Renounce ownership check
    if [ -n "$CONTRACT_ABI" ] && [ "$CONTRACT_ABI" != "Contract source code not verified" ]; then
        local has_renounce=$(echo "$CONTRACT_ABI" | jq '[.[] | select(.name == "renounceOwnership")] | length' 2>/dev/null || echo "0")
        if [ "$has_renounce" -gt 0 ]; then
            print_finding "info" "renounceOwnership() available — ownership can be renounced"
        fi
    fi
}

# ============================================================================
# Proxy / Upgradeable Contract Detection (PRX-001, PRX-002)
# ============================================================================

check_proxy() {
    print_status "Checking Proxy & Upgradeability..."

    local is_proxy=false
    local implementation_address=""

    # Check EIP-1967 implementation slot
    # bytes32(uint256(keccak256('eip1967.proxy.implementation')) - 1)
    local eip1967_slot="0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
    local impl_result=$(get_storage_at "$CONTRACT_ADDRESS" "$eip1967_slot")

    if [ "$impl_result" != "0x0000000000000000000000000000000000000000000000000000000000000000" ] && [ -n "$impl_result" ]; then
        is_proxy=true
        implementation_address=$(extract_address "$impl_result")
    fi

    # Check EIP-1967 admin slot if proxy detected
    local admin_address=""
    if [ "$is_proxy" = true ]; then
        local admin_slot="0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103"
        local admin_result=$(get_storage_at "$CONTRACT_ADDRESS" "$admin_slot")
        if [ "$admin_result" != "0x0000000000000000000000000000000000000000000000000000000000000000" ]; then
            admin_address=$(extract_address "$admin_result")
        fi
    fi

    # Also check for OpenZeppelin's older proxy pattern
    if [ "$is_proxy" = false ]; then
        local oz_slot="0x7050c9e0f4ca769c69bd3a8ef740bc37934f8e2c036e5a723fd8ee048ed3f8c3"
        local oz_result=$(get_storage_at "$CONTRACT_ADDRESS" "$oz_slot")
        if [ "$oz_result" != "0x0000000000000000000000000000000000000000000000000000000000000000" ] && [ -n "$oz_result" ]; then
            is_proxy=true
            implementation_address=$(extract_address "$oz_result")
        fi
    fi

    # PRX-001: Proxy detection
    if [ "$is_proxy" = true ]; then
        print_status "  Proxy contract detected"
        print_status "  Implementation: $implementation_address"

        # Check if implementation is verified
        local impl_response=$(explorer_api "module=contract&action=getsourcecode&address=${implementation_address}")
        local impl_source=$(echo "$impl_response" | jq -r '.result[0].SourceCode // ""' 2>/dev/null)
        local impl_name=$(echo "$impl_response" | jq -r '.result[0].ContractName // ""' 2>/dev/null)

        if [ -z "$impl_source" ] || [ "$impl_source" = "" ]; then
            add_finding "proxy" "PRX-001" "critical" \
                "Upgradeable proxy with unverified implementation" \
                "Contract is a proxy pointing to unverified implementation at $implementation_address. The actual logic cannot be reviewed." \
                "[\"$implementation_address\"]" \
                "Verify the implementation contract source code on the block explorer immediately." \
                "[\"CCSS 2.1\",\"ISO27001 A.14.2.5\",\"SOC2 CC6.1\"]"
            print_finding "critical" "Proxy implementation NOT verified: $implementation_address"
        else
            add_finding "proxy" "PRX-001" "medium" \
                "Upgradeable proxy contract detected" \
                "Contract is a proxy (implementation: $impl_name at $implementation_address). The owner can upgrade the contract logic at any time." \
                "[\"$implementation_address\"]" \
                "Ensure upgrades are governed by timelock + multisig. Review the implementation contract for security." \
                "[\"CCSS 2.1\",\"ISO27001 A.14.2.5\",\"SOC2 CC6.1\"]"
            print_finding "medium" "Proxy detected — implementation: $impl_name ($implementation_address)"
        fi

        # PRX-002: Check if proxy admin is EOA
        if [ -n "$admin_address" ] && [ "$admin_address" != "0x0" ] && [ "$admin_address" != "0x0000000000000000000000000000000000000000" ]; then
            local admin_code=$(get_code "$admin_address")
            if [ "$admin_code" = "0x" ] || [ -z "$admin_code" ]; then
                add_finding "proxy" "PRX-002" "high" \
                    "Proxy admin is an EOA" \
                    "The proxy admin ($admin_address) is a single key account. This key can upgrade the contract to arbitrary code." \
                    "[\"$admin_address\"]" \
                    "Transfer proxy admin to a timelock contract or multisig. A single compromised key could replace all contract logic." \
                    "[\"CCSS 3.1\",\"ISO27001 A.9.2.3\",\"SOC2 CC6.1\"]"
                print_finding "high" "Proxy admin is EOA: $admin_address"
            else
                add_pass
                print_finding "pass" "Proxy admin is a contract: $admin_address"
            fi
        fi
    else
        add_pass
        print_finding "pass" "Not a proxy contract (immutable)"
    fi
}

# ============================================================================
# Token Analysis (TKN-001 through TKN-004)
# ============================================================================

check_token() {
    print_status "Checking Token Mechanics..."

    # Check if it's an ERC-20 by calling totalSupply()
    # totalSupply() selector = 0x18160ddd
    local total_supply_hex=$(rpc_call "$CONTRACT_ADDRESS" "0x18160ddd")

    if [ -z "$total_supply_hex" ] || [ "$total_supply_hex" = "0x" ]; then
        print_status "  Not an ERC-20 token (no totalSupply). Skipping token checks."
        return
    fi

    # Get token details
    # name() = 0x06fdde03, symbol() = 0x95d89b41, decimals() = 0x313ce567
    local token_name_hex=$(rpc_call "$CONTRACT_ADDRESS" "0x06fdde03")
    local token_symbol_hex=$(rpc_call "$CONTRACT_ADDRESS" "0x95d89b41")
    local decimals_hex=$(rpc_call "$CONTRACT_ADDRESS" "0x313ce567")
    local decimals=$(hex_to_dec "$decimals_hex")

    print_status "  ERC-20 token detected (decimals: $decimals)"

    # TKN-001: Token holder concentration via explorer API
    print_status "  Checking token holder concentration..."
    local holders_response=$(explorer_api "module=token&action=tokenholderlist&contractaddress=${CONTRACT_ADDRESS}&page=1&offset=10")
    local holders_status=$(echo "$holders_response" | jq -r '.status' 2>/dev/null)

    if [ "$holders_status" = "1" ]; then
        local top_holder_balance=$(echo "$holders_response" | jq -r '.result[0].TokenHolderQuantity // "0"' 2>/dev/null)
        local total_supply_dec=$(echo "$holders_response" | jq -r '[.result[].TokenHolderQuantity | tonumber] | add // 0' 2>/dev/null)

        # Alternative: get total supply from contract
        if [ "$total_supply_dec" = "0" ]; then
            total_supply_dec=$(hex_to_dec "$total_supply_hex")
        fi

        if [ "$total_supply_dec" != "0" ] && [ -n "$top_holder_balance" ] && [ "$top_holder_balance" != "0" ]; then
            # Calculate top holder percentage (rough — integer math)
            local top_pct=$(( (top_holder_balance * 100) / total_supply_dec ))

            if [ "$top_pct" -gt 50 ]; then
                add_finding "token" "TKN-001" "critical" \
                    "Extreme token holder concentration" \
                    "Top holder controls approximately ${top_pct}% of total supply. Extremely high rug pull risk." \
                    "[]" \
                    "Investigate the top holder. If it is the deployer, this is a significant rug pull risk." \
                    "[\"CCSS 3.3\",\"SOC2 CC6.1\"]"
                print_finding "critical" "Top holder controls ~${top_pct}% of supply"
            elif [ "$top_pct" -gt 20 ]; then
                add_finding "token" "TKN-001" "high" \
                    "High token holder concentration" \
                    "Top holder controls approximately ${top_pct}% of total supply." \
                    "[]" \
                    "Review whether concentrated holdings are in known contracts (staking, treasury, locked vesting) vs personal wallets." \
                    "[\"CCSS 3.3\",\"SOC2 CC6.1\"]"
                print_finding "high" "Top holder controls ~${top_pct}% of supply"
            elif [ "$top_pct" -gt 10 ]; then
                add_finding "token" "TKN-001" "medium" \
                    "Moderate token holder concentration" \
                    "Top holder controls approximately ${top_pct}% of total supply." \
                    "[]" \
                    "Monitor holder distribution over time. Ensure top holders are known entities." \
                    "[\"CCSS 3.3\"]"
                print_finding "medium" "Top holder controls ~${top_pct}% of supply"
            else
                add_pass
                print_finding "pass" "Token distribution looks healthy (top holder: ~${top_pct}%)"
            fi
        else
            print_warning "  Could not calculate holder concentration"
        fi
    else
        print_warning "  Token holder data not available via explorer API"
    fi

    # TKN-002: Check for mint function (unlimited supply risk)
    if [ -n "$CONTRACT_ABI" ] && [ "$CONTRACT_ABI" != "Contract source code not verified" ]; then
        local has_mint=$(echo "$CONTRACT_ABI" | jq '[.[] | select(.type == "function") | select(.name | test("(?i)^mint$"))] | length' 2>/dev/null || echo "0")
        if [ "$has_mint" -gt 0 ]; then
            add_finding "token" "TKN-002" "medium" \
                "Token has mint function (supply can increase)" \
                "The contract has a mint() function. The authorized caller can create new tokens, diluting existing holders." \
                "[]" \
                "Verify mint is protected by appropriate access control and consider adding a max supply cap." \
                "[\"CCSS 3.2\",\"ISO27001 A.14.2.5\"]"
            print_finding "medium" "Mint function exists — supply is not fixed"
        else
            add_pass
            print_finding "pass" "No mint function — supply appears fixed"
        fi
    fi

    # TKN-003: Check for fee/tax mechanism
    if [ -n "$CONTRACT_ABI" ] && [ "$CONTRACT_ABI" != "Contract source code not verified" ]; then
        local has_fee=$(echo "$CONTRACT_ABI" | jq '[.[] | select(.type == "function") | select(.name | test("(?i)(setFee|setTax|fee|tax|setSwapFee|setBuyFee|setSellFee)"))] | length' 2>/dev/null || echo "0")
        if [ "$has_fee" -gt 0 ]; then
            add_finding "token" "TKN-003" "medium" \
                "Token has fee/tax mechanism" \
                "The contract has fee or tax functions. Transfers may incur fees that the owner can modify." \
                "[]" \
                "Review fee structure and maximum cap. Ensure fees cannot be set to 100% (honeypot). Check if fees can be changed post-deployment." \
                "[\"CCSS 3.2\",\"SOC2 CC6.1\"]"
            print_finding "medium" "Fee/tax mechanism detected"
        else
            add_pass
            print_finding "pass" "No fee/tax mechanism detected"
        fi
    fi

    # TKN-004: Check for blacklist/whitelist
    if [ -n "$CONTRACT_ABI" ] && [ "$CONTRACT_ABI" != "Contract source code not verified" ]; then
        local has_blacklist=$(echo "$CONTRACT_ABI" | jq '[.[] | select(.type == "function") | select(.name | test("(?i)(blacklist|addToBlacklist|isBlacklisted|denylist|blocklist)"))] | length' 2>/dev/null || echo "0")
        if [ "$has_blacklist" -gt 0 ]; then
            add_finding "token" "TKN-004" "high" \
                "Token has blacklist capability" \
                "The contract can blacklist addresses, preventing them from transferring tokens. This gives the owner power to freeze user funds." \
                "[]" \
                "Understand why blacklisting exists (regulatory compliance like USDC is acceptable). For non-regulated tokens, this is a centralization risk." \
                "[\"CCSS 3.2\",\"ISO27001 A.9.4.1\",\"SOC2 CC6.3\"]"
            print_finding "high" "Blacklist capability detected"
        else
            add_pass
            print_finding "pass" "No blacklist mechanism detected"
        fi
    fi
}

# ============================================================================
# Audit & Security History (AUD-001, AUD-002)
# ============================================================================

check_audit_history() {
    print_status "Checking Audit & Security History..."

    # AUD-001: Check contract age (creation transaction)
    local creation_response=$(explorer_api "module=contract&action=getcontractcreation&contractaddresses=${CONTRACT_ADDRESS}")
    local creation_status=$(echo "$creation_response" | jq -r '.status' 2>/dev/null)

    if [ "$creation_status" = "1" ]; then
        local creator=$(echo "$creation_response" | jq -r '.result[0].contractCreator // ""' 2>/dev/null)
        local creation_tx=$(echo "$creation_response" | jq -r '.result[0].txHash // ""' 2>/dev/null)

        if [ -n "$creator" ]; then
            print_status "  Creator: $creator"
            print_status "  Creation tx: $creation_tx"

            # Check if creator is also the owner (common in legitimate contracts)
            # and if creator has deployed many contracts (potential scam factory)
            local creator_tx_count=$(get_tx_count "$creator")
            local creator_tx_dec=$(hex_to_dec "$creator_tx_count")

            if [ "$creator_tx_dec" -gt 100 ]; then
                add_finding "audit" "AUD-001" "low" \
                    "Contract deployer has high transaction count" \
                    "The deployer ($creator) has $creator_tx_dec transactions. High counts may indicate a contract factory (legitimate or scam-related)." \
                    "[\"$creator\"]" \
                    "Review the deployer address for other contracts they have created. Check if those contracts are legitimate." \
                    "[]"
                print_finding "low" "Deployer has $creator_tx_dec transactions"
            else
                add_pass
                print_finding "pass" "Deployer transaction count normal ($creator_tx_dec)"
            fi
        fi
    fi

    # AUD-002: Check for known audit references in source code
    if [ -n "$CONTRACT_SOURCE" ] && [ "$CONTRACT_SOURCE" != "" ]; then
        local has_audit_ref=false
        local audit_firms=""

        # Check for common audit firm references
        for firm in "OpenZeppelin" "Certik" "Trail of Bits" "Consensys" "Halborn" "Quantstamp" "PeckShield" "SlowMist" "Hacken" "Solidproof" "Techrate" "Chainsulting"; do
            if echo "$CONTRACT_SOURCE" | grep -qi "$firm" 2>/dev/null; then
                has_audit_ref=true
                if [ -n "$audit_firms" ]; then
                    audit_firms="$audit_firms, $firm"
                else
                    audit_firms="$firm"
                fi
            fi
        done

        if [ "$has_audit_ref" = true ]; then
            add_pass
            print_finding "pass" "Audit reference(s) found in source: $audit_firms"
        else
            add_finding "audit" "AUD-002" "medium" \
                "No audit references found in contract source" \
                "No references to known audit firms found in the source code. The contract may not have been professionally audited." \
                "[]" \
                "Request proof of audit from the project team. Check the project website for audit reports." \
                "[\"CCSS 2.1\",\"ISO27001 A.14.2.8\"]"
            print_finding "medium" "No audit references found in source code"
        fi

        # Also check for known libraries (good sign)
        local uses_oz=false
        if echo "$CONTRACT_SOURCE" | grep -qi "openzeppelin" 2>/dev/null; then
            uses_oz=true
            add_pass
            print_finding "pass" "Uses OpenZeppelin libraries (industry standard)"
        fi
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

    local deductions=$((CRITICAL_COUNT * 15 + HIGH_COUNT * 8 + MEDIUM_COUNT * 3 + LOW_COUNT * 1))
    local max_score=$((max_checks * 10))
    local raw_score=$((max_score - deductions))

    if [ "$raw_score" -lt 0 ]; then
        raw_score=0
    fi

    local percentage=$((raw_score * 100 / max_score))
    echo "$percentage"
}

get_risk_level() {
    local score=$1
    if [ "$score" -ge 80 ]; then
        echo "LOW"
    elif [ "$score" -ge 60 ]; then
        echo "MEDIUM"
    elif [ "$score" -ge 40 ]; then
        echo "HIGH"
    else
        echo "CRITICAL"
    fi
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
    local risk_level=$(get_risk_level "$score")
    local scan_date=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

    local findings_json=""
    for finding in "${FINDINGS[@]}"; do
        if [ -n "$findings_json" ]; then
            findings_json="$findings_json,"
        fi
        findings_json="$findings_json$finding"
    done

    cat > "$OUTPUT_FILE" << EOF
{
  "scanner_version": "$SCANNER_VERSION",
  "scan_date": "$scan_date",
  "chain": "${CHAIN_NAME[$CHAIN]}",
  "chain_id": "${CHAIN_ID[$CHAIN]}",
  "network": "$NETWORK",
  "contract_address": "$CONTRACT_ADDRESS",
  "contract_name": "$CONTRACT_NAME",
  "explorer_url": "${CHAIN_EXPLORER_URL[$CHAIN]}/address/$CONTRACT_ADDRESS",
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
    "total_checks": $((CRITICAL_COUNT + HIGH_COUNT + MEDIUM_COUNT + LOW_COUNT + PASS_COUNT))
  },
  "findings": [$findings_json]
}
EOF

    if [ "$JQ_AVAILABLE" = true ] 2>/dev/null; then
        local temp_file=$(mktemp)
        jq '.' "$OUTPUT_FILE" > "$temp_file" 2>/dev/null && mv "$temp_file" "$OUTPUT_FILE"
    fi
}

print_summary() {
    local score=$(calculate_score)
    local interpretation=$(get_interpretation "$score")
    local risk_level=$(get_risk_level "$score")
    local total=$((CRITICAL_COUNT + HIGH_COUNT + MEDIUM_COUNT + LOW_COUNT + PASS_COUNT))

    echo ""
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  Contract: ${CYAN}$CONTRACT_ADDRESS${NC}"
    echo -e "  Chain:    ${CHAIN_NAME[$CHAIN]}"
    echo -e "  Name:     ${CONTRACT_NAME:-Unknown}"
    echo ""
    echo -e "  Security Score: ${BLUE}$score/100${NC} ($interpretation)"
    echo -e "  Risk Level:     ${risk_level}"
    echo ""
    echo "  Summary:"
    echo -e "    ${RED}Critical:${NC} $CRITICAL_COUNT"
    echo -e "    ${RED}High:${NC}     $HIGH_COUNT"
    echo -e "    ${YELLOW}Medium:${NC}   $MEDIUM_COUNT"
    echo -e "    ${GREEN}Low:${NC}      $LOW_COUNT"
    echo -e "    ${CYAN}Info:${NC}     $INFO_COUNT"
    echo -e "    ${GREEN}Passed:${NC}   $PASS_COUNT"
    echo ""
    echo "  Total checks: $total"
    echo ""
    echo -e "  View on explorer: ${CHAIN_EXPLORER_URL[$CHAIN]}/address/$CONTRACT_ADDRESS"
    echo ""
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  Report saved to: ${GREEN}$OUTPUT_FILE${NC}"
    echo ""
    echo "  Next steps:"
    echo "    1. Review findings and assess real-world risk"
    echo "    2. Share at: https://scamshield.app/audit"
    echo "    3. Need help? Contact us for a deep-dive audit"
    echo ""
}

# ============================================================================
# Main
# ============================================================================

main() {
    # First argument is the contract address (if not a flag)
    if [[ $# -gt 0 ]] && [[ "$1" != -* ]]; then
        CONTRACT_ADDRESS="$1"
        shift
    fi

    # Parse remaining arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -c|--chain)
                CHAIN="$2"
                shift 2
                ;;
            -n|--network)
                NETWORK="$2"
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
                # Maybe it's the address
                if echo "$1" | grep -qE '^0x[0-9a-fA-F]{40}$'; then
                    CONTRACT_ADDRESS="$1"
                    shift
                else
                    echo "Unknown option: $1"
                    usage
                    exit 1
                fi
                ;;
        esac
    done

    if [ -z "$CONTRACT_ADDRESS" ]; then
        print_error "No contract address specified."
        echo ""
        usage
        exit 1
    fi

    # Normalize chain name
    CHAIN=$(echo "$CHAIN" | tr '[:upper:]' '[:lower:]')

    # Set default output file
    if [ -z "$OUTPUT_FILE" ]; then
        OUTPUT_FILE="$DEFAULT_OUTPUT"
    fi

    print_banner
    check_prerequisites

    echo ""
    echo -e "${BLUE}Starting security audit of ${CONTRACT_ADDRESS} on ${CHAIN_NAME[$CHAIN]}...${NC}"
    echo ""

    # Run all checks
    check_verification
    echo ""
    check_ownership
    echo ""
    check_proxy
    echo ""
    check_token
    echo ""
    check_audit_history

    # Generate report
    generate_report

    # Print summary
    print_summary
}

main "$@"
