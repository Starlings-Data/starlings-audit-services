#!/bin/bash
#
# Starlings Avalanche C-Chain Smart Contract Scanner
# ===================================================
#
# Thin wrapper around the EVM Smart Contract Auditor for Avalanche C-Chain.
# Audits contract verification, ownership, proxy patterns, token mechanics,
# and audit history using Snowtrace API + Avalanche JSON-RPC.
#
# Avalanche-specific notes:
#   - C-Chain is EVM-compatible (same Solidity contracts as Ethereum)
#   - Snowtrace uses Etherscan-compatible API format
#   - Lower gas costs mean more complex contract interactions are common
#   - Subnet contracts are NOT supported (C-Chain only)
#
# Usage:
#   ./starlings-avalanche-scan.sh <CONTRACT_ADDRESS> [OPTIONS]
#
# Environment:
#   SNOWTRACE_API_KEY    Free API key from snowtrace.io/apis (recommended)
#
# Examples:
#   ./starlings-avalanche-scan.sh 0xB97EF9Ef8734C71904D8002F8b6Bc66Dd9c48a6E          # USDC
#   ./starlings-avalanche-scan.sh 0x9702230A8Ea53601f5cD2dc00fDBc13d4dF4A8c7 -v      # USDt
#   ./starlings-avalanche-scan.sh 0x49D5c2BdFfac6CE2BFdB6640F4F80f226bc10bAB -o weth.json  # WETH.e
#

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EVM_SCANNER="$SCRIPT_DIR/../evm/starlings-blockchain-audit.sh"

if [[ ! -f "$EVM_SCANNER" ]]; then
    echo "Error: EVM scanner not found at $EVM_SCANNER"
    echo "Ensure the evm/ directory exists in the repository root."
    exit 1
fi

exec bash "$EVM_SCANNER" "$@" --chain avalanche
