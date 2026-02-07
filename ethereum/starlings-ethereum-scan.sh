#!/bin/bash
#
# Starlings Ethereum Smart Contract Scanner
# ==========================================
#
# Thin wrapper around the EVM Smart Contract Auditor for Ethereum mainnet.
# Audits contract verification, ownership, proxy patterns, token mechanics,
# and audit history using Etherscan API + Ethereum JSON-RPC.
#
# Usage:
#   ./starlings-ethereum-scan.sh <CONTRACT_ADDRESS> [OPTIONS]
#
# Environment:
#   ETHERSCAN_API_KEY    Free API key from etherscan.io/apis (recommended)
#
# Examples:
#   ./starlings-ethereum-scan.sh 0xdAC17F958D2ee523a2206206994597C13D831ec7          # USDT
#   ./starlings-ethereum-scan.sh 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48 -v      # USDC
#   ./starlings-ethereum-scan.sh 0x6B175474E89094C44Da98b954EedeAC495271d0F -o dai.json  # DAI
#

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EVM_SCANNER="$SCRIPT_DIR/../evm/starlings-blockchain-audit.sh"

if [[ ! -f "$EVM_SCANNER" ]]; then
    echo "Error: EVM scanner not found at $EVM_SCANNER"
    echo "Ensure the evm/ directory exists in the repository root."
    exit 1
fi

exec bash "$EVM_SCANNER" "$@" --chain ethereum
