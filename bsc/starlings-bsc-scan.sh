#!/bin/bash
#
# Starlings BNB Smart Chain (BSC) Smart Contract Scanner
# =======================================================
#
# Thin wrapper around the EVM Smart Contract Auditor for BNB Smart Chain.
# Audits contract verification, ownership, proxy patterns, token mechanics,
# and audit history using BscScan API + BSC JSON-RPC.
#
# BSC-specific notes:
#   - High volume of token deployments — many scam/rug-pull contracts
#   - Low gas costs attract honeypot and fee-on-transfer tokens
#   - TKN-001 (holder concentration) and TKN-003 (fee mechanisms) are
#     especially important on BSC
#   - BscScan uses Etherscan-compatible API format
#
# Usage:
#   ./starlings-bsc-scan.sh <CONTRACT_ADDRESS> [OPTIONS]
#
# Environment:
#   BSCSCAN_API_KEY    Free API key from bscscan.com/apis (recommended)
#
# Examples:
#   ./starlings-bsc-scan.sh 0x55d398326f99059fF775485246999027B3197955          # BSC-USD (USDT)
#   ./starlings-bsc-scan.sh 0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c -v      # WBNB
#   ./starlings-bsc-scan.sh 0xe9e7CEA3DedcA5984780Bafc599bD69ADd087D56 -o busd.json  # BUSD
#

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EVM_SCANNER="$SCRIPT_DIR/../evm/starlings-blockchain-audit.sh"

if [[ ! -f "$EVM_SCANNER" ]]; then
    echo "Error: EVM scanner not found at $EVM_SCANNER"
    echo "Ensure the evm/ directory exists in the repository root."
    exit 1
fi

exec bash "$EVM_SCANNER" "$@" --chain bsc
