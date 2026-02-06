#!/bin/bash
#
# Starlings Polygon (PoS) Smart Contract Scanner
# ===============================================
#
# Thin wrapper around the EVM Smart Contract Auditor for Polygon PoS.
# Audits contract verification, ownership, proxy patterns, token mechanics,
# and audit history using PolygonScan API + Polygon JSON-RPC.
#
# Polygon-specific notes:
#   - Very low gas costs attract high-volume token deployments
#   - Many Ethereum projects deploy identical contracts on Polygon
#   - Bridge contracts (PoS Bridge, Plasma Bridge) are common — check
#     bridge security and mapped token legitimacy
#   - PolygonScan uses Etherscan-compatible API format
#   - Polygon zkEVM is a SEPARATE chain — this scanner covers PoS only
#
# Usage:
#   ./starlings-polygon-scan.sh <CONTRACT_ADDRESS> [OPTIONS]
#
# Environment:
#   POLYGONSCAN_API_KEY    Free API key from polygonscan.com/apis (recommended)
#
# Examples:
#   ./starlings-polygon-scan.sh 0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359          # USDC
#   ./starlings-polygon-scan.sh 0xc2132D05D31c914a87C6611C10748AEb04B58e8F -v      # USDT
#   ./starlings-polygon-scan.sh 0x7ceB23fD6bC0adD59E62ac25578270cFf1b9f619 -o weth.json  # WETH
#

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EVM_SCANNER="$SCRIPT_DIR/../evm/starlings-blockchain-audit.sh"

if [[ ! -f "$EVM_SCANNER" ]]; then
    echo "Error: EVM scanner not found at $EVM_SCANNER"
    echo "Ensure the evm/ directory exists in the repository root."
    exit 1
fi

exec bash "$EVM_SCANNER" "$@" --chain polygon
