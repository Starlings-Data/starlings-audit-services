# Starlings BNB Smart Chain (BSC) Smart Contract Scanner

Security auditor for smart contracts deployed on **BNB Smart Chain** (formerly Binance Smart Chain).

This is a thin wrapper around the [EVM Smart Contract Auditor](../evm/) — the shared engine that powers all EVM-chain scanners.

## Quick Start

```bash
export BSCSCAN_API_KEY="your-key"   # Free at bscscan.com/apis
./starlings-bsc-scan.sh <CONTRACT_ADDRESS>
```

## Examples

```bash
# Scan BSC-USD (USDT on BSC)
./starlings-bsc-scan.sh 0x55d398326f99059fF775485246999027B3197955

# Scan WBNB with verbose output
./starlings-bsc-scan.sh 0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c -v

# Scan BUSD, save JSON report
./starlings-bsc-scan.sh 0xe9e7CEA3DedcA5984780Bafc599bD69ADd087D56 -o busd.json
```

## What Gets Checked

| Category | Checks | Description |
|----------|--------|-------------|
| Contract Verification | VER-001 – VER-003 | Source code verified on BscScan, compiler version, optimization settings |
| Owner/Admin | OWN-001 – OWN-004 | Centralized control, admin functions, multisig requirements |
| Proxy Patterns | PRX-001 – PRX-003 | Upgrade risk, implementation transparency, storage collisions |
| Token Mechanics | TKN-001 – TKN-005 | Mint/burn, fee structure, holder concentration, transferability |
| Audit History | AUD-001 – AUD-002 | Known audits, vulnerability cross-reference |
| Honeypot Detection | HPT-001 – HPT-003 | Sell restrictions, hidden fees, blacklists |

## BSC-Specific Notes

- **High scam volume**: BSC's low gas costs attract a disproportionate number of scam tokens, rug pulls, and honeypot contracts
- **TKN-001 (Holder Concentration)**: Especially critical on BSC — many tokens have 80%+ supply held by the deployer
- **TKN-003 (Fee Mechanisms)**: Fee-on-transfer tokens are extremely common; watch for hidden or dynamic fees
- **Honeypot prevalence**: BSC has the highest rate of honeypot tokens among EVM chains — always check HPT findings
- **PancakeSwap liquidity**: Most BSC tokens trade on PancakeSwap — verify liquidity is locked and sufficient
- **BscScan API**: Uses Etherscan-compatible format, same rate limits apply

## API Key

Get a free API key at [bscscan.com/apis](https://bscscan.com/apis). Without a key, scans are rate-limited to 1 request per 5 seconds.

## Full Documentation

See the [EVM Smart Contract Auditor README](../evm/README.md) for complete documentation on all checks, scoring methodology, and output format.
