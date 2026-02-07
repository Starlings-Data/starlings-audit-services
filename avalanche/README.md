# Starlings Avalanche C-Chain Smart Contract Scanner

Security auditor for smart contracts deployed on **Avalanche C-Chain**.

This is a thin wrapper around the [EVM Smart Contract Auditor](../evm/) — the shared engine that powers all EVM-chain scanners.

## Quick Start

```bash
export SNOWTRACE_API_KEY="your-key"   # Free at snowtrace.io/apis
./starlings-avalanche-scan.sh <CONTRACT_ADDRESS>
```

## Examples

```bash
# Scan USDC on Avalanche
./starlings-avalanche-scan.sh 0xB97EF9Ef8734C71904D8002F8b6Bc66Dd9c48a6E

# Scan USDt with verbose output
./starlings-avalanche-scan.sh 0x9702230A8Ea53601f5cD2dc00fDBc13d4dF4A8c7 -v

# Scan WETH.e, save JSON report
./starlings-avalanche-scan.sh 0x49D5c2BdFfac6CE2BFdB6640F4F80f226bc10bAB -o weth.json
```

## What Gets Checked

| Category | Checks | Description |
|----------|--------|-------------|
| Contract Verification | VER-001 – VER-003 | Source code verified on Snowtrace, compiler version, optimization settings |
| Owner/Admin | OWN-001 – OWN-004 | Centralized control, admin functions, multisig requirements |
| Proxy Patterns | PRX-001 – PRX-003 | Upgrade risk, implementation transparency, storage collisions |
| Token Mechanics | TKN-001 – TKN-005 | Mint/burn, fee structure, holder concentration, transferability |
| Audit History | AUD-001 – AUD-002 | Known audits, vulnerability cross-reference |
| Honeypot Detection | HPT-001 – HPT-003 | Sell restrictions, hidden fees, blacklists |

## Avalanche-Specific Notes

- **C-Chain only**: This scanner covers Avalanche's C-Chain (Contract Chain). Subnet contracts are NOT supported.
- **Bridged tokens (.e suffix)**: Many tokens on Avalanche are bridged from Ethereum (e.g., WETH.e, USDC.e). Verify the bridge contract and mapped token legitimacy.
- **Native vs bridged USDC**: Avalanche has both native USDC (Circle-issued) and bridged USDC.e — these are different contracts with different security profiles.
- **Lower gas costs**: More complex contract interactions are economically viable, meaning contracts may have more elaborate logic to audit.
- **Snowtrace API**: Uses Etherscan-compatible format, same rate limits apply.

## API Key

Get a free API key at [snowtrace.io/apis](https://snowtrace.io/apis). Without a key, scans are rate-limited to 1 request per 5 seconds.

## Full Documentation

See the [EVM Smart Contract Auditor README](../evm/README.md) for complete documentation on all checks, scoring methodology, and output format.
