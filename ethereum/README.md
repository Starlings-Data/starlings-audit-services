# Starlings Ethereum Smart Contract Scanner

Security auditor for smart contracts deployed on **Ethereum mainnet**.

This is a thin wrapper around the [EVM Smart Contract Auditor](../evm/) — the shared engine that powers all EVM-chain scanners.

## Quick Start

```bash
export ETHERSCAN_API_KEY="your-key"   # Free at etherscan.io/apis
./starlings-ethereum-scan.sh <CONTRACT_ADDRESS>
```

## Examples

```bash
# Scan USDT
./starlings-ethereum-scan.sh 0xdAC17F958D2ee523a2206206994597C13D831ec7

# Scan USDC with verbose output
./starlings-ethereum-scan.sh 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48 -v

# Scan DAI, save JSON report
./starlings-ethereum-scan.sh 0x6B175474E89094C44Da98b954EedeAC495271d0F -o dai.json
```

## What Gets Checked

| Category | Checks | Description |
|----------|--------|-------------|
| Contract Verification | VER-001 – VER-003 | Source code verified on Etherscan, compiler version, optimization settings |
| Owner/Admin | OWN-001 – OWN-004 | Centralized control, admin functions, multisig requirements |
| Proxy Patterns | PRX-001 – PRX-003 | Upgrade risk, implementation transparency, storage collisions |
| Token Mechanics | TKN-001 – TKN-005 | Mint/burn, fee structure, holder concentration, transferability |
| Audit History | AUD-001 – AUD-002 | Known audits, vulnerability cross-reference |
| Honeypot Detection | HPT-001 – HPT-003 | Sell restrictions, hidden fees, blacklists |

## Ethereum-Specific Notes

- **Gas costs**: Higher gas means fewer spam tokens, but also more financial impact per transaction
- **DeFi concentration**: Most major DeFi protocols live on Ethereum — check for composability risks
- **MEV exposure**: Contracts interacting with AMMs may be susceptible to sandwich attacks
- **L2 bridges**: If the contract bridges to L2s, verify bridge contract security separately

## API Key

Get a free API key at [etherscan.io/apis](https://etherscan.io/apis). Without a key, scans are rate-limited to 1 request per 5 seconds.

## Full Documentation

See the [EVM Smart Contract Auditor README](../evm/README.md) for complete documentation on all checks, scoring methodology, and output format.
