# Starlings Polygon (PoS) Smart Contract Scanner

Security auditor for smart contracts deployed on **Polygon PoS**.

This is a thin wrapper around the [EVM Smart Contract Auditor](../evm/) — the shared engine that powers all EVM-chain scanners.

## Quick Start

```bash
export POLYGONSCAN_API_KEY="your-key"   # Free at polygonscan.com/apis
./starlings-polygon-scan.sh <CONTRACT_ADDRESS>
```

## Examples

```bash
# Scan USDC on Polygon
./starlings-polygon-scan.sh 0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359

# Scan USDT with verbose output
./starlings-polygon-scan.sh 0xc2132D05D31c914a87C6611C10748AEb04B58e8F -v

# Scan WETH, save JSON report
./starlings-polygon-scan.sh 0x7ceB23fD6bC0adD59E62ac25578270cFf1b9f619 -o weth.json
```

## What Gets Checked

| Category | Checks | Description |
|----------|--------|-------------|
| Contract Verification | VER-001 – VER-003 | Source code verified on PolygonScan, compiler version, optimization settings |
| Owner/Admin | OWN-001 – OWN-004 | Centralized control, admin functions, multisig requirements |
| Proxy Patterns | PRX-001 – PRX-003 | Upgrade risk, implementation transparency, storage collisions |
| Token Mechanics | TKN-001 – TKN-005 | Mint/burn, fee structure, holder concentration, transferability |
| Audit History | AUD-001 – AUD-002 | Known audits, vulnerability cross-reference |
| Honeypot Detection | HPT-001 – HPT-003 | Sell restrictions, hidden fees, blacklists |

## Polygon-Specific Notes

- **PoS only**: This scanner covers Polygon PoS. Polygon zkEVM is a separate chain and is NOT supported.
- **Bridge contracts**: Many tokens on Polygon are bridged from Ethereum via the PoS Bridge or Plasma Bridge. Verify mapped token legitimacy and bridge security.
- **Very low gas costs**: Attracts high-volume token deployments — similar scam risk profile to BSC.
- **Ethereum mirrors**: Many projects deploy identical contracts on both Ethereum and Polygon. Cross-reference the Ethereum deployment for audit history.
- **Gaming/NFT heavy**: Polygon hosts many gaming and NFT contracts with complex mechanics — pay attention to admin/owner privileges (OWN checks).
- **PolygonScan API**: Uses Etherscan-compatible format, same rate limits apply.

## API Key

Get a free API key at [polygonscan.com/apis](https://polygonscan.com/apis). Without a key, scans are rate-limited to 1 request per 5 seconds.

## Full Documentation

See the [EVM Smart Contract Auditor README](../evm/README.md) for complete documentation on all checks, scoring methodology, and output format.
