# Starlings Multi-Chain Blockchain Security Auditor

Automated smart contract security analysis for EVM-compatible chains. Audits contract verification status, ownership privileges, proxy/upgradeability patterns, token mechanics, and audit history -- all from public blockchain data. No private keys required.

## Supported Chains

| Chain | Explorer API | API Key Env Var | Chain ID |
|-------|-------------|-----------------|----------|
| Ethereum | `api.etherscan.io` | `ETHERSCAN_API_KEY` | 1 |
| Avalanche C-Chain | `api.snowtrace.io` | `SNOWTRACE_API_KEY` | 43114 |
| BNB Smart Chain (BSC) | `api.bscscan.com` | `BSCSCAN_API_KEY` | 56 |
| Polygon | `api.polygonscan.com` | `POLYGONSCAN_API_KEY` | 137 |

## Prerequisites

- `bash` (4.0+ for associative arrays)
- `curl`
- `jq` (JSON processing)
- Block explorer API key for your target chain (free tier is sufficient)

### Getting API Keys

All block explorer API keys are free. Register at the explorer site for your chain:

- Ethereum: [etherscan.io/apis](https://etherscan.io/apis)
- Avalanche: [snowtrace.io/apis](https://snowtrace.io/apis)
- BSC: [bscscan.com/apis](https://bscscan.com/apis)
- Polygon: [polygonscan.com/apis](https://polygonscan.com/apis)

Export the key for your target chain before running:

```bash
export ETHERSCAN_API_KEY="your-key-here"
```

The scanner will work without an API key, but requests will be rate-limited by the explorer.

## Usage

### Basic Scan (Ethereum)

```bash
./starlings-blockchain-audit.sh 0xdAC17F958D2ee523a2206206994597C13D831ec7
```

### Avalanche

```bash
./starlings-blockchain-audit.sh 0xB97EF9Ef8734C71904D8002F8b6Bc66Dd9c48a6E --chain avalanche
```

### BNB Smart Chain

```bash
./starlings-blockchain-audit.sh 0x55d398326f99059fF775485246999027B3197955 --chain bsc
```

### Polygon

```bash
./starlings-blockchain-audit.sh 0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174 --chain polygon
```

### Custom Output File

```bash
./starlings-blockchain-audit.sh 0xdAC17F958D2ee523a2206206994597C13D831ec7 --output usdt-report.json
```

### Verbose Mode

```bash
./starlings-blockchain-audit.sh 0xdAC17F958D2ee523a2206206994597C13D831ec7 --verbose
```

### Help

```bash
./starlings-blockchain-audit.sh --help
```

## Security Checks

The auditor runs 15 checks across 5 domains:

### Verification (3 checks)

| ID | Check | Severity | Description |
|----|-------|----------|-------------|
| SC-001 | Contract source code verification | Critical | Whether the contract source is verified on the block explorer. Unverified contracts cannot be reviewed and are a major red flag. |
| SC-002 | Solidity compiler version | High / Medium | Flags outdated compilers with known vulnerabilities. Versions before 0.4.20 are high severity; 0.4.x-0.6.x are medium. |
| SC-003 | License type | Low | Checks if an SPDX license identifier is present. Missing licenses may indicate informal development practices. |

### Ownership and Admin (4 checks)

| ID | Check | Severity | Description |
|----|-------|----------|-------------|
| OWN-001 | Owner is EOA vs multisig | High | Determines if the contract owner is a single key (EOA) or a contract (likely multisig). EOA ownership means one compromised key grants full control. |
| OWN-002 | Privileged admin functions | High / Medium | Scans the ABI for privileged functions (mint, pause, blacklist, freeze, selfdestruct, etc.). Elevated severity if destructive functions are present. |
| OWN-003 | Pause capability / currently paused | High / Low | Detects pausable contracts and checks if the contract is currently paused. A paused contract blocks all transfers. |
| OWN-004 | Renounce ownership availability | Info | Reports whether `renounceOwnership()` is available in the ABI, indicating ownership can be permanently surrendered. |

### Proxy and Upgradeability (2 checks)

| ID | Check | Severity | Description |
|----|-------|----------|-------------|
| PRX-001 | Proxy detection + implementation verification | Critical / Medium | Checks EIP-1967 and OpenZeppelin proxy storage slots. If a proxy is found, verifies the implementation contract source is published. Unverified implementations are critical risk. |
| PRX-002 | Proxy admin is EOA | High | If a proxy is detected, checks whether the proxy admin is a single key. An EOA proxy admin can upgrade the contract to arbitrary code. |

### Token Mechanics (4 checks)

| ID | Check | Severity | Description |
|----|-------|----------|-------------|
| TKN-001 | Token holder concentration | Critical / High / Medium | Queries the top token holders and calculates concentration. Top holder above 50% is critical (rug pull risk), above 20% is high, above 10% is medium. |
| TKN-002 | Mint function (inflationary supply) | Medium | Detects a `mint()` function in the ABI, meaning the supply is not fixed and authorized callers can dilute holders. |
| TKN-003 | Fee/tax mechanism | Medium | Scans for fee or tax functions (setFee, setTax, setBuyFee, setSellFee). Modifiable transfer fees can be exploited as honeypots. |
| TKN-004 | Blacklist capability | High | Detects blacklist, denylist, or blocklist functions. The owner can freeze individual addresses, preventing them from transferring tokens. |

### Audit and Security History (2 checks)

| ID | Check | Severity | Description |
|----|-------|----------|-------------|
| AUD-001 | Deployer analysis | Low | Looks up the contract creator and checks their transaction count. High counts may indicate a contract factory (legitimate or scam-related). |
| AUD-002 | Audit firm references in source | Medium | Searches the verified source code for references to known audit firms (OpenZeppelin, Certik, Trail of Bits, Halborn, Quantstamp, PeckShield, SlowMist, Hacken, and others). |

## Scoring

### Score Calculation (0-100)

Each check that runs contributes to the score. Findings reduce the score based on severity:

| Severity | Point Deduction |
|----------|----------------|
| Critical | -15 |
| High | -8 |
| Medium | -3 |
| Low | -1 |
| Pass | 0 (no deduction) |

The raw deductions are calculated against the maximum possible score and normalized to a 0-100 scale.

### Risk Levels

| Score Range | Risk Level | Interpretation |
|-------------|-----------|----------------|
| 90-100 | LOW | Excellent security posture |
| 70-89 | LOW | Good security posture |
| 60-69 | MEDIUM | Fair -- address failing checks |
| 40-59 | HIGH | Multiple security gaps, implement recommendations |
| 0-39 | CRITICAL | Serious issues, urgent action required |

## Output Format

The scanner generates a JSON report:

```json
{
  "scanner_version": "1.0.0",
  "scan_date": "2026-02-05T14:30:00Z",
  "chain": "Ethereum",
  "chain_id": "1",
  "network": "mainnet",
  "contract_address": "0xdAC17F958D2ee523a2206206994597C13D831ec7",
  "contract_name": "TetherToken",
  "explorer_url": "https://etherscan.io/address/0xdAC17F958D2ee523a2206206994597C13D831ec7",
  "score": {
    "overall": 62,
    "interpretation": "Fair",
    "risk_level": "MEDIUM"
  },
  "summary": {
    "critical": 0,
    "high": 2,
    "medium": 3,
    "low": 1,
    "info": 1,
    "passed": 8,
    "total_checks": 14
  },
  "findings": [
    {
      "domain": "ownership",
      "check_id": "OWN-001",
      "severity": "high",
      "title": "Contract owned by an EOA (single key)",
      "description": "The contract owner is an externally owned account...",
      "resources": ["0x..."],
      "remediation": "Transfer ownership to a multisig wallet...",
      "frameworks": ["CCSS 3.1", "ISO27001 A.9.2.3", "SOC2 CC6.1"]
    }
  ]
}
```

## Adding a New Chain

To add support for a new EVM-compatible chain, add configuration entries to the chain configuration block in `starlings-blockchain-audit.sh`:

```bash
# New Chain
CHAIN_RPC[newchain]="https://rpc.newchain.io"
CHAIN_EXPLORER_API[newchain]="https://api.newchainscan.io/api"
CHAIN_EXPLORER_KEY_VAR[newchain]="NEWCHAINSCAN_API_KEY"
CHAIN_NAME[newchain]="New Chain"
CHAIN_CURRENCY[newchain]="TOKEN"
CHAIN_ID[newchain]="12345"
CHAIN_EXPLORER_URL[newchain]="https://newchainscan.io"
```

Requirements for the new chain:
- An EVM-compatible JSON-RPC endpoint
- A block explorer with an Etherscan-compatible API (most EVM explorers use this format)
- That is it -- all 15 checks will work automatically

## Testing

Run the test suite:

```bash
cd test/
bash test_runner.sh
```

### Test Suites

1. **test_prerequisites.sh** - Validates curl, jq, address format, and RPC connectivity
2. **test_report_structure.sh** - Validates JSON report has all required fields and correct structure
3. **test_runner.sh** - Runs all test suites and reports pass/fail summary

## Privacy and Security

- **Read-Only**: All queries use public blockchain data via RPC and explorer APIs
- **No Private Keys**: The scanner never asks for or handles private keys
- **Local Reports**: Output stays on your machine in JSON format
- **API Keys**: Explorer API keys are used only for rate-limit bypass, never sent elsewhere

## Need Help?

- Review the findings in your report and assess real-world risk
- Share your report for community review: [scamshield.app/audit](https://scamshield.app/audit)
- Contact us for a deep-dive professional audit

## License

MIT License - See LICENSE file in repository root

---

**Built by Starlings Security**
*Smart contract and infrastructure auditing for the decentralized economy*
