# Starlings DigitalOcean Security Scanner

A lightweight, transparent security scanner that runs **locally in your environment**. Your DigitalOcean credentials never leave your machine.

## Quick Start

```bash
# Clone the repository
git clone https://github.com/Starlings-Data/starlings-audit-services.git
cd starlings-audit-services/digitalocean

# Make it executable
chmod +x starlings-do-scan.sh

# Run the scan
./starlings-do-scan.sh
```

## Prerequisites

- **doctl CLI** installed and authenticated ([install guide](https://docs.digitalocean.com/reference/doctl/how-to/install/))
- **Bash** (macOS, Linux, or WSL on Windows)
- **jq** (optional, for prettier JSON output)

### Setting Up doctl

1. Install doctl:
```bash
# macOS
brew install doctl

# Linux (snap)
sudo snap install doctl

# Manual download
# See: https://docs.digitalocean.com/reference/doctl/how-to/install/
```

2. Create a read-only API token:
   - Go to [DigitalOcean API Tokens](https://cloud.digitalocean.com/account/api/tokens)
   - Click "Generate New Token"
   - Name: "Starlings Security Scanner"
   - Scope: **Read Only** (write access is never needed)
   - Click "Generate Token" and save the token securely

3. Authenticate doctl:
```bash
doctl auth init --access-token YOUR_READ_ONLY_TOKEN
```

4. Verify access:
```bash
doctl account get
```

## Usage

```bash
# Run full scan with default output (do-security-report.json)
./starlings-do-scan.sh

# Custom output file
./starlings-do-scan.sh --output my-report.json

# Verbose output
./starlings-do-scan.sh --verbose

# Show help
./starlings-do-scan.sh --help
```

## What It Checks

The scanner runs **33 read-only checks** across 7 security domains:

### App Platform (4 checks)

| Check ID | Description | Severity | Compliance |
|----------|-------------|----------|------------|
| APP-001 | Plaintext secrets in environment variables | Critical | ISO 27001 A.10.1.1, SOC 2 CC6.1, CCSS 3.2 |
| APP-002 | Auto-deploy on push enabled | Medium | ISO 27001 A.14.2.2, SOC 2 CC8.1 |
| APP-003 | Unpinned container images from untrusted sources | High | ISO 27001 A.14.2.5, SOC 2 CC7.1, CCSS 2.1 |
| APP-004 | HTTP to HTTPS redirect not enforced | High | ISO 27001 A.14.1.2, SOC 2 CC6.7, CCSS 5.2 |

### Databases (6 checks)

| Check ID | Description | Severity | Compliance |
|----------|-------------|----------|------------|
| DB-001 | Unrestricted public access (0.0.0.0/0) | Critical | CIS 4.1, ISO 27001 A.13.1.1, SOC 2 CC6.6, CCSS 5.1 |
| DB-002 | SSL connections not enforced | High | CIS 4.2, ISO 27001 A.14.1.2, SOC 2 CC6.7, CCSS 5.2 |
| DB-003 | No trusted sources / firewall rules configured | High | CIS 4.1, ISO 27001 A.13.1.1, SOC 2 CC6.6, CCSS 5.1 |
| DB-004 | No recent backups available | High | ISO 27001 A.17.1.1, SOC 2 CC9.1, CCSS 7.1 |
| DB-005 | Outdated database engine version | Medium | ISO 27001 A.14.2.2, SOC 2 CC7.1, CCSS 2.2 |
| DB-006 | Redis noeviction policy (may cause write failures) | Low | ISO 27001 A.17.1.1, SOC 2 CC9.1 |

### Networking (5 checks)

| Check ID | Description | Severity | Compliance |
|----------|-------------|----------|------------|
| NET-001 | Droplets without Cloud Firewall protection | Critical | CIS 5.1, ISO 27001 A.13.1.1, SOC 2 CC6.6, CCSS 5.1 |
| NET-002 | Overly permissive firewall rules (all TCP from anywhere) | Critical | CIS 5.2, ISO 27001 A.13.1.1, SOC 2 CC6.6, CCSS 5.1 |
| NET-003 | SSH (port 22) open to the world (0.0.0.0/0) | High | CIS 5.2, ISO 27001 A.13.1.1, SOC 2 CC6.6, CCSS 5.1 |
| NET-004 | Load balancers without HTTPS forwarding | High | ISO 27001 A.14.1.2, SOC 2 CC6.7, CCSS 5.2 |
| NET-006 | No custom VPC network segmentation | Medium | ISO 27001 A.13.1.3, SOC 2 CC6.6, CCSS 5.3 |

### Storage (3 checks)

| Check ID | Description | Severity | Compliance |
|----------|-------------|----------|------------|
| STO-001 | CDN Spaces endpoints without custom domain | Low | ISO 27001 A.14.1.2, SOC 2 CC6.7 |
| STO-002 | CDN Spaces endpoints without SSL certificate (public CORS) | Medium | ISO 27001 A.14.1.2, SOC 2 CC6.7, CCSS 5.2 |
| STO-003 | Container Registry configuration review | Low | ISO 27001 A.14.2.5, SOC 2 CC7.1 |

### Droplets (7 checks)

| Check ID | Description | Severity | Compliance |
|----------|-------------|----------|------------|
| DRP-001 | No SSH keys configured (password auth likely) | Critical | CIS 5.3, ISO 27001 A.9.4.2, SOC 2 CC6.1, CCSS 4.1 |
| DRP-002 | Automated backups not enabled | High | ISO 27001 A.17.1.1, SOC 2 CC9.1, CCSS 7.1 |
| DRP-003 | Monitoring agent not enabled | Medium | ISO 27001 A.12.4.1, SOC 2 CC7.2, CCSS 6.1 |
| DRP-004 | Droplets in default VPC (no segmentation) | Low | ISO 27001 A.13.1.3, SOC 2 CC6.6, CCSS 5.3 |
| DRP-005 | Public IPv4 addresses assigned | Medium | ISO 27001 A.13.1.1, SOC 2 CC6.6 |
| DRP-006 | User data / cloud-init review | Low | ISO 27001 A.14.2.5, SOC 2 CC7.1 |
| DRP-007 | End-of-life or outdated OS images | High | ISO 27001 A.14.2.2, SOC 2 CC7.1, CCSS 2.2 |

### DNS (3 checks)

| Check ID | Description | Severity | Compliance |
|----------|-------------|----------|------------|
| DNS-001 | DNSSEC not available (DigitalOcean DNS limitation) | Low | ISO 27001 A.13.1.1, SOC 2 CC6.7, CCSS 5.2 |
| DNS-002 | Missing SPF / DKIM / DMARC records | Medium | ISO 27001 A.13.2.1, SOC 2 CC6.7 |
| DNS-004 | SSL certificates expiring soon or expired | High | ISO 27001 A.14.1.2, SOC 2 CC6.7, CCSS 5.2 |

### Access Control (5 checks)

| Check ID | Description | Severity | Compliance |
|----------|-------------|----------|------------|
| ACL-001 | Two-factor authentication not verified | High | CIS 1.5, ISO 27001 A.9.4.2, SOC 2 CC6.1, CCSS 4.1 |
| ACL-002 | API token scope and rotation review | Medium | CIS 1.14, ISO 27001 A.9.2.5, SOC 2 CC6.1, CCSS 4.2 |
| ACL-003 | Weak SSH key algorithms (DSA, short RSA) | Medium | CIS 5.3, ISO 27001 A.10.1.1, SOC 2 CC6.1, CCSS 4.1 |
| ACL-004 | Team member access review | Low | CIS 1.16, ISO 27001 A.9.2.6, SOC 2 CC6.2, CCSS 4.3 |
| ACL-005 | Resources not organized into projects | Low | ISO 27001 A.8.1.1, SOC 2 CC6.3 |

## Compliance Framework Coverage

Each finding maps to one or more compliance frameworks:

| Framework | Description | Checks Mapped |
|-----------|-------------|---------------|
| **CIS Benchmarks** | Center for Internet Security best practices | 12 checks |
| **ISO 27001** | Information security management (Annex A controls) | 33 checks |
| **SOC 2** | Trust Services Criteria (CC controls) | 33 checks |
| **CCSS** | Cryptocurrency Security Standard for digital asset compliance | 22 checks |

## Output

The scanner generates a JSON report (`do-security-report.json`) with:

```json
{
  "scanner_version": "1.0.0",
  "scan_date": "2026-02-05T14:30:00Z",
  "platform": "digitalocean",
  "account_email": "<REDACTED_EMAIL>",
  "account_uuid": "abc123",
  "score": {
    "overall": 72,
    "interpretation": "Good"
  },
  "summary": {
    "critical": 1,
    "high": 3,
    "medium": 5,
    "low": 2,
    "passed": 22,
    "total_checks": 33
  },
  "compliance_coverage": {
    "cis_benchmarks": true,
    "iso_27001": true,
    "soc_2": true,
    "ccss": true
  },
  "findings": [
    {
      "domain": "database",
      "check_id": "DB-001",
      "severity": "critical",
      "title": "Databases with unrestricted public access",
      "description": "...",
      "resources": ["my-db-cluster"],
      "remediation": "...",
      "frameworks": ["CIS 4.1", "ISO27001 A.13.1.1", "SOC2 CC6.6", "CCSS 5.1"]
    }
  ]
}
```

### Automatic Redaction

The scanner automatically redacts email addresses from the output report. **Always review the output** before sharing to ensure no sensitive information is included.

## Scoring

The scanner calculates a weighted security score from 0 to 100:

| Severity | Point Deduction |
|----------|-----------------|
| Critical | -15 points per finding |
| High | -8 points per finding |
| Medium | -3 points per finding |
| Low | -1 point per finding |

Each check contributes 10 points to the maximum possible score. The final percentage reflects your overall security posture.

| Score | Interpretation |
|-------|----------------|
| 90-100 | **Excellent** - Minor improvements recommended |
| 70-89 | **Good** - Some important gaps to address |
| 50-69 | **Fair** - Significant security improvements needed |
| Below 50 | **Needs Attention** - Critical issues require immediate action |

## Testing

Run the test suite:

```bash
cd test/
bash test_runner.sh
```

### Test Cases

1. **test_doctl_connection.sh** - Validates doctl is installed, authenticated, and has account access
2. **test_report_structure.sh** - Validates JSON report has required fields and correct structure
3. **test_runner.sh** - Runs all tests and reports pass/fail summary

## Security and Privacy

- **Runs locally** - Your credentials never leave your machine
- **Read-only** - No modifications to your DigitalOcean environment
- **Transparent** - Full source code available for review
- **Auto-redacts** - Email addresses removed from output reports
- **Read-only token** - Write access is never required

## Troubleshooting

### "doctl CLI not found"
- Install doctl: `brew install doctl` (macOS) or see the [install guide](https://docs.digitalocean.com/reference/doctl/how-to/install/)

### "doctl not authenticated or token invalid"
- Run `doctl auth init` and provide your API token
- Verify with `doctl account get`

### "jq not found"
- Install jq: `brew install jq` (macOS) or `apt-get install jq` (Linux)
- jq is optional but recommended for formatted output

### Slow scan
- Normal scan time: 30-90 seconds depending on resource count
- The scanner makes multiple API calls to check each resource
- DigitalOcean API rate limit: 5,000 requests/hour

## Next Steps

1. **Review** the generated report
2. **Share** at [scamshield.app/audit](https://scamshield.app/audit) to get your personalized remediation plan
3. **Address** critical and high severity findings first
4. **Re-scan** regularly to track security improvements

---

**Need help?** Contact us at [scamshield.app/audit](https://scamshield.app/audit) for expert guidance on remediation and compliance.

---

**Built by Starlings Security**
*Professional infrastructure auditing for startups and enterprises*

## License

MIT License - See [LICENSE](../LICENSE) for details.
