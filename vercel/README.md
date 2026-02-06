# Starlings Vercel Security Scanner

Automated security analysis for Vercel projects and teams. Audits authentication, environment variables, deployment configuration, domain/TLS security, firewall/WAF, edge config, logging, and project hardening -- all via the Vercel REST API. No secrets are sent anywhere.

## Security Checks

The scanner runs 30+ checks across 8 domains:

### Authentication & Access Control (3 checks)

| ID | Check | Severity | Description |
|----|-------|----------|-------------|
| AUTH-001 | SSO/SAML enforcement | High / Medium | Whether team has SSO configured and enforced. |
| AUTH-002 | Excessive team owners | Medium | Flags teams with more than 3 owner accounts. |
| AUTH-003 | Access groups | Low | Whether fine-grained access groups are configured. |

### Environment Variables & Secrets (3 checks)

| ID | Check | Severity | Description |
|----|-------|----------|-------------|
| ENV-001 | Sensitive vars in preview | High | Flags secrets (API keys, tokens, passwords) exposed to preview deployments triggered by PRs. |
| ENV-002 | Plaintext secrets | Medium | Detects sensitive values stored as plaintext instead of encrypted. |
| ENV-003 | Broad env var scoping | Low | Flags variables available across all environments when scoping may be appropriate. |

### Deployment Security (3 checks)

| ID | Check | Severity | Description |
|----|-------|----------|-------------|
| DEP-001 | Git integration | Medium | Whether the project is connected to a Git repository for code review. |
| DEP-003 | Risky build commands | High | Detects shell execution, curl, wget, or eval in custom build commands. |
| DEP-006 | Manual/CLI deployments | Low | Flags recent deployments made outside Git-based workflow. |

### Domain & TLS Security (3 checks)

| ID | Check | Severity | Description |
|----|-------|----------|-------------|
| DOM-001 | Unverified domains | High | Custom domains that are not verified (can be claimed by others). |
| DOM-002 | Domain misconfiguration | High | DNS misconfiguration that may cause SSL errors or downtime. |
| DOM-003 | Expiring domains | Medium | Team domains expiring within 30 days. |

### Firewall & WAF (5 checks)

| ID | Check | Severity | Description |
|----|-------|----------|-------------|
| FW-001 | Firewall enabled | High / Medium | Whether the Vercel Firewall is enabled for each project. |
| FW-002 | OWASP managed rules | High | Whether OWASP WAF rules are active (XSS, SQLi, etc.). |
| FW-003 | Bot protection | Medium | Whether bot protection managed rules are enabled. |
| FW-004 | IP rules | Info | Whether IP allow/deny rules are configured. |
| FW-005 | Custom WAF rules | Low | Whether custom firewall rules exist for app-specific protections. |

### Edge Config & Serverless (2 checks)

| ID | Check | Severity | Description |
|----|-------|----------|-------------|
| EDGE-001 | Edge Config token count | Low | Flags Edge Config stores with excessive access tokens. |
| EDGE-002 | Serverless function region | Info | Whether a specific region is configured for data residency. |

### Logging & Monitoring (3 checks)

| ID | Check | Severity | Description |
|----|-------|----------|-------------|
| LOG-001 | Log drains | Medium | Whether log drains are configured for centralized logging. |
| LOG-002 | Log drain HTTPS | High | Flags log drains sending to non-HTTPS endpoints. |
| LOG-003 | Webhook HTTPS | Medium | Flags deployment webhooks using non-HTTPS endpoints. |

### Project Configuration (4 checks)

| ID | Check | Severity | Description |
|----|-------|----------|-------------|
| PROJ-001 | Preview deployment protection | Medium | Whether preview deployments require authentication or password. |
| PROJ-003 | Security headers | Medium | Checks for HSTS, CSP, X-Frame-Options, X-Content-Type-Options on production. |
| PROJ-004 | Source map exposure | Low | Detects source maps served in production. |
| PROJ-005 | Node.js version | Medium | Flags outdated Node.js runtimes past end-of-life. |

## Prerequisites

- `curl`
- `jq`
- Vercel API token (`VERCEL_TOKEN`)

### Getting a Vercel Token

1. Go to [vercel.com/account/tokens](https://vercel.com/account/tokens)
2. Create a new token (read-only scope is sufficient)
3. Export it:

```bash
export VERCEL_TOKEN="your-token-here"
```

For team-scoped scans, also export:

```bash
export VERCEL_TEAM_ID="team_xxxxxxxxxxxx"
```

## Usage

### Scan All Projects (Personal Account)

```bash
./starlings-vercel-scan.sh
```

### Scan All Projects (Team)

```bash
export VERCEL_TEAM_ID="team_xxxxxxxxxxxx"
./starlings-vercel-scan.sh
```

### Scan a Specific Project

```bash
./starlings-vercel-scan.sh --project my-app
```

### Custom Output File

```bash
./starlings-vercel-scan.sh --output my-report.json
```

### Verbose Mode

```bash
./starlings-vercel-scan.sh --verbose
```

### Help

```bash
./starlings-vercel-scan.sh --help
```

## Scoring

### Score Calculation (0-100)

Each check contributes to the score. Findings reduce the score based on severity:

| Severity | Point Deduction |
|----------|----------------|
| Critical | -15 |
| High | -8 |
| Medium | -3 |
| Low | -1 |
| Info | 0 (no deduction) |
| Pass | 0 (no deduction) |

### Risk Levels

| Score Range | Risk Level | Interpretation |
|-------------|-----------|----------------|
| 90-100 | LOW | Excellent security posture |
| 70-89 | LOW | Good security posture |
| 60-69 | MEDIUM | Fair -- address failing checks |
| 40-59 | HIGH | Multiple security gaps |
| 0-39 | CRITICAL | Serious issues, urgent action required |

## Output Format

The scanner generates a JSON report:

```json
{
  "scanner_version": "1.0.0",
  "scan_date": "2026-02-05T20:00:00Z",
  "platform": "Vercel",
  "scope": "team",
  "team_name": "My Team",
  "projects_scanned": [
    {"id": "prj_xxx", "name": "my-app"}
  ],
  "score": {
    "overall": 72,
    "interpretation": "Good",
    "risk_level": "LOW"
  },
  "summary": {
    "critical": 0,
    "high": 1,
    "medium": 3,
    "low": 2,
    "info": 1,
    "passed": 18,
    "total_checks": 25
  },
  "findings": [
    {
      "domain": "env",
      "check_id": "ENV-001",
      "severity": "high",
      "title": "Sensitive env vars exposed to preview deployments",
      "description": "...",
      "resources": ["DATABASE_URL"],
      "remediation": "Restrict sensitive variables to production environment only.",
      "frameworks": ["ISO27001 A.14.2.5", "SOC2 CC6.1", "CIS 5.2", "CCSS 3.4"]
    }
  ]
}
```

## Testing

Run the test suite:

```bash
cd test/
bash test_runner.sh
```

## Privacy and Security

- **Read-Only**: All queries use the Vercel REST API in read-only mode
- **Local Reports**: Output stays on your machine in JSON format
- **No Secrets Exfiltrated**: The scanner never reads or logs environment variable values
- **API Token**: Your token is used only for API authentication, never sent elsewhere

## Need Help?

- Review the findings in your report and assess real-world risk
- Contact us for a deep-dive professional audit

## License

MIT License - See LICENSE file in repository root

---

**Built by Starlings Security**
*Cloud and application security auditing for modern deployment platforms*
