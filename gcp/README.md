# Starlings GCP Security Scanner

A lightweight, transparent security scanner that runs **locally in your environment**. Your GCP credentials never leave your machine.

## Quick Start

```bash
# Clone the repository
git clone https://github.com/Starlings-Data/starlings-audit-services.git
cd starlings-audit-services/gcp

# Make it executable
chmod +x starlings-gcp-scan.sh

# Run the scan
./starlings-gcp-scan.sh
```

## Requirements

- **gcloud CLI** installed and authenticated (`gcloud auth login`)
- **gsutil** (included with gcloud SDK)
- **Bash** (macOS, Linux, or WSL on Windows)
- **jq** (optional, for prettier output)

### Permissions

The scanner requires **read-only** access to your GCP project. For least-privilege access, create a custom IAM role using the provided `gcp-scan-policy.yaml`:

```bash
# Create the custom role
gcloud iam roles create StarlingsSecurityScanner \
  --project=YOUR_PROJECT_ID \
  --file=gcp-scan-policy.yaml

# Create a service account and bind the role
gcloud iam service-accounts create starlings-scanner \
  --display-name="Starlings Security Scanner" \
  --project=YOUR_PROJECT_ID

gcloud projects add-iam-policy-binding YOUR_PROJECT_ID \
  --member="serviceAccount:starlings-scanner@YOUR_PROJECT_ID.iam.gserviceaccount.com" \
  --role="projects/YOUR_PROJECT_ID/roles/StarlingsSecurityScanner"

# Authenticate as the service account (optional)
gcloud auth activate-service-account \
  --key-file=path/to/key.json
```

After the scan, you can remove the service account:
```bash
gcloud iam service-accounts delete \
  starlings-scanner@YOUR_PROJECT_ID.iam.gserviceaccount.com \
  --project=YOUR_PROJECT_ID
```

## Usage

```bash
# Scan default project (from gcloud config)
./starlings-gcp-scan.sh

# Scan specific project
./starlings-gcp-scan.sh --project my-project-123

# Custom output file
./starlings-gcp-scan.sh --output my-report.json

# Verbose output
./starlings-gcp-scan.sh --verbose

# Combined options
./starlings-gcp-scan.sh --project my-project-123 --output report.json --verbose

# Show help
./starlings-gcp-scan.sh --help
```

## What It Checks

The scanner runs **34 read-only checks** across 5 security domains:

### IAM & Access Management (8 checks)

| Check ID | Description | Severity | Compliance |
|----------|-------------|----------|------------|
| IAM-001 | Default compute service account has IAM bindings | High | CIS-GCP 1.1, ISO27001 A.9.2.3, SOC2 CC6.3, CCSS 4.3 |
| IAM-002 | User-managed service account keys exist | High | CIS-GCP 1.4, ISO27001 A.9.2.5, SOC2 CC6.1, CCSS 4.1 |
| IAM-003 | Service accounts with Owner or Editor roles | Critical | CIS-GCP 1.5, ISO27001 A.9.2.3, SOC2 CC6.3, CCSS 4.3 |
| IAM-004 | Service account keys older than 90 days | Medium | CIS-GCP 1.7, ISO27001 A.9.2.5, SOC2 CC6.1 |
| IAM-005 | Users with primitive Owner/Editor roles | High | CIS-GCP 1.3, ISO27001 A.9.2.3, SOC2 CC6.3, CCSS 4.3 |
| IAM-006 | Domain-restricted sharing not configured | Medium | CIS-GCP 1.1, ISO27001 A.9.2.3, SOC2 CC6.1 |
| IAM-007 | Users with service account impersonation rights | Medium | CIS-GCP 1.6, ISO27001 A.9.2.3, SOC2 CC6.3 |
| IAM-008 | API keys without restrictions | High | CIS-GCP 1.12, ISO27001 A.9.4.1, SOC2 CC6.1, CCSS 4.2 |

### Cloud Storage (5 checks)

| Check ID | Description | Severity | Compliance |
|----------|-------------|----------|------------|
| GCS-001 | Publicly accessible Cloud Storage buckets | Critical | CIS-GCP 5.1, ISO27001 A.13.1.1, SOC2 CC6.1, CCSS 3.1 |
| GCS-002 | Buckets without customer-managed encryption keys (CMEK) | Medium | CIS-GCP 5.3, ISO27001 A.10.1.1, SOC2 CC6.1, CCSS 3.2 |
| GCS-003 | Cloud Storage buckets without access logging | Medium | CIS-GCP 5.3, ISO27001 A.12.4.1, SOC2 CC7.2 |
| GCS-004 | Cloud Storage buckets without object versioning | Low | ISO27001 A.17.1.1, SOC2 CC9.1 |
| GCS-005 | Buckets without uniform bucket-level access | Medium | CIS-GCP 5.2, ISO27001 A.9.2.3, SOC2 CC6.1 |

### Compute & Network (9 checks)

| Check ID | Description | Severity | Compliance |
|----------|-------------|----------|------------|
| GCE-001 | Firewall rules allow SSH (port 22) from 0.0.0.0/0 | Critical | CIS-GCP 3.6, ISO27001 A.13.1.1, SOC2 CC6.6, CCSS 5.1 |
| GCE-002 | Firewall rules allow RDP (port 3389) from 0.0.0.0/0 | Critical | CIS-GCP 3.7, ISO27001 A.13.1.1, SOC2 CC6.6, CCSS 5.1 |
| GCE-003 | Compute instances with external IP addresses | Medium | CIS-GCP 4.9, ISO27001 A.13.1.1, SOC2 CC6.6 |
| GCE-004 | OS Login not enabled at project level | Medium | CIS-GCP 4.4, ISO27001 A.9.2.1, SOC2 CC6.1, CCSS 4.1 |
| GCE-005 | Serial port access enabled at project level | Medium | CIS-GCP 4.5, ISO27001 A.13.1.1, SOC2 CC6.6 |
| GCE-006 | Instances with IP forwarding enabled | Low | CIS-GCP 4.6, ISO27001 A.13.1.1, SOC2 CC6.6 |
| GCE-007 | VPC subnets without Flow Logs enabled | Medium | CIS-GCP 3.8, ISO27001 A.12.4.1, SOC2 CC7.2, CCSS 6.1 |
| GCE-008 | SSL policies with weak TLS versions or cipher profiles | High | CIS-GCP 3.9, ISO27001 A.14.1.2, SOC2 CC6.7, CCSS 3.2 |
| GCE-009 | No Cloud Armor security policies configured | Low | ISO27001 A.13.1.1, SOC2 CC6.6, CCSS 5.2 |

### Cloud SQL & Database (4 checks)

| Check ID | Description | Severity | Compliance |
|----------|-------------|----------|------------|
| SQL-001 | Cloud SQL instances with public IP addresses | High | CIS-GCP 6.5, ISO27001 A.13.1.1, SOC2 CC6.6, CCSS 3.1 |
| SQL-002 | Cloud SQL instances without SSL/TLS enforcement | High | CIS-GCP 6.4, ISO27001 A.14.1.2, SOC2 CC6.7, CCSS 3.2 |
| SQL-003 | Cloud SQL instances without automated backups | High | CIS-GCP 6.7, ISO27001 A.17.1.1, SOC2 CC9.1, CCSS 7.1 |
| SQL-004 | Cloud SQL instances with 0.0.0.0/0 in authorized networks | Critical | CIS-GCP 6.5, ISO27001 A.13.1.1, SOC2 CC6.6, CCSS 5.1 |

### Logging & Monitoring (8 checks)

| Check ID | Description | Severity | Compliance |
|----------|-------------|----------|------------|
| LOG-001 | Data Access audit logs not configured | High | CIS-GCP 2.1, ISO27001 A.12.4.1, SOC2 CC7.2, CCSS 6.1 |
| LOG-002 | No log sinks (exports) configured | High | CIS-GCP 2.2, ISO27001 A.12.4.1, SOC2 CC7.2, CCSS 6.1 |
| LOG-003 | No Cloud Monitoring alerting policies | Medium | CIS-GCP 2.4, ISO27001 A.16.1.2, SOC2 CC7.3, CCSS 6.2 |
| LOG-004 | No uptime checks configured | Low | ISO27001 A.17.1.1, SOC2 CC7.1 |
| LOG-005 | Security Command Center not enabled | Medium | CIS-GCP 2.12, ISO27001 A.12.6.1, SOC2 CC7.1, CCSS 6.2 |
| LOG-006 | Cloud Asset Inventory API not enabled | Low | ISO27001 A.8.1.1, SOC2 CC6.1 |
| LOG-007 | VPC Service Controls not configured | Medium | CIS-GCP 3.10, ISO27001 A.13.1.3, SOC2 CC6.1, CCSS 3.1 |
| LOG-008 | Binary Authorization not enabled | Low | ISO27001 A.14.2.7, SOC2 CC7.1, CCSS 2.1 |

## Compliance Framework Coverage

Each finding maps to relevant compliance frameworks:

| Framework | Description | Checks Mapped |
|-----------|-------------|---------------|
| **CIS GCP Foundations Benchmark** | Center for Internet Security benchmark for GCP | 23 of 34 |
| **ISO 27001** | International information security management standard (Annex A) | 34 of 34 |
| **SOC 2** | Trust Services Criteria for service organizations | 34 of 34 |
| **CCSS** | Cryptocurrency Security Standard for digital asset compliance | 21 of 34 |

Example finding with framework references:
```json
{
  "check_id": "IAM-003",
  "severity": "critical",
  "title": "Service accounts with Owner or Editor roles",
  "frameworks": ["CIS-GCP 1.5", "ISO27001 A.9.2.3", "SOC2 CC6.3", "CCSS 4.3"]
}
```

## Output

The scanner generates a JSON report (`gcp-security-report.json`) with:

```json
{
  "scanner_version": "1.0.0",
  "scan_date": "2026-02-05T10:30:00Z",
  "project_id": "my-project-123",
  "project_number": "REDACTED",
  "score": {
    "overall": 72,
    "interpretation": "Good"
  },
  "summary": {
    "critical": 1,
    "high": 3,
    "medium": 5,
    "low": 2,
    "passed": 23,
    "total_checks": 34
  },
  "compliance_coverage": {
    "cis_gcp_foundations": true,
    "iso_27001": true,
    "soc_2": true,
    "ccss": true
  },
  "findings": [
    {
      "domain": "iam",
      "check_id": "IAM-003",
      "severity": "critical",
      "title": "Service accounts with Owner or Editor roles",
      "description": "...",
      "resources": ["my-sa@my-project.iam.gserviceaccount.com"],
      "remediation": "...",
      "frameworks": ["CIS-GCP 1.5", "ISO27001 A.9.2.3", "SOC2 CC6.3", "CCSS 4.3"]
    }
  ]
}
```

### Automatic Redaction

The scanner automatically redacts:
- GCP project numbers (12-digit numbers replaced with `REDACTED`)

**Always review the output** before sharing to ensure no sensitive information is included.

## Scoring

The scanner uses weighted severity deductions to calculate a score out of 100:

| Severity | Deduction per Finding |
|----------|-----------------------|
| Critical | -15 points |
| High | -8 points |
| Medium | -3 points |
| Low | -1 point |

| Score | Interpretation |
|-------|----------------|
| 90-100 | Excellent - Minor improvements recommended |
| 70-89 | Good - Some important gaps to address |
| 50-69 | Fair - Significant security improvements needed |
| Below 50 | Needs Attention - Critical issues require immediate action |

## Testing

Run the test suite:

```bash
cd test/
bash test_runner.sh
```

### Test Cases

1. **test_gcloud_connection.sh** - Validates gcloud CLI installation, authentication, and API access
2. **test_report_structure.sh** - Validates JSON report structure and required fields

## Next Steps

1. **Review** the generated report
2. **Share** at [scamshield.app/audit](https://scamshield.app/audit)
3. **Get** your personalized remediation plan

## Security & Privacy

- **Runs locally** - Your credentials never leave your machine
- **Read-only** - No modifications to your GCP environment
- **Transparent** - Full source code available for review
- **Auto-redacts** - Project numbers removed from output

## License

MIT License - See [LICENSE](../LICENSE) for details.

## Support

- Email: security@starlingsdata.com
- Web: [starlingsdata.com](https://starlingsdata.com)
- Issues: [GitHub Issues](https://github.com/Starlings-Data/starlings-audit-services/issues)

---

**Built by Starlings Security**
*Professional infrastructure auditing for startups and enterprises*
