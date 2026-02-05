# Starlings Cloudflare Security Scanner

Comprehensive security audit tool for Cloudflare domains. Checks DNS security, HTTPS/TLS configuration, DDoS protection, WAF rules, access control, and performance settings.

## Features

- **DNS Security**: DNSSEC validation, nameserver configuration, registrar lock status
- **HTTPS/TLS**: Minimum TLS version, certificate status, HTTPS redirect, HSTS headers
- **DDoS & Security**: DDoS protection level, WAF rules, bot management, rate limiting
- **Access Control**: Zero Trust setup, API token rotation, firewall rules, IP restrictions
- **Performance**: Caching rules, image optimization, minification, Polish settings
- **Compliance Mapping**: CIS Cloudflare Framework, PCI-DSS requirements
- **JSON Reports**: Structured output with security score (0-100) and remediation steps

## Installation

### Prerequisites

- `bash` (4.0+)
- `curl`
- `jq` (for JSON processing)
- A Cloudflare account with API access

### Setup

1. Clone the repository:
```bash
git clone https://github.com/Starlings-Data/starlings-audit-services.git
cd starlings-audit-services/cloudflare
chmod +x starlings-cf-scan.sh
```

2. **Create a Cloudflare API Token**:
   - Go to [Cloudflare Dashboard](https://dash.cloudflare.com/)
   - User Profile > API Tokens > Create Token
   - Name: "Starlings Scanner"
   - Permissions:
     - Account > Account Settings: Read
     - Zone > Zone: Read
     - Zone > DNS: Read
     - Zone > SSL and Certificates: Read
     - Zone > Firewall Services: Read
     - Zone > Caching: Read
   - Click "Continue to Summary" > "Create Token"
   - **Save the token securely** (you'll need it for scanning)

## Usage

### Basic Scan

```bash
./starlings-cf-scan.sh --api-token YOUR_API_TOKEN --zone example.com
```

### Using Environment Variable

```bash
export CF_API_TOKEN="YOUR_API_TOKEN"
./starlings-cf-scan.sh --zone example.com
```

### Custom Output File

```bash
./starlings-cf-scan.sh --api-token YOUR_TOKEN --zone example.com --output custom-report.json
```

### Debug Mode

```bash
./starlings-cf-scan.sh --api-token YOUR_TOKEN --zone example.com --debug
```

### Help

```bash
./starlings-cf-scan.sh --help
```

## Output

The scanner generates a JSON report with the following structure:

```json
{
  "metadata": {
    "scanType": "Cloudflare Security Audit",
    "timestamp": "2026-02-05T14:30:00Z",
    "zone": "example.com",
    "scanDuration": 23
  },
  "summary": {
    "overallScore": 78,
    "riskLevel": "MEDIUM",
    "checksTotal": 20,
    "checksPassed": 15,
    "checksFailed": 2,
    "checksWarning": 3
  },
  "checks": {
    "dns": [
      {
        "name": "Nameserver Configuration",
        "status": "PASS",
        "message": "Nameservers properly configured",
        "remediation": "Monitor for unexpected changes"
      }
    ],
    "https_tls": [...],
    "ddos_security": [...],
    "access_control": [...],
    "performance": [...]
  },
  "frameworks": {
    "CIS Cloudflare": {...},
    "PCI-DSS": {...}
  }
}
```

## Security Checks Explained

### DNS Security

- **DNSSEC Enabled**: Prevents DNS spoofing by signing records. Essential for security.
- **Nameserver Configuration**: Ensures authoritative nameservers are properly configured.
- **Domain Registrar Lock**: Prevents unauthorized domain transfers.

### HTTPS/TLS

- **Minimum TLS Version**: Should be 1.2 or higher to prevent downgrade attacks.
- **SSL Certificate Status**: Validates certificate is active and managed properly.
- **HTTPS Redirect**: Forces all traffic to encrypted connections.
- **HSTS Headers**: Instructs browsers to only use HTTPS for future connections.

### DDoS & Security

- **DDoS Protection**: Cloudflare's automatic DDoS protection should be enabled.
- **WAF Rules**: Web Application Firewall rules protect against common exploits.
- **Bot Management**: Advanced bot detection and mitigation.
- **Rate Limiting**: Prevents brute force and abuse attacks.

### Access Control

- **Zero Trust**: Cloudflare Zero Trust (formerly Access) provides zero-trust network access.
- **API Token Rotation**: Regular token rotation prevents long-lived credential exposure.
- **Firewall Rules**: Custom rules for fine-grained access control.
- **IP Restrictions**: Limit access to sensitive areas by IP address.

### Performance

- **Caching Rules**: Improves performance by caching static content.
- **Image Optimization**: Reduces image file sizes without quality loss.
- **Minification**: Reduces CSS/JavaScript file sizes.
- **Polish**: Automatic image optimization and WebP conversion.

## Security Score Interpretation

- **80-100 (GREEN / LOW RISK)**: Excellent security posture. Continue monitoring.
- **60-79 (YELLOW / MEDIUM RISK)**: Address failing checks. Consider enabling additional protections.
- **40-59 (ORANGE / HIGH RISK)**: Multiple security gaps. Implement recommended changes immediately.
- **0-39 (RED / CRITICAL RISK)**: Serious security issues. Urgent action required.

## Remediation Examples

### Enable DNSSEC
1. Zone > DNS > DNSSEC
2. Click "Enable DNSSEC"
3. Copy DS records and add to parent domain registrar

### Enforce TLS 1.2+
1. Zone > SSL/TLS > Edge Certificates
2. Set "Minimum TLS Version" to 1.2

### Enable WAF
1. Zone > Security > WAF
2. Enable OWASP ModSecurity Core Rule Set
3. Configure sensitivity level (Essentially Off → I'm Under Attack)

### Set Up Rate Limiting
1. Zone > Security > Rate Limiting
2. Create rules for endpoints prone to abuse
3. Set appropriate thresholds (e.g., 100 requests/minute)

## Compliance Frameworks

### CIS Cloudflare Benchmark

The scanner maps checks to the CIS Cloudflare Benchmark:

- 1.1 - Ensure DNSSEC is enabled
- 1.2 - Ensure TLS minimum version is 1.2+
- 2.1 - Ensure HTTPS redirect is enabled
- 3.1 - Ensure WAF is configured
- 3.2 - Ensure DDoS protection is enabled

### PCI-DSS v3.2.1

- **Requirement 4.1**: Encryption in transit (TLS 1.2+, HTTPS)
- **Requirement 6.5.1**: Injection attacks (WAF protection)

## Testing

Run the test suite:

```bash
cd test/
bash test_runner.sh
```

### Test Cases

1. **test_api_connection.sh** - Validates API connectivity
2. **test_dns_security.sh** - Tests DNS checks
3. **test_https_tls.sh** - Tests HTTPS/TLS configuration
4. **test_ddos_security.sh** - Tests DDoS and WAF checks
5. **test_access_control.sh** - Tests access control checks
6. **test_performance.sh** - Tests caching and optimization

## Troubleshooting

### "Zone not found"
- Verify the domain name matches your Cloudflare account
- Ensure the domain is active in your account

### "Unauthorized"
- Check API token is correct and not expired
- Verify token has required permissions (Zone > Zone: Read)

### "Unable to verify [check]"
- Some checks require manual verification (Zero Trust setup, API rotation)
- Review Cloudflare dashboard for these settings

### Slow Scan
- Normal scan time: 15-30 seconds
- Cloudflare API rate limits: 1200 requests/5 minutes
- If slow, check your network connection

## Performance

- **Typical Scan Time**: 20-30 seconds
- **API Calls**: ~25-30 per scan
- **Memory Usage**: <50MB
- **Rate Limiting**: Safe to run repeatedly (respects Cloudflare's rate limits)

## Privacy & Security

- **No Data Collection**: Audit tool only reads your zone configuration
- **Credentials**: API token stays local, never sent to third parties
- **Reports**: Saved locally in JSON format
- **Redaction**: Sensitive data (full API responses) not included in reports

## API Token Permissions

**Required (minimum)**:
- Account > Account Settings: Read
- Zone > Zone: Read  
- Zone > DNS: Read
- Zone > SSL and Certificates: Read

**Optional** (for advanced checks):
- Zone > Firewall Services: Read
- Zone > Caching: Read
- Zone > Bot Management: Read (if using bot management)

**Never Grant**:
- Zone > Edit (write access unnecessary)
- Account > Billing (data leak risk)
- Organization > All (scope creep)

## Next Steps

After scanning:

1. **Review the report** - Prioritize failed checks (FAIL status)
2. **Address critical issues** - Fix any CRITICAL or HIGH risk items
3. **Enable protections** - Follow remediation steps for WARNING items
4. **Re-scan regularly** - Schedule monthly audits to track improvements
5. **Reach out** - Contact Starlings for help implementing recommendations

## Support

For questions or issues:
- Check [Cloudflare API Docs](https://developers.cloudflare.com/api/)
- Review test cases in `test/` directory
- Open an issue on GitHub

## License

MIT License - See LICENSE file in repository root

---

**Built by Starlings Security**  
*Professional infrastructure auditing for startups and enterprises*
