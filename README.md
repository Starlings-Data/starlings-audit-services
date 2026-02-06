# Starlings Open Source Audit Services

Comprehensive, production-grade security audit tools for multi-cloud and multi-chain infrastructure. Purpose-built for startups and companies preparing for mainnet launch or security certifications.

**Free. Open source. No pricing, no gatekeeping. Just value.**

## 🎯 Why Starlings Audit?

- **Infrastructure Defense**: Audit AWS, GCP, DigitalOcean, Cloudflare configurations
- **Blockchain Security**: Audit smart contracts, tokens, and protocols across 7 blockchains
- **Vulnerability Detection**: Identify misconfigurations, compliance gaps, and security risks
- **Actionable Reports**: Every finding includes remediation steps and framework mapping (CIS, PCI-DSS, ISO27001, SOC2)
- **No Vendor Lock-in**: Run locally, own your data, integrate anywhere

## 🚀 Quick Start

### Cloudflare Security Audit

```bash
# Clone the repository
git clone https://github.com/Starlings-Data/starlings-audit-services.git
cd starlings-audit-services/cloudflare

# Create a Cloudflare API token (read-only recommended)
# https://dash.cloudflare.com/ → User Profile → API Tokens

# Run the scan
./starlings-cf-scan.sh --api-token YOUR_TOKEN --zone example.com

# Review the JSON report
cat cloudflare-scan-report.json
```

See [cloudflare/README.md](cloudflare/README.md) for full documentation.

### AWS Security Audit

```bash
cd starlings-audit-services/aws

# Configure AWS credentials
export AWS_ACCESS_KEY_ID="..."
export AWS_SECRET_ACCESS_KEY="..."

# Run the scan
./starlings-aws-scan.sh --region us-east-1

# Review the report
cat aws-scan-report.json
```

See [aws/README.md](aws/README.md) for full documentation.

### GCP Security Audit

```bash
cd starlings-audit-services/gcp

# Set up service account credentials
export GOOGLE_APPLICATION_CREDENTIALS="/path/to/service-account.json"

# Run the scan
./starlings-gcp-scan.sh --project my-project-id

# Review the report
cat gcp-scan-report.json
```

See [gcp/README.md](gcp/README.md) for full documentation.

### Blockchain / Smart Contract Audit

```bash
cd starlings-audit-services

# Scan an Ethereum contract
./ethereum/starlings-ethereum-scan.sh 0xdAC17F958D2ee523a2206206994597C13D831ec7

# Scan a BSC contract
./bsc/starlings-bsc-scan.sh 0x55d398326f99059fF775485246999027B3197955

# Scan on Polygon or Avalanche
./polygon/starlings-polygon-scan.sh 0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359
./avalanche/starlings-avalanche-scan.sh 0xB97EF9Ef8734C71904D8002F8b6Bc66Dd9c48a6E

# Review the report
cat blockchain-audit-report.json
```

See per-chain READMEs: [Ethereum](ethereum/README.md) | [BSC](bsc/README.md) | [Polygon](polygon/README.md) | [Avalanche](avalanche/README.md) | [Core Engine](evm/README.md)

## 📁 Repository Structure

```
starlings-audit-services/
├── aws/                          # AWS security scanner
│   ├── starlings-aws-scan.sh
│   ├── README.md
│   └── test/
├── gcp/                          # Google Cloud security scanner
│   ├── starlings-gcp-scan.sh
│   ├── README.md
│   └── test/
├── cloudflare/                   # Cloudflare security scanner
│   ├── starlings-cf-scan.sh
│   ├── README.md
│   └── test/
├── digitalocean/                 # DigitalOcean security scanner
│   ├── starlings-do-scan.sh
│   ├── README.md
│   └── test/
├── vercel/                       # Vercel security scanner
│   ├── starlings-vercel-scan.sh
│   ├── README.md
│   └── test/
├── ethereum/                     # Ethereum smart contract scanner
│   ├── starlings-ethereum-scan.sh
│   └── README.md
├── bsc/                          # BNB Smart Chain scanner
│   ├── starlings-bsc-scan.sh
│   └── README.md
├── polygon/                      # Polygon (PoS) scanner
│   ├── starlings-polygon-scan.sh
│   └── README.md
├── avalanche/                    # Avalanche C-Chain scanner
│   ├── starlings-avalanche-scan.sh
│   └── README.md
├── evm/                          # EVM core engine (shared by all chain scanners)
│   ├── starlings-blockchain-audit.sh
│   ├── README.md
│   └── test/
├── docs/                         # Architecture & guides
├── .github/                      # GitHub workflows (CI/CD)
├── LICENSE                       # MIT License
└── README.md                     # This file
```

## 🔧 Tools Overview

| Tool | Purpose | Platform | Status |
|------|---------|----------|--------|
| **aws-scan** | Infrastructure security audit | AWS | ✅ Available |
| **gcp-scan** | Cloud security audit | Google Cloud | ✅ Available |
| **cf-scan** | Edge & DNS security audit | Cloudflare | ✅ Available |
| **do-scan** | Infrastructure security audit | DigitalOcean | ✅ Available |
| **vercel-scan** | Platform security audit | Vercel | ✅ Available |
| **ethereum-scan** | Smart contract audit | Ethereum | ✅ Available |
| **bsc-scan** | Smart contract audit | BNB Smart Chain | ✅ Available |
| **polygon-scan** | Smart contract audit | Polygon (PoS) | ✅ Available |
| **avalanche-scan** | Smart contract audit | Avalanche C-Chain | ✅ Available |

## 📊 Security Frameworks Supported

Each scanner maps findings to industry standards:

- **CIS Benchmarks**: CIS AWS, GCP, Cloudflare Foundations Benchmarks
- **PCI-DSS v3.2.1**: Payment Card Industry compliance
- **ISO 27001**: Information Security Management
- **SOC 2**: Service Organization Control
- **NIST Cybersecurity Framework**: Risk management guidelines
- **OWASP Top 10**: Common web vulnerabilities
- **Web3 Standards**: Token audit frameworks, smart contract verification

## 🛡️ What Gets Audited?

### AWS Scanner
- ✅ IAM security (users, roles, policies, MFA)
- ✅ Network security (security groups, NACLs, VPC)
- ✅ Storage security (S3 bucket policies, encryption, versioning)
- ✅ Database security (RDS encryption, backups, access)
- ✅ Logging & monitoring (CloudTrail, CloudWatch, Config)
- ✅ Certificate management (ACM)
- ✅ Route 53 DNS security

### GCP Scanner
- ✅ IAM & service account security
- ✅ Cloud Storage bucket security
- ✅ Compute & network security
- ✅ Cloud SQL & database security
- ✅ Logging & monitoring
- ✅ Cloud DNS security

### Cloudflare Scanner
- ✅ DNS security (DNSSEC, nameserver config)
- ✅ HTTPS/TLS (minimum versions, certificates, HSTS)
- ✅ DDoS protection & WAF rules
- ✅ Bot management & rate limiting
- ✅ Access control & firewall rules
- ✅ Caching & performance optimization

### DigitalOcean Scanner
- ✅ App Platform security (environment variables, deployment settings)
- ✅ Database security (PostgreSQL, MySQL, Redis)
- ✅ Networking (firewalls, load balancers, VPCs)
- ✅ Storage (Spaces bucket security)
- ✅ Droplets (instance hardening, SSH keys, backups)
- ✅ DNS/Domain & SSL configuration
- ✅ Access control (API tokens, SSH keys, 2FA)

### Vercel Scanner
- ✅ Authentication & team security (SSO/SAML, access groups)
- ✅ Environment variable security (plaintext secrets, preview exposure)
- ✅ Deployment security (git integration, build commands)
- ✅ Domain configuration (verification, SSL, expiration)
- ✅ Firewall & WAF (OWASP rules, bot protection, IP rules)
- ✅ Edge config & serverless security
- ✅ Logging & monitoring (log drains, webhooks)
- ✅ Project security (preview protection, security headers, source maps)

### EVM Smart Contract Auditor (Ethereum, BSC, Polygon, Avalanche)
- ✅ Smart contract verification (code available on chain)
- ✅ Owner/admin privileges (centralization risk)
- ✅ Proxy contracts (upgrade risk assessment)
- ✅ Token mechanics (mint/burn/fees)
- ✅ Known vulnerabilities (public audit cross-reference)
- ✅ Honeypot detection (can users sell?)
- ✅ Rug pull indicators (holder concentration)
- ✅ Blacklist/freeze capability detection

## 📈 Output Format

All scanners generate **structured JSON reports** with:

1. **Metadata**: Scan time, zone/account, scanner version
2. **Summary**: Overall security score (0-100), risk level, check breakdown
3. **Detailed Findings**: Per-category checks with status, message, remediation
4. **Framework Mapping**: Which standards each check addresses
5. **Remediation Steps**: Specific, actionable instructions to fix issues

Example:
```json
{
  "summary": {
    "overallScore": 78,
    "riskLevel": "MEDIUM",
    "checksTotal": 20,
    "checksPassed": 15,
    "checksFailed": 2,
    "checksWarning": 3
  },
  "checks": {
    "aws": {
      "iam": [...],
      "storage": [...],
      "network": [...]
    }
  }
}
```

## 🔐 Security & Privacy

- **No Data Collection**: Tools only read your infrastructure configs
- **Credentials Stay Local**: API tokens/keys never leave your machine
- **Open Source**: Audit the code yourself (MIT License)
- **No Phoning Home**: Run offline or air-gapped
- **Minimal Permissions**: Each scanner uses least-privilege API access

## 🚀 Use Cases

### Pre-Launch Startups
Run audits before mainnet launch to catch critical misconfigurations.

### Security Certification Prep
Map findings to compliance frameworks (SOC 2, ISO 27001) for audit readiness.

### Continuous Compliance
Schedule recurring scans to monitor configuration drift.

### Incident Response
Quickly audit infrastructure after security events.

### Team Training
Learn infrastructure security best practices through detailed findings.

## 📖 Documentation

- **[Architecture Overview](docs/ARCHITECTURE.md)** - System design & data flow
- **[Compliance Mapping](docs/COMPLIANCE.md)** - Framework coverage details
- **[Deployment Guide](docs/DEPLOYMENT.md)** - Production deployment options
- **[FAQ](docs/FAQ.md)** - Common questions & troubleshooting
- **[Contributing](CONTRIBUTING.md)** - How to contribute improvements

## 💬 Getting Help

- **Bug Reports**: Open an issue on GitHub
- **Feature Requests**: Discussions tab on GitHub
- **Security Issues**: Email security@starlings.ai (do not open public issues)
- **Professional Support**: Contact starlings.ai for consulting

## 🤝 Contributing

Contributions welcome! We're looking for:

- **New Scanners**: Azure, Kubernetes, Terraform validators
- **Enhanced Checks**: More security tests for existing platforms
- **Framework Mappings**: Additional compliance standards
- **Documentation**: Guides, tutorials, examples
- **Testing**: Bug reports, edge case discoveries

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## 📜 License

MIT License - See [LICENSE](LICENSE) file for details.

**In short**: Use however you want. Give credit. Don't blame us if it breaks.

## 🏢 About Starlings

Starlings builds security solutions for the modern tech stack. We specialize in:

- Infrastructure auditing (cloud & blockchain)
- Threat intelligence and fraud detection
- Security engineering services
- Compliance automation

**Learn more**: https://starlings.ai

---

**Starlings Audit Services** — Professional security auditing, free and open.

*Built for founders, engineers, and security teams who move fast and take security seriously.*
