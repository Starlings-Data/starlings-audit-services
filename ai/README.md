# Starlings AI Security Scanner

Static analysis scanner for **AI/LLM security risks** in GitHub repositories. Detects hardcoded API keys, prompt injection vulnerabilities, deprecated model usage, and insecure LLM integration patterns.

This is a **code-level scanner** — it clones a repository and analyzes source files. No API keys or cloud credentials required to run the scanner itself.

## Quick Start

```bash
# Scan a GitHub repository
./starlings-ai-scan.sh --repo https://github.com/org/my-ai-app

# Scan a local directory
./starlings-ai-scan.sh --repo ./my-project

# Verbose output, custom report file
./starlings-ai-scan.sh --repo https://github.com/org/chatbot -v -o report.json

# Scan a specific branch
./starlings-ai-scan.sh --repo https://github.com/org/app --branch develop
```

## Prerequisites

- `git` (for cloning repositories)
- `grep` (pattern matching — included on all Unix systems)
- `jq` (optional, for pretty-printing JSON reports)

## Security Checks

The scanner runs **14 checks** across 4 domains:

### Secrets Detection (5 checks)

| ID | Check | Severity | Description |
|----|-------|----------|-------------|
| KEY-001 | OpenAI API keys | Critical | Detects `sk-...` and `sk-proj-...` patterns (OpenAI key format) |
| KEY-002 | Anthropic API keys | Critical | Detects `sk-ant-...` patterns (Anthropic/Claude key format) |
| KEY-003 | Generic hardcoded secrets | Critical | Detects `*_API_KEY=`, `*_SECRET=`, `DATABASE_URL=` with real values (filters out placeholders) |
| KEY-004 | Committed .env files | High | Detects `.env`, `.env.local`, `.env.production` committed to repo (excludes `.env.example`) |
| KEY-005 | Secrets in Jupyter notebooks | Critical | API keys embedded in `.ipynb` files (persists in cell history even after re-run) |

### Prompt Injection (4 checks)

| ID | Check | Severity | Description |
|----|-------|----------|-------------|
| INJ-001 | f-string / template literal injection | Critical | User input directly interpolated into prompts via f-strings or JS template literals |
| INJ-002 | String concatenation in prompts | High | User input concatenated into prompts via `+`, `.concat()`, `.format()` |
| INJ-003 | Unvalidated input to LLM API | High | HTTP request body passed directly to LLM API calls without validation |
| CFG-004 | System prompt in client-side code | Medium | System prompts hardcoded in JS/TS files that may be served to browsers |

### Model Security (1 check)

| ID | Check | Severity | Description |
|----|-------|----------|-------------|
| MOD-001 | Deprecated model versions | High | References to sunset models (`gpt-3.5-turbo-0301`, `text-davinci-003`, `claude-1.3`, etc.) |

### Configuration & Best Practices (4 checks)

| ID | Check | Severity | Description |
|----|-------|----------|-------------|
| CFG-001 | Missing rate limiting | Medium | LLM-backed API endpoints without rate limiting middleware |
| CFG-002 | No token limits | Medium | LLM API calls without `max_tokens` parameter (unbounded cost risk) |
| CFG-003 | Insecure API communication | Medium | HTTP (non-TLS) calls to AI APIs or disabled SSL verification |
| CFG-005 | .gitignore gaps | Low | Missing `.env` or model weight patterns in `.gitignore` |

## Scoring

### Score Calculation (0-100)

| Severity | Point Deduction |
|----------|----------------|
| Critical | -15 |
| High | -8 |
| Medium | -3 |
| Low | -1 |
| Pass | 0 |

### Risk Levels

| Score | Risk Level | Interpretation |
|-------|-----------|----------------|
| 90-100 | LOW | Excellent — minimal AI security risks |
| 70-89 | LOW | Good — minor issues to address |
| 60-69 | MEDIUM | Fair — several risks need attention |
| 40-59 | HIGH | Poor — significant security gaps |
| 0-39 | CRITICAL | Critical — urgent remediation required |

## Output Format

```json
{
  "scanner_version": "1.0.0",
  "scan_date": "2026-02-06T14:30:00Z",
  "platform": "AI/LLM Code Analysis",
  "repository": "https://github.com/org/my-app",
  "files_scanned": 142,
  "score": {
    "overall": 55,
    "interpretation": "Poor",
    "risk_level": "HIGH"
  },
  "summary": {
    "critical": 2,
    "high": 1,
    "medium": 2,
    "low": 0,
    "info": 0,
    "passed": 9,
    "total_checks": 14
  },
  "findings": [
    {
      "domain": "secrets",
      "check_id": "KEY-001",
      "severity": "critical",
      "title": "Hardcoded OpenAI API key(s) found in 1 file(s)",
      "description": "OpenAI API keys matching sk-... pattern found committed to the repository...",
      "resources": ["src/config.py:12"],
      "remediation": "Remove keys from source code immediately. Rotate compromised keys...",
      "frameworks": ["OWASP A07:2021", "CIS 14.1", "ISO27001 A.9.4.3", "SOC2 CC6.1"]
    }
  ]
}
```

## Languages Supported

The scanner analyzes files with these extensions:

| Language | Extensions |
|----------|-----------|
| Python | `.py` |
| JavaScript | `.js`, `.jsx` |
| TypeScript | `.ts`, `.tsx` |
| Ruby | `.rb` |
| Go | `.go` |
| Java | `.java` |
| Config | `.yaml`, `.yml`, `.json`, `.toml`, `.cfg`, `.ini` |
| Environment | `.env` |
| Notebooks | `.ipynb` |
| Shell | `.sh` |
| Documentation | `.md` |

Vendored directories (`node_modules/`, `vendor/`, `.venv/`, `dist/`, `build/`) are automatically excluded.

## False Positive Handling

The scanner implements several heuristics to reduce false positives:

- **Comment filtering**: Lines starting with `#`, `//`, `*`, `/*`, `<!--` are excluded
- **Placeholder filtering**: Values like `your-key-here`, `CHANGEME`, `xxx`, `<...>` are not flagged
- **Example file filtering**: `.env.example`, `.env.sample`, `.env.template` are excluded from KEY-004
- **SSH key filtering**: `ssh-`, `sk_test_`, `sk_live_` patterns excluded from KEY-001

Target false positive rate: <5%

## Compliance Frameworks

Findings map to industry standards:

- **OWASP Top 10 2021**: A02 (Cryptographic Failures), A07 (Identification/Authentication)
- **OWASP Top 10 for LLMs 2025**: LLM01 (Prompt Injection), LLM02 (Output Handling), LLM06 (Excessive Agency), LLM07 (System Prompt Leakage), LLM10 (Unbounded Consumption)
- **CIS Benchmarks**: Secret management, access controls
- **ISO 27001**: Information security controls
- **SOC 2**: Common criteria controls

## Testing

```bash
cd test/
bash test_runner.sh
```

### Test Suites

1. **test_prerequisites.sh** — Validates git, grep, jq, scanner syntax, CLI flags (9 tests)
2. **test_report_structure.sh** — Runs scanner against vulnerable fixtures, validates JSON report structure and detection accuracy (18 tests)

### Test Fixtures

The `test/fixtures/` directory contains intentionally vulnerable code:
- `vulnerable_app.py` — Hardcoded keys, f-string injection, deprecated models, SSL bypass
- `vulnerable_app.js` — Template literal injection, string concatenation, system prompt exposure
- `.env` — Committed environment file with secrets
- `clean_app.py` — Secure patterns that should NOT trigger findings

## Privacy & Security

- **Read-Only**: The scanner only reads source files — no modifications
- **Local Analysis**: All scanning happens on your machine
- **Shallow Clone**: Repositories are cloned with `--depth 1` (minimal data transfer)
- **Auto-Cleanup**: Cloned repos are deleted after scanning
- **No Telemetry**: Nothing is sent anywhere

## Need Help?

- Review findings and prioritize by severity
- Share reports for team review: [starlings.ai/audit](https://starlings.ai/audit)
- Contact us for a deep-dive AI security audit

## License

MIT License — See LICENSE file in repository root

---

**Built by Starlings Security**
*AI security auditing for the age of LLMs*
