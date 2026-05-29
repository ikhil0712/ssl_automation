# ssl-automation 🔒

Automated SSL/TLS certificate and configuration validation tool.  
Scans a list of targets, checks them against a security policy, and generates  
JSON / HTML / plain-text reports.  Runs standalone or inside Jenkins / GitHub Actions.

---

## Project structure

```
ssl-automation/
├── config/
│   ├── targets.yaml        # Hosts to scan
│   └── policy.yaml         # Allowed TLS versions, ciphers, cert rules
├── scripts/
│   ├── ssl_validator.py    # CLI entry point & orchestrator
│   ├── certificate_checks.py
│   ├── tls_checks.py
│   ├── cipher_checks.py
│   └── report_generator.py
├── reports/                # Generated reports (git-ignored)
├── logs/                   # Run logs (git-ignored)
├── requirements.txt
├── Jenkinsfile
├── github-actions.yml
└── README.md
```

---

## Quick start

```bash
# Clone & install
git clone https://github.com/your-org/ssl-automation.git
cd ssl-automation
pip install -r requirements.txt

# Run against all targets (HTML report)
python scripts/ssl_validator.py

# Filter by tag, choose format
python scripts/ssl_validator.py --tag production --format json

# Validate a single ad-hoc host
python scripts/ssl_validator.py --host example.com --port 443

# Exit with code 1 if any target fails (useful in CI)
python scripts/ssl_validator.py --fail-fast
```

---

## Configuration

### `config/targets.yaml`

| Field    | Required | Description |
|----------|----------|-------------|
| `name`   | yes      | Human-readable label |
| `host`   | yes      | Hostname or IP |
| `port`   | no       | Defaults to `443` |
| `tags`   | no       | Used with `--tag` filter |
| `notify` | no       | Email list for future alerting integration |

```yaml
targets:
  - name: "Production API"
    host: "api.example.com"
    port: 443
    tags: [production, critical]
    notify: ["ops-team@example.com"]
```

### `config/policy.yaml`

Key sections:

| Section       | What it controls |
|---------------|-----------------|
| `tls`         | Allowed / forbidden TLS versions, preferred version |
| `ciphers`     | Allowed cipher suites, forbidden keywords |
| `certificate` | Min key sizes, forbidden sig algs, expiry thresholds |
| `reporting`   | Whether to `fail` or `warn` on each issue type |

---

## Checks performed

### Certificate checks (`certificate_checks.py`)
| Check | Severity |
|-------|----------|
| Certificate expired | fail |
| Expiry within critical threshold (default 14 days) | fail |
| Expiry within warning threshold (default 30 days) | warn |
| Hostname / SAN mismatch | fail |
| Self-signed certificate | fail |
| Chain validation failure | fail |
| RSA key below 2048 bits | fail |
| ECDSA key below 256 bits | fail |
| Forbidden signature algorithm (e.g. SHA-1, MD5) | fail |
| Missing SAN extension | warn |

### TLS version checks (`tls_checks.py`)
| Check | Severity |
|-------|----------|
| Forbidden version accepted (SSLv3, TLS 1.0, 1.1) | fail |
| No allowed version available | fail |
| Preferred version not supported | warn |

### Cipher suite checks (`cipher_checks.py`)
| Check | Severity |
|-------|----------|
| Forbidden cipher keyword accepted (RC4, NULL, DES…) | fail |
| Negotiated cipher contains forbidden keyword | fail |
| No allowed cipher available | warn |

---

## CI / CD

### GitHub Actions

Copy `github-actions.yml` to `.github/workflows/ssl-validation.yml`.

- Runs **daily at 06:00 UTC**.
- Triggered manually via **workflow_dispatch** (choose tag, format, fail-fast).
- Uploads report + logs as **artifacts** (30-day retention).
- Posts a summary to the **GitHub Step Summary** tab.

### Jenkins

Use the included `Jenkinsfile`.

- Daily **cron trigger** at 06:00.
- Build parameters: format, tag filter, fail-fast toggle.
- Archives HTML report and publishes it via the **HTML Publisher** plugin.

---

## Report output

| Format | File extension | Notes |
|--------|---------------|-------|
| `html` | `.html` | Dark-themed interactive report with collapsible cards (default) |
| `json` | `.json` | Machine-readable; suitable for downstream tooling / SIEM ingestion |
| `text` | `.txt`  | Plain-text summary for email or log storage |

Reports are written to `reports/report_<YYYYMMDD_HHMMSS>.<ext>`.

---

## Exit codes

| Code | Meaning |
|------|---------|
| `0`  | All targets passed (or warnings only, without `--fail-fast`) |
| `1`  | One or more targets failed (when `--fail-fast` is set) |

---

## Requirements

- Python ≥ 3.11
- `PyYAML` ≥ 6.0
- `cryptography` ≥ 42.0

---

## Contributing

1. Fork the repo and create a feature branch.
2. Add or modify checks in `scripts/`.
3. Update `config/policy.yaml` defaults as needed.
4. Open a PR with a clear description of what changed and why.

---

## License

MIT — see `LICENSE`.
