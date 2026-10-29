# Codigo-Seguro

**Defensive security scanner for AI-assisted web applications.**

VibeShield is an open-source CLI for identifying potential security
issues in web applications, including projects developed with
AI coding assistants.

It combines static analysis, configuration checks, optional
dependency vulnerability lookups and safe HTTP header checks.

> Codigo-Seguro is a security review assistant, not a replacement
> for professional penetration testing or a full SAST platform.

## Features

- Python AST analysis
- Optional Tree-sitter parsing for JavaScript and TypeScript
- Heuristic source-to-sink data-flow analysis
- Hardcoded secret detection with redacted evidence
- Potential SQL injection, command injection and SSRF detection
- Authorization and multi-tenancy review hypotheses
- Database row-level security configuration checks
- Terraform, Docker and GitHub Actions checks
- Experimental anomaly detection
- Optional OSV dependency vulnerability lookups
- Authorized HTTP HEAD security-header checks
- HTML, JSON, Markdown and SARIF reports
- Individual AI remediation prompts
- Interactive CLI and configurable scan levels
- GitHub Actions integration

## Requirements

- Python 3.11 or newer
- pip

## Installation

Clone the repository:

```bash
git clone https://github.com/YOUR_USERNAME/VibeShield.git
cd VibeShield
```

Install the CLI:

```bash
python -m pip install -e .
```

For development and JavaScript/TypeScript AST support:

```bash
python -m pip install -e ".[dev,ast]"
```

## Quick start

```bash
vibeshield scan .
```

Run a deep scan:

```bash
vibeshield scan . --level deep
```

Generate all report formats:

```bash
vibeshield scan . \
  --level deep \
  --format all \
  --output reports
```

Start the interactive CLI:

```bash
vibeshield scan . --interactive
```

## Scan levels

| Level | Description |
|---|---|
| `quick` | Secrets and configuration checks |
| `standard` | Quick checks plus Python and JS/TS analysis |
| `deep` | Standard checks plus experimental review hypotheses |

Deep mode can produce more false positives.

## Categories

Available categories:

- `code`
- `secrets`
- `config`
- `anomaly`
- `dependencies`
- `http`

Example:

```bash
vibeshield scan ./my-app \
  --category code,secrets,config \
  --level deep
```

Run only selected rules:

```bash
vibeshield scan . --rules VS001,VS003,VS005
```

Limit scanning:

```bash
vibeshield scan . \
  --max-files 1000 \
  --max-findings 100
```

## OSV dependency checks

OSV integration is disabled by default.

Enable it explicitly:

```bash
vibeshield scan . \
  --category dependencies \
  --osv \
  --osv-limit 30
```

Supported dependency files:

- `requirements*.txt` with exact versions
- `package-lock.json`
- `poetry.lock`
- `Pipfile.lock`

Only dependency names, versions and ecosystems are sent to OSV.
Source code is not uploaded.

The implementation does not yet resolve every dependency format
or determine whether a reported vulnerability is reachable.

## Safe HTTP checks

By default, only loopback targets are allowed.

```bash
vibeshield scan . \
  --category http \
  --http-url http://127.0.0.1:8000
```

For an explicitly authorized remote target:

```bash
vibeshield scan . \
  --category http \
  --http-url https://staging.example.com \
  --allow-host staging.example.com
```

Only test systems you own or are authorized to assess.

HTTP checks:

- Use HEAD requests only
- Do not follow redirects
- Do not attempt exploitation
- Do not perform fuzzing or brute force

## Reports

```text
reports/
├── report.html
├── report.json
├── report.md
├── report.sarif
└── remediation-prompts/
    ├── <finding-id>.md
    └── ...
```

SARIF findings are limited to repository file locations.
HTTP observations are available in the other report formats.

## CI integration

The repository includes a GitHub Actions workflow that:

1. Installs VibeShield.
2. Runs the automated tests.
3. Scans the repository.
4. Generates a SARIF report.
5. Uploads the report as a workflow artifact.
6. Attempts to publish SARIF to GitHub Code Scanning.

GitHub Code Scanning availability depends on repository settings
and plan eligibility.

## Run tests

```bash
pytest -q
```

## Important limitations

VibeShield 0.2 is an initial functional implementation.

- Data-flow analysis is heuristic, not fully interprocedural.
- JavaScript/TypeScript parsing requires optional dependencies.
- Without Tree-sitter, JS/TS checks use conservative text patterns.
- A finding does not automatically prove exploitability.
- Authorization, multi-tenancy and LLM issues generally require
  manual review and application-specific tests.
- Experimental anomalies are explicitly labeled as hypotheses.
- False positives and false negatives are expected.
- The scanner does not execute analyzed source code.
- The scanner does not automatically modify application code.
- OSV queries require explicit opt-in.
- This release has not undergone independent security validation.

## Privacy

VibeShield analyzes source code locally by default.

Secret findings redact the matched value in generated reports.

Review reports before publishing them: paths, URLs, package names
and other non-secret metadata may still be sensitive.

Do not commit `.env` files, real credentials or private reports.

## License

MIT.