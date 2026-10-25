# n8n-secret-scanner

`n8n-secret-scanner` is an offline Python CLI that scans exported n8n workflow JSON files for:

- hardcoded secrets and API keys,
- personal data (PII), and
- risky n8n configuration choices.

It can also write a sanitized copy of workflows for safe sharing.

## Security note

This tool runs fully offline and makes **no network calls**. It does not validate whether keys are live.

## Install

```bash
python -m pip install -e .
```

## Usage

```bash
n8n-secret-scanner scan path/to/workflow.json
n8n-secret-scanner scan path/to/folder --recursive
n8n-secret-scanner scan workflow.json --redact out/workflow.clean.json
cat workflow.json | n8n-secret-scanner scan -
```

### Output formats

- default: rich terminal table grouped by file
- `--format json`: machine-readable output

Exit codes:

- `0` no findings
- `1` findings found
- `2` errors (missing file, invalid JSON, invalid arguments)

## Rule IDs

### Secret rules

- `SEC001` AWS access key format
- `SEC002` Google API key format
- `SEC003` GitHub token format
- `SEC004` Slack token format
- `SEC005` Stripe key format
- `SEC006` OpenAI/Anthropic key format
- `SEC007` JWT-like token
- `SEC008` ******
- `SEC009` Private key blocks
- `SEC010` Supabase service-role indicators
- `SEC011` Meta WhatsApp Cloud API token style
- `SEC012` Retell AI key style
- `SEC013` GoHighLevel API key style
- `SEC020` Suspicious key name with literal value
- `SEC030` Credentials inside URL/query string
- `SEC040` High-entropy secret-like value

### PII rules

- `PII001` Email address
- `PII002` Phone number (includes UAE/GCC formats)
- `PII003` Emirates ID format

### Misconfiguration rules

- `MIS001` Webhook node authentication is none
- `MIS002` Code/Function node risky execution patterns (`eval`, `new Function`, `child_process`, `exec`)
- `MIS003` HTTP Request with SSL validation disabled (`allowUnauthorizedCerts`)
- `MIS004` Hardcoded production/internal webhook hosts

## Safe n8n handling

- Credential references in the `credentials` object are treated as safe.
- Expressions beginning with `=` that reference `$env`, `$json`, `$credentials`, etc. are treated as safe.
- Single workflow objects and list-of-workflows files are supported.
- Files that look like decrypted credential exports trigger a critical warning (`CRT001`) and skip normal scanning.

## Redact mode

Use `--redact <output-path>` to write a sanitized copy. The scanner never modifies the source file and refuses to overwrite the input path.

Sensitive values are replaced by placeholders like:

```text
[REDACTED:SEC001]
```

## Ignore file

Use `--ignore-file .n8nscanignore` with lines containing either rule IDs (for example `SEC020`) or path globs.

## Baseline

- `--write-baseline baseline.json` creates fingerprints.
- `--baseline baseline.json` suppresses existing findings.

Baseline fingerprints use stable metadata (`rule_id + file + node + json_path`) and never store secret values.

## Pre-commit hook

This repository includes `.pre-commit-hooks.yaml`.

Example `.pre-commit-config.yaml` snippet:

```yaml
repos:
  - repo: https://github.com/CyberZenithX/n8n-secret-scanner
    rev: v0.1.0
    hooks:
      - id: n8n-secret-scanner
        args: ["scan"]
```

## Add a new rule

1. Add a new entry in `src/n8n_secret_scanner/rules.py` with a stable ID.
2. Ensure it has severity, confidence, and a suggested fix.
3. Add or update tests in `tests/` with fake sample values.

## Limitations

A clean scan is **not** a guarantee that no sensitive data exists. Use this as a guardrail plus code review and secure credential practices.
