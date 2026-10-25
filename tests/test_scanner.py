from __future__ import annotations

import json
from pathlib import Path

from n8n_secret_scanner.scanner import (
    DECRYPTED_CREDENTIALS_RULE_ID,
    ScanOptions,
    load_workflow_data,
    scan_documents,
    write_baseline,
)

FIXTURES = Path(__file__).parent / "fixtures"


def test_findings_workflow_has_expected_rule_ids() -> None:
    docs = load_workflow_data(str(FIXTURES / "workflow_with_findings.json"))
    result = scan_documents(docs, ScanOptions())

    assert result.files_scanned == 1
    rule_ids = {f.rule_id for f in result.findings}
    expected = {
        "SEC005",
        "SEC012",
        "SEC020",
        "SEC030",
        "PII001",
        "PII002",
        "PII003",
        "MIS001",
        "MIS002",
        "MIS003",
        "MIS004",
    }
    assert expected.issubset(rule_ids)


def test_clean_workflow_has_no_findings() -> None:
    docs = load_workflow_data(str(FIXTURES / "clean_workflow.json"))
    result = scan_documents(docs, ScanOptions())

    assert result.findings == []


def test_multi_workflow_file_is_supported() -> None:
    docs = load_workflow_data(str(FIXTURES / "multi_workflow.json"))
    result = scan_documents(docs, ScanOptions())

    assert any(f.rule_id == "SEC013" for f in result.findings)
    assert any(f.json_path.startswith("$[0].") for f in result.findings)


def test_decrypted_credentials_export_has_loud_warning() -> None:
    docs = load_workflow_data(str(FIXTURES / "decrypted_credentials_export.json"))
    result = scan_documents(docs, ScanOptions())

    assert len(result.findings) == 1
    assert result.findings[0].rule_id == DECRYPTED_CREDENTIALS_RULE_ID
    assert result.findings[0].severity == "critical"


def test_redaction_replaces_secret_values(tmp_path: Path) -> None:
    input_path = FIXTURES / "workflow_with_findings.json"
    docs = load_workflow_data(str(input_path))
    result = scan_documents(docs, ScanOptions())

    output_path = tmp_path / "redacted.json"
    payload = next(iter(result.redacted_data.values()))
    output_path.write_text(json.dumps(payload), encoding="utf-8")
    written = output_path.read_text(encoding="utf-8")

    assert "rtk_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234" not in written
    assert "person@example.com" not in written
    assert "[REDACTED:" in written


def test_bearer_token_rule_triggers() -> None:
    bearer_value = "Bearer " + ("abc123" * 6)
    docs = {
        "inline.json": {
            "nodes": [
                {
                    "name": "HTTP Request",
                    "type": "n8n-nodes-base.httpRequest",
                    "parameters": {"headers": {"authorization": bearer_value}},
                }
            ]
        }
    }
    result = scan_documents(docs, ScanOptions())
    assert any(f.rule_id == "SEC008" for f in result.findings)


def test_baseline_filters_existing_findings(tmp_path: Path) -> None:
    docs = load_workflow_data(str(FIXTURES / "workflow_with_findings.json"))
    first = scan_documents(docs, ScanOptions())
    baseline_path = tmp_path / "baseline.json"
    write_baseline(str(baseline_path), first.findings)

    baseline_data = json.loads(baseline_path.read_text(encoding="utf-8"))
    baseline_fingerprints = {entry["fingerprint"] for entry in baseline_data}

    second = scan_documents(docs, ScanOptions(baseline_fingerprints=baseline_fingerprints))
    assert second.findings == []
