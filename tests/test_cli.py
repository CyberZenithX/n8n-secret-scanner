from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from n8n_secret_scanner.cli import app

runner = CliRunner()
FIXTURES = Path(__file__).parent / "fixtures"


def test_cli_json_output_and_exit_code() -> None:
    result = runner.invoke(
        app, ["scan", str(FIXTURES / "workflow_with_findings.json"), "--format", "json"]
    )
    assert result.exit_code == 1
    payload = json.loads(result.stdout)
    assert payload["files_scanned"] == 1
    assert len(payload["findings"]) > 0


def test_cli_redact_refuses_overwrite_input() -> None:
    source = FIXTURES / "workflow_with_findings.json"
    result = runner.invoke(app, ["scan", str(source), "--redact", str(source)])
    assert result.exit_code == 2
    assert "Refusing to overwrite input file" in result.stderr
