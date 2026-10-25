from __future__ import annotations

import json
from collections import Counter, defaultdict
from typing import Any

from rich.console import Console
from rich.table import Table

from .models import Finding


def render_text(
    findings: list[Finding], files_scanned: int, show_full_warning: bool = False
) -> str:
    console = Console(record=True)
    by_file: dict[str, list[Finding]] = defaultdict(list)
    for finding in findings:
        by_file[finding.file].append(finding)

    if show_full_warning:
        console.print("[bold yellow]Warning:[/] --show-full prints sensitive values.")

    for file_path, file_findings in sorted(by_file.items()):
        console.print(f"\n[bold]{file_path}[/bold]")
        table = Table(show_lines=False)
        table.add_column("Rule")
        table.add_column("Severity")
        table.add_column("Node")
        table.add_column("Path")
        table.add_column("Preview")
        table.add_column("Fix")
        for finding in file_findings:
            table.add_row(
                finding.rule_id,
                finding.severity,
                finding.node_name,
                finding.json_path,
                finding.preview,
                finding.suggestion,
            )
        console.print(table)

    sev = Counter(f.severity for f in findings)
    summary_parts = [
        f"{level}:{sev.get(level, 0)}" for level in ["critical", "high", "medium", "low", "info"]
    ]
    console.print(
        f"\nScanned {files_scanned} file(s). Findings={len(findings)} ({', '.join(summary_parts)})"
    )
    return console.export_text()


def render_json(findings: list[Finding], files_scanned: int, show_full: bool = False) -> str:
    payload: dict[str, Any] = {
        "files_scanned": files_scanned,
        "findings": [finding.as_dict(show_full=show_full) for finding in findings],
    }
    return json.dumps(payload, indent=2)
