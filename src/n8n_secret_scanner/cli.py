from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Optional

import typer

from .reporting import render_json, render_text
from .scanner import (
    ScanOptions,
    iter_input_files,
    load_baseline,
    load_workflow_data,
    parse_ignore_file,
    scan_documents,
    write_baseline,
)

app = typer.Typer(
    add_completion=False, help="Scan exported n8n workflows for secrets, PII, and risky config."
)


@app.callback()
def _root() -> None:
    """CLI root."""
    return None


@app.command("scan")
def scan(
    target: str = typer.Argument(..., help="Workflow JSON file, folder, or '-' for stdin."),
    recursive: bool = typer.Option(
        False, "--recursive", help="Recursively scan folders for JSON files."
    ),
    redact: Optional[str] = typer.Option(
        None, "--redact", help="Write sanitized copy to this output path."
    ),
    output_format: str = typer.Option("text", "--format", help="Output format: text or json."),
    severity: str = typer.Option(
        "info", "--severity", help="Minimum severity (info, low, medium, high, critical)."
    ),
    confidence: str = typer.Option(
        "low", "--confidence", help="Minimum confidence (low, medium, high)."
    ),
    no_pii: bool = typer.Option(False, "--no-pii", help="Disable PII detection rules."),
    show_full: bool = typer.Option(
        False, "--show-full", help="Show full sensitive values (unsafe)."
    ),
    ignore_file: Optional[str] = typer.Option(
        None, "--ignore-file", help="Path to .n8nscanignore style file."
    ),
    baseline: Optional[str] = typer.Option(
        None, "--baseline", help="Ignore findings already in baseline file."
    ),
    write_baseline_path: Optional[str] = typer.Option(
        None, "--write-baseline", help="Write findings fingerprints to baseline file."
    ),
) -> None:
    try:
        stdin_text = sys.stdin.read() if target == "-" else None
        docs = load_workflow_data(target, recursive=recursive, stdin_text=stdin_text)
        if not docs:
            raise FileNotFoundError("No JSON workflow files found to scan")

        ignore_rules, ignore_paths = parse_ignore_file(ignore_file) if ignore_file else (set(), [])
        baseline_fingerprints = load_baseline(baseline) if baseline else set()

        options = ScanOptions(
            include_pii=not no_pii,
            min_severity=severity,
            min_confidence=confidence,
            show_full=show_full,
            ignore_rule_ids=ignore_rules,
            ignore_path_patterns=ignore_paths,
            baseline_fingerprints=baseline_fingerprints,
        )

        result = scan_documents(docs, options)

        if write_baseline_path:
            write_baseline(write_baseline_path, result.findings)

        if redact:
            if target != "-":
                source_files = iter_input_files(target, recursive=recursive)
                if len(source_files) != 1:
                    raise ValueError("--redact currently requires scanning exactly one input file")
                source_resolved = source_files[0].resolve()
                output_resolved = Path(redact).resolve()
                if source_resolved == output_resolved:
                    raise ValueError("Refusing to overwrite input file with --redact")
            key = "<stdin>" if target == "-" else next(iter(result.redacted_data))
            out = Path(redact)
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(json.dumps(result.redacted_data[key], indent=2), encoding="utf-8")
            typer.echo(f"Redacted {result.redacted_counts[key]} value(s) into {out}")

        if output_format == "json":
            typer.echo(render_json(result.findings, result.files_scanned, show_full=show_full))
        else:
            typer.echo(
                render_text(result.findings, result.files_scanned, show_full_warning=show_full)
            )

        raise typer.Exit(code=1 if result.findings else 0)
    except (FileNotFoundError, ValueError, json.JSONDecodeError) as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=2) from None


if __name__ == "__main__":
    app()
