from __future__ import annotations

import copy
import fnmatch
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from .models import CONFIDENCE_ORDER, SEVERITY_ORDER, Finding
from .rules import (
    build_regex_rules,
    contains_code_execution,
    detect_hardcoded_host,
    has_url_credentials,
    is_expression,
    is_safe_expression,
    looks_high_entropy_secret,
    match_regex_rules,
    suspicious_key_name,
)

DECRYPTED_CREDENTIALS_RULE_ID = "CRT001"


@dataclass(slots=True)
class ScanOptions:
    include_pii: bool = True
    min_severity: str = "info"
    min_confidence: str = "low"
    show_full: bool = False
    ignore_rule_ids: set[str] | None = None
    ignore_path_patterns: list[str] | None = None
    baseline_fingerprints: set[str] | None = None


@dataclass(slots=True)
class ScanResult:
    findings: list[Finding]
    errors: list[str]
    files_scanned: int
    redacted_data: dict[str, Any]
    redacted_counts: dict[str, int]


def mask_value(value: str) -> str:
    if not value:
        return ""
    if len(value) <= 4:
        return "*" * len(value)
    return value[:4] + "*" * min(len(value) - 4, 24)


def parse_ignore_file(ignore_file: str | None) -> tuple[set[str], list[str]]:
    if not ignore_file:
        return set(), []
    content = Path(ignore_file).read_text(encoding="utf-8")
    rule_ids: set[str] = set()
    path_patterns: list[str] = []
    for line in content.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.upper().startswith(("SEC", "PII", "MIS", "CRT")):
            rule_ids.add(stripped.upper())
        else:
            path_patterns.append(stripped)
    return rule_ids, path_patterns


def load_baseline(path: str | None) -> set[str]:
    if not path:
        return set()
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return {
        entry["fingerprint"] for entry in data if isinstance(entry, dict) and "fingerprint" in entry
    }


def write_baseline(path: str, findings: list[Finding]) -> None:
    payload = [{"fingerprint": finding.fingerprint} for finding in findings]
    Path(path).write_text(json.dumps(payload, indent=2), encoding="utf-8")


def iter_input_files(target: str, recursive: bool = False) -> list[Path]:
    if target == "-":
        return []
    p = Path(target)
    if not p.exists():
        raise FileNotFoundError(f"Input not found: {target}")
    if p.is_file():
        return [p]
    pattern = "**/*.json" if recursive else "*.json"
    return sorted([path for path in p.glob(pattern) if path.is_file()])


def _load_json_from_path(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def load_workflow_data(
    target: str, recursive: bool = False, stdin_text: str | None = None
) -> dict[str, Any]:
    docs: dict[str, Any] = {}
    if target == "-":
        if stdin_text is None:
            raise ValueError("stdin data is required when target is '-'")
        docs["<stdin>"] = json.loads(stdin_text)
        return docs
    for path in iter_input_files(target, recursive=recursive):
        docs[str(path)] = _load_json_from_path(path)
    return docs


def _looks_like_decrypted_credentials_export(payload: Any) -> bool:
    return (
        isinstance(payload, list)
        and bool(payload)
        and all(isinstance(item, dict) and "type" in item and "data" in item for item in payload)
    )


def _ensure_workflows(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, dict):
        return [payload]
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    return []


def _path_to_str(tokens: list[str | int]) -> str:
    path = "$"
    for token in tokens:
        if isinstance(token, int):
            path += f"[{token}]"
        else:
            path += f".{token}"
    return path


def _passes_filters(finding: Finding, options: ScanOptions) -> bool:
    if SEVERITY_ORDER[finding.severity] < SEVERITY_ORDER[options.min_severity]:
        return False
    if CONFIDENCE_ORDER[finding.confidence] < CONFIDENCE_ORDER[options.min_confidence]:
        return False
    if options.ignore_rule_ids and finding.rule_id in options.ignore_rule_ids:
        return False
    if options.ignore_path_patterns:
        if any(
            fnmatch.fnmatch(finding.file, p) or fnmatch.fnmatch(finding.json_path, p)
            for p in options.ignore_path_patterns
        ):
            return False
    if options.baseline_fingerprints and finding.fingerprint in options.baseline_fingerprints:
        return False
    return True


def _add_finding(
    findings: list[Finding],
    options: ScanOptions,
    file_path: str,
    node_name: str,
    node_type: str,
    tokens: list[str | int],
    rule_id: str,
    category: str,
    severity: str,
    confidence: str,
    suggestion: str,
    value: str,
) -> None:
    finding = Finding(
        file=file_path,
        node_name=node_name,
        node_type=node_type,
        json_path=_path_to_str(tokens),
        rule_id=rule_id,
        category=category,
        severity=severity,
        confidence=confidence,
        preview=value if options.show_full else mask_value(value),
        suggestion=suggestion,
        full_value=value,
        tokens=tokens.copy(),
    )
    if _passes_filters(finding, options):
        findings.append(finding)


def _scan_string_value(
    findings: list[Finding],
    options: ScanOptions,
    regex_rules,
    file_path: str,
    node_name: str,
    node_type: str,
    tokens: list[str | int],
    key_name: str,
    value: str,
) -> None:
    for rule in match_regex_rules(value, regex_rules):
        _add_finding(
            findings,
            options,
            file_path,
            node_name,
            node_type,
            tokens,
            rule.rule_id,
            rule.category,
            rule.severity,
            rule.confidence,
            rule.suggestion,
            value,
        )

    if suspicious_key_name(key_name) and value.strip() and not is_expression(value):
        _add_finding(
            findings,
            options,
            file_path,
            node_name,
            node_type,
            tokens,
            "SEC020",
            "secret",
            "medium",
            "medium",
            "Move this into an n8n credential and reference it from the node.",
            value,
        )

    if has_url_credentials(value):
        _add_finding(
            findings,
            options,
            file_path,
            node_name,
            node_type,
            tokens,
            "SEC030",
            "secret",
            "high",
            "high",
            "Remove credentials from URLs and use secure credential fields.",
            value,
        )

    if looks_high_entropy_secret(value):
        _add_finding(
            findings,
            options,
            file_path,
            node_name,
            node_type,
            tokens,
            "SEC040",
            "secret",
            "medium",
            "low",
            (
                "This value looks like a secret. Move it to "
                "credentials/environment and rotate if exposed."
            ),
            value,
        )

    if node_type.lower().endswith("code") or "function" in node_type.lower():
        if contains_code_execution(value):
            _add_finding(
                findings,
                options,
                file_path,
                node_name,
                node_type,
                tokens,
                "MIS002",
                "misconfig",
                "high",
                "high",
                "Avoid eval/new Function/exec patterns in workflow code nodes.",
                value,
            )

    if detect_hardcoded_host(value):
        _add_finding(
            findings,
            options,
            file_path,
            node_name,
            node_type,
            tokens,
            "MIS004",
            "misconfig",
            "low",
            "medium",
            "Avoid hardcoded production/internal endpoints; use environment-based routing.",
            value,
        )


def _walk_values(
    findings: list[Finding],
    options: ScanOptions,
    regex_rules,
    file_path: str,
    node_name: str,
    node_type: str,
    obj: Any,
    tokens: list[str | int],
    key_name: str = "",
) -> None:
    if isinstance(obj, dict):
        for key, value in obj.items():
            if key == "credentials":
                continue
            _walk_values(
                findings,
                options,
                regex_rules,
                file_path,
                node_name,
                node_type,
                value,
                tokens + [key],
                key,
            )
        return
    if isinstance(obj, list):
        for i, item in enumerate(obj):
            _walk_values(
                findings,
                options,
                regex_rules,
                file_path,
                node_name,
                node_type,
                item,
                tokens + [i],
                key_name,
            )
        return
    if isinstance(obj, str):
        if is_safe_expression(obj):
            return
        _scan_string_value(
            findings,
            options,
            regex_rules,
            file_path,
            node_name,
            node_type,
            tokens,
            key_name,
            obj,
        )


def _apply_misconfig_node_rules(
    findings: list[Finding],
    options: ScanOptions,
    file_path: str,
    node: dict[str, Any],
    node_index: int,
) -> None:
    node_type = str(node.get("type", ""))
    node_name = str(node.get("name", f"node[{node_index}]"))
    params = node.get("parameters", {})

    if "webhook" in node_type.lower() and isinstance(params, dict):
        auth = str(params.get("authentication", "none")).lower()
        if auth in {"", "none"}:
            _add_finding(
                findings,
                options,
                file_path,
                node_name,
                node_type,
                ["nodes", node_index, "parameters", "authentication"],
                "MIS001",
                "misconfig",
                "medium",
                "high",
                "Turn on authentication for this webhook.",
                auth or "none",
            )

    if "httprequest" in node_type.lower() and isinstance(params, dict):
        allow = params.get("allowUnauthorizedCerts")
        if allow is None and isinstance(params.get("options"), dict):
            allow = params["options"].get("allowUnauthorizedCerts")
        if allow is True:
            _add_finding(
                findings,
                options,
                file_path,
                node_name,
                node_type,
                ["nodes", node_index, "parameters", "allowUnauthorizedCerts"],
                "MIS003",
                "misconfig",
                "high",
                "high",
                "Enable SSL certificate validation for HTTP Request nodes.",
                "true",
            )


def _redact_targets_for_file(original_data: Any, findings: Iterable[Finding]) -> tuple[Any, int]:
    redacted = copy.deepcopy(original_data)
    redactions = 0
    for finding in findings:
        if finding.category not in {"secret", "pii"}:
            continue
        target = redacted
        if not finding.tokens:
            continue
        for token in finding.tokens[:-1]:
            if isinstance(target, dict) and isinstance(token, str) and token in target:
                target = target[token]
            elif isinstance(target, list) and isinstance(token, int) and 0 <= token < len(target):
                target = target[token]
            else:
                target = None
                break
        if target is None:
            continue
        last = finding.tokens[-1]
        replacement = f"[REDACTED:{finding.rule_id}]"
        if (
            isinstance(target, dict)
            and isinstance(last, str)
            and last in target
            and isinstance(target[last], str)
        ):
            if not str(target[last]).startswith("[REDACTED:"):
                target[last] = replacement
                redactions += 1
        elif (
            isinstance(target, list)
            and isinstance(last, int)
            and 0 <= last < len(target)
            and isinstance(target[last], str)
        ):
            if not str(target[last]).startswith("[REDACTED:"):
                target[last] = replacement
                redactions += 1
    return redacted, redactions


def scan_documents(documents: dict[str, Any], options: ScanOptions) -> ScanResult:
    findings: list[Finding] = []
    errors: list[str] = []
    regex_rules = build_regex_rules(include_pii=options.include_pii)
    redacted_data: dict[str, Any] = {}
    redacted_counts: dict[str, int] = {}

    for file_path, payload in documents.items():
        if _looks_like_decrypted_credentials_export(payload):
            _add_finding(
                findings,
                options,
                file_path,
                "<credentials-export>",
                "credentials-export",
                [],
                DECRYPTED_CREDENTIALS_RULE_ID,
                "secret",
                "critical",
                "high",
                (
                    "This appears to be decrypted credentials export data. "
                    "Never share or commit this file."
                ),
                "decrypted credentials export",
            )
            redacted_data[file_path] = payload
            redacted_counts[file_path] = 0
            continue

        workflows = _ensure_workflows(payload)
        local_findings_start = len(findings)
        for workflow_index, workflow in enumerate(workflows):
            workflow_tokens = [] if len(workflows) == 1 else [workflow_index]
            nodes = workflow.get("nodes", [])
            for node_index, node in enumerate(nodes):
                if not isinstance(node, dict):
                    continue
                node_name = str(node.get("name", f"node[{node_index}]"))
                node_type = str(node.get("type", ""))
                params = node.get("parameters")
                if params is not None:
                    _walk_values(
                        findings,
                        options,
                        regex_rules,
                        file_path,
                        node_name,
                        node_type,
                        params,
                        workflow_tokens + ["nodes", node_index, "parameters"],
                    )
                for extra in ("pinData", "staticData", "notes"):
                    if extra in node:
                        _walk_values(
                            findings,
                            options,
                            regex_rules,
                            file_path,
                            node_name,
                            node_type,
                            node[extra],
                            workflow_tokens + ["nodes", node_index, extra],
                        )
                _apply_misconfig_node_rules(findings, options, file_path, node, node_index)

            for wf_key in ("settings", "staticData"):
                if wf_key in workflow:
                    _walk_values(
                        findings,
                        options,
                        regex_rules,
                        file_path,
                        "<workflow>",
                        "workflow",
                        workflow[wf_key],
                        workflow_tokens + [wf_key],
                    )

        file_findings = [
            finding for finding in findings[local_findings_start:] if finding.file == file_path
        ]
        redacted, redaction_count = _redact_targets_for_file(payload, file_findings)
        redacted_data[file_path] = redacted
        redacted_counts[file_path] = redaction_count

    return ScanResult(
        findings=findings,
        errors=errors,
        files_scanned=len(documents),
        redacted_data=redacted_data,
        redacted_counts=redacted_counts,
    )
