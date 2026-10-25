from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
CONFIDENCE_ORDER = {"low": 0, "medium": 1, "high": 2}


@dataclass(slots=True)
class Finding:
    file: str
    node_name: str
    node_type: str
    json_path: str
    rule_id: str
    category: str
    severity: str
    confidence: str
    preview: str
    suggestion: str
    full_value: str | None = None
    tokens: list[str | int] = field(default_factory=list)

    @property
    def fingerprint(self) -> str:
        return f"{self.rule_id}|{self.file}|{self.node_name}|{self.json_path}"

    def as_dict(self, show_full: bool = False) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "file": self.file,
            "node_name": self.node_name,
            "node_type": self.node_type,
            "json_path": self.json_path,
            "rule_id": self.rule_id,
            "category": self.category,
            "severity": self.severity,
            "confidence": self.confidence,
            "preview": self.preview,
            "suggestion": self.suggestion,
            "fingerprint": self.fingerprint,
        }
        if show_full:
            payload["value"] = self.full_value
        return payload
