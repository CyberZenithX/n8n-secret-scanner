from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import Iterable
from urllib.parse import parse_qsl, urlparse

SUSPICIOUS_KEYS = {
    "apikey",
    "api_key",
    "secret",
    "token",
    "password",
    "authorization",
    "x-api-key",
    "client_secret",
}

UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
)
PRIVATE_IP_RE = re.compile(
    r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3})\b"
)


@dataclass(frozen=True, slots=True)
class RegexRule:
    rule_id: str
    category: str
    severity: str
    confidence: str
    pattern: re.Pattern[str]
    suggestion: str


def _compile(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.IGNORECASE)


def build_regex_rules(include_pii: bool = True) -> list[RegexRule]:
    rules = [
        RegexRule(
            "SEC001",
            "secret",
            "high",
            "high",
            _compile(r"\bAKIA[0-9A-Z]{16}\b"),
            "Rotate this key and move it into an n8n credential.",
        ),
        RegexRule(
            "SEC002",
            "secret",
            "high",
            "high",
            _compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
            (
                "Move this value to an n8n credential or env expression like "
                "{{ $env.GOOGLE_API_KEY }}."
            ),
        ),
        RegexRule(
            "SEC003",
            "secret",
            "high",
            "high",
            _compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,255}\b"),
            "Rotate this GitHub token and store it outside workflow JSON.",
        ),
        RegexRule(
            "SEC004",
            "secret",
            "high",
            "high",
            _compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
            "Rotate this Slack token and reference credentials in n8n.",
        ),
        RegexRule(
            "SEC005",
            "secret",
            "high",
            "high",
            _compile(r"\bsk_(live|test)_[A-Za-z0-9]{16,}\b"),
            "Rotate this Stripe key and use n8n credential references.",
        ),
        RegexRule(
            "SEC006",
            "secret",
            "high",
            "medium",
            _compile(r"\b(sk-[A-Za-z0-9]{20,}|sk-ant-[A-Za-z0-9_\-]{20,})\b"),
            "Move this model provider key to env/credentials and rotate it.",
        ),
        RegexRule(
            "SEC007",
            "secret",
            "medium",
            "medium",
            _compile(r"\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b"),
            "Treat this JWT as sensitive and avoid committing it.",
        ),
        RegexRule(
            "SEC008",
            "secret",
            "high",
            "medium",
            _compile(r"\bBearer\s+[A-Za-z0-9\-._~+/]+=*\b"),
            "Do not hardcode bearer tokens; load from environment or credentials.",
        ),
        RegexRule(
            "SEC009",
            "secret",
            "critical",
            "high",
            _compile(r"-----BEGIN(?: RSA| EC| OPENSSH)? PRIVATE KEY-----"),
            "Revoke and replace this private key immediately.",
        ),
        RegexRule(
            "SEC010",
            "secret",
            "high",
            "medium",
            _compile(r"\bservice[_-]?role\b"),
            "Never expose Supabase service-role secrets in workflow JSON.",
        ),
        RegexRule(
            "SEC011",
            "secret",
            "high",
            "medium",
            _compile(r"\bEAA[A-Za-z0-9]{20,}\b"),
            "Rotate this WhatsApp Cloud API token and move it into credentials.",
        ),
        RegexRule(
            "SEC012",
            "secret",
            "high",
            "medium",
            _compile(r"\brtk_[A-Za-z0-9]{20,}\b"),
            "Move this Retell key to credentials/env and rotate it.",
        ),
        RegexRule(
            "SEC013",
            "secret",
            "high",
            "medium",
            _compile(r"\bghl_[A-Za-z0-9]{20,}\b"),
            "Move this GoHighLevel key to credentials/env and rotate it.",
        ),
    ]
    if include_pii:
        rules.extend(
            [
                RegexRule(
                    "PII001",
                    "pii",
                    "low",
                    "high",
                    _compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b"),
                    "Replace with test data or pull from safe runtime data.",
                ),
                RegexRule(
                    "PII002",
                    "pii",
                    "low",
                    "medium",
                    _compile(
                        r"\b(?:\+971\s?5\d\s?\d{3}\s?\d{4}|"
                        r"\+?\d{1,3}[- ]\d{2,4}[- ]\d{3,4}[- ]\d{3,4})\b"
                    ),
                    "Remove personal phone numbers from shared workflows.",
                ),
                RegexRule(
                    "PII003",
                    "pii",
                    "low",
                    "high",
                    _compile(r"\b784-\d{4}-\d{7}-\d\b"),
                    "Remove Emirates ID values before sharing.",
                ),
            ]
        )
    return rules


def is_expression(value: str) -> bool:
    return value.strip().startswith("=")


def is_safe_expression(value: str) -> bool:
    if not is_expression(value):
        return False
    marker = value.lower()
    return any(token in marker for token in ("$env", "$json", "$credentials", "$node", "$items"))


def is_plain_url_without_credentials(value: str) -> bool:
    if not (value.startswith("http://") or value.startswith("https://")):
        return False
    parsed = urlparse(value)
    return parsed.username is None and parsed.password is None and not parsed.query


def shannon_entropy(value: str) -> float:
    counts: dict[str, int] = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    entropy = 0.0
    for c in counts.values():
        p = c / len(value)
        entropy -= p * math.log2(p)
    return entropy


def has_url_credentials(value: str) -> bool:
    if not (value.startswith("http://") or value.startswith("https://")):
        return False
    parsed = urlparse(value)
    if parsed.username or parsed.password:
        return True
    for key, v in parse_qsl(parsed.query, keep_blank_values=True):
        lowered = key.lower()
        if lowered in {"api_key", "apikey", "token", "access_token", "key", "secret"} and v:
            return True
    return False


def looks_high_entropy_secret(value: str, threshold: float = 4.2) -> bool:
    stripped = value.strip()
    if len(stripped) < 20:
        return False
    if UUID_RE.match(stripped):
        return False
    if is_plain_url_without_credentials(stripped):
        return False
    if re.fullmatch(r"[0-9a-f]{24,}", stripped, re.IGNORECASE):
        return False
    return shannon_entropy(stripped) >= threshold


def suspicious_key_name(key: str) -> bool:
    cleaned = key.replace("-", "_").lower()
    return cleaned in SUSPICIOUS_KEYS


def detect_hardcoded_host(value: str) -> bool:
    lowered = value.lower()
    if "webhook" in lowered and value.startswith("http"):
        return True
    if "localhost" in lowered or ".internal" in lowered:
        return True
    return bool(PRIVATE_IP_RE.search(value))


def contains_code_execution(value: str) -> bool:
    lowered = value.lower()
    return any(token in lowered for token in ("eval(", "new function", "child_process", "exec("))


def match_regex_rules(value: str, rules: Iterable[RegexRule]) -> list[RegexRule]:
    return [rule for rule in rules if rule.pattern.search(value)]
