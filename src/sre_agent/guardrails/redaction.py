"""Redacts secrets and personal data from tool output before it reaches the
LLM, the audit log or a report. Logs routinely contain tokens, card numbers
and emails, and none of that should leave the cluster in a prompt."""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any


def _luhn_ok(digits: str) -> bool:
    total, alt = 0, False
    for ch in reversed(digits):
        d = int(ch)
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


@dataclass(frozen=True)
class Rule:
    name: str
    pattern: re.Pattern[str]
    validate: Callable[[str], bool] | None = None
    keep_group: int | None = None  # keep this group (e.g. "password=") and redact the rest


SECRET_KEY = re.compile(
    r"(?i)^(password|passwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|authorization)$"
)

RULES: list[Rule] = [
    Rule(
        "private_key",
        re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]+?-----END [A-Z ]*PRIVATE KEY-----"),
    ),
    Rule("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    Rule("github_token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,})\b")),
    Rule("slack_token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    Rule("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    Rule("bearer", re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]{16,}"), keep_group=1),
    Rule(
        "secret_kv",
        re.compile(
            r"(?i)((?:password|passwd|pwd|secret|api[_-]?key|token|access[_-]?key)\s*[=:]\s*)"
            r"(\"[^\"]*\"|'[^']*'|[^\s,;&\"']+)"
        ),
        keep_group=1,
    ),
    Rule(
        "card_number",
        re.compile(r"\b\d(?:[ -]?\d){12,18}\b"),
        validate=lambda m: _luhn_ok(re.sub(r"\D", "", m)),
    ),
    Rule("us_ssn", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    Rule("email", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
]


@dataclass
class RedactionResult:
    text: str
    counts: dict[str, int] = field(default_factory=dict)

    @property
    def total(self) -> int:
        return sum(self.counts.values())


class Redactor:
    def __init__(self, rules: list[Rule] | None = None) -> None:
        self.rules = rules or RULES

    def redact_text(self, text: str) -> RedactionResult:
        counts: dict[str, int] = {}
        for rule in self.rules:

            def repl(m: re.Match[str], rule: Rule = rule) -> str:
                if rule.validate and not rule.validate(m.group(0)):
                    return m.group(0)
                counts[rule.name] = counts.get(rule.name, 0) + 1
                prefix = m.group(rule.keep_group) if rule.keep_group else ""
                return f"{prefix}[REDACTED:{rule.name}]"

            text = rule.pattern.sub(repl, text)
        return RedactionResult(text, counts)

    def redact(self, data: Any) -> tuple[Any, int]:
        """Redact a nested structure leaf by leaf; returns (clean_data, count).

        Values under secret-looking keys are dropped entirely; every string is
        scanned with the pattern rules. Working on leaves (not on a JSON dump)
        means a match can never corrupt the structure.
        """
        total = 0

        def walk(node: Any) -> Any:
            nonlocal total
            if isinstance(node, dict):
                out = {}
                for k, v in node.items():
                    if isinstance(k, str) and SECRET_KEY.search(k) and v not in (None, ""):
                        total += 1
                        out[k] = "[REDACTED:secret_field]"
                    else:
                        out[k] = walk(v)
                return out
            if isinstance(node, (list, tuple)):
                return [walk(v) for v in node]
            if isinstance(node, str):
                r = self.redact_text(node)
                total += r.total
                return r.text
            return node

        return walk(data), total
