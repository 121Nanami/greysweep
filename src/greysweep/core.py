"""Core types and helpers shared by every check and reporter."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from enum import IntEnum

from .secretscan import redact


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.lower()

    @classmethod
    def parse(cls, value: str) -> "Severity":
        try:
            return cls[value.strip().upper()]
        except KeyError:
            raise ValueError(f"unknown severity: {value!r}") from None


@dataclass(frozen=True)
class Rule:
    id: str
    severity: Severity
    title: str
    why: str
    fix: str


_INVISIBLE = re.compile(r"[​-‏‪-‮⁠-⁩﻿\U000E0000-\U000E01EF]")


def clip(text: str, limit: int = 180) -> str:
    """One printable line: invisible characters removed, whitespace collapsed."""
    text = " ".join(_INVISIBLE.sub("", text).split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


@dataclass
class Finding:
    rule: Rule
    path: str
    line: int
    detail: str
    evidence: str = ""
    severity: Severity | None = None

    def __post_init__(self) -> None:
        if self.severity is None:
            self.severity = self.rule.severity
        # Last line of defence: no report string leaves here unredacted.
        self.detail = redact(self.detail)
        self.evidence = clip(redact(self.evidence))

    def to_dict(self) -> dict:
        return {
            "rule": self.rule.id,
            "severity": self.severity.label,
            "title": self.rule.title,
            "path": self.path,
            "line": self.line,
            "detail": self.detail,
            "evidence": self.evidence,
            "why": self.rule.why,
            "fix": self.rule.fix,
        }


PENALTY = {
    Severity.CRITICAL: 25,
    Severity.HIGH: 10,
    Severity.MEDIUM: 4,
    Severity.LOW: 1,
    Severity.INFO: 0,
}
COUNTED_PER_RULE = 3


def score(findings: list[Finding]) -> tuple[int, str]:
    """0-100 score and a letter grade. Any critical finding caps the grade at D.

    Each rule counts at most COUNTED_PER_RULE times (worst first), so one habit
    repeated across fifty skills does not drown out everything else.
    """
    by_rule: dict[str, list[int]] = {}
    for finding in findings:
        by_rule.setdefault(finding.rule.id, []).append(PENALTY[finding.severity])
    penalty = sum(sum(sorted(costs, reverse=True)[:COUNTED_PER_RULE]) for costs in by_rule.values())
    value = max(0, 100 - penalty)
    grade = "A" if value >= 90 else "B" if value >= 80 else "C" if value >= 65 else "D" if value >= 50 else "F"
    if grade in "ABC" and any(f.severity == Severity.CRITICAL for f in findings):
        grade = "D"
    return value, grade


def line_at(text: str, pos: int) -> int:
    return text.count("\n", 0, max(pos, 0)) + 1


def strip_jsonc(source: str) -> str:
    """Remove // and /* */ comments and trailing commas, keeping line numbers stable."""
    out: list[str] = []
    i, n, in_string = 0, len(source), False
    while i < n:
        ch = source[i]
        if in_string:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(source[i + 1])
                i += 2
                continue
            in_string = ch != '"'
            i += 1
        elif ch == '"':
            in_string = True
            out.append(ch)
            i += 1
        elif source.startswith("//", i):
            end = source.find("\n", i)
            i = n if end < 0 else end
        elif source.startswith("/*", i):
            end = source.find("*/", i + 2)
            end = n if end < 0 else end + 2
            out.append("\n" * source.count("\n", i, end))
            i = end
        else:
            out.append(ch)
            i += 1
    return re.sub(r",(\s*[}\]])", r"\1", "".join(out))


def load_jsonc(source: str) -> object:
    """Parse strict JSON, falling back to JSON-with-comments (VS Code, Zed)."""
    try:
        return json.loads(source)
    except ValueError:
        return json.loads(strip_jsonc(source))
