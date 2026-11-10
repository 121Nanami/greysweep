"""Secret detection and redaction. Nothing in this module returns a full secret."""
from __future__ import annotations

import re

# Order matters: the first pattern to claim a span wins (Anthropic before OpenAI).
TOKEN_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("Anthropic API key", re.compile(r"sk-ant-[A-Za-z0-9_\-]{20,}")),
    ("OpenAI API key", re.compile(r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_\-]{32,}")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}|\bgithub_pat_[A-Za-z0-9_]{40,}")),
    ("AWS access key ID", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("Slack token", re.compile(r"\bxox[abeprs]-[A-Za-z0-9-]{10,}")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("Stripe live key", re.compile(r"\b[sr]k_live_[0-9A-Za-z]{20,}")),
    ("Notion token", re.compile(r"\b(?:secret|ntn)_[A-Za-z0-9]{40,}\b")),
    ("Private key block", re.compile(r"-----BEGIN (?:[A-Z]+ )*PRIVATE KEY-----")),
    ("JSON Web Token", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
    ("Bearer token", re.compile(r"(?i)\bbearer\s+(?!\$)[A-Za-z0-9_\-.=+/]{20,}")),
    ("URL with embedded password", re.compile(r"\b[a-z][a-z0-9+.-]*://[^/\s:@]+:(?!\$)[^/\s:@]{6,}@")),
]

KEYISH = re.compile(
    r"(?i)(secret|token|passw(or)?d|api[_-]?key|apikey|private[_-]?key|access[_-]?key|credential)"
)
_NOT_A_SECRET_KEY = re.compile(
    r"(?i)(_|-)(url|uri|path|file|dir|endpoint|host|type|method|header|name|ttl|limit|count|expiry|scope)s?$"
)
_PLACEHOLDER = re.compile(
    r"(?i)^(<.*>|\[.*\]|%\w+%|your[_-].*|x{3,}|\*{3,}|\.{3,}|changeme|placeholder|todo|none|null|"
    r"true|false|example.*|dummy.*|redacted|insert[_-].*)$"
)
_ASSIGNMENT = re.compile(
    r"""(?ix)\b([\w.-]*(?:secret|token|passw(?:or)?d|api[_-]?key|apikey|private[_-]?key|access[_-]?key)
        [\w.-]*["']?\s*[=:]\s*["']?)([^\s"',;&)]{8,})"""
)
_FLAG_VALUE = re.compile(
    r"""(?ix)(--?[\w-]*(?:secret|token|passw(?:or)?d|api[_-]?key|apikey|access[_-]?key)[\w-]*\s+)
        ([^\s"'$-][^\s"']{7,})"""
)


def mask(value: str) -> str:
    """Keep four characters for recognition, drop the rest."""
    return value[:4] + "…[redacted]"


def is_reference(value: str) -> bool:
    """True when the value points at a secret instead of containing one."""
    v = value.strip()
    return (
        not v
        or v.startswith("$")
        or "${" in v
        or "{{" in v
        or v.startswith(("/", "~", "./", "file:", "op://", "keychain:", "env:"))
        or bool(_PLACEHOLDER.match(v))
    )


def find_tokens(text: str) -> list[tuple[str, int, int]]:
    """Known credential formats in text, as (label, start, end), without overlaps."""
    hits: list[tuple[str, int, int]] = []
    for label, pattern in TOKEN_PATTERNS:
        for m in pattern.finditer(text):
            if not any(m.start() < e and s < m.end() for _, s, e in hits):
                hits.append((label, m.start(), m.end()))
    return sorted(hits, key=lambda h: h[1])


def looks_hardcoded(key: str, value: object) -> bool:
    """A key whose name says 'credential' holding a literal value."""
    if not isinstance(value, str):
        return False
    v = value.strip()
    if len(v) < 8 or is_reference(v) or v.lower().startswith(("http://", "https://")):
        return False
    return bool(KEYISH.search(key)) and not _NOT_A_SECRET_KEY.search(key)


def redact(text: str) -> str:
    """Mask anything secret-shaped. Applied to every string a report prints."""
    if not text:
        return text
    for _, pattern in TOKEN_PATTERNS:
        text = pattern.sub(lambda m: mask(m.group(0)), text)

    def _assign(m: re.Match[str]) -> str:
        value = m.group(2)
        if value.startswith("$") or "[redacted]" in value:
            return m.group(0)
        return m.group(1) + mask(value)

    text = _ASSIGNMENT.sub(_assign, text)
    return _FLAG_VALUE.sub(lambda m: m.group(0) if "[redacted]" in m.group(2) else m.group(1) + mask(m.group(2)), text)
