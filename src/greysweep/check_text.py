"""Checks on text the agent loads as instructions: CLAUDE.md, AGENTS.md, rules, skills,
commands, and the scripts that ship with them."""
from __future__ import annotations

import re
from pathlib import Path

from . import shellscan
from .core import Finding, Severity, line_at
from .rules import RULES
from .secretscan import find_tokens, mask

TAG_RUN = re.compile(r"[\U000E0000-\U000E007F]+")
VARIATION_RUN = re.compile(r"[︀-️\U000E0100-\U000E01EF]{4,}")
BIDI = re.compile(r"[‪-‮⁦-⁩]")
ZERO_WIDTH = re.compile(r"[​⁠᠎﻿]")
HTML_COMMENT = re.compile(r"<!--(.*?)-->", re.S)
FLAG_BASE = "\U0001F3F4"  # tag characters legitimately follow this in subdivision-flag emoji

_USER = r"(?:the\s+)?(?:user|human|developer|operator)"
# "do not tell the user to run X" is advice about what to recommend, not concealment.
_NOT_ADVICE = r"(?!s?\s+(?:to|how|that\s+(?:they|it)|which|what)\b)"
QUOTE_BEFORE = "\"'`“‘«"
SCRIPT_COMMENT = re.compile(r"^\s*(?:#(?!!)|//|--\s|REM\s|::)")
OVERRIDE = re.compile(
    r"(?i)\b(?:ignore|disregard|forget|override)\s+(?:all\s+|any\s+)?(?:of\s+)?(?:the\s+|your\s+)?"
    r"(?:previous|prior|above|earlier|preceding|system|original)\s+"
    r"(?:instructions?|prompts?|rules|directions|guidelines|context)"
    r"|\byou\s+are\s+no\s+longer\b|\bnew\s+system\s+prompt\b|\b(?:real|actual|true)\s+instructions\s+are\b"
)
SECRECY = re.compile(
    r"(?i)\b(?:do\s+not|don'?t|never|must\s+not)\s+(?:tell|inform|alert|notify|"
    r"(?:mention|reveal|show|disclose)\s+(?:this|it|that|these|any\s+of\s+this)\s+to)\s+" + _USER + _NOT_ADVICE
    + r"|\b(?:hide|conceal|keep)\s+(?:this|it|these|that)\s+(?:secret\s+|hidden\s+)?from\s+" + _USER
    + r"|\bwithout\s+" + _USER + r"(?:'s)?\s+(?:knowing|knowledge|noticing|awareness)"
    + r"|\bdo\s+not\s+(?:mention|reveal|disclose)\s+(?:this|these)\s+(?:instruction|step|rule|section|note)s?\b"
)
CONSENT = re.compile(
    r"(?i)\bwithout\s+(?:asking|telling|informing|notifying|prompting|confirming\s+with)\s+" + _USER + _NOT_ADVICE
    + r"|\b(?:do\s+not|don'?t|never)\s+ask\s+(?:" + _USER + r"\s+)?for\s+(?:permission|confirmation|approval)"
    + r"|--dangerously-skip-permissions|--dangerously-bypass-approvals-and-sandbox"
    + r"|\b(?:skip|bypass|disable|turn\s+off)\s+(?:all\s+)?(?:the\s+)?(?:permission|approval|safety|confirmation)"
      r"\s+(?:prompts?|checks?|dialogs?|system)"
)
AGENT_ADDRESS = re.compile(r"(?i)\b(claude|assistant|ai\s+agents?|agents?|llm|copilot|cursor|codex|model)\b")
IMPERATIVE = re.compile(r"(?i)\b(must|always|run|execute|send|fetch|read|upload|post|curl|wget|include|append)\b")
IMAGE_EXFIL = re.compile(r"!\[[^\]]*\]\(\s*https?://[^)\s]*[?&][^)\s]*(?:\{|\$|<|%7B)[^)\s]*\)")
ALLOWED_TOOLS = re.compile(r"(?im)^allowed-tools:[ \t]*(.*(?:\n[ \t]+-[ \t]+.*)*)")
SHELL_ANY = re.compile(r"^Bash(\(\s*(\*|:\*|\*\*)?\s*\))?$")
POISON = re.compile(
    r"(?i)<\s*(important|system|secret|instructions?)\s*>|\bbefore\s+(?:using|calling)\s+(?:this|any(?:\s+other)?)\s+tool"
    r"|\bside[\s_-]?note\b|\bpass\s+(?:its|their|the)\s+contents?\b"
)
POISON_FILES = re.compile(
    r"/\.ssh\b|\bid_(?:rsa|ed25519|ecdsa)\b|\.aws/credentials|\.netrc\b|\.git-credentials"
    r"|\.claude\.json|\.cursor/|\bmcp\.json\b|/etc/(?:passwd|shadow)\b|login\.keychain"
)

MAX_PER_RULE = 5


class _Collector:
    def __init__(self, path: Path, text: str) -> None:
        self.path, self.text = str(path), text
        self.findings: list[Finding] = []
        self._counts: dict[str, int] = {}
        self._seen: set[tuple[str, int]] = set()

    def add(self, rule_id: str, pos: int, detail: str, evidence: str = "",
            severity: Severity | None = None) -> None:
        line = line_at(self.text, pos)
        if (rule_id, line) in self._seen or self._counts.get(rule_id, 0) >= MAX_PER_RULE:
            return
        self._seen.add((rule_id, line))
        self._counts[rule_id] = self._counts.get(rule_id, 0) + 1
        self.findings.append(Finding(RULES[rule_id], self.path, line, detail, evidence, severity))


def decode_tags(run: str) -> str:
    return "".join(chr(ord(c) - 0xE0000) for c in run if 0xE0020 <= ord(c) <= 0xE007E)


def _line_text(text: str, pos: int) -> str:
    start = text.rfind("\n", 0, pos) + 1
    end = text.find("\n", pos)
    return text[start : len(text) if end < 0 else end]


def _bump(severity: Severity) -> Severity:
    return Severity(min(severity + 1, Severity.CRITICAL))


def hidden_unicode(out: _Collector) -> None:
    text = out.text
    for m in TAG_RUN.finditer(text):
        if m.start() > 0 and text[m.start() - 1] == FLAG_BASE:
            continue
        decoded = decode_tags(m.group(0))
        out.add("GS-TXT-001", m.start(), f"{len(m.group(0))} invisible tag characters decode to hidden text",
                f"hidden text: {decoded}" if decoded else "")
    for m in VARIATION_RUN.finditer(text):
        out.add("GS-TXT-001", m.start(),
                f"run of {len(m.group(0))} variation selectors, a known way to encode hidden bytes")
    bidi = BIDI.search(text)
    if bidi:
        out.add("GS-TXT-002", bidi.start(), f"{len(BIDI.findall(text))} bidirectional control character(s)",
                _line_text(text, bidi.start()))
    zero = [m for m in ZERO_WIDTH.finditer(text) if not (m.start() == 0 and m.group(0) == "﻿")]
    if zero:
        out.add("GS-TXT-003", zero[0].start(), f"{len(zero)} zero-width character(s)",
                _line_text(text, zero[0].start()), None if len(zero) >= 3 else Severity.LOW)


def injection_phrases(out: _Collector) -> None:
    text = out.text
    comments = [(m.start(), m.end()) for m in HTML_COMMENT.finditer(text)]
    flagged_comments: set[int] = set()

    def comment_index(pos: int) -> int:
        return next((i for i, (s, e) in enumerate(comments) if s <= pos < e), -1)

    for rule_id, pattern, what in (
        ("GS-TXT-010", OVERRIDE, "tells the agent to discard its instructions"),
        ("GS-TXT-011", SECRECY, "tells the agent to conceal something from the user"),
        ("GS-TXT-012", CONSENT, "tells the agent to act without confirmation"),
    ):
        for m in pattern.finditer(text):
            idx = comment_index(m.start())
            severity = None
            detail = what
            if idx >= 0:
                flagged_comments.add(idx)
                severity = _bump(RULES[rule_id].severity)
                detail += ", inside an HTML comment that is invisible when rendered"
            elif m.start() > 0 and text[m.start() - 1] in QUOTE_BEFORE:
                # A quoted phrase is usually a document describing an attack, not making one.
                severity = Severity.LOW
                detail = f"quotes a phrase that {what}; usually an example or a warning"
            out.add(rule_id, m.start(), detail, _line_text(text, m.start()), severity)

    for idx, (start, end) in enumerate(comments):
        body = text[start + 4 : end - 3]
        if idx in flagged_comments:
            continue
        if shellscan.analyze(body) or (AGENT_ADDRESS.search(body) and IMPERATIVE.search(body)):
            out.add("GS-TXT-013", start, "comment addresses the agent or carries commands", body)


def shell_behaviour(out: _Collector, prose: bool) -> None:
    pos = 0
    for line in out.text.splitlines(keepends=True):
        # A comment in a script never runs; in prose every line is something the agent reads.
        hits = [] if not prose and SCRIPT_COMMENT.match(line) else shellscan.analyze(line)
        for rule_id, what in hits:
            severity = None
            if prose and rule_id == "GS-EXE-003" and shellscan.NEGATION.search(line):
                severity = Severity.MEDIUM  # "never send ~/.ssh ..." reads as a prohibition
            out.add(rule_id, pos, what, line, severity)
        pos += len(line)


def secrets(out: _Collector) -> None:
    for label, start, end in find_tokens(out.text):
        out.add("GS-TXT-030", start, f"{label} in file", mask(out.text[start:end]))


def skill_frontmatter(out: _Collector) -> None:
    text = out.text
    if not text.startswith("---"):
        return
    end = text.find("\n---", 3)
    if end < 0:
        return
    m = ALLOWED_TOOLS.search(text[:end])
    if not m:
        return
    tools = [t.strip(" \t-\"'[]") for t in re.split(r"[,\n]", m.group(1))]
    broad = [t for t in tools if SHELL_ANY.match(t) or t == "*"]
    if broad:
        out.add("GS-TXT-040", m.start(), f"allowed-tools includes {broad[0]}", m.group(0))


def check_text(text: str, path: Path, kind: str = "text") -> list[Finding]:
    """kind is "text" for instruction/Markdown files, "script" for code shipped with them."""
    out = _Collector(path, text)
    hidden_unicode(out)
    secrets(out)
    shell_behaviour(out, prose=kind == "text")
    if kind == "text":
        injection_phrases(out)
        skill_frontmatter(out)
        for m in IMAGE_EXFIL.finditer(text):
            out.add("GS-TXT-020", m.start(), "image URL carries a templated value in its query string", m.group(0))
    return out.findings


def poison_reasons(text: str) -> list[str]:
    """Why a piece of MCP tool metadata looks like an attack on the model. Empty if clean."""
    reasons: list[str] = []
    for m in TAG_RUN.finditer(text):
        reasons.append(f"invisible tag characters hiding: {decode_tags(m.group(0))[:80]}")
        break
    if VARIATION_RUN.search(text) or BIDI.search(text):
        reasons.append("invisible or bidirectional control characters")
    if OVERRIDE.search(text):
        reasons.append("instruction-override phrase")
    if SECRECY.search(text):
        reasons.append("tells the model to hide behaviour from the user")
    if POISON.search(text):
        reasons.append("embedded directive block aimed at the model")
    if POISON_FILES.search(text):
        reasons.append("references credential or agent-config files")
    if shellscan.analyze(text):
        reasons.append("contains a command that downloads/executes or exfiltrates")
    return reasons
