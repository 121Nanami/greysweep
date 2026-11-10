"""Reporters: terminal, JSON, SARIF 2.1.0 and a self-contained HTML page."""
from __future__ import annotations

import html
import json
from urllib.parse import quote

from . import __version__
from .core import Severity
from .rules import RULES
from .scan import Result

ANSI = {
    Severity.CRITICAL: "\033[1;97;41m", Severity.HIGH: "\033[1;31m", Severity.MEDIUM: "\033[33m",
    Severity.LOW: "\033[36m", Severity.INFO: "\033[2m",
}
RESET, BOLD, DIM = "\033[0m", "\033[1m", "\033[2m"
GRADE_ANSI = {"A": "\033[1;32m", "B": "\033[1;32m", "C": "\033[1;33m", "D": "\033[1;31m", "F": "\033[1;97;41m"}
SARIF_LEVEL = {Severity.CRITICAL: "error", Severity.HIGH: "error", Severity.MEDIUM: "warning",
               Severity.LOW: "note", Severity.INFO: "note"}
SECURITY_SEVERITY = {Severity.CRITICAL: "9.5", Severity.HIGH: "8.0", Severity.MEDIUM: "5.5",
                     Severity.LOW: "3.0", Severity.INFO: "0.0"}


def _summary_line(result: Result) -> str:
    parts = [f"{count} {label}" for label, count in result.counts().items() if count]
    return ", ".join(parts) if parts else "no findings"


def _scanned_line(result: Result) -> str:
    line = f"{result.files} file(s), {result.servers} MCP server definition(s)"
    if result.probed:
        line += f", {result.probed} started for live inspection"
    return line


def _notes(result: Result) -> list[str]:
    notes = []
    if result.suppressed:
        notes.append(f"{result.suppressed} finding(s) suppressed by ignore markers or --ignore")
    if result.skipped_files:
        notes.append(f"{result.skipped_files} file(s) excluded by .greysweepignore")
    if notes:
        notes.append("re-run with --no-ignore to see everything")
    return notes


def render_tty(result: Result, color: bool = False, verbose: bool = False) -> str:
    def paint(code: str, text: str) -> str:
        return f"{code}{text}{RESET}" if color else text

    out = [paint(BOLD, f"greysweep {__version__}") + "  agent attack-surface audit", ""]
    badge = paint(GRADE_ANSI[result.grade], f" {result.grade} ") if color else result.grade
    out.append(f"  Grade {badge}   score {result.score}/100")
    out.append(f"  {_summary_line(result)}")
    out.append(paint(DIM, f"  scanned {_scanned_line(result)}"))
    out.append("")
    for finding in result.findings:
        tag = paint(ANSI[finding.severity], f"{finding.severity.label.upper():<8}")
        out.append(f"{tag} {paint(BOLD, finding.rule.title)}  {paint(DIM, finding.rule.id)}")
        out.append(f"  {finding.path}:{finding.line}")
        out.append(f"  {finding.detail}")
        if finding.evidence:
            out.append(paint(DIM, f"  > {finding.evidence}"))
        if verbose:
            out.append(f"  why: {finding.rule.why}")
        out.append(f"  fix: {finding.rule.fix}")
        out.append("")
    if not result.findings:
        out += ["  Nothing to report in the files that were found.", ""]
    for note in _notes(result):
        out.append(paint(DIM, f"  note: {note}"))
    if result.servers and not result.probed:
        out.append(paint(DIM, "  tip: --live starts stdio MCP servers and inspects the tool descriptions they send"))
    return "\n".join(out).rstrip() + "\n"


def render_json(result: Result) -> str:
    return json.dumps({
        "tool": "greysweep",
        "version": __version__,
        "score": result.score,
        "grade": result.grade,
        "summary": result.counts(),
        "scanned": {"files": result.files, "mcp_servers": result.servers, "live_probed": result.probed},
        "suppressed": result.suppressed,
        "ignored_files": result.skipped_files,
        "findings": [f.to_dict() for f in result.findings],
    }, indent=2, ensure_ascii=False) + "\n"


def render_sarif(result: Result) -> str:
    used = sorted({f.rule.id for f in result.findings})
    rules = [{
        "id": rule.id,
        "name": "".join(word.capitalize() for word in rule.title.replace("-", " ").split() if word.isalnum()),
        "shortDescription": {"text": rule.title},
        "fullDescription": {"text": rule.why},
        "help": {"text": rule.fix},
        "defaultConfiguration": {"level": SARIF_LEVEL[rule.severity]},
        "properties": {"security-severity": SECURITY_SEVERITY[rule.severity], "tags": ["security", "ai-agent"]},
    } for rule in (RULES[i] for i in used)]
    results = [{
        "ruleId": f.rule.id,
        "ruleIndex": used.index(f.rule.id),
        "level": SARIF_LEVEL[f.severity],
        "message": {"text": f.detail + (f" [{f.evidence}]" if f.evidence else "")},
        "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": quote(f.path, safe="/~.-_")},
            "region": {"startLine": max(f.line, 1)},
        }}],
        "properties": {"security-severity": SECURITY_SEVERITY[f.severity]},
    } for f in result.findings]
    return json.dumps({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "greysweep", "version": __version__, "rules": rules}},
                  "results": results}],
    }, indent=2) + "\n"


_CSS = """
:root{--bg:#f6f5f2;--card:#fff;--ink:#1b1b1f;--mute:#63636e;--line:#deddd8;--code:#efeee9;
--critical:#b3123b;--high:#c2410c;--medium:#a16207;--low:#0e6f8f;--info:#63636e}
@media (prefers-color-scheme:dark){:root{--bg:#131316;--card:#1c1c21;--ink:#ececf1;--mute:#9a9aa6;--line:#2e2e36;
--code:#26262d;--critical:#ff5c7f;--high:#ff8a4c;--medium:#e5b93c;--low:#56c2e6;--info:#9a9aa6}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);
font:15px/1.5 ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:920px;margin:0 auto;padding:32px 16px 64px}
header{display:flex;gap:20px;align-items:center;flex-wrap:wrap;margin-bottom:8px}
.grade{width:76px;height:76px;border-radius:14px;display:grid;place-items:center;font-size:42px;font-weight:800;
color:var(--bg);background:var(--ink)}
.grade.D,.grade.F{background:var(--critical)}.grade.C{background:var(--medium)}
h1{font-size:22px;margin:0}p.sub{margin:2px 0 0;color:var(--mute)}
.filters{display:flex;gap:8px;flex-wrap:wrap;margin:20px 0}
.filters label{border:1px solid var(--line);border-radius:999px;padding:4px 12px;cursor:pointer;background:var(--card);
user-select:none}
.filters input{margin-right:6px}
article{background:var(--card);border:1px solid var(--line);border-left:5px solid var(--sev);border-radius:10px;
padding:14px 16px;margin:12px 0}
article h2{font-size:16px;margin:0 0 2px}
.sev{color:var(--sev);font-weight:700;text-transform:uppercase;font-size:12px;letter-spacing:.06em}
.id,.loc{color:var(--mute);font:13px ui-monospace,SFMono-Regular,Menlo,monospace}
pre{background:var(--code);border-radius:6px;padding:8px 10px;margin:8px 0;white-space:pre-wrap;word-break:break-word;
font:13px ui-monospace,SFMono-Regular,Menlo,monospace}
dl{margin:8px 0 0;display:grid;grid-template-columns:auto 1fr;gap:4px 12px}dt{color:var(--mute)}dd{margin:0}
footer{color:var(--mute);margin-top:28px;font-size:13px}
"""

_JS = """
document.querySelectorAll('.filters input').forEach(function(box){box.addEventListener('change',function(){
document.querySelectorAll('article[data-sev="'+box.value+'"]').forEach(function(a){a.hidden=!box.checked})})});
"""


def render_html(result: Result) -> str:
    esc = html.escape
    filters = "".join(
        f'<label style="color:var(--{label})"><input type="checkbox" value="{label}" checked>{count} {label}</label>'
        for label, count in result.counts().items() if count)
    cards = []
    for f in result.findings:
        sev = f.severity.label
        evidence = f"<pre>{esc(f.evidence)}</pre>" if f.evidence else ""
        cards.append(
            f'<article data-sev="{sev}" style="--sev:var(--{sev})">'
            f'<span class="sev">{sev}</span> <span class="id">{esc(f.rule.id)}</span>'
            f"<h2>{esc(f.rule.title)}</h2>"
            f'<div class="loc">{esc(f.path)}:{f.line}</div>'
            f"<p>{esc(f.detail)}</p>{evidence}"
            f"<dl><dt>Why</dt><dd>{esc(f.rule.why)}</dd><dt>Fix</dt><dd>{esc(f.rule.fix)}</dd></dl>"
            "</article>")
    notes = "".join(f"<div>{esc(note)}</div>" for note in _notes(result))
    body = "".join(cards) or "<p>Nothing to report in the files that were found.</p>"
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        f"<title>greysweep report</title><style>{_CSS}</style></head><body><main>"
        f'<header><div class="grade {result.grade}">{result.grade}</div><div>'
        f"<h1>Agent attack-surface audit</h1>"
        f'<p class="sub">Score {result.score}/100 · {esc(_summary_line(result))}</p>'
        f'<p class="sub">Scanned {esc(_scanned_line(result))}</p></div></header>'
        f'<div class="filters">{filters}</div>{body}'
        f"<footer>{notes}<div>Generated by greysweep {__version__}. Credentials are redacted.</div></footer>"
        f"</main><script>{_JS}</script></body></html>\n")


def render(result: Result, fmt: str, color: bool = False, verbose: bool = False) -> str:
    if fmt == "json":
        return render_json(result)
    if fmt == "sarif":
        return render_sarif(result)
    if fmt == "html":
        return render_html(result)
    return render_tty(result, color, verbose)
