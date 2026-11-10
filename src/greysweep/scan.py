"""Run every check over the discovered files and assemble one result."""
from __future__ import annotations

import json
import os
import re
import stat
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from . import live
from .check_mcp import check_config, check_server, command_tokens, extract_servers
from .check_settings import check_claude_settings, check_codex, check_hooks_file
from .check_text import check_text
from .core import Finding, Severity, load_jsonc, score
from .discover import Target, discover
from .rules import RULES

SECRET_RULES = {"GS-MCP-002", "GS-CFG-008", "GS-TXT-030"}
# Softer in instruction files the user installed themself than in ones that arrive with a cloned repository.
INSTALLED_BY_USER = {"GS-TXT-040": Severity.LOW, "GS-EXE-001": Severity.MEDIUM}
IGNORE_MARK =re.compile(r"greysweep:ignore\b(?:[ \t]+((?:GS-[A-Z]+-\d+[ \t,]*)+))?")


@dataclass
class Options:
    project: Path | None = None
    home: Path | None = None
    ignore_rules: frozenset[str] = frozenset()
    min_severity: Severity = Severity.INFO
    honour_ignores: bool = True
    live: bool = False
    live_servers: frozenset[str] = frozenset()  # empty means every stdio server
    repin: bool = False
    timeout: float = 15.0


@dataclass
class Result:
    findings: list[Finding] = field(default_factory=list)
    files: int = 0
    servers: int = 0
    probed: int = 0
    suppressed: int = 0
    skipped_files: int = 0
    score: int = 100
    grade: str = "A"

    def counts(self) -> dict[str, int]:
        totals = {sev.label: 0 for sev in sorted(Severity, reverse=True)}
        for finding in self.findings:
            totals[finding.severity.label] += 1
        return totals

    def worst(self) -> Severity | None:
        return max((f.severity for f in self.findings), default=None)


def read_text(path: Path) -> str:
    return path.read_bytes().decode("utf-8", errors="replace")


def display(path: str, project: Path | None, home: Path | None) -> str:
    """Path as shown in reports: relative to the project, or ~/ for the home directory."""
    for base, prefix in ((project, ""), (home, "~/")):
        if base is None:
            continue
        try:
            return prefix + Path(path).relative_to(base).as_posix()
        except ValueError:
            continue
    return path


def _permission_findings(target: Target, findings: list[Finding]) -> list[Finding]:
    if os.name == "nt":
        return []
    try:
        mode = stat.S_IMODE(target.path.stat().st_mode)
    except OSError:
        return []
    shown = f"mode {mode:04o}"
    if mode & stat.S_IWOTH:
        return [Finding(RULES["GS-CFG-009"], str(target.path), 1, "any local user can rewrite this file", shown)]
    if target.scope == "user" and mode & (stat.S_IRGRP | stat.S_IROTH) and any(
            f.rule.id in SECRET_RULES for f in findings):
        return [Finding(RULES["GS-CFG-010"], str(target.path), 1,
                        "holds a credential and is readable by other local users", shown)]
    return []


def scan_file(target: Target, home: Path | None) -> tuple[list[Finding], list[tuple[str, dict, str]], str]:
    """Findings for one file, plus the MCP servers it defines and its text."""
    path = target.path
    try:
        text = read_text(path)
    except OSError as exc:
        return [Finding(RULES["GS-CFG-012"], str(path), 1, f"could not be read: {exc.strerror or exc}")], [], ""

    if target.kind in {"text", "script"}:
        findings = check_text(text, path, target.kind)
        if target.scope == "user" and target.kind == "text":
            for finding in findings:
                softer = INSTALLED_BY_USER.get(finding.rule.id)
                if softer is not None and finding.severity > softer:
                    finding.severity = softer
        return findings + _permission_findings(target, findings), [], text

    try:
        source = text.lstrip("﻿")
        data = tomllib.loads(source) if target.kind == "codex" else load_jsonc(source)
    except (ValueError, RecursionError) as exc:
        reason = str(exc).splitlines()[0][:120] if str(exc) else type(exc).__name__
        return [Finding(RULES["GS-CFG-012"], str(path), 1, f"not valid {'TOML' if target.kind == 'codex' else 'JSON'}: {reason}")], [], text

    # settings.local.json is the user's own, uncommitted override file.
    scope = "user" if path.name == "settings.local.json" else target.scope
    if target.kind == "settings":
        findings = check_claude_settings(data, path, text, scope, home)
    elif target.kind == "hooks":
        findings = check_hooks_file(data, path, text, scope)
    elif target.kind == "codex":
        findings = check_codex(data, path, text, scope, home)
    else:
        findings = check_config(data, path, text, home)
    return findings + _permission_findings(target, findings), extract_servers(data), text


def _inline_ignored(finding: Finding, lines: list[str]) -> bool:
    """True when the finding's line, or the one above it, carries a greysweep:ignore marker."""
    for number in (finding.line, finding.line - 1):
        if 1 <= number <= len(lines):
            mark = IGNORE_MARK.search(lines[number - 1])
            if mark and (not mark.group(1) or finding.rule.id in mark.group(1)):
                return True
    return False


def scan(options: Options) -> Result:
    result = Result()
    skipped: list[Path] = []
    targets = discover(options.project, options.home, options.honour_ignores, skipped)
    result.files, result.skipped_files = len(targets), len(skipped)

    findings: list[Finding] = []
    with_servers: list[tuple[Target, list[tuple[str, dict, str]], str]] = []
    for target in targets:
        found, servers, text = scan_file(target, options.home)
        result.servers += len(servers)
        if servers:
            with_servers.append((target, servers, text))
        if options.honour_ignores and found and "greysweep:ignore" in text:
            lines = text.splitlines()
            kept = [f for f in found if not _inline_ignored(f, lines)]
            result.suppressed += len(found) - len(kept)
            found = kept
        findings += found

    if options.live:
        pins = live.Pins((options.home or Path.home()) / ".config" / "greysweep" / "pins.json")
        started: set[str] = set()
        for target, servers, text in with_servers:
            for name, cfg, context in servers:
                tokens = command_tokens(cfg)
                if not tokens or (options.live_servers and name not in options.live_servers):
                    continue
                key = json.dumps([name, tokens, cfg.get("env")], sort_keys=True, default=str)
                if key in started:
                    continue
                started.add(key)
                static = {f.rule.id for f in check_server(name, cfg, context, target.path, text, options.home)}
                findings += live.probe_server(name, cfg, target.path, text, static, pins,
                                              repin=options.repin, timeout=options.timeout)
                result.probed += 1
        pins.save()

    counted = [f for f in findings if f.rule.id not in options.ignore_rules]
    result.suppressed += len(findings) - len(counted)
    result.score, result.grade = score(counted)  # --min-severity filters the listing, not the score
    kept = [f for f in counted if f.severity >= options.min_severity]
    for finding in kept:
        finding.path = display(finding.path, options.project, options.home)
    kept.sort(key=lambda f: (-f.severity, f.path, f.line, f.rule.id))
    result.findings = kept
    return result
