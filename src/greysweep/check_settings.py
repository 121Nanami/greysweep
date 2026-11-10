"""Checks on agent settings: Claude Code settings.json, hook files and Codex config.toml.

``scope`` is "project" for files a repository ships to everyone who opens it, and
"user" for files only the local user controls. The same setting is far more
dangerous in the first case, so severities differ.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from urllib.parse import urlsplit

from . import shellscan
from .check_mcp import check_config, is_local_host
from .core import Finding, Severity, line_at
from .rules import RULES
from .secretscan import find_tokens, is_reference, looks_hardcoded, mask

SHELL_ANY = re.compile(r"^Bash(\(\s*(\*|:\*|\*:\*|\*\*)?\s*\))?$")
SHELL_PREFIX = re.compile(r"^Bash\(\s*([\w./-]+)\s*(?::\*|\s\*|\*)\s*\)$")
RISKY_COMMANDS = {
    "curl", "wget", "sudo", "rm", "bash", "sh", "zsh", "python", "python3", "node", "eval", "ssh",
    "scp", "nc", "osascript", "perl", "ruby", "env", "xargs", "dd", "npx", "uvx", "powershell",
}
FILE_RULE = re.compile(r"^(Read|Edit|Write|MultiEdit)\((.+)\)$")
SENSITIVE_PATH = re.compile(
    r"\.ssh\b|\.aws\b|\.gnupg\b|\.kube\b|\.netrc|\.npmrc|\.git-credentials|\.claude\.json|"
    r"credentials|keychain|(?<![\w.])\.env\b"
)
WHOLE_DISK = re.compile(r"^(~|//|/|\$HOME|/Users/[^/]+|/home/[^/]+)/?\*\*(/\*)?$")
ROUTING_VARS = {
    "ANTHROPIC_BASE_URL", "ANTHROPIC_API_URL", "ANTHROPIC_BEDROCK_BASE_URL", "ANTHROPIC_VERTEX_BASE_URL",
    "OPENAI_BASE_URL", "OPENAI_API_BASE", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
}
TRUSTED_API_HOSTS = ("anthropic.com", "openai.com", "amazonaws.com", "googleapis.com", "azure.com")
AUTO_COMMAND_KEYS = ("apiKeyHelper", "awsAuthRefresh", "awsCredentialExport", "otelHeadersHelper")


class _Locator:
    """Maps a value back to a line number in the raw file text."""

    def __init__(self, path: Path, text: str) -> None:
        self.path, self.text = str(path), text

    def line(self, *needles: str) -> int:
        for needle in needles:
            pos = self.text.find(needle) if needle else -1
            if pos >= 0:
                return line_at(self.text, pos)
        return 1

    def finding(self, rule_id: str, detail: str, evidence: str = "", needles: tuple[str, ...] = (),
                severity: Severity | None = None) -> Finding:
        return Finding(RULES[rule_id], self.path, self.line(*needles), detail, evidence, severity)


def _hook_commands(node: object) -> list[str]:
    commands: list[str] = []
    if isinstance(node, dict):
        if isinstance(node.get("command"), str) and node.get("type", "command") == "command":
            commands.append(node["command"])
        for value in node.values():
            commands.extend(_hook_commands(value))
    elif isinstance(node, list):
        for item in node:
            commands.extend(_hook_commands(item))
    return commands


def check_hooks(hooks: object, loc: _Locator, scope: str) -> list[Finding]:
    findings: list[Finding] = []
    commands = _hook_commands(hooks)
    if not commands:
        return findings
    if scope == "project":
        findings.append(loc.finding(
            "GS-HOOK-001", f"{len(commands)} hook command(s) run automatically for everyone who opens this project",
            commands[0], ('"hooks"',)))
    for command in commands:
        needles = (json.dumps(command)[1:-1], command[:40], '"hooks"')
        behaviours = shellscan.analyze(command)
        for rule_id, what in behaviours:
            severity = Severity.CRITICAL if rule_id == "GS-EXE-001" else None
            findings.append(loc.finding(rule_id, f"hook {what}", command, needles, severity))
        if not behaviours and shellscan.NET.search(command):
            hosts = ", ".join(sorted(set(shellscan.URL_HOST.findall(command)))) or "a remote host"
            findings.append(loc.finding("GS-HOOK-002", f"hook contacts {hosts}", command, needles))
    return findings


def check_claude_settings(data: object, path: Path, text: str, scope: str,
                          home: Path | None = None) -> list[Finding]:
    if not isinstance(data, dict):
        return []
    loc = _Locator(path, text)
    findings: list[Finding] = []
    shared = scope == "project"
    where = "shared project settings" if shared else "settings"

    permissions = data.get("permissions") if isinstance(data.get("permissions"), dict) else {}
    if permissions.get("defaultMode") == "bypassPermissions":
        findings.append(loc.finding(
            "GS-CFG-001", f"defaultMode is bypassPermissions in {where}", '"defaultMode": "bypassPermissions"',
            ('"defaultMode"',), Severity.CRITICAL if shared else None))
    if data.get("skipDangerousModePermissionPrompt") is True:
        findings.append(loc.finding(
            "GS-CFG-001", "the warning shown before entering bypass mode is suppressed",
            '"skipDangerousModePermissionPrompt": true', ('"skipDangerousModePermissionPrompt"',), Severity.MEDIUM))

    allow = permissions.get("allow") if isinstance(permissions.get("allow"), list) else []
    for entry in allow:
        if not isinstance(entry, str):
            continue
        needles = (json.dumps(entry), entry)
        if SHELL_ANY.match(entry) or entry.strip() == "*":
            findings.append(loc.finding("GS-CFG-002", f"allow rule {entry} approves every shell command", entry, needles))
            continue
        prefix = SHELL_PREFIX.match(entry)
        if prefix and prefix.group(1).rsplit("/", 1)[-1] in RISKY_COMMANDS:
            findings.append(loc.finding(
                "GS-CFG-003", f"allow rule {entry} approves any {prefix.group(1)} invocation", entry, needles))
            continue
        file_rule = FILE_RULE.match(entry)
        if file_rule and (SENSITIVE_PATH.search(file_rule.group(2)) or WHOLE_DISK.match(file_rule.group(2))):
            findings.append(loc.finding(
                "GS-CFG-004", f"allow rule {entry} covers credential paths or the whole home directory", entry, needles))

    if data.get("enableAllProjectMcpServers") is True:
        findings.append(loc.finding(
            "GS-CFG-005", "enableAllProjectMcpServers is true", '"enableAllProjectMcpServers": true',
            ('"enableAllProjectMcpServers"',)))

    env = data.get("env") if isinstance(data.get("env"), dict) else {}
    for key, value in env.items():
        if not isinstance(value, str):
            continue
        if str(key).upper() in ROUTING_VARS:
            host = (urlsplit(value if "://" in value else "//" + value).hostname or "").lower()
            trusted = any(host == h or host.endswith("." + h) for h in TRUSTED_API_HOSTS)
            if host and not trusted and (shared or not is_local_host(host)):
                detail = f"{key} routes traffic to {host}"
                if shared:
                    findings.append(loc.finding("GS-CFG-006", f"{detail}, set by the repository", f"{key}={host}", (f'"{key}"',)))
                else:
                    findings.append(loc.finding(
                        "GS-CFG-006", f"{detail}; confirm this is a gateway you operate", f"{key}={host}",
                        (f'"{key}"',), Severity.MEDIUM))
            continue
        hits = find_tokens(value)
        if (hits and not is_reference(value)) or looks_hardcoded(str(key), value):
            what = hits[0][0] if hits else "literal value"
            findings.append(loc.finding("GS-CFG-008", f"{what} in env {key}", f"{key}={mask(value)}", (f'"{key}"',)))

    automatic = [(key, data[key]) for key in AUTO_COMMAND_KEYS if isinstance(data.get(key), str)]
    status_line = data.get("statusLine")
    if isinstance(status_line, dict) and isinstance(status_line.get("command"), str):
        automatic.append(("statusLine.command", status_line["command"]))
    for key, command in automatic:
        needles = (f'"{key.split(".")[0]}"',)
        if shared:
            findings.append(loc.finding("GS-CFG-007", f"{key} is set by the repository", command, needles))
        for rule_id, what in shellscan.analyze(command):
            findings.append(loc.finding(rule_id, f"{key} {what}", command, needles))

    findings.extend(check_hooks(data.get("hooks"), loc, scope))
    findings.extend(check_config(data, path, text, home))  # settings may embed mcpServers
    return findings


def check_hooks_file(data: object, path: Path, text: str, scope: str) -> list[Finding]:
    hooks = data.get("hooks", data) if isinstance(data, dict) else data
    return check_hooks(hooks, _Locator(path, text), scope)


def check_codex(data: object, path: Path, text: str, scope: str, home: Path | None = None) -> list[Finding]:
    if not isinstance(data, dict):
        return []
    loc = _Locator(path, text)
    findings: list[Finding] = []
    blocks = [("", data)]
    if isinstance(data.get("profiles"), dict):
        blocks += [(f"profile {n}: ", p) for n, p in data["profiles"].items() if isinstance(p, dict)]
    for prefix, block in blocks:
        sandbox, approval = block.get("sandbox_mode"), block.get("approval_policy")
        if sandbox == "danger-full-access":
            unattended = approval == "never"
            detail = prefix + ("sandbox disabled and approvals off: fully unattended, unconfined"
                               if unattended else "sandbox_mode is danger-full-access")
            findings.append(loc.finding(
                "GS-CFG-011", detail, f'sandbox_mode = "{sandbox}"', ("danger-full-access",),
                Severity.CRITICAL if unattended or scope == "project" else None))
        elif approval == "never":
            findings.append(loc.finding(
                "GS-CFG-001", prefix + "approval_policy is never", 'approval_policy = "never"',
                ("approval_policy",), Severity.MEDIUM))
    findings.extend(check_config(data, path, text, home))
    return findings
