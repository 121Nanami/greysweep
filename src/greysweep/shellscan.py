"""Recognise dangerous shell behaviour in a command or a line of text."""
from __future__ import annotations

import re

_INTERP = r"(?:sudo\s+)?(?:(?:ba|z|da|k)?sh|python3?|node|perl|ruby|pwsh|powershell)\b"
PIPE_SHELL = re.compile(
    r"\b(?:curl|wget)\s+[^\n|;]*\|\s*" + _INTERP
    + r"|\b(?:ba|z)?sh\s+(?:-c\s+)?[\"']?(?:<\(|\$\()\s*(?:curl|wget)\b"
    + r"|(?i:\b(?:iwr|irm|invoke-webrequest|invoke-restmethod)\b[^\n|;]*\|\s*iex\b)"
)
B64_EXEC = re.compile(
    r"base64\s+(?:-d|-D|--decode)\b[^\n]*\|\s*" + _INTERP
    + r"|\beval\b[^\n]*base64\s+(?:-d|-D|--decode)"
    + r"|\bexec\(\s*(?:base64\.)?b64decode\("
    + r"|\beval\(\s*atob\("
)
NET = re.compile(
    r"\b(?:curl|wget|ncat|netcat|scp|sftp)\b|\bnc\s+-|/dev/tcp/"
    r"|requests\.(?:post|put)|urllib\.request|\bfetch\(|https?\.request\("
    r"|(?i:invoke-webrequest|invoke-restmethod)"
)
SENSITIVE = re.compile(
    r"/\.ssh\b|\bid_(?:rsa|ed25519|ecdsa)\b|\.aws/credentials|\.netrc\b|\.npmrc\b|\.git-credentials"
    r"|\.claude\.json|\.claude/\.credentials|find-generic-password|login\.keychain|/etc/(?:passwd|shadow)\b"
    r"|\.kube/config|\.docker/config\.json|\bprintenv\b|\benv\s*\||\$\(env\)|`env`"
    r"|(?<![\w.])\.env\b(?!\.(?:example|sample|template))"
)
ENV_SECRET = re.compile(
    r"\$\{?\w*(?:API_KEY|TOKEN|SECRET|PASSWORD)\w*\}?|process\.env\.\w*(?:KEY|TOKEN|SECRET)\w*"
)
URL_HOST = re.compile(r"https?://([^/\s\"'`)>\]:]+)")
NEGATION = re.compile(r"(?i)\b(never|do not|don't|must not|should not|avoid|refuse)\b")

# Sending a vendor's own key to that vendor's API is normal usage, not exfiltration.
_VENDOR_HOSTS = (
    "anthropic.com", "openai.com", "googleapis.com", "github.com", "githubusercontent.com",
    "gitlab.com", "slack.com", "notion.com", "stripe.com", "localhost", "127.0.0.1",
)


def _is_vendor(host: str) -> bool:
    host = host.lower()
    return any(host == v or host.endswith("." + v) for v in _VENDOR_HOSTS)


def is_exfil(line: str) -> bool:
    if not NET.search(line):
        return False
    if SENSITIVE.search(line):
        return True
    if ENV_SECRET.search(line):
        hosts = URL_HOST.findall(line)
        return bool(hosts) and not all(_is_vendor(h) for h in hosts)
    return False


def analyze(command: str) -> list[tuple[str, str]]:
    """Return (rule_id, what it does) for each dangerous behaviour in a command."""
    hits: list[tuple[str, str]] = []
    if PIPE_SHELL.search(command):
        hits.append(("GS-EXE-001", "downloads a script and pipes it straight into an interpreter"))
    if B64_EXEC.search(command):
        hits.append(("GS-EXE-002", "decodes an encoded payload and executes it"))
    if is_exfil(command):
        hits.append(("GS-EXE-003", "reads credentials or environment secrets and sends them to a remote host"))
    return hits
