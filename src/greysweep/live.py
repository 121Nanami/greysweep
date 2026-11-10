"""Opt-in live probing: start a stdio MCP server, read its tool definitions, inspect and pin them.

This executes the configured server command, exactly as the agent would. It only
runs under --live, and never for servers the static checks already consider
dangerous to start.
"""
from __future__ import annotations

import hashlib
import json
import os
import queue
import subprocess
import threading
import time
from pathlib import Path

from . import __version__
from .check_mcp import command_tokens, safe_cmdline
from .check_text import poison_reasons
from .core import Finding, line_at
from .rules import RULES

UNSAFE_TO_START = {"GS-MCP-005", "GS-MCP-006", "GS-MCP-009", "GS-EXE-002", "GS-EXE-003"}
PROTOCOL_VERSION = "2025-06-18"


class ProbeError(Exception):
    pass


def list_tools(cfg: dict, timeout: float = 15.0, cwd: str | None = None) -> list[dict]:
    """Speak just enough MCP over stdio to fetch the server's tool list."""
    argv = [os.path.expandvars(os.path.expanduser(t)) for t in command_tokens(cfg)]
    if not argv:
        raise ProbeError("not a stdio server")
    env = dict(os.environ)
    if isinstance(cfg.get("env"), dict):
        env.update({str(k): os.path.expandvars(str(v)) for k, v in cfg["env"].items()})
    try:
        proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                env=env, cwd=cwd, text=True, encoding="utf-8", errors="replace", bufsize=1)
    except OSError as exc:
        raise ProbeError(f"could not start: {exc.strerror or exc}") from None

    lines: queue.Queue[str | None] = queue.Queue()

    def pump() -> None:
        try:
            for line in proc.stdout:  # type: ignore[union-attr]
                lines.put(line)
        except (OSError, ValueError):
            pass  # pipe closed underneath us during shutdown
        finally:
            lines.put(None)

    reader = threading.Thread(target=pump, daemon=True)
    reader.start()
    deadline = time.monotonic() + timeout

    def send(message: dict) -> None:
        try:
            proc.stdin.write(json.dumps(message) + "\n")  # type: ignore[union-attr]
            proc.stdin.flush()  # type: ignore[union-attr]
        except OSError:
            raise ProbeError("server closed its input") from None

    def wait_for(request_id: int) -> dict:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ProbeError(f"no response within {timeout:.0f}s")
            try:
                line = lines.get(timeout=remaining)
            except queue.Empty:
                raise ProbeError(f"no response within {timeout:.0f}s") from None
            if line is None:
                raise ProbeError("server exited before answering")
            try:
                message = json.loads(line)
            except ValueError:
                continue  # servers sometimes log to stdout
            if isinstance(message, dict) and message.get("id") == request_id:
                if "error" in message:
                    raise ProbeError(f"server error: {str(message['error'])[:120]}")
                result = message.get("result")
                return result if isinstance(result, dict) else {}

    try:
        send({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": PROTOCOL_VERSION, "capabilities": {},
            "clientInfo": {"name": "greysweep", "version": __version__}}})
        wait_for(1)
        send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        tools: list[dict] = []
        cursor, request_id = None, 2
        while True:
            params = {"cursor": cursor} if cursor else {}
            send({"jsonrpc": "2.0", "id": request_id, "method": "tools/list", "params": params})
            result = wait_for(request_id)
            tools += [t for t in result.get("tools", []) if isinstance(t, dict)]
            cursor = result.get("nextCursor")
            request_id += 1
            if not cursor or request_id > 50:
                return tools
    finally:
        try:
            proc.kill()
            proc.wait(timeout=2)
        except (OSError, subprocess.TimeoutExpired):
            pass
        reader.join(timeout=2)
        for pipe in (proc.stdin, proc.stdout):
            try:
                pipe.close()  # type: ignore[union-attr]
            except (OSError, ValueError):
                pass


def _strings(node: object) -> list[str]:
    if isinstance(node, str):
        return [node]
    if isinstance(node, dict):
        return [s for value in node.values() for s in _strings(value)]
    if isinstance(node, list):
        return [s for value in node for s in _strings(value)]
    return []


def tool_text(tool: dict) -> str:
    """Everything in a tool definition that ends up in the model's context."""
    return "\n".join(_strings({k: tool.get(k) for k in ("name", "title", "description", "inputSchema", "annotations")}))


def fingerprint(tool: dict) -> str:
    canonical = json.dumps({k: tool.get(k) for k in ("name", "description", "inputSchema")},
                           sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class Pins:
    """Remembered tool fingerprints, so a later silent change is visible."""

    def __init__(self, path: Path) -> None:
        self.path = path
        try:
            self.data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            self.data = {}
        self.dirty = False

    def compare(self, server_key: str, tools: list[dict], repin: bool) -> list[str]:
        """Names of tools whose definition differs from the pinned one. New tools get pinned."""
        known = self.data.setdefault(server_key, {})
        changed: list[str] = []
        for tool in tools:
            name, digest = str(tool.get("name", "")), fingerprint(tool)
            if name in known and known[name] != digest and not repin:
                changed.append(name)
                continue
            if known.get(name) != digest:
                known[name] = digest
                self.dirty = True
        return changed

    def save(self) -> None:
        if not self.dirty:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self.data, indent=2, sort_keys=True), encoding="utf-8")


def probe_server(name: str, cfg: dict, path: Path, text: str, static_rules: set[str], pins: Pins,
                 repin: bool = False, timeout: float = 15.0) -> list[Finding]:
    tokens = command_tokens(cfg)
    if not tokens:
        return []
    line = line_at(text, text.find(json.dumps(name)))
    label = f'server "{name}"'

    def finding(rule_id: str, detail: str, evidence: str = "") -> Finding:
        return Finding(RULES[rule_id], str(path), line, f"{label}: {detail}", evidence)

    blocked = sorted(static_rules & UNSAFE_TO_START)
    if blocked:
        return [finding("GS-LIVE-003", f"not started because of {', '.join(blocked)}")]
    try:
        tools = list_tools(cfg, timeout=timeout, cwd=str(path.parent))
    except ProbeError as exc:
        return [finding("GS-LIVE-003", str(exc), safe_cmdline(tokens))]

    findings: list[Finding] = []
    for tool in tools:
        reasons = poison_reasons(tool_text(tool))
        if reasons:
            findings.append(finding("GS-LIVE-001", f'tool "{tool.get("name")}": ' + "; ".join(reasons),
                                    str(tool.get("description", ""))))
    server_key = f"{name}:{hashlib.sha256(' '.join(tokens).encode()).hexdigest()[:12]}"
    for changed in pins.compare(server_key, tools, repin):
        findings.append(finding("GS-LIVE-002", f'tool "{changed}" no longer matches its pinned definition'))
    return findings
