"""Static checks on MCP server definitions, whichever client's config they live in."""
from __future__ import annotations

import json
import re
import shlex
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

from . import shellscan
from .core import Finding, Severity, line_at
from .rules import RULES
from .secretscan import KEYISH, find_tokens, is_reference, looks_hardcoded, mask

SHELLS = {"sh", "bash", "zsh", "dash", "fish", "cmd", "powershell", "pwsh"}
SHELL_C_FLAGS = {"-c", "-lc", "-ic", "/c", "/k", "-command"}
SCRIPT_EXT = (".js", ".mjs", ".cjs", ".ts", ".py", ".sh", ".rb", ".pl", ".ps1", ".jar")
TEMP_PATH = re.compile(r"^(/tmp/|/var/tmp/|/private/tmp/|/dev/shm/|.*/Downloads/|[A-Za-z]:\\+(Windows\\+)?Temp\\)")
BROAD_ROOTS = {"/", "~", "$HOME", "${HOME}", "/Users", "/home", "C:\\", "C:/", "%USERPROFILE%"}
DOCKER_DANGER = re.compile(
    r"--privileged\b|--(?:network|net)[= ]host\b|--pid[= ]host\b|docker\.sock"
    r"|--cap-add[= ](?:ALL|SYS_ADMIN)\b"
    r"|(?:-v|--volume)[= ](?:/|~|\$HOME|\$\{HOME\}|/Users/[^/:\s]+|/home/[^/:\s]+)/?:"
    r"|--mount[= ]\S*(?:source|src)=/,"
)
DOCKER_VALUE_FLAGS = {
    "-e", "--env", "-v", "--volume", "--name", "--network", "--net", "-p", "--publish", "--mount",
    "-w", "--workdir", "--env-file", "-u", "--user", "--entrypoint", "-l", "--label", "--platform",
    "--add-host", "--cap-add", "--cap-drop", "--security-opt", "-m", "--memory", "--cpus", "--pull",
    "-h", "--hostname", "--pid",
}

# Widely used server packages. Names one or two edits away from these get flagged.
KNOWN_PACKAGES = {
    "@modelcontextprotocol/server-filesystem", "@modelcontextprotocol/server-github",
    "@modelcontextprotocol/server-memory", "@modelcontextprotocol/server-puppeteer",
    "@modelcontextprotocol/server-postgres", "@modelcontextprotocol/server-slack",
    "@modelcontextprotocol/server-brave-search", "@modelcontextprotocol/server-everything",
    "@modelcontextprotocol/server-sequential-thinking", "@modelcontextprotocol/server-gitlab",
    "@modelcontextprotocol/server-google-maps", "@modelcontextprotocol/server-sqlite",
    "@modelcontextprotocol/inspector", "@playwright/mcp", "@upstash/context7-mcp",
    "@notionhq/notion-mcp-server", "@supabase/mcp-server-supabase", "@sentry/mcp-server",
    "@stripe/mcp", "@cloudflare/mcp-server-cloudflare", "@browsermcp/mcp",
    "@wonderwhy-er/desktop-commander", "@executeautomation/playwright-mcp-server",
    "mcp-remote", "firecrawl-mcp", "figma-developer-mcp", "chrome-devtools-mcp", "tavily-mcp",
    "exa-mcp-server", "mcp-server-fetch", "mcp-server-git", "mcp-server-time",
    "mcp-server-sqlite", "mcp-server-postgres", "playwright-mcp",
}

_NPM_PKG_FLAGS, _NPM_SKIP = {"-p", "--package"}, {"-c", "--call", "--registry", "--node-options"}
_PY_PKG_FLAGS = {"--from", "--spec"}
_PY_SKIP = {"--with", "--with-editable", "--python", "-p", "--index-url", "--extra-index-url", "--index"}


def _base(command: str) -> str:
    name = re.split(r"[\\/]", command)[-1].lower()
    return re.sub(r"\.(cmd|exe|bat)$", "", name)


def package_spec(tokens: list[str]) -> tuple[str, str] | None:
    """Find the package a launcher command line will fetch: ('npm'|'pypi', spec)."""
    if not tokens:
        return None
    base, rest = _base(tokens[0]), tokens[1:]
    if base in SHELLS:
        for i, tok in enumerate(rest[:-1]):
            if tok.lower() in SHELL_C_FLAGS:
                inner = rest[i + 1 :]
                if len(inner) == 1:
                    try:
                        inner = shlex.split(inner[0])
                    except ValueError:
                        return None
                return package_spec(inner)
        return None
    if base == "env":
        while rest and ("=" in rest[0] or rest[0].startswith("-")):
            rest = rest[1:]
        return package_spec(rest)
    if base in {"npx", "bunx", "pnpx"}:
        eco = "npm"
    elif base in {"npm", "pnpm", "yarn", "bun"} and rest[:1] and rest[0] in {"exec", "dlx", "x"}:
        eco, rest = "npm", rest[1:]
    elif base == "uvx":
        eco = "pypi"
    elif base == "uv" and rest[:2] == ["tool", "run"]:
        eco, rest = "pypi", rest[2:]
    elif base == "pipx" and rest[:1] == ["run"]:
        eco, rest = "pypi", rest[1:]
    else:
        return None
    pkg_flags, skip = (_NPM_PKG_FLAGS, _NPM_SKIP) if eco == "npm" else (_PY_PKG_FLAGS, _PY_SKIP)
    i = 0
    while i < len(rest):
        arg = rest[i]
        if arg.startswith("-") and arg != "--":
            flag, _, value = arg.partition("=")
            if flag in pkg_flags:
                if value:
                    return eco, value
                if i + 1 < len(rest):
                    return eco, rest[i + 1]
            i += 1 if value or flag not in skip else 2
        elif arg == "--":
            i += 1
        else:
            return eco, arg
    return None


def _is_local_spec(spec: str) -> bool:
    return spec.startswith((".", "/", "~", "file:")) or re.match(r"^[A-Za-z]:[\\/]", spec) is not None


def is_pinned(eco: str, spec: str) -> bool:
    if _is_local_spec(spec):
        return True
    if spec.startswith(("git+", "github:", "https://", "http://")):
        return re.search(r"[@#][0-9a-f]{7,40}$", spec) is not None
    if eco == "npm":
        m = re.match(r"^(?:@[^/]+/)?[^@]+@(.+)$", spec)
        return bool(m and re.match(r"^\d+\.\d+\.\d+", m.group(1)))
    return re.search(r"(?:==|@)\d+(?:\.\d+)+", spec) is not None


def package_name(eco: str, spec: str) -> str:
    if eco == "npm":
        m = re.match(r"^((?:@[^/]+/)?[^@]+)", spec)
        return m.group(1) if m else spec
    return re.split(r"[=<>!~@\[]", spec, maxsplit=1)[0]


def _edit_distance(a: str, b: str, limit: int = 2) -> int:
    if abs(len(a) - len(b)) > limit:
        return limit + 1
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        if min(cur) > limit:
            return limit + 1
        prev = cur
    return prev[-1]


def lookalike(name: str) -> str | None:
    """The well-known package this name is suspiciously close to, if any."""
    name = name.lower()
    if name in KNOWN_PACKAGES or len(name) < 8:
        return None
    for known in sorted(KNOWN_PACKAGES):
        if _edit_distance(name, known) <= 2:
            return known
    return None


def is_local_host(host: str) -> bool:
    host = (host or "").lower().strip("[]")
    return (
        host in {"localhost", "::1", "0.0.0.0", "host.docker.internal"}
        or host.endswith((".localhost", ".local", ".internal", ".lan"))
        or re.match(r"^(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)", host) is not None
    )


def _docker_image(tokens: list[str]) -> str | None:
    if "run" not in tokens:
        return None
    i = tokens.index("run") + 1
    while i < len(tokens):
        tok = tokens[i]
        if tok in DOCKER_VALUE_FLAGS:
            i += 2
        elif tok.startswith("-"):
            i += 1
        else:
            return tok
    return None


def extract_servers(data: object) -> list[tuple[str, dict, str]]:
    """Every server definition in a config, as (name, config, context)."""
    found: list[tuple[str, dict, str]] = []

    def add(block: object, context: str) -> None:
        if isinstance(block, dict):
            for name, cfg in block.items():
                if isinstance(cfg, dict):
                    found.append((str(name), cfg, context))

    if not isinstance(data, dict):
        return found
    for key in ("mcpServers", "servers", "context_servers", "mcp_servers"):
        add(data.get(key), "")
    if isinstance(data.get("mcp"), dict):
        add(data["mcp"].get("servers"), "")
    if isinstance(data.get("projects"), dict):
        for project, cfg in data["projects"].items():
            if isinstance(cfg, dict):
                add(cfg.get("mcpServers"), f"project {project}")
    return found


def command_tokens(cfg: dict) -> list[str]:
    """Normalise the ways clients spell a stdio command into one argv list."""
    command, args = cfg.get("command"), cfg.get("args") or []
    if isinstance(command, dict):  # Zed: {"command": {"path": ..., "args": [...]}}
        args = command.get("args") or args
        command = command.get("path")
    if isinstance(command, list):
        command, args = (command[0] if command else None), list(command[1:]) + list(args)
    if not isinstance(command, str) or not command.strip():
        return []
    if not isinstance(args, list):
        args = [args]
    if not args and " " in command.strip():
        try:
            return shlex.split(command)
        except ValueError:
            return command.split()
    return [command, *(str(a) for a in args)]


def safe_cmdline(tokens: list[str]) -> str:
    """The command line as one string, with credential-looking arguments masked."""
    shown: list[str] = []
    previous = ""
    for tok in tokens:
        flag, _, value = tok.partition("=")
        if find_tokens(tok):
            shown.append(mask(tok))
        elif flag.startswith("-") and value and looks_hardcoded(flag, value):
            shown.append(f"{flag}={mask(value)}")
        elif previous.startswith("-") and "=" not in previous and looks_hardcoded(previous, tok):
            shown.append(mask(tok))
        else:
            shown.append(tok)
        previous = tok
    return " ".join(shown)


def check_server(name: str, cfg: dict, context: str, path: Path, text: str,
                 home: Path | None = None) -> list[Finding]:
    findings: list[Finding] = []
    anchor = max(text.find(json.dumps(name)), text.find(f"mcp_servers.{name}"))
    label = f'server "{name}"' + (f" ({context})" if context else "")

    def add(rule_id: str, detail: str, evidence: str = "", needle: str = "",
            severity: Severity | None = None) -> None:
        pos = text.find(needle, max(anchor, 0)) if needle else -1
        line = line_at(text, pos if pos >= 0 else anchor) if max(pos, anchor) >= 0 else 1
        findings.append(Finding(RULES[rule_id], str(path), line, f"{label}: {detail}", evidence, severity))

    tokens = command_tokens(cfg)
    cmdline = safe_cmdline(tokens)
    env = cfg.get("env")
    if isinstance(cfg.get("command"), dict):
        env = cfg["command"].get("env") or env

    if tokens:
        behaviours = shellscan.analyze(cmdline)
        for rule_id, what in behaviours:
            add("GS-MCP-005" if rule_id == "GS-EXE-001" else rule_id, what, cmdline, tokens[0])
        base = _base(tokens[0])
        if base in SHELLS and any(t.lower() in SHELL_C_FLAGS for t in tokens[1:]) and not behaviours:
            add("GS-MCP-004", f"runs through {base} instead of invoking the server directly", cmdline, tokens[0])

        for i, tok in enumerate(tokens):
            if TEMP_PATH.match(tok) and (i == 0 or tok.lower().endswith(SCRIPT_EXT)):
                add("GS-MCP-006", f"executes {tok}", cmdline, tok)
                break

        spec = package_spec(tokens)
        if spec and not _is_local_spec(spec[1]):
            eco, raw = spec
            if not is_pinned(eco, raw):
                add("GS-MCP-001", f"{eco} package {raw} has no exact version", cmdline, raw)
            near = lookalike(package_name(eco, raw))
            if near:
                add("GS-MCP-009", f"{package_name(eco, raw)} is not {near}", raw, raw)

        if "filesystem" in cmdline.lower() or name.lower() in {"filesystem", "fs", "files"}:
            home_str = str(home).rstrip("/") if home else None
            for tok in tokens[1:]:
                bare = tok.rstrip("/") or "/"
                if bare in BROAD_ROOTS or tok in BROAD_ROOTS or (home_str and bare == home_str):
                    add("GS-MCP-007", f"grants access to {tok}", cmdline, tok)
                    break

        if base in {"docker", "podman", "nerdctl"}:
            danger = DOCKER_DANGER.search(cmdline)
            if danger:
                add("GS-MCP-008", f"uses {danger.group(0).strip()}", cmdline, tokens[0])
            image = _docker_image(tokens)
            if image and "@sha256:" not in image:
                tag = image.rsplit("/", 1)[-1].partition(":")[2]
                if tag in {"", "latest"}:
                    add("GS-MCP-010", f"image {image} is not pinned", image, image)

        for tok in tokens:
            if tok.lower().startswith(("http://", "ws://")) and not is_local_host(urlsplit(tok).hostname or ""):
                add("GS-MCP-003", f"connects to {urlsplit(tok).hostname} without TLS", tok, tok)
                break

    # Credentials: env, args, headers, URL.
    if isinstance(env, dict):
        for key, value in env.items():
            if not isinstance(value, str):
                continue
            tokens_found = find_tokens(value)
            if tokens_found and not is_reference(value):
                add("GS-MCP-002", f"{tokens_found[0][0]} in env {key}", f"{key}={mask(value)}", str(key))
            elif looks_hardcoded(str(key), value):
                add("GS-MCP-002", f"literal value in env {key}", f"{key}={mask(value)}", str(key))
    previous = ""
    for tok in tokens[1:]:
        hit = find_tokens(tok)
        flag, _, value = tok.partition("=")
        if hit:
            add("GS-MCP-002", f"{hit[0][0]} passed as a command-line argument", mask(tok[hit[0][1]:hit[0][2]]), tok)
        elif flag.startswith("-") and value and looks_hardcoded(flag, value):
            add("GS-MCP-002", f"literal value for {flag}", f"{flag}={mask(value)}", tok)
        elif previous.startswith("-") and "=" not in previous and looks_hardcoded(previous, tok):
            add("GS-MCP-002", f"literal value for {previous}", f"{previous} {mask(tok)}", tok)
        previous = tok
    headers = cfg.get("headers") or cfg.get("http_headers")
    if isinstance(headers, dict):
        for key, value in headers.items():
            if not isinstance(value, str) or is_reference(value):
                continue
            authish = str(key).lower() in {"authorization", "x-api-key", "api-key", "x-auth-token", "cookie"}
            if find_tokens(value) or ((authish or KEYISH.search(str(key))) and len(value.strip()) >= 8):
                add("GS-MCP-002", f"literal credential in header {key}", f"{key}: {mask(value)}", str(key))

    url = next((cfg[k] for k in ("url", "serverUrl", "httpUrl", "uri") if isinstance(cfg.get(k), str)), None)
    if url:
        parts = urlsplit(url)
        if parts.scheme in {"http", "ws"} and not is_local_host(parts.hostname or ""):
            add("GS-MCP-003", f"connects to {parts.hostname} without TLS", url, url)
        if find_tokens(url):
            add("GS-MCP-002", "credential embedded in the server URL", mask(url), url)
        else:
            for key, value in parse_qsl(parts.query):
                if looks_hardcoded(key, value):
                    add("GS-MCP-002", f"literal value in URL parameter {key}", f"{key}={mask(value)}", url)
    return findings


def check_config(data: object, path: Path, text: str, home: Path | None = None) -> list[Finding]:
    findings: list[Finding] = []
    for name, cfg, context in extract_servers(data):
        findings.extend(check_server(name, cfg, context, path, text, home))
    return findings
