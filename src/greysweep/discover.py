"""Find the files that shape an agent's behaviour, in a project and in the user's home."""
from __future__ import annotations

import fnmatch
import os
from dataclasses import dataclass
from pathlib import Path

SKIP_DIRS = {
    ".git", "node_modules", ".venv", "venv", "env", "__pycache__", "dist", "build", "target", ".next",
    ".nuxt", "vendor", "Pods", "DerivedData", ".tox", ".mypy_cache", ".pytest_cache", ".gradle",
    ".idea", "Intermediate", "Saved", "Binaries", ".Trash", "site-packages", ".cache",
}
TEXT_NAMES = {
    "CLAUDE.md", "CLAUDE.local.md", "AGENTS.md", "AGENTS.override.md", "GEMINI.md", "SKILL.md",
    ".cursorrules", ".windsurfrules", ".clinerules", "copilot-instructions.md",
}
MCP_NAMES = {".mcp.json", "mcp.json", "mcp_config.json", "claude_desktop_config.json"}
SCRIPT_EXT = {".sh", ".bash", ".zsh", ".py", ".js", ".mjs", ".cjs", ".ts", ".ps1", ".rb"}
TEXT_EXT = {".md", ".mdc", ".markdown", ".txt"}
AGENT_HOMES = {".claude", ".cursor", ".codex", ".gemini", ".windsurf", ".roo", ".cline", ".agents", ".github", ".continue"}
AGENT_DIRS = {"skills", "agents", "commands", "rules", "prompts", "hooks", "instructions", "workflows-agent"}

MAX_DEPTH = 7
MAX_FILE_BYTES = 1_000_000
MAX_CONFIG_BYTES = 30_000_000
MAX_TARGETS = 5000


@dataclass(frozen=True)
class Target:
    path: Path
    kind: str   # mcp | settings | hooks | codex | text | script
    scope: str  # project | user


def _in_agent_dir(parts: tuple[str, ...], plugin_root: bool) -> bool:
    """True for files under e.g. .claude/skills/ or .cursor/rules/ at any depth."""
    for i, part in enumerate(parts[:-1]):
        if part in AGENT_HOMES and any(p in AGENT_DIRS for p in parts[i + 1 : -1]):
            return True
    return plugin_root and parts[0] in AGENT_DIRS


def classify(parts: tuple[str, ...], in_skill: bool, plugin_root: bool = False) -> str | None:
    name = parts[-1]
    parent = parts[-2] if len(parts) > 1 else ""
    suffix = os.path.splitext(name)[1].lower()
    if name in MCP_NAMES:
        return "mcp"
    if parent == ".claude" and name in {"settings.json", "settings.local.json"}:
        return "settings"
    if parent == ".codex" and name == "config.toml":
        return "codex"
    if name == "hooks.json":
        return "hooks"
    if name in TEXT_NAMES:
        return "text"
    if in_skill or _in_agent_dir(parts, plugin_root):
        if suffix in TEXT_EXT:
            return "text"
        if suffix in SCRIPT_EXT:
            return "script"
    return None


def _load_ignore(root: Path) -> list[str]:
    try:
        lines = (root / ".greysweepignore").read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    return [ln.strip() for ln in lines if ln.strip() and not ln.lstrip().startswith("#")]


def _ignored(rel: str, patterns: list[str]) -> bool:
    for pattern in patterns:
        if pattern.endswith("/") and (rel.startswith(pattern) or f"/{pattern}" in f"/{rel}"):
            return True
        if fnmatch.fnmatch(rel, pattern) or fnmatch.fnmatch(os.path.basename(rel), pattern):
            return True
    return False


def walk(root: Path, base: Path, scope: str, max_depth: int = MAX_DEPTH,
         use_ignore: bool = True, skipped: list[Path] | None = None) -> list[Target]:
    """Collect targets under root. Paths are classified relative to base.

    Files excluded by .greysweepignore are appended to ``skipped`` so a report can
    say so: a repository must not be able to hide files from the scan silently.
    """
    targets: list[Target] = []
    if not root.is_dir():
        return targets
    ignore = _load_ignore(base) if use_ignore else []
    plugin_root = (base / ".claude-plugin").is_dir()
    skill_roots: list[str] = []
    for current, dirs, files in os.walk(root, followlinks=False):
        rel_dir = os.path.relpath(current, base)
        depth = 0 if rel_dir == "." else rel_dir.count(os.sep) + 1
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS) if depth < max_depth else []
        if "SKILL.md" in files:
            skill_roots.append(current + os.sep)
        in_skill = any((current + os.sep).startswith(r) for r in skill_roots)
        for name in sorted(files):
            rel = name if rel_dir == "." else os.path.join(rel_dir, name)
            kind = classify(tuple(Path(rel).parts), in_skill, plugin_root)
            if kind is None:
                continue
            path = Path(current) / name
            if _ignored(Path(rel).as_posix(), ignore):
                if skipped is not None:
                    skipped.append(path)
                continue
            try:
                if path.stat().st_size > MAX_FILE_BYTES:
                    continue
            except OSError:
                continue
            targets.append(Target(path, kind, scope))
            if len(targets) >= MAX_TARGETS:
                return targets
    return targets


def user_targets(home: Path) -> list[Target]:
    """Per-user agent configuration: client configs, global instructions, installed skills/plugins."""
    fixed = [
        (".claude.json", "mcp"),
        (".claude/settings.json", "settings"),
        (".claude/settings.local.json", "settings"),
        (".claude/CLAUDE.md", "text"),
        ("Library/Application Support/Claude/claude_desktop_config.json", "mcp"),
        (".config/Claude/claude_desktop_config.json", "mcp"),
        ("AppData/Roaming/Claude/claude_desktop_config.json", "mcp"),
        (".cursor/mcp.json", "mcp"),
        (".codeium/windsurf/mcp_config.json", "mcp"),
        (".gemini/settings.json", "mcp"),
        (".gemini/GEMINI.md", "text"),
        ("Library/Application Support/Code/User/mcp.json", "mcp"),
        (".config/Code/User/mcp.json", "mcp"),
        (".config/zed/settings.json", "mcp"),
        (".lmstudio/mcp.json", "mcp"),
        (".codex/config.toml", "codex"),
        (".codex/AGENTS.md", "text"),
    ]
    targets: list[Target] = []
    for rel, kind in fixed:
        path = home / rel
        try:
            if path.is_file() and path.stat().st_size <= MAX_CONFIG_BYTES:
                targets.append(Target(path, kind, "user"))
        except OSError:
            continue
    # plugins/cache holds what is installed; plugins/marketplaces is only the catalogue it came from.
    for rel in (".claude/skills", ".claude/agents", ".claude/commands", ".claude/rules", ".claude/plugins/cache",
                ".codex/skills", ".codex/prompts", ".cursor/rules", ".agents/skills", ".gemini/extensions"):
        targets.extend(walk(home / rel, home, "user", max_depth=10))
    return targets


def discover(project: Path | None, home: Path | None, use_ignore: bool = True,
             skipped: list[Path] | None = None) -> list[Target]:
    seen: set[Path] = set()
    ordered: list[Target] = []
    found: list[Target] = []
    if project is not None and (home is None or project.resolve() != home.resolve()):
        found += walk(project, project, "project", use_ignore=use_ignore, skipped=skipped)
    if home is not None:
        found += user_targets(home)
    for target in found:
        try:
            key = target.path.resolve()
        except OSError:
            key = target.path
        if key not in seen:
            seen.add(key)
            ordered.append(target)
    return ordered
