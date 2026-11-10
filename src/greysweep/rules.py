"""The rule catalogue. Every finding greysweep reports points at one of these."""
from __future__ import annotations

from .core import Rule, Severity

RULES: dict[str, Rule] = {}

C, H, M, L, I = Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO


def _rule(id: str, severity: Severity, title: str, why: str, fix: str) -> None:
    RULES[id] = Rule(id, severity, title, why, fix)


# --- MCP servers -----------------------------------------------------------
_rule("GS-MCP-001", M, "Unpinned MCP server package",
      "The launcher fetches whatever version is newest each time the agent starts. A hijacked or "
      "malicious release runs on your machine with your credentials, with no review step.",
      "Pin an exact version (npx pkg@1.2.3, uvx pkg==1.2.3) and upgrade deliberately.")
_rule("GS-MCP-002", H, "Hardcoded credential in MCP config",
      "Config files get committed, synced, backed up and read by every tool on the machine. "
      "A literal token here is one accidental push away from being public.",
      "Move the value to an environment variable or secret manager and reference it (${VAR}). "
      "Rotate the exposed credential.")
_rule("GS-MCP-003", H, "MCP server reached over plaintext HTTP",
      "Tool calls, results and auth headers travel unencrypted. Anyone on the network path can "
      "read them or inject tool output that the agent will trust.",
      "Use https:// (or a local stdio server).")
_rule("GS-MCP-004", M, "MCP server launched through a shell",
      "Wrapping the server in sh -c hides what actually runs and makes the entry sensitive to "
      "shell expansion and injection through arguments.",
      "Invoke the server binary directly with an args array.")
_rule("GS-MCP-005", C, "MCP server downloads and executes remote code",
      "The entry pipes a download straight into an interpreter. Whoever controls that URL, or the "
      "network path to it, controls your machine every time the agent starts.",
      "Remove the entry. Install the server from a pinned, reviewed package instead.")
_rule("GS-MCP-006", H, "MCP server runs from a transient or shared-writable path",
      "Files under /tmp or Downloads can be replaced by any local process or a later download. "
      "The agent will execute whatever is there.",
      "Move the server into a directory only you can write, or install it as a pinned package.")
_rule("GS-MCP-007", H, "Filesystem server exposes home or root",
      "The agent, and anything that prompt-injects it, can read SSH keys, cloud credentials and "
      "browser data, and write anywhere.",
      "Scope the server to the specific project directories it needs.")
_rule("GS-MCP-008", H, "Container isolation disabled for MCP server",
      "Privileged mode, host networking, the Docker socket or a root/home mount hand the "
      "container the host. The sandbox is decorative.",
      "Drop the flag; mount only the directories the server needs, read-only where possible.")
_rule("GS-MCP-009", H, "Package name resembles a well-known MCP server",
      "Typosquatted packages copy popular names one character off and ship malware. This name is "
      "close to, but not the same as, a widely used server.",
      "Verify the package name against the official source before running it.")
_rule("GS-MCP-010", L, "Unpinned container image",
      "A mutable tag (or none) means the image can change under you between runs.",
      "Pin the image by digest (image@sha256:…) or at least an exact version tag.")

# --- Agent settings --------------------------------------------------------
_rule("GS-CFG-001", H, "Permission prompts disabled",
      "With approval bypassed, every tool call runs unreviewed. One poisoned web page, README or "
      "tool result is enough to run arbitrary commands.",
      "Remove the bypass. Allow specific commands instead of everything.")
_rule("GS-CFG-002", H, "Unrestricted shell access pre-approved",
      "A blanket Bash allow rule approves any command, including ones an attacker plants through "
      "prompt injection.",
      "Replace it with narrow rules for the commands you actually use, e.g. Bash(npm run test:*).")
_rule("GS-CFG-003", M, "Interpreter or network tool pre-approved with a wildcard",
      "Wildcards on curl, bash, python, ssh and similar are equivalent to arbitrary code execution "
      "or data exfiltration without a prompt.",
      "Narrow the rule to exact subcommands, or drop it and approve case by case.")
_rule("GS-CFG-004", H, "Sensitive paths readable or writable without a prompt",
      "The allow list covers credential stores or your whole home directory, so a hijacked agent "
      "can read keys silently.",
      "Remove the rule and add a deny rule for credential paths.")
_rule("GS-CFG-005", H, "Repository MCP servers auto-approved",
      "Any repo you open can ship a .mcp.json; with auto-approval its servers start without asking, "
      "which is code execution on clone.",
      "Set enableAllProjectMcpServers to false and approve servers per project.")
_rule("GS-CFG-006", C, "Model API traffic redirected to a third-party host",
      "A base-URL or proxy override sends your prompts, code and API key to that host. Set from a "
      "repository, it steals the key of everyone who opens the project.",
      "Remove the override unless it is a gateway you operate; never accept it from a repo.")
_rule("GS-CFG-007", H, "Repository-supplied command runs automatically",
      "Helper commands in shared project settings execute on your machine when you open the "
      "project, before you have reviewed anything.",
      "Remove it from project settings; keep helpers in user-level settings you control.")
_rule("GS-CFG-008", H, "Hardcoded credential in agent settings",
      "Settings files are shared, synced and often committed. A literal secret here leaks with them.",
      "Reference an environment variable or use a credential helper. Rotate the exposed value.")
_rule("GS-CFG-009", H, "Agent config is writable by other users",
      "Anyone who can write this file can add an MCP server, hook or instruction that runs as you.",
      "chmod go-w the file and its directory.")
_rule("GS-CFG-010", L, "File holding secrets is readable by other users",
      "Other accounts and processes on this machine can read the credentials stored here.",
      "chmod 600 the file.")
_rule("GS-CFG-011", H, "Codex sandbox disabled",
      "danger-full-access removes filesystem and network confinement; combined with "
      "approval_policy = never the agent can do anything with no review.",
      "Use workspace-write with approvals, and widen access only per task.")
_rule("GS-CFG-012", I, "Config file could not be parsed",
      "greysweep could not read this file, so nothing in it was checked.",
      "Fix the syntax error and re-run.")

# --- Hooks -----------------------------------------------------------------
_rule("GS-HOOK-001", M, "Repository ships agent hooks",
      "Hooks are shell commands that run automatically around tool calls. Shipped in a repo, they "
      "run on every contributor's machine.",
      "Read each hook command. Keep only those you would run by hand.")
_rule("GS-HOOK-002", M, "Hook makes network calls",
      "A hook that talks to the network on every tool call is a ready-made exfiltration channel "
      "for prompts, file paths and code.",
      "Confirm the destination and payload, or remove the hook.")

# --- Shell behaviour, wherever it appears ------------------------------------
_rule("GS-EXE-001", H, "Downloads a script and pipes it into an interpreter",
      "curl | sh runs whatever the server returns at that moment. When an agent follows this "
      "instruction, nobody reads the script first.",
      "Download, review and pin the script, or install from a package manager.")
_rule("GS-EXE-002", H, "Decodes and executes an obfuscated payload",
      "Base64-then-execute hides what runs from reviewers and scanners. Legitimate tooling rarely "
      "needs it.",
      "Replace it with the plain commands it decodes to, or remove it.")
_rule("GS-EXE-003", C, "Sends credentials or environment secrets over the network",
      "The command reads key material or the environment and transmits it to a remote host. That "
      "is the shape of credential theft.",
      "Remove it. If any of this ran, rotate the credentials it touched.")

# --- Instruction, skill and rule files --------------------------------------
_rule("GS-TXT-001", C, "Invisible Unicode payload",
      "Unicode tag or variation-selector characters render as nothing in editors and diffs, but "
      "the model reads them as text. This is how instructions are smuggled past human review.",
      "Delete the invisible characters. Treat the file's source as compromised.")
_rule("GS-TXT-002", H, "Bidirectional override characters",
      "Bidi controls reorder how text is displayed, so what you review is not what the model or "
      "interpreter receives (the Trojan Source technique).",
      "Remove the control characters.")
_rule("GS-TXT-003", M, "Zero-width characters",
      "Zero-width characters can hide or split keywords so that filters and reviewers miss them.",
      "Strip them unless the text genuinely needs them.")
_rule("GS-TXT-010", H, "Instruction-override phrase",
      "Text that tells the agent to drop its prior instructions is the classic prompt-injection "
      "opener. In a file the agent loads automatically, it executes with your trust.",
      "Remove it, and check how it got into the file.")
_rule("GS-TXT-011", H, "Tells the agent to hide actions from the user",
      "Legitimate instructions do not need secrecy. A directive to conceal behaviour from the "
      "person at the keyboard is a strong sign of malicious intent.",
      "Remove it and review everything else the file asks for.")
_rule("GS-TXT-012", M, "Tells the agent to skip confirmation",
      "Instructions that waive approval prompts widen what a hijacked agent can do unreviewed.",
      "Make sure you wrote this and that its scope is as narrow as you intend.")
_rule("GS-TXT-013", M, "Agent-directed text hidden in an HTML comment",
      "HTML comments vanish when Markdown is rendered, so reviewers never see them, but the agent "
      "reads the raw file.",
      "Move the instruction into visible text or delete it.")
_rule("GS-TXT-020", M, "Image URL with a templated query string",
      "Asking the agent to render an image whose URL embeds data is a zero-click exfiltration "
      "channel: the fetch delivers the data to the host.",
      "Remove the templated image.")
_rule("GS-TXT-030", H, "Credential in an instruction or skill file",
      "These files are loaded into model context and commonly committed, so the secret reaches "
      "the model provider and your repo history.",
      "Remove and rotate the credential; pass it through the environment.")
_rule("GS-TXT-040", M, "Skill grants itself unrestricted shell",
      "allowed-tools: Bash pre-approves any command while the skill is active, so the skill's "
      "text decides what runs on your machine.",
      "Scope it, e.g. Bash(git status:*), or drop it so commands prompt normally.")

# --- Live probing (--live) --------------------------------------------------
_rule("GS-LIVE-001", C, "Tool description poisoning",
      "The server's tool metadata contains instructions aimed at the model. Tool descriptions are "
      "injected into context verbatim and are never shown to you.",
      "Disconnect the server and report it.")
_rule("GS-LIVE-002", H, "Tool definition changed since it was pinned",
      "A server that passes review and later rewrites its tool descriptions is the 'rug pull' "
      "pattern. The change may be benign, but nobody approved it.",
      "Diff the new definition; if expected, accept it with --repin.")
_rule("GS-LIVE-003", I, "Server was not probed",
      "greysweep could not, or chose not to, start this server, so its tool descriptions were not "
      "inspected.",
      "Resolve the static findings or the startup error, then re-run with --live.")
