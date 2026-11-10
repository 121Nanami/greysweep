"""Command line interface: greysweep scan | rules | demo."""
from __future__ import annotations

import argparse
import os
import sys
import tempfile
from pathlib import Path

from . import __version__
from .core import Severity
from .report import render
from .rules import RULES
from .scan import Options, Result, scan

COMMANDS = {"scan", "rules", "demo"}
SEVERITIES = [sev.label for sev in sorted(Severity, reverse=True)]


def _fail(message: str) -> int:
    print(f"greysweep: {message}", file=sys.stderr)
    return 2


def _add_output_args(parser: argparse.ArgumentParser) -> None:
    out = parser.add_argument_group("output")
    out.add_argument("-f", "--format", choices=["tty", "json", "sarif", "html"], default="tty",
                     help="report format (default: tty)")
    out.add_argument("-o", "--output", metavar="FILE", help="write the report to FILE instead of stdout")
    out.add_argument("-v", "--verbose", action="store_true", help="explain why each finding matters")
    out.add_argument("--no-color", action="store_true", help="plain terminal output")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="greysweep",
        description="Audit the attack surface of your AI coding agents: MCP servers, agent settings, "
                    "hooks, skills and instruction files. Static, local and read-only unless --live is given.")
    parser.add_argument("--version", action="version", version=f"greysweep {__version__}")
    sub = parser.add_subparsers(dest="command", metavar="{scan,rules,demo}")

    s = sub.add_parser("scan", help="scan a project and your user-level agent configuration (default)")
    s.add_argument("path", nargs="?", default=".", help="project directory (default: current directory)")
    s.add_argument("--no-user", action="store_true", help="skip user-level configuration in the home directory")
    s.add_argument("--no-project", action="store_true", help="skip the project directory")
    s.add_argument("--home", metavar="DIR", help="treat DIR as the home directory")
    s.add_argument("--fail-on", choices=[*SEVERITIES, "none"], default="high",
                   help="exit 1 when a finding of this severity or worse is reported (default: high)")
    s.add_argument("--min-severity", choices=SEVERITIES, default="info", help="hide findings below this severity")
    s.add_argument("--ignore", action="append", default=[], metavar="RULES",
                   help="comma-separated rule IDs to leave out; repeatable")
    s.add_argument("--no-ignore", action="store_true",
                   help="disregard .greysweepignore and inline greysweep:ignore markers")
    live = s.add_argument_group("live inspection (starts the configured server commands)")
    live.add_argument("--live", action="store_true",
                      help="start stdio MCP servers and inspect the tool definitions they send to the model")
    live.add_argument("--live-server", action="append", default=[], metavar="NAME",
                      help="only start this server; repeatable; implies --live")
    live.add_argument("--repin", action="store_true", help="accept current tool definitions as the new baseline")
    live.add_argument("--timeout", type=float, default=15.0, metavar="SECONDS", help="per-server limit (default: 15)")
    _add_output_args(s)

    r = sub.add_parser("rules", help="list the rules, or explain one")
    r.add_argument("rule", nargs="?", metavar="ID", help="rule to explain, e.g. GS-MCP-001")

    d = sub.add_parser("demo", help="write a deliberately unsafe example project and scan it")
    d.add_argument("dir", nargs="?", help="where to write the example (default: a new temporary directory)")
    d.add_argument("--no-live", action="store_true", help="do not start the example MCP server")
    _add_output_args(d)
    return parser


def _emit(result: Result, args: argparse.Namespace) -> None:
    color = (args.format == "tty" and not args.output and not args.no_color
             and "NO_COLOR" not in os.environ and sys.stdout.isatty())
    text = render(result, args.format, color=color, verbose=args.verbose)
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
        summary = ", ".join(f"{n} {label}" for label, n in result.counts().items() if n) or "no findings"
        print(f"greysweep: grade {result.grade} ({summary}); report written to {args.output}", file=sys.stderr)
    else:
        sys.stdout.write(text)


def cmd_scan(args: argparse.Namespace) -> int:
    project = None if args.no_project else Path(args.path).expanduser().resolve()
    if project is not None and not project.is_dir():
        return _fail(f"not a directory: {args.path}")
    home = None
    if not args.no_user:
        home = (Path(args.home).expanduser() if args.home else Path.home()).resolve()
        if not home.is_dir():
            return _fail(f"not a directory: {home}")
    if project is None and home is None:
        return _fail("nothing to scan: --no-project and --no-user together")
    ignore = {rule.strip().upper() for chunk in args.ignore for rule in chunk.split(",") if rule.strip()}
    unknown = sorted(ignore - RULES.keys())
    if unknown:
        return _fail(f"unknown rule ID: {', '.join(unknown)} (see `greysweep rules`)")

    result = scan(Options(
        project=project, home=home, ignore_rules=frozenset(ignore),
        min_severity=Severity.parse(args.min_severity), honour_ignores=not args.no_ignore,
        live=args.live or bool(args.live_server), live_servers=frozenset(args.live_server),
        repin=args.repin, timeout=args.timeout))
    _emit(result, args)
    worst = result.worst()
    if args.fail_on != "none" and worst is not None and worst >= Severity.parse(args.fail_on):
        return 1
    return 0


def cmd_rules(args: argparse.Namespace) -> int:
    if args.rule:
        rule = RULES.get(args.rule.upper())
        if rule is None:
            return _fail(f"unknown rule ID: {args.rule}")
        print(f"{rule.id}  {rule.severity.label}\n{rule.title}\n\nWhy: {rule.why}\n\nFix: {rule.fix}")
        return 0
    for rule in RULES.values():
        print(f"{rule.id:<12} {rule.severity.label:<9} {rule.title}")
    return 0


def cmd_demo(args: argparse.Namespace) -> int:
    from .demo import MARKER, write_demo

    if args.dir:
        root = Path(args.dir).expanduser().resolve()
        if root.exists() and (not root.is_dir() or (any(root.iterdir()) and not (root / MARKER).exists())):
            return _fail(f"{root} exists and is not an earlier greysweep demo; choose an empty directory")
    else:
        root = Path(tempfile.mkdtemp(prefix="greysweep-demo-")).resolve()
    project, home = write_demo(root)
    result = scan(Options(project=project, home=home, honour_ignores=False,
                          live=not args.no_live, live_servers=frozenset({"weather"})))
    _emit(result, args)
    print(f"\ngreysweep: example written to {root}\n"
          "greysweep: every file in it is a harmless imitation of a real attack; delete the directory when done.",
          file=sys.stderr)
    return 0


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] not in COMMANDS | {"-h", "--help", "--version"}:
        argv.insert(0, "scan")
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")
    args = build_parser().parse_args(argv)
    try:
        return {"scan": cmd_scan, "rules": cmd_rules, "demo": cmd_demo}[args.command](args)
    except BrokenPipeError:
        return 0
    except KeyboardInterrupt:
        return 130
