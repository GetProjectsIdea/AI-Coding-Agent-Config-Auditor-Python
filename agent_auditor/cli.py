"""Command-line interface:  python -m agent_auditor <folder | --clone URL>"""
from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

from . import __version__
from .models import Severity
from .report import to_json, to_markdown, to_text
from .demo import build_risky_repo
from .safe_clone import safe_clone
from .scanner import scan_path


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="agent-audit",
        description="Flag risky AI coding-agent files (AGENTS.md, CLAUDE.md, hooks, MCP configs) "
                    "in a repo before you open it with an AI assistant. Read-only.")
    p.add_argument("path", nargs="?", help="Folder to scan (a repo you already cloned)")
    p.add_argument("--clone", metavar="URL", help="Shallow-clone a GitHub/GitLab URL safely, scan it, then delete it")
    p.add_argument("--demo", action="store_true", help="Build the harmless risky demo repo in a temp folder and scan it")
    p.add_argument("--keep", action="store_true", help="With --clone, keep the cloned copy")
    p.add_argument("-f", "--format", choices=["text", "json", "markdown"], default="text")
    p.add_argument("-o", "--output", help="Write the report to a file")
    p.add_argument("--min-severity", default="info", help="Hide findings below this level")
    p.add_argument("--fail-on", default="high",
                   help="Exit with code 1 if any finding is at or above this level (default: high)")
    p.add_argument("--show-info", action="store_true", help="Also print INFO findings in text mode")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    if not args.path and not args.clone and not args.demo:
        build_parser().print_help()
        return 2
    cloned = None
    try:
        target = args.path
        if args.demo:
            cloned = build_risky_repo()
            target = str(cloned)
        elif args.clone:
            cloned = safe_clone(args.clone)
            target = str(cloned)
        result = scan_path(target, Severity.parse(args.min_severity))
    except (ValueError, NotADirectoryError, KeyError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    finally:
        if cloned and not args.keep:
            shutil.rmtree(cloned.parent, ignore_errors=True)
    if args.demo:
        result.root = "demo:risky-repo"
    elif args.clone:
        result.root = args.clone
    if args.format == "json":
        report = to_json(result)
    elif args.format == "markdown":
        report = to_markdown(result)
    else:
        color = not args.no_color and not args.output and sys.stdout.isatty()
        report = to_text(result, color=color, show_info=args.show_info)
    if args.output:
        Path(args.output).write_text(report, encoding="utf-8")
        print(f"Report written to {args.output} (verdict: {result.verdict}, score {result.risk_score}/100)")
    else:
        print(report)
    return 1 if result.max_severity >= Severity.parse(args.fail_on) and result.findings else 0


if __name__ == "__main__":
    sys.exit(main())
