"""CLI interface for DevGuard."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from devguard.engine import scan_repository
from devguard.models import GuardConfig, Severity
from devguard.reporters import render_html, render_json, render_text


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="devguard", description="Repository security and hygiene scanner")
    sub = parser.add_subparsers(dest="command", required=True)

    scan_p = sub.add_parser("scan", help="Scan a repository directory")
    scan_p.add_argument("path", nargs="?", default=".", help="Repository path to scan")
    scan_p.add_argument("--config", type=Path, default=None, help="Path to .devguard.toml config")
    scan_p.add_argument("--format", choices=["text", "json", "html"], default="text")
    scan_p.add_argument("--output", type=Path, default=None, help="Optional output file path")
    scan_p.add_argument("--plugin", type=Path, action="append", default=[], help="Custom Python plugin path")
    scan_p.add_argument(
        "--fail-on",
        choices=["low", "medium", "high", "critical", "none"],
        default="high",
        help="Minimum severity that causes a non-zero exit code",
    )

    args = parser.parse_args(argv)
    if args.command == "scan":
        root = Path(args.path)
        cfg = GuardConfig.load(root, args.config)
        result = scan_repository(root, cfg=cfg, plugin_paths=args.plugin)

        if args.format == "json":
            rendered = render_json(result)
        elif args.format == "html":
            rendered = render_html(result)
        else:
            rendered = render_text(result)

        if args.output:
            args.output.write_text(rendered, encoding="utf-8")
        else:
            print(rendered)

        if args.fail_on != "none" and result.has_findings_at_or_above(Severity.from_str(args.fail_on)):
            return 1
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
