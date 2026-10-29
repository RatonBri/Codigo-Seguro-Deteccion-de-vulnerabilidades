from __future__ import annotations

import argparse
import itertools
import sys
import threading
from pathlib import Path

from . import __version__
from .core import (
    SEVERITY_ORDER,
    deduplicate,
    iter_source_files,
)
from .dependencies import check_osv, collect_dependencies
from .detectors import scan_source
from .httpcheck import check_http
from .reports import write_reports

CATEGORIES = {
    "code", "secrets", "config",
    "anomaly", "dependencies", "http",
}


class Spinner:
    def __init__(self, message: str, enabled: bool = True):
        self.message = message
        self.enabled = enabled and sys.stderr.isatty()
        self.done = threading.Event()
        self.thread = None

    def _animate(self):
        for symbol in itertools.cycle("|/-\\"):
            if self.done.wait(0.12):
                break

            print(
                f"\r{symbol} {self.message}",
                end="",
                file=sys.stderr,
                flush=True,
            )

    def __enter__(self):
        if self.enabled:
            self.thread = threading.Thread(
                target=self._animate,
                daemon=True,
            )
            self.thread.start()
        return self

    def __exit__(self, exc_type, exc, traceback):
        self.done.set()

        if self.thread is not None:
            self.thread.join()
            print(
                "\r" + " " * (len(self.message) + 4) + "\r",
                end="",
                file=sys.stderr,
                flush=True,
            )


def _parse_categories(value: str) -> set[str]:
    selected = {
        part.strip().lower()
        for part in value.split(",")
        if part.strip()
    }

    if "all" in selected:
        return CATEGORIES.copy()

    unknown = selected - CATEGORIES
    if unknown:
        raise ValueError(
            f"Unknown categories: {', '.join(sorted(unknown))}"
        )

    if not selected:
        raise ValueError("At least one category is required.")

    return selected


def _interactive(args):
    if not sys.stdin.isatty():
        print(
            "Interactive mode requires a terminal.",
            file=sys.stderr,
        )
        return

    print("\nVibeShield interactive scan")
    print("---------------------------")

    level = input(
        f"Level [quick/standard/deep] ({args.level}): "
    ).strip().lower()

    if level in {"quick", "standard", "deep"}:
        args.level = level

    category = input(
        f"Categories [all/code/secrets/config/"
        f"anomaly/dependencies/http] ({args.category}): "
    ).strip()

    if category:
        args.category = category

    output = input(
        f"Output directory ({args.output}): "
    ).strip()

    if output:
        args.output = output


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vibeshield",
        description=(
            "Defensive security scanner for AI-assisted web apps."
        ),
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"VibeShield {__version__}",
    )

    subcommands = parser.add_subparsers(
        dest="command", required=True
    )

    scan = subcommands.add_parser(
        "scan",
        help="Scan a local source directory.",
    )

    scan.add_argument(
        "path", nargs="?", default=".",
        help="Directory to scan.",
    )
    scan.add_argument(
        "--level",
        choices=["quick", "standard", "deep"],
        default="standard",
    )
    scan.add_argument(
        "--category",
        default="all",
        help="Comma-separated categories or 'all'.",
    )
    scan.add_argument(
        "--rules",
        default="",
        help="Optional comma-separated rule IDs, e.g. VS001,VS003.",
    )
    scan.add_argument(
        "--max-files", type=int, default=2500
    )
    scan.add_argument(
        "--max-findings", type=int, default=500
    )
    scan.add_argument(
        "--format",
        choices=["all", "json", "html", "md", "sarif"],
        default="all",
    )
    scan.add_argument(
        "--output", default="reports"
    )
    scan.add_argument(
        "--osv",
        action="store_true",
        help="Opt in to OSV dependency queries.",
    )
    scan.add_argument(
        "--osv-limit", type=int, default=30
    )
    scan.add_argument(
        "--http-url",
        action="append",
        default=[],
        help="URL to check using HEAD only. Repeatable.",
    )
    scan.add_argument(
        "--allow-host",
        action="append",
        default=[],
        help="Explicitly authorized remote hostname. Repeatable.",
    )
    scan.add_argument(
        "--interactive", action="store_true"
    )
    scan.add_argument(
        "--quiet", action="store_true"
    )
    scan.add_argument(
        "--fail-on",
        choices=[
            "none", "low", "medium", "high", "critical"
        ],
        default="none",
        help="Exit with status 1 when threshold is reached.",
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command != "scan":
        parser.error("Unknown command.")

    if args.interactive:
        _interactive(args)

    if (
        args.max_files < 1
        or args.max_findings < 1
        or args.osv_limit < 1
    ):
        parser.error("Limits must be positive integers.")

    try:
        categories = _parse_categories(args.category)
    except ValueError as exc:
        parser.error(str(exc))

    root = Path(args.path).expanduser().resolve()

    if not root.is_dir():
        parser.error(
            f"Not a directory: {root}"
        )

    selected_rules = {
        item.strip().upper()
        for item in args.rules.split(",")
        if item.strip()
    }

    findings = []
    warnings = []

    with Spinner("Discovering source files", not args.quiet):
        files = list(
            iter_source_files(root, args.max_files)
        )

    source_categories = {
        "code", "secrets", "config", "anomaly"
    }

    if categories & source_categories:
        with Spinner("Analyzing source code", not args.quiet):
            for path in files:
                findings.extend(
                    f for f in scan_source(
                        path, root, args.level
                    )
                    if f.category in categories
                )

    if "dependencies" in categories and args.osv:
        dependencies = collect_dependencies(files, root)

        with Spinner("Checking OSV advisories", not args.quiet):
            osv_findings, osv_warnings = check_osv(
                dependencies,
                max_queries=args.osv_limit,
            )

        findings.extend(osv_findings)
        warnings.extend(osv_warnings)

    if "dependencies" in categories and not args.osv:
        warnings.append(
            "OSV dependency queries disabled. "
            "Use --osv to enable them."
        )

    if "http" in categories:
        for url in args.http_url:
            try:
                http_findings, http_warnings = check_http(
                    url,
                    allowed_hosts=args.allow_host,
                )
                findings.extend(http_findings)
                warnings.extend(http_warnings)
            except ValueError as exc:
                warnings.append(
                    f"HTTP target rejected: {exc}"
                )

    if selected_rules:
        findings = [
            f for f in findings
            if f.rule_id in selected_rules
        ]

    findings = deduplicate(findings)

    if len(findings) > args.max_findings:
        warnings.append(
            f"Results truncated to {args.max_findings} findings."
        )
        findings = findings[:args.max_findings]

    output = Path(args.output).expanduser().resolve()

    created = write_reports(
        findings,
        warnings,
        output,
        args.format,
    )

    counts = {
        severity: sum(
            f.severity == severity for f in findings
        )
        for severity in (
            "critical", "high", "medium", "low"
        )
    }

    print("\nVibeShield 0.2")
    print("=" * 42)
    print(f"Files discovered : {len(files)}")
    print(f"Findings         : {len(findings)}")
    print(f"Critical         : {counts['critical']}")
    print(f"High             : {counts['high']}")
    print(f"Medium           : {counts['medium']}")
    print(f"Low              : {counts['low']}")
    print(
        "Hypotheses       : "
        f"{sum(f.hypothesis for f in findings)}"
    )

    print("\nGenerated reports:")
    for path in created:
        print(f"  {path}")

    print(
        f"  {output / 'remediation-prompts'}"
    )

    if warnings:
        print("\nWarnings:")
        for warning in warnings[:10]:
            print(f"  - {warning}")

    if args.fail_on != "none":
        threshold = SEVERITY_ORDER[args.fail_on]
        if any(
            SEVERITY_ORDER[f.severity] >= threshold
            for f in findings
        ):
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())