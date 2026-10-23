"""Command line interface for dockerfile-doctor."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import List, Optional, Set

from dockerfile_doctor import __version__
from dockerfile_doctor.fixer import fix_dockerfile, fix_dockerfile_content
from dockerfile_doctor.linter import lint_dockerfile, lint_dockerfile_content
from dockerfile_doctor.models import Diagnostic, Severity
from dockerfile_doctor.reporter import (
    format_fix_report,
    format_json_diagnostics,
    format_sarif,
    format_text_diagnostics,
    format_text_scan,
)
from dockerfile_doctor.scanner import scan_dockerfile, scan_dockerfile_content


def _parse_rule_set(rule_str: Optional[str]) -> Optional[Set[str]]:
    if not rule_str:
        return None
    return {r.strip().upper() for r in rule_str.split(",") if r.strip()}


def _resolve_paths(paths: List[str]) -> List[Path]:
    """Resolve file or directory paths to target Dockerfile paths."""
    resolved: List[Path] = []
    if not paths:
        paths = ["Dockerfile"]

    for p_str in paths:
        if p_str == "-":
            # Stdin indicator
            continue
        p = Path(p_str)
        if p.is_dir():
            # Check for Dockerfile in directory
            df = p / "Dockerfile"
            if df.is_file():
                resolved.append(df)
            else:
                for sub in p.glob("Dockerfile*"):
                    if sub.is_file():
                        resolved.append(sub)
        elif p.is_file():
            resolved.append(p)
        else:
            # File might not exist yet or specific name
            resolved.append(p)

    return resolved


def handle_lint(args: argparse.Namespace) -> int:
    """Execute lint subcommand."""
    include_rules = _parse_rule_set(args.include)
    ignore_rules = _parse_rule_set(args.ignore)

    fail_severity = Severity.from_string(args.fail_on)
    if args.strict:
        fail_severity = Severity.INFO

    # Read from stdin if '-' passed
    if "-" in args.paths:
        content = sys.stdin.read()
        diagnostics = lint_dockerfile_content(
            content, include_rules=include_rules, ignore_rules=ignore_rules
        )
        if args.format == "json":
            print(format_json_diagnostics(diagnostics, file_path="<stdin>"))
        elif args.format == "sarif":
            print(format_sarif(diagnostics, file_path="<stdin>"))
        else:
            print(format_text_diagnostics(diagnostics, file_path="<stdin>"))

        has_failure = any(d.severity.level >= fail_severity.level for d in diagnostics)
        return 1 if has_failure else 0

    target_paths = _resolve_paths(args.paths)
    if not target_paths:
        print("Error: No Dockerfile found in specified path(s).", file=sys.stderr)
        return 2

    overall_failure = False

    for path in target_paths:
        if not path.exists():
            print(f"Error: File not found: {path}", file=sys.stderr)
            return 2

        diagnostics = lint_dockerfile(
            path, include_rules=include_rules, ignore_rules=ignore_rules
        )

        if args.format == "json":
            print(format_json_diagnostics(diagnostics, file_path=str(path)))
        elif args.format == "sarif":
            print(format_sarif(diagnostics, file_path=str(path)))
        else:
            print(format_text_diagnostics(diagnostics, file_path=str(path)))

        if any(d.severity.level >= fail_severity.level for d in diagnostics):
            overall_failure = True

    return 1 if overall_failure else 0


def handle_fix(args: argparse.Namespace) -> int:
    """Execute fix subcommand."""
    target_rules = _parse_rule_set(args.rules)
    in_place = args.in_place and not args.dry_run

    # Stdin
    if "-" in args.paths:
        content = sys.stdin.read()
        fixed_content, diff_text, results = fix_dockerfile_content(
            content, rules=target_rules, filename="<stdin>"
        )
        if args.dry_run or not args.in_place:
            print(diff_text or "No fixes needed.")
        else:
            sys.stdout.write(fixed_content)
        return 0

    target_paths = _resolve_paths(args.paths)
    if not target_paths:
        print("Error: No Dockerfile found to fix.", file=sys.stderr)
        return 2

    for path in target_paths:
        if not path.exists():
            print(f"Error: File not found: {path}", file=sys.stderr)
            return 2

        fixed_content, diff_text, results = fix_dockerfile(
            path, rules=target_rules, in_place=in_place
        )
        report = format_fix_report(str(path), diff_text, results, in_place=in_place)
        print(report)

    return 0


def handle_scan(args: argparse.Namespace) -> int:
    """Execute scan subcommand."""
    if "-" in args.paths:
        content = sys.stdin.read()
        report = scan_dockerfile_content(content, file_path="<stdin>")
        if args.format == "json":
            import json
            print(json.dumps(report.to_dict(), indent=2))
        else:
            print(format_text_scan(report))

        failed = False
        if args.fail_under is not None and report.security_score < args.fail_under:
            failed = True
        if args.strict and report.grade not in ("A+", "A"):
            failed = True
        return 1 if failed else 0

    target_paths = _resolve_paths(args.paths)
    if not target_paths:
        target_paths = [Path("Dockerfile")]

    overall_failure = False

    for path in target_paths:
        if not path.exists():
            print(f"Error: File not found: {path}", file=sys.stderr)
            return 2
        report = scan_dockerfile(path)

        if args.format == "json":
            import json

            print(json.dumps(report.to_dict(), indent=2))
        else:
            print(format_text_scan(report))

        if args.fail_under is not None and report.security_score < args.fail_under:
            overall_failure = True

        if args.strict and report.grade not in ("A+", "A"):
            overall_failure = True

    return 1 if overall_failure else 0


def build_parser() -> argparse.ArgumentParser:
    """Build root argument parser with subcommands."""
    parser = argparse.ArgumentParser(
        prog="dockerfile-doctor",
        description="dockerfile-doctor: Production-grade Dockerfile linter, security scanner, and autofixer.",
    )
    parser.add_argument(
        "-v", "--version", action="version", version=f"%(prog)s {__version__}"
    )

    subparsers = parser.add_subparsers(
        dest="command", required=True, title="subcommands"
    )

    # 1. lint
    lint_parser = subparsers.add_parser(
        "lint", help="Lint Dockerfile(s) for security issues and anti-patterns"
    )
    lint_parser.add_argument(
        "paths",
        nargs="*",
        default=["Dockerfile"],
        help="Path(s) to Dockerfile(s) or directories (use '-' for stdin)",
    )
    lint_parser.add_argument(
        "--format",
        choices=["text", "json", "sarif"],
        default="text",
        help="Output format (default: text)",
    )
    lint_parser.add_argument(
        "--fail-on",
        choices=["error", "warning", "info", "style"],
        default="warning",
        help="Minimum severity level to trigger non-zero exit code (default: warning)",
    )
    lint_parser.add_argument(
        "--strict",
        action="store_true",
        help="Fail on any diagnostic (equivalent to --fail-on info)",
    )
    lint_parser.add_argument(
        "--ignore",
        type=str,
        help="Comma-separated rule IDs to ignore (e.g. --ignore STYLE001,PERF004)",
    )
    lint_parser.add_argument(
        "--include",
        type=str,
        help="Comma-separated rule IDs to exclusively check",
    )

    # 2. fix
    fix_parser = subparsers.add_parser(
        "fix", help="Automatically fix detected Dockerfile anti-patterns"
    )
    fix_parser.add_argument(
        "paths",
        nargs="*",
        default=["Dockerfile"],
        help="Path(s) to Dockerfile(s) (use '-' for stdin)",
    )
    fix_parser.add_argument(
        "-i",
        "--in-place",
        action="store_true",
        help="Write changes directly to file(s)",
    )
    fix_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Display unified diff without modifying files (default behavior)",
    )
    fix_parser.add_argument(
        "--rules",
        type=str,
        help="Comma-separated rule IDs to fix (e.g. --rules PERF001,PERF004)",
    )

    # 3. scan
    scan_parser = subparsers.add_parser(
        "scan", help="Run comprehensive security and multi-stage dependency scan"
    )
    scan_parser.add_argument(
        "paths",
        nargs="*",
        default=["Dockerfile"],
        help="Path(s) to Dockerfile(s) (use '-' for stdin)",
    )
    scan_parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text)",
    )
    scan_parser.add_argument(
        "--fail-under",
        type=int,
        default=None,
        help="Fail if security score is below threshold (0-100)",
    )
    scan_parser.add_argument(
        "--strict",
        action="store_true",
        help="Fail if grade is below A (score < 90)",
    )

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    """CLI entry point."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "lint":
        return handle_lint(args)
    elif args.command == "fix":
        return handle_fix(args)
    elif args.command == "scan":
        return handle_scan(args)
    else:
        parser.print_help()
        return 2


if __name__ == "__main__":
    sys.exit(main())
