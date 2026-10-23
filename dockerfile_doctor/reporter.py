"""Report formatting for CLI output (Text, JSON, SARIF)."""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from dockerfile_doctor.models import Diagnostic, FixResult, ScanReport, Severity


def format_text_diagnostics(
    diagnostics: List[Diagnostic], file_path: str = "Dockerfile"
) -> str:
    """Format diagnostics into human-readable text output."""
    if not diagnostics:
        return f"✓ {file_path}: No Dockerfile issues found. Clean build!"

    lines: List[str] = [f"=== dockerfile-doctor report for {file_path} ==="]
    for d in diagnostics:
        sev_tag = f"[{d.severity.value}]"
        fix_tag = " (Fixable)" if d.fixable else ""
        cwe_tag = f" [{d.cwe}]" if d.cwe else ""
        lines.append(
            f"Line {d.line:3d} {sev_tag:9s} {d.rule_id}: {d.title}{cwe_tag}{fix_tag}"
        )
        lines.append(f"          Message: {d.message}")
        if d.suggestion:
            lines.append(f"          Action : {d.suggestion}")
        lines.append("")

    # Summary
    errors = sum(1 for d in diagnostics if d.severity == Severity.ERROR)
    warnings = sum(1 for d in diagnostics if d.severity == Severity.WARNING)
    infos = sum(1 for d in diagnostics if d.severity in (Severity.INFO, Severity.STYLE))
    lines.append(
        f"Summary: {errors} error(s), {warnings} warning(s), {infos} notice(s)."
    )
    return "\n".join(lines)


def format_json_diagnostics(
    diagnostics: List[Diagnostic], file_path: str = "Dockerfile"
) -> str:
    """Format diagnostics as a JSON string."""
    data = {
        "file": file_path,
        "total_issues": len(diagnostics),
        "issues": [d.to_dict() for d in diagnostics],
    }
    return json.dumps(data, indent=2)


def format_sarif(
    diagnostics: List[Diagnostic], file_path: str = "Dockerfile"
) -> str:
    """Format diagnostics into standard SARIF 2.1.0 format."""
    rules_map: Dict[str, Dict[str, Any]] = {}
    results: List[Dict[str, Any]] = []

    for d in diagnostics:
        if d.rule_id not in rules_map:
            level = "error" if d.severity == Severity.ERROR else "warning"
            rules_map[d.rule_id] = {
                "id": d.rule_id,
                "name": d.title.replace(" ", ""),
                "shortDescription": {"text": d.title},
                "defaultConfiguration": {"level": level},
            }

        sarif_level = "error" if d.severity == Severity.ERROR else "warning"
        if d.severity in (Severity.INFO, Severity.STYLE):
            sarif_level = "note"

        results.append(
            {
                "ruleId": d.rule_id,
                "level": sarif_level,
                "message": {"text": d.message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": file_path},
                            "region": {
                                "startLine": d.line,
                                "endLine": d.end_line or d.line,
                            },
                        }
                    }
                ],
            }
        )

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "dockerfile-doctor",
                        "informationUri": "https://github.com/slopggobblercobbler81/dockerfile-doctor",
                        "rules": list(rules_map.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=2)


def format_text_scan(report: ScanReport) -> str:
    """Format ScanReport into a terminal summary."""
    lines: List[str] = [
        "============================================================",
        f"        DOCKERFILE SECURITY & ARCHITECTURE SCAN",
        "============================================================",
        f"Target File    : {report.file_path}",
        f"Total Stages   : {report.total_stages}",
        f"Security Score : {report.security_score}/100 [Grade: {report.grade}]",
        f"Issues Found   : {report.stats['errors']} errors, {report.stats['warnings']} warnings, {report.stats['style'] + report.stats['info']} notices",
        f"Autofixable    : {report.stats['fixable']} issue(s) can be fixed automatically with 'dockerfile-doctor fix'",
        "",
        "--- Multi-Stage Build Dependency Graph ---",
        report.stage_graph.get("ascii_tree", "No stages defined."),
        "",
        "--- Diagnostics ---",
    ]

    if not report.diagnostics:
        lines.append("✓ No security or configuration issues detected!")
    else:
        for d in report.diagnostics:
            fix_str = " [FIXABLE]" if d.fixable else ""
            cwe_str = f" [{d.cwe}]" if d.cwe else ""
            lines.append(
                f"• Line {d.line:3d} [{d.severity.value}] {d.rule_id}: {d.title}{cwe_str}{fix_str}"
            )
            lines.append(f"    {d.message}")

    if report.recommendations:
        lines.append("")
        lines.append("--- Key Recommendations ---")
        for idx, rec in enumerate(report.recommendations, 1):
            lines.append(f"{idx}. {rec}")

    lines.append("============================================================")
    return "\n".join(lines)


def format_fix_report(
    file_path: str, diff_text: str, fixes: List[FixResult], in_place: bool
) -> str:
    """Format report after running fix."""
    if not fixes:
        return f"✓ {file_path}: No fixable issues found."

    lines: List[str] = [f"=== dockerfile-doctor fix applied to {file_path} ==="]
    for idx, f in enumerate(fixes, 1):
        lines.append(f"{idx}. [{f.rule_id}] Line {f.line}: {f.description}")

    if diff_text:
        lines.append("\n--- Unified Diff ---")
        lines.append(diff_text)

    if in_place:
        lines.append(f"\n✓ Successfully wrote {len(fixes)} fix(es) in-place to {file_path}")
    else:
        lines.append(f"\nℹ Dry-run mode: Run with '-i' or '--in-place' to write changes to disk.")

    return "\n".join(lines)
