"""Security and multi-stage build scanner."""

from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Union

from dockerfile_doctor.linter import lint_dockerfile_content
from dockerfile_doctor.models import Diagnostic, Dockerfile, ScanReport, Severity
from dockerfile_doctor.multistage import build_stage_graph
from dockerfile_doctor.parser import parse_dockerfile, parse_dockerfile_content


def scan_dockerfile(path: Union[str, Path]) -> ScanReport:
    """Scan a Dockerfile file for security, best practices, and stage dependencies."""
    p = Path(path)
    content = p.read_text(encoding="utf-8")
    report = scan_dockerfile_content(content, file_path=str(p))
    return report


def scan_dockerfile_content(
    content: str, file_path: str = "Dockerfile"
) -> ScanReport:
    """Scan Dockerfile content and produce a detailed ScanReport."""
    doc = parse_dockerfile_content(content)
    diagnostics = lint_dockerfile_content(doc)
    stage_graph = build_stage_graph(doc)

    stats: Dict[str, int] = {
        "errors": 0,
        "warnings": 0,
        "info": 0,
        "style": 0,
        "fixable": 0,
    }

    penalty = 0
    recommendations: List[str] = []

    for d in diagnostics:
        if d.fixable:
            stats["fixable"] += 1

        if d.severity == Severity.ERROR:
            stats["errors"] += 1
            penalty += 20
        elif d.severity == Severity.WARNING:
            stats["warnings"] += 1
            penalty += 10
        elif d.severity == Severity.STYLE:
            stats["style"] += 1
            penalty += 2
        elif d.severity == Severity.INFO:
            stats["info"] += 1
            penalty += 1

        if d.suggestion and d.suggestion not in recommendations:
            recommendations.append(d.suggestion)

    score = max(0, min(100, 100 - penalty))

    if score >= 95:
        grade = "A+"
    elif score >= 90:
        grade = "A"
    elif score >= 80:
        grade = "B"
    elif score >= 70:
        grade = "C"
    elif score >= 60:
        grade = "D"
    else:
        grade = "F"

    return ScanReport(
        file_path=file_path,
        total_stages=len(doc.stages),
        security_score=score,
        grade=grade,
        diagnostics=diagnostics,
        stage_graph=stage_graph,
        stats=stats,
        recommendations=recommendations,
    )
