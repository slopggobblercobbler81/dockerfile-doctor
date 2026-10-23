"""Dockerfile linter combining static rules and multi-stage checks."""

from __future__ import annotations

from pathlib import Path
from typing import List, Optional, Set, Union

from dockerfile_doctor.models import Diagnostic, Dockerfile, Severity
from dockerfile_doctor.multistage import validate_multistage
from dockerfile_doctor.parser import parse_dockerfile, parse_dockerfile_content
from dockerfile_doctor.rules import ALL_RULES, RULE_REGISTRY


def lint_dockerfile(
    path: Union[str, Path],
    include_rules: Optional[Set[str]] = None,
    ignore_rules: Optional[Set[str]] = None,
) -> List[Diagnostic]:
    """Lint a Dockerfile from path."""
    doc = parse_dockerfile(path)
    return lint_dockerfile_content(
        doc, include_rules=include_rules, ignore_rules=ignore_rules
    )


def lint_dockerfile_content(
    doc_or_content: Union[str, Dockerfile],
    include_rules: Optional[Set[str]] = None,
    ignore_rules: Optional[Set[str]] = None,
) -> List[Diagnostic]:
    """Lint parsed Dockerfile or Dockerfile string."""
    if isinstance(doc_or_content, str):
        doc = parse_dockerfile_content(doc_or_content)
    else:
        doc = doc_or_content

    diagnostics: List[Diagnostic] = []

    # 1. Run static rules
    for rule in ALL_RULES:
        if include_rules and rule.rule_id not in include_rules:
            continue
        if ignore_rules and rule.rule_id in ignore_rules:
            continue
        diagnostics.extend(rule.check(doc))

    # 2. Run multi-stage checks
    ms_diags = validate_multistage(doc)
    for diag in ms_diags:
        if include_rules and diag.rule_id not in include_rules:
            continue
        if ignore_rules and diag.rule_id in ignore_rules:
            continue
        diagnostics.append(diag)

    # Sort diagnostics cleanly by line number, then rule_id
    diagnostics.sort(key=lambda d: (d.line, d.rule_id))
    return diagnostics
