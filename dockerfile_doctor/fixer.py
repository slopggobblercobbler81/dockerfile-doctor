"""Autofix engine for Dockerfile diagnostics."""

from __future__ import annotations

import difflib
import re
from pathlib import Path
from typing import List, Optional, Set, Tuple, Union

from dockerfile_doctor.linter import lint_dockerfile_content
from dockerfile_doctor.models import Diagnostic, Dockerfile, FixResult
from dockerfile_doctor.parser import parse_dockerfile_content


def fix_dockerfile(
    path: Union[str, Path],
    rules: Optional[Set[str]] = None,
    in_place: bool = False,
) -> Tuple[str, str, List[FixResult]]:
    """Fix a Dockerfile file.

    Returns (fixed_content, diff_text, fix_results).
    If in_place is True, writes the fixed content back to path.
    """
    p = Path(path)
    content = p.read_text(encoding="utf-8")
    fixed_content, diff_text, results = fix_dockerfile_content(
        content, rules=rules, filename=str(p)
    )
    if in_place and results:
        p.write_text(fixed_content, encoding="utf-8")
    return fixed_content, diff_text, results


def fix_dockerfile_content(
    content: str,
    rules: Optional[Set[str]] = None,
    filename: str = "Dockerfile",
) -> Tuple[str, str, List[FixResult]]:
    """Apply automated fixes to Dockerfile content.

    Returns: (fixed_content, diff_text, list_of_applied_fixes)
    """
    current_content = content
    applied_fixes: List[FixResult] = []

    # Iterative fixing: apply fixes pass-by-pass
    max_passes = 3
    for _ in range(max_passes):
        doc = parse_dockerfile_content(current_content)
        diagnostics = lint_dockerfile_content(doc, include_rules=rules)
        fixable_diags = [d for d in diagnostics if d.fixable]

        if not fixable_diags:
            break

        pass_applied = False
        lines = current_content.splitlines(keepends=True)

        for diag in fixable_diags:
            rule_id = diag.rule_id
            if rules and rule_id not in rules:
                continue

            # Apply rule fix
            fixed_lines, result = _apply_single_fix(doc, lines, diag)
            if result is not None:
                applied_fixes.append(result)
                lines = fixed_lines
                current_content = "".join(lines)
                pass_applied = True
                # Break to re-parse and re-lint cleanly with updated line offsets
                break

        if not pass_applied:
            break

    # Generate unified diff
    orig_lines = content.splitlines(keepends=True)
    fixed_lines = current_content.splitlines(keepends=True)
    diff = list(
        difflib.unified_diff(
            orig_lines,
            fixed_lines,
            fromfile=f"a/{filename}",
            tofile=f"b/{filename}",
        )
    )
    diff_text = "".join(diff)

    return current_content, diff_text, applied_fixes


def _apply_single_fix(
    doc: Dockerfile, lines: List[str], diag: Diagnostic
) -> Tuple[List[str], Optional[FixResult]]:
    """Attempt to fix a single diagnostic.

    Returns (new_lines, FixResult or None).
    """
    rule_id = diag.rule_id
    line_idx = diag.line - 1  # 0-indexed line

    if line_idx < 0 or line_idx >= len(lines):
        return lines, None

    original_line = lines[line_idx]

    # Rule: STYLE001 - Replace ADD with COPY
    if rule_id == "STYLE001":
        match = re.match(r"^(\s*)ADD(\s+.*)$", original_line, re.IGNORECASE)
        if match:
            indent, rest = match.group(1), match.group(2)
            new_line = f"{indent}COPY{rest}"
            lines[line_idx] = new_line
            return lines, FixResult(
                rule_id=rule_id,
                line=diag.line,
                description="Replaced ADD with COPY for local files",
                original_snippet=original_line.strip(),
                fixed_snippet=new_line.strip(),
            )

    # Rule: STYLE002 - Absolute WORKDIR
    if rule_id == "STYLE002":
        match = re.match(r"^(\s*WORKDIR\s+)([^/\\$\s][^\r\n]*)(\r?\n?)$", original_line, re.IGNORECASE)
        if match:
            prefix, path, newline = match.group(1), match.group(2), match.group(3)
            new_line = f"{prefix}/{path}{newline}"
            lines[line_idx] = new_line
            return lines, FixResult(
                rule_id=rule_id,
                line=diag.line,
                description="Converted relative WORKDIR path to absolute path",
                original_snippet=original_line.strip(),
                fixed_snippet=new_line.strip(),
            )

    # Rule: SEC005 - Remove sudo
    if rule_id == "SEC005":
        new_line = re.sub(r"(?:(?<=^)|(?<=[;&|]\s)|\b)sudo\s+", "", original_line)
        if new_line != original_line:
            lines[line_idx] = new_line
            return lines, FixResult(
                rule_id=rule_id,
                line=diag.line,
                description="Removed redundant 'sudo' command from RUN instruction",
                original_snippet=original_line.strip(),
                fixed_snippet=new_line.strip(),
            )

    # Rule: PERF004 - pip install --no-cache-dir
    if rule_id == "PERF004":
        # Find instruction range
        start_idx = diag.line - 1
        end_idx = (diag.end_line or diag.line) - 1
        modified = False
        orig_snip = lines[start_idx].strip()
        for i in range(start_idx, min(end_idx + 1, len(lines))):
            if re.search(r"\bpip\d*\s+install\b", lines[i]):
                lines[i] = re.sub(
                    r"(\bpip\d*\s+install\s+)", r"\1--no-cache-dir ", lines[i]
                )
                modified = True
        if modified:
            return lines, FixResult(
                rule_id=rule_id,
                line=diag.line,
                description="Added '--no-cache-dir' to pip install command",
                original_snippet=orig_snip,
                fixed_snippet=lines[start_idx].strip(),
            )

    # Rule: PERF005 - apk add --no-cache
    if rule_id == "PERF005":
        start_idx = diag.line - 1
        end_idx = (diag.end_line or diag.line) - 1
        modified = False
        orig_snip = lines[start_idx].strip()
        for i in range(start_idx, min(end_idx + 1, len(lines))):
            if re.search(r"\bapk\s+add\b", lines[i]):
                lines[i] = re.sub(r"(\bapk\s+add\s+)", r"\1--no-cache ", lines[i])
                modified = True
        if modified:
            return lines, FixResult(
                rule_id=rule_id,
                line=diag.line,
                description="Added '--no-cache' to apk add command",
                original_snippet=orig_snip,
                fixed_snippet=lines[start_idx].strip(),
            )

    # Rule: PERF001 - apt-get install --no-install-recommends
    if rule_id == "PERF001":
        start_idx = diag.line - 1
        end_idx = (diag.end_line or diag.line) - 1
        modified = False
        orig_snip = lines[start_idx].strip()
        for i in range(start_idx, min(end_idx + 1, len(lines))):
            if re.search(r"\bapt-get\s+install\b", lines[i]):
                lines[i] = re.sub(
                    r"(\bapt-get\s+install\s+(?:-y\s+)?)",
                    r"\1--no-install-recommends ",
                    lines[i],
                )
                modified = True
        if modified:
            return lines, FixResult(
                rule_id=rule_id,
                line=diag.line,
                description="Added '--no-install-recommends' to apt-get install",
                original_snippet=orig_snip,
                fixed_snippet=lines[start_idx].strip(),
            )

    # Rule: PERF002 - Clean apt-get cache
    if rule_id == "PERF002":
        end_idx = (diag.end_line or diag.line) - 1
        if 0 <= end_idx < len(lines):
            target_line = lines[end_idx]
            clean_cmd = " && rm -rf /var/lib/apt/lists/*"
            newline_match = re.search(r"(\r?\n)$", target_line)
            newline = newline_match.group(1) if newline_match else "\n"
            content_part = target_line.rstrip("\r\n")

            # Check if ends with line continuation
            if content_part.rstrip().endswith("\\"):
                new_line = content_part.rstrip()[:-1].rstrip() + clean_cmd + " \\\n"
            else:
                new_line = content_part + clean_cmd + newline

            lines[end_idx] = new_line
            return lines, FixResult(
                rule_id=rule_id,
                line=diag.line,
                description="Appended 'rm -rf /var/lib/apt/lists/*' to apt RUN instruction",
                original_snippet=target_line.strip(),
                fixed_snippet=new_line.strip(),
            )

    # Rule: STYLE003 - Multiple CMD / ENTRYPOINT: comment out earlier redundant one
    if rule_id == "STYLE003":
        target_line = lines[line_idx]
        new_line = f"# Redundant CMD removed by dockerfile-doctor:\n# {target_line}"
        lines[line_idx] = new_line
        return lines, FixResult(
            rule_id=rule_id,
            line=diag.line,
            description="Commented out redundant CMD instruction",
            original_snippet=target_line.strip(),
            fixed_snippet=new_line.strip(),
        )

    # Rule: SEC001 - Non-root USER in final stage
    if rule_id == "SEC001":
        final_stage = doc.final_stage
        if final_stage:
            # Find insertion position before CMD/ENTRYPOINT in final stage, or at end
            insert_idx = len(lines)
            for instr in final_stage.instructions:
                if instr.name in ("CMD", "ENTRYPOINT"):
                    insert_idx = instr.start_line - 1
                    break

            user_block = (
                "\n# Run as non-root user (dockerfile-doctor SEC001)\n"
                "USER 10001\n"
            )
            lines.insert(insert_idx, user_block)
            return lines, FixResult(
                rule_id=rule_id,
                line=insert_idx + 1,
                description="Added non-root 'USER 10001' before container entrypoint",
                original_snippet="",
                fixed_snippet="USER 10001",
            )

    # Rule: SEC006 - Add HEALTHCHECK
    if rule_id == "SEC006":
        final_stage = doc.final_stage
        if final_stage:
            insert_idx = len(lines)
            for instr in final_stage.instructions:
                if instr.name in ("CMD", "ENTRYPOINT"):
                    insert_idx = instr.start_line - 1
                    break

            hc_block = (
                "\n# Basic healthcheck scaffold (dockerfile-doctor SEC006)\n"
                "HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \\\n"
                "    CMD curl -f http://localhost/ || exit 1\n"
            )
            lines.insert(insert_idx, hc_block)
            return lines, FixResult(
                rule_id=rule_id,
                line=insert_idx + 1,
                description="Scaffolded basic HEALTHCHECK instruction",
                original_snippet="",
                fixed_snippet="HEALTHCHECK --interval=30s ...",
            )

    return lines, None
