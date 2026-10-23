"""Multi-stage build validation and dependency graph analysis."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Set, Tuple

from dockerfile_doctor.models import Diagnostic, Dockerfile, Severity, Stage

COPY_FROM_PATTERN = re.compile(r"--from=([^\s]+)")
MOUNT_FROM_PATTERN = re.compile(r"--mount=[^\s]*\bfrom=([^\s,]+)")


def validate_multistage(doc: Dockerfile) -> List[Diagnostic]:
    """Validate multi-stage Dockerfile logic, dependencies, and stage names."""
    diagnostics: List[Diagnostic] = []
    if not doc.stages:
        return diagnostics

    # 1. Check duplicate stage names (MS004)
    seen_names: Dict[str, Stage] = {}
    for stage in doc.stages:
        if stage.name:
            name_lower = stage.name.lower()
            if name_lower in seen_names:
                prev = seen_names[name_lower]
                diagnostics.append(
                    Diagnostic(
                        rule_id="MS004",
                        title="Duplicate Stage Name",
                        message=(
                            f"Stage name '{stage.name}' is already defined at line {prev.start_line}. "
                            "Stage names within a Dockerfile must be unique."
                        ),
                        severity=Severity.ERROR,
                        line=stage.start_line,
                        stage_index=stage.index,
                        fixable=False,
                    )
                )
            else:
                seen_names[name_lower] = stage

    # Map name -> stage index, and list of defined stages
    stage_name_to_idx: Dict[str, int] = {}
    for stage in doc.stages:
        if stage.name:
            stage_name_to_idx[stage.name.lower()] = stage.index

    # Track which stages are referenced by subsequent stages
    referenced_stage_indices: Set[int] = set()

    # 2. Check stage references in COPY and RUN mount
    for stage in doc.stages:
        for instr in stage.instructions:
            ref_names: List[str] = []
            if instr.name == "COPY":
                match = COPY_FROM_PATTERN.search(instr.arguments)
                if match:
                    ref_names.append(match.group(1))

            if instr.name == "RUN":
                mount_match = MOUNT_FROM_PATTERN.search(instr.arguments)
                if mount_match:
                    ref_names.append(mount_match.group(1))

            for ref in ref_names:
                ref_clean = ref.strip()
                # Could be numeric index or name
                target_stage_idx: Optional[int] = None
                if ref_clean.isdigit():
                    idx_val = int(ref_clean)
                    if idx_val < len(doc.stages):
                        target_stage_idx = idx_val
                    else:
                        # Referencing non-existent numeric stage
                        diagnostics.append(
                            Diagnostic(
                                rule_id="MS001",
                                title="Missing Stage Reference",
                                message=(
                                    f"Instruction references non-existent stage index '{ref_clean}'. "
                                    f"Total stages defined: {len(doc.stages)}."
                                ),
                                severity=Severity.ERROR,
                                line=instr.start_line,
                                stage_index=stage.index,
                            )
                        )
                        continue
                else:
                    ref_lower = ref_clean.lower()
                    if ref_lower in stage_name_to_idx:
                        target_stage_idx = stage_name_to_idx[ref_lower]
                    else:
                        # Note: In BuildKit, --from can also reference an external image (e.g. --from=nginx:alpine)
                        # If it contains ':' or '/' or is a valid image, it might be external.
                        # But if it's a simple token that matches no stage, it's flagged or warned.
                        if ":" not in ref_clean and "/" not in ref_clean:
                            diagnostics.append(
                                Diagnostic(
                                    rule_id="MS001",
                                    title="Missing Stage Reference",
                                    message=(
                                        f"Instruction references unknown build stage '{ref_clean}'. "
                                        "Verify the stage name is defined in an earlier 'FROM ... AS <name>'."
                                    ),
                                    severity=Severity.ERROR,
                                    line=instr.start_line,
                                    stage_index=stage.index,
                                )
                            )
                        continue

                if target_stage_idx is not None:
                    # Check forward reference (MS002)
                    if target_stage_idx > stage.index:
                        diagnostics.append(
                            Diagnostic(
                                rule_id="MS002",
                                title="Forward Stage Reference",
                                message=(
                                    f"Instruction references future stage '{ref_clean}' (stage {target_stage_idx}) "
                                    f"which is defined after current stage {stage.index}."
                                ),
                                severity=Severity.ERROR,
                                line=instr.start_line,
                                stage_index=stage.index,
                            )
                        )
                    elif target_stage_idx == stage.index:
                        diagnostics.append(
                            Diagnostic(
                                rule_id="MS002",
                                title="Self-Referencing Stage",
                                message=f"Stage cannot copy from itself (--from={ref_clean}).",
                                severity=Severity.ERROR,
                                line=instr.start_line,
                                stage_index=stage.index,
                            )
                        )
                    else:
                        referenced_stage_indices.add(target_stage_idx)

    # 3. Check for unused intermediate stages (MS003)
    if len(doc.stages) > 1:
        for stage in doc.stages[:-1]:  # Exclude the final stage
            # If the stage is not referenced and not base of another stage
            is_base_of_another = any(
                other.base_image.lower() == (stage.name.lower() if stage.name else "")
                for other in doc.stages[stage.index + 1 :]
            )
            if stage.index not in referenced_stage_indices and not is_base_of_another:
                diagnostics.append(
                    Diagnostic(
                        rule_id="MS003",
                        title="Unused Intermediate Stage",
                        message=(
                            f"Intermediate stage '{stage.name or stage.index}' is defined but never referenced "
                            "by any subsequent build stage. This dead stage increases build overhead."
                        ),
                        severity=Severity.INFO,
                        line=stage.start_line,
                        stage_index=stage.index,
                        suggestion="Remove the unused stage or ensure artifacts are copied to final stage.",
                    )
                )

    return diagnostics


def build_stage_graph(doc: Dockerfile) -> Dict[str, Any]:
    """Build multi-stage dependency graph metadata and ASCII visualization."""
    stages_data: List[Dict[str, Any]] = []
    edges: List[Dict[str, Any]] = []

    stage_name_to_idx: Dict[str, int] = {}
    for stage in doc.stages:
        if stage.name:
            stage_name_to_idx[stage.name.lower()] = stage.index

    for stage in doc.stages:
        stage_dict = stage.to_dict()
        stage_dict["dependencies"] = []
        stage_dict["is_final"] = stage.index == len(doc.stages) - 1
        stage_dict["has_nonroot_user"] = stage.has_user_instruction
        stages_data.append(stage_dict)

        # Check references in this stage
        for instr in stage.instructions:
            ref_name = None
            if instr.name == "COPY":
                m = COPY_FROM_PATTERN.search(instr.arguments)
                if m:
                    ref_name = m.group(1).strip()
            elif instr.name == "RUN":
                m = MOUNT_FROM_PATTERN.search(instr.arguments)
                if m:
                    ref_name = m.group(1).strip()

            if ref_name:
                from_idx: Optional[int] = None
                if ref_name.isdigit():
                    val = int(ref_name)
                    if val < len(doc.stages):
                        from_idx = val
                elif ref_name.lower() in stage_name_to_idx:
                    from_idx = stage_name_to_idx[ref_name.lower()]

                if from_idx is not None and from_idx != stage.index:
                    edge = {
                        "from_stage": from_idx,
                        "to_stage": stage.index,
                        "via": instr.name,
                    }
                    if edge not in edges:
                        edges.append(edge)
                    if from_idx not in stage_dict["dependencies"]:
                        stage_dict["dependencies"].append(from_idx)

    # ASCII Graph representation
    ascii_lines: List[str] = []
    for s in stages_data:
        idx = s["index"]
        name_str = f" AS {s['name']}" if s["name"] else ""
        user_status = "✓ non-root" if s["has_nonroot_user"] else "⚠ root"
        final_str = " [FINAL]" if s["is_final"] else ""
        ascii_lines.append(
            f"Stage {idx}: FROM {s['base_image']}{(':' + s['base_tag']) if s['base_tag'] else ''}{name_str} ({user_status}){final_str}"
        )
        deps = s["dependencies"]
        if deps:
            dep_names = [f"Stage {d}" for d in deps]
            ascii_lines.append(f"  └── depends on: {', '.join(dep_names)}")

    return {
        "stage_count": len(doc.stages),
        "stages": stages_data,
        "edges": edges,
        "ascii_tree": "\n".join(ascii_lines),
    }
