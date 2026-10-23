"""Parser for Dockerfiles."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

from dockerfile_doctor.models import Dockerfile, Instruction, Stage

KNOWN_INSTRUCTIONS = {
    "FROM",
    "RUN",
    "CMD",
    "LABEL",
    "EXPOSE",
    "ENV",
    "ADD",
    "COPY",
    "ENTRYPOINT",
    "VOLUME",
    "USER",
    "WORKDIR",
    "ARG",
    "ONBUILD",
    "STOPSIGNAL",
    "HEALTHCHECK",
    "SHELL",
}

FROM_PATTERN = re.compile(
    r"^(?:--platform=(?P<platform>[^\s]+)\s+)?(?P<image>[^\s:]+)(?::(?P<tag>[^\s@]+))?(?:@(?P<digest>[^\s]+))?(?:\s+[Aa][Ss]\s+(?P<stage_name>[^\s]+))?$"
)


def parse_dockerfile(path: Union[str, Path]) -> Dockerfile:
    """Parse a Dockerfile from a file path."""
    p = Path(path)
    content = p.read_text(encoding="utf-8")
    doc = parse_dockerfile_content(content)
    doc.file_path = str(p)
    return doc


def parse_dockerfile_content(content: str) -> Dockerfile:
    """Parse Dockerfile text into structured Dockerfile model."""
    lines = content.splitlines()
    escape_char = "\\"
    directives: Dict[str, str] = {}

    # 1. Parse parser directives at the top (e.g. # syntax=..., # escape=...)
    idx = 0
    while idx < len(lines):
        line = lines[idx].strip()
        if not line:
            idx += 1
            continue
        if line.startswith("#"):
            directive_match = re.match(r"^#\s*([a-zA-Z0-9_-]+)\s*=\s*(.+)$", line)
            if directive_match:
                key, val = directive_match.group(1).lower(), directive_match.group(2).strip()
                directives[key] = val
                if key == "escape":
                    escape_char = val
                idx += 1
                continue
        break

    # 2. Extract multi-line instructions with line tracking
    raw_instructions: List[Tuple[str, str, int, int, List[str]]] = []
    current_raw_lines: List[str] = []
    current_start_line = 0
    in_continuation = False
    buffer_text = ""

    for line_num, original_line in enumerate(lines, start=1):
        stripped = original_line.strip()

        # Handle comments
        if stripped.startswith("#"):
            # Inside a continuation, comments can be ignored or collected
            if in_continuation:
                current_raw_lines.append(original_line)
            continue

        if not stripped:
            if in_continuation:
                current_raw_lines.append(original_line)
            continue

        if not in_continuation:
            current_start_line = line_num
            current_raw_lines = [original_line]
        else:
            current_raw_lines.append(original_line)

        # Check for line continuation escape
        if stripped.endswith(escape_char):
            in_continuation = True
            content_part = stripped[:-1].rstrip()
            if buffer_text:
                buffer_text += " " + content_part
            else:
                buffer_text = content_part
            continue
        else:
            if buffer_text:
                full_line = (buffer_text + " " + stripped).strip()
                buffer_text = ""
            else:
                full_line = stripped
            in_continuation = False

            # Split instruction and arguments
            parts = full_line.split(None, 1)
            inst_name = parts[0].upper()
            inst_args = parts[1] if len(parts) > 1 else ""

            raw_instructions.append(
                (inst_name, inst_args, current_start_line, line_num, current_raw_lines)
            )

    # 3. Build Stages and Instructions
    stages: List[Stage] = []
    all_instructions: List[Instruction] = []
    current_stage: Optional[Stage] = None
    stage_idx = -1

    for name, args, s_line, e_line, raw_l in raw_instructions:
        if name == "FROM":
            stage_idx += 1
            platform, img, tag, digest, s_name = _parse_from_args(args)
            new_stage = Stage(
                index=stage_idx,
                name=s_name,
                base_image=img,
                base_tag=tag,
                base_digest=digest,
                platform=platform,
                start_line=s_line,
                end_line=e_line,
            )
            if current_stage is not None:
                current_stage.end_line = s_line - 1
            stages.append(new_stage)
            current_stage = new_stage

        cur_stage_idx = stage_idx if stage_idx >= 0 else 0
        cur_stage_name = current_stage.name if current_stage else None

        instr = Instruction(
            name=name,
            arguments=args,
            start_line=s_line,
            end_line=e_line,
            raw_lines=raw_l,
            stage_index=cur_stage_idx,
            stage_name=cur_stage_name,
        )
        all_instructions.append(instr)
        if current_stage is not None:
            current_stage.instructions.append(instr)
            current_stage.end_line = max(current_stage.end_line, e_line)

    if current_stage is not None and lines:
        current_stage.end_line = max(current_stage.end_line, len(lines))

    return Dockerfile(
        stages=stages,
        all_instructions=all_instructions,
        directives=directives,
        raw_content=content,
        lines=lines,
    )


def _parse_from_args(
    args: str,
) -> Tuple[Optional[str], str, Optional[str], Optional[str], Optional[str]]:
    """Parse arguments to FROM instruction.

    Returns: (platform, image, tag, digest, stage_name)
    """
    clean = args.strip()
    platform: Optional[str] = None
    stage_name: Optional[str] = None

    # Check for --platform=...
    if clean.startswith("--platform="):
        platform_part, remainder = clean.split(None, 1)
        platform = platform_part.split("=", 1)[1]
        clean = remainder.strip()

    # Check for AS <stage_name>
    as_parts = re.split(r"\s+[Aa][Ss]\s+", clean, maxsplit=1)
    image_part = as_parts[0].strip()
    if len(as_parts) > 1:
        stage_name = as_parts[1].strip()

    # Parse image, tag, digest
    image = image_part
    tag = None
    digest = None

    if "@" in image_part:
        image_sub, digest = image_part.split("@", 1)
        if ":" in image_sub:
            image, tag = image_sub.split(":", 1)
        else:
            image = image_sub
    elif ":" in image_part:
        # Care for host:port/repo:tag
        parts = image_part.rsplit(":", 1)
        if "/" in parts[1]:
            # The colon was part of registry host:port
            image = image_part
        else:
            image = parts[0]
            tag = parts[1]

    return platform, image, tag, digest, stage_name
