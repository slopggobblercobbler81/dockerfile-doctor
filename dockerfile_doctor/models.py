"""Data models for dockerfile-doctor."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class Severity(str, Enum):
    """Diagnostic severity levels."""
    ERROR = "ERROR"
    WARNING = "WARNING"
    INFO = "INFO"
    STYLE = "STYLE"

    @property
    def level(self) -> int:
        """Numeric rank for threshold comparison."""
        mapping = {
            Severity.INFO: 1,
            Severity.STYLE: 2,
            Severity.WARNING: 3,
            Severity.ERROR: 4,
        }
        return mapping[self]

    @classmethod
    def from_string(cls, value: str) -> Severity:
        upper = value.strip().upper()
        for item in cls:
            if item.value == upper:
                return item
        return cls.WARNING


@dataclass
class Instruction:
    """Represents a single Dockerfile instruction (e.g. FROM, RUN, COPY)."""
    name: str  # Always uppercase (e.g., 'FROM', 'RUN', 'COPY')
    arguments: str  # Unfolded argument string
    start_line: int  # 1-indexed
    end_line: int  # 1-indexed
    raw_lines: List[str] = field(default_factory=list)
    stage_index: int = 0
    stage_name: Optional[str] = None

    @property
    def is_json_form(self) -> bool:
        """Check if arguments represent an exec-form JSON array."""
        stripped = self.arguments.strip()
        return stripped.startswith("[") and stripped.endswith("]")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "arguments": self.arguments,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "stage_index": self.stage_index,
            "stage_name": self.stage_name,
        }


@dataclass
class Stage:
    """Represents a build stage in a multi-stage Dockerfile."""
    index: int
    name: Optional[str]
    base_image: str
    base_tag: Optional[str] = None
    base_digest: Optional[str] = None
    platform: Optional[str] = None
    instructions: List[Instruction] = field(default_factory=list)
    start_line: int = 1
    end_line: int = 1

    @property
    def is_scratch(self) -> bool:
        return self.base_image.lower() == "scratch"

    @property
    def full_image(self) -> str:
        s = self.base_image
        if self.base_tag:
            s += f":{self.base_tag}"
        if self.base_digest:
            s += f"@{self.base_digest}"
        return s

    @property
    def has_user_instruction(self) -> bool:
        """Check if non-root user instruction is specified in this stage."""
        for instr in reversed(self.instructions):
            if instr.name == "USER":
                val = instr.arguments.strip().lower()
                if val not in ("root", "0", "0:0", "root:root"):
                    return True
        return False

    @property
    def exposed_ports(self) -> List[str]:
        ports: List[str] = []
        for instr in self.instructions:
            if instr.name == "EXPOSE":
                ports.extend(instr.arguments.split())
        return ports

    @property
    def has_healthcheck(self) -> bool:
        for instr in self.instructions:
            if instr.name == "HEALTHCHECK":
                return True
        return False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "index": self.index,
            "name": self.name,
            "base_image": self.base_image,
            "base_tag": self.base_tag,
            "base_digest": self.base_digest,
            "platform": self.platform,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "instruction_count": len(self.instructions),
        }


@dataclass
class Dockerfile:
    """Structured representation of a parsed Dockerfile."""
    stages: List[Stage] = field(default_factory=list)
    all_instructions: List[Instruction] = field(default_factory=list)
    directives: Dict[str, str] = field(default_factory=dict)
    raw_content: str = ""
    lines: List[str] = field(default_factory=list)
    file_path: Optional[str] = None

    @property
    def final_stage(self) -> Optional[Stage]:
        return self.stages[-1] if self.stages else None


@dataclass
class Diagnostic:
    """Represents a linting or security diagnostic."""
    rule_id: str
    title: str
    message: str
    severity: Severity
    line: int
    end_line: Optional[int] = None
    stage_index: Optional[int] = None
    fixable: bool = False
    suggestion: Optional[str] = None
    cwe: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "message": self.message,
            "severity": self.severity.value,
            "line": self.line,
            "end_line": self.end_line or self.line,
            "stage_index": self.stage_index,
            "fixable": self.fixable,
            "suggestion": self.suggestion,
            "cwe": self.cwe,
        }


@dataclass
class FixResult:
    """Result of an applied autofix."""
    rule_id: str
    line: int
    description: str
    original_snippet: str
    fixed_snippet: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "line": self.line,
            "description": self.description,
            "original_snippet": self.original_snippet,
            "fixed_snippet": self.fixed_snippet,
        }


@dataclass
class ScanReport:
    """Comprehensive security and multi-stage scan report."""
    file_path: str
    total_stages: int
    security_score: int  # 0 to 100
    grade: str  # A+, A, B, C, D, F
    diagnostics: List[Diagnostic]
    stage_graph: Dict[str, Any]
    stats: Dict[str, int]
    recommendations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "file_path": self.file_path,
            "total_stages": self.total_stages,
            "security_score": self.security_score,
            "grade": self.grade,
            "stats": self.stats,
            "stage_graph": self.stage_graph,
            "diagnostics": [d.to_dict() for d in self.diagnostics],
            "recommendations": self.recommendations,
        }
