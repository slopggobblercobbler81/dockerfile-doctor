"""dockerfile-doctor: Production-grade Dockerfile linter, security scanner, and autofixer."""

from dockerfile_doctor.models import (
    Diagnostic,
    Dockerfile,
    FixResult,
    Instruction,
    ScanReport,
    Severity,
    Stage,
)
from dockerfile_doctor.parser import parse_dockerfile, parse_dockerfile_content
from dockerfile_doctor.linter import lint_dockerfile, lint_dockerfile_content
from dockerfile_doctor.fixer import fix_dockerfile, fix_dockerfile_content
from dockerfile_doctor.scanner import scan_dockerfile, scan_dockerfile_content
from dockerfile_doctor.multistage import validate_multistage, build_stage_graph

__version__ = "1.0.0"
__all__ = [
    "Diagnostic",
    "Dockerfile",
    "FixResult",
    "Instruction",
    "ScanReport",
    "Severity",
    "Stage",
    "parse_dockerfile",
    "parse_dockerfile_content",
    "lint_dockerfile",
    "lint_dockerfile_content",
    "fix_dockerfile",
    "fix_dockerfile_content",
    "scan_dockerfile",
    "scan_dockerfile_content",
    "validate_multistage",
    "build_stage_graph",
    "__version__",
]
