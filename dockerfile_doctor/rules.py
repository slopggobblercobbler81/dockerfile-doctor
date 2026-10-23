"""Linting and security rules for Dockerfile inspection."""

from __future__ import annotations

import re
from typing import Callable, List, Optional

from dockerfile_doctor.models import Diagnostic, Dockerfile, Instruction, Severity, Stage

# Secret token detection pattern
SECRET_PATTERN = re.compile(
    r"(?i)\b(password|secret(?:_key)?|api[_-]?key|access_token|auth_token|private_key|aws_secret_access_key)\s*=\s*['\"]?([a-zA-Z0-9_\-+=/]{8,})['\"]?"
)

# Piping curl/wget into shell
CURL_PIPE_PATTERN = re.compile(
    r"\b(curl\b[^|;&\n]+|wget\b[^|;&\n]+)\|\s*(ba|z|da|a)?sh\b"
)

# Archive extensions for ADD check
ARCHIVE_EXTS = (
    ".tar",
    ".tar.gz",
    ".tgz",
    ".tar.bz2",
    ".tbz",
    ".tbz2",
    ".tar.xz",
    ".txz",
)


class BaseRule:
    rule_id: str
    title: str
    severity: Severity
    cwe: Optional[str] = None
    fixable: bool = False

    def check(self, doc: Dockerfile) -> List[Diagnostic]:
        raise NotImplementedError


class RootUserRule(BaseRule):
    """SEC001: Detects missing non-root USER instruction in final production stage."""
    rule_id = "SEC001"
    title = "Missing Non-Root USER Instruction"
    severity = Severity.WARNING
    cwe = "CWE-250"
    fixable = True

    def check(self, doc: Dockerfile) -> List[Diagnostic]:
        diagnostics: List[Diagnostic] = []
        if not doc.stages:
            return diagnostics

        final_stage = doc.final_stage
        if not final_stage or final_stage.is_scratch:
            return diagnostics

        # Determine last USER instruction in final stage
        last_user: Optional[str] = None
        user_line: Optional[int] = None
        for instr in final_stage.instructions:
            if instr.name == "USER":
                last_user = instr.arguments.strip()
                user_line = instr.start_line

        is_root = False
        if last_user is None:
            is_root = True
        elif last_user.lower() in ("root", "0", "0:0", "root:root"):
            is_root = True

        if is_root:
            line = user_line if user_line is not None else final_stage.end_line
            diagnostics.append(
                Diagnostic(
                    rule_id=self.rule_id,
                    title=self.title,
                    message=(
                        f"Final stage '{final_stage.name or final_stage.index}' does not specify a non-root USER. "
                        "Containers running as root present elevated privilege escalation risks."
                    ),
                    severity=self.severity,
                    line=line,
                    stage_index=final_stage.index,
                    fixable=self.fixable,
                    suggestion="Add 'USER appuser' or numeric 'USER 10001' before container entrypoint.",
                    cwe=self.cwe,
                )
            )
        return diagnostics


class UnpinnedTagRule(BaseRule):
    """SEC002: Base images should specify explicit immutable version tag, not :latest."""
    rule_id = "SEC002"
    title = "Unpinned or Mutable Base Image Tag"
    severity = Severity.WARNING
    fixable = True

    def check(self, doc: Dockerfile) -> List[Diagnostic]:
        diagnostics: List[Diagnostic] = []
        # Stage names defined within file (can be used as base of subsequent stages)
        stage_names = {s.name.lower() for s in doc.stages if s.name}

        for stage in doc.stages:
            img = stage.base_image.lower()
            if img == "scratch" or img in stage_names:
                continue

            tag = stage.base_tag
            digest = stage.base_digest

            if digest is None:
                if tag is None:
                    diagnostics.append(
                        Diagnostic(
                            rule_id=self.rule_id,
                            title=self.title,
                            message=f"Base image '{stage.base_image}' has no tag specified (defaults to mutable :latest).",
                            severity=self.severity,
                            line=stage.start_line,
                            stage_index=stage.index,
                            fixable=True,
                            suggestion=f"Pin to an explicit version tag (e.g. '{stage.base_image}:<version>') or SHA256 digest.",
                        )
                    )
                elif tag.lower() == "latest":
                    diagnostics.append(
                        Diagnostic(
                            rule_id=self.rule_id,
                            title=self.title,
                            message=f"Base image '{stage.base_image}' uses mutable ':latest' tag.",
                            severity=self.severity,
                            line=stage.start_line,
                            stage_index=stage.index,
                            fixable=True,
                            suggestion=f"Pin to an explicit version tag or SHA256 digest instead of ':latest'.",
                        )
                    )
        return diagnostics


class CurlPipeShellRule(BaseRule):
    """SEC003: Dangerous curl or wget piped directly into shell."""
    rule_id = "SEC003"
    title = "Dangerous Curl/Wget Piped into Shell"
    severity = Severity.ERROR
    cwe = "CWE-494"
    fixable = False

    def check(self, doc: Dockerfile) -> List[Diagnostic]:
        diagnostics: List[Diagnostic] = []
        for instr in doc.all_instructions:
            if instr.name == "RUN":
                if CURL_PIPE_PATTERN.search(instr.arguments):
                    diagnostics.append(
                        Diagnostic(
                            rule_id=self.rule_id,
                            title=self.title,
                            message="Piping untrusted remote scripts (curl/wget | sh/bash) creates code execution vulnerability.",
                            severity=self.severity,
                            line=instr.start_line,
                            end_line=instr.end_line,
                            stage_index=instr.stage_index,
                            fixable=False,
                            suggestion="Download file first, verify sha256 checksum, then execute.",
                            cwe=self.cwe,
                        )
                    )
        return diagnostics


class SecretInEnvRule(BaseRule):
    """SEC004: Hardcoded credentials or tokens detected in ENV or ARG."""
    rule_id = "SEC004"
    title = "Hardcoded Secret in ENV or ARG"
    severity = Severity.ERROR
    cwe = "CWE-798"
    fixable = False

    def check(self, doc: Dockerfile) -> List[Diagnostic]:
        diagnostics: List[Diagnostic] = []
        for instr in doc.all_instructions:
            if instr.name in ("ENV", "ARG"):
                match = SECRET_PATTERN.search(instr.arguments)
                if match:
                    key = match.group(1)
                    diagnostics.append(
                        Diagnostic(
                            rule_id=self.rule_id,
                            title=self.title,
                            message=f"Possible hardcoded secret '{key}' in {instr.name} instruction. Values persist in image metadata.",
                            severity=self.severity,
                            line=instr.start_line,
                            end_line=instr.end_line,
                            stage_index=instr.stage_index,
                            fixable=False,
                            suggestion="Pass sensitive credentials via runtime environment variables or Docker build secrets (--mount=type=secret).",
                            cwe=self.cwe,
                        )
                    )
        return diagnostics


class SudoUsageRule(BaseRule):
    """SEC005: Sudo command used in container build RUN instruction."""
    rule_id = "SEC005"
    title = "Sudo Usage in Container RUN"
    severity = Severity.WARNING
    cwe = "CWE-250"
    fixable = True

    def check(self, doc: Dockerfile) -> List[Diagnostic]:
        diagnostics: List[Diagnostic] = []
        pattern = re.compile(r"(?:^|[;&|]\s*|\b)sudo\s+")
        for instr in doc.all_instructions:
            if instr.name == "RUN":
                if pattern.search(instr.arguments):
                    diagnostics.append(
                        Diagnostic(
                            rule_id=self.rule_id,
                            title=self.title,
                            message="Using 'sudo' inside container is unnecessary and leads to permission or tty errors.",
                            severity=self.severity,
                            line=instr.start_line,
                            end_line=instr.end_line,
                            stage_index=instr.stage_index,
                            fixable=True,
                            suggestion="Remove 'sudo' or use root USER during build steps.",
                            cwe=self.cwe,
                        )
                    )
        return diagnostics


class MissingHealthcheckRule(BaseRule):
    """SEC006: Exposed network services missing HEALTHCHECK."""
    rule_id = "SEC006"
    title = "Missing HEALTHCHECK Instruction"
    severity = Severity.WARNING
    fixable = True

    def check(self, doc: Dockerfile) -> List[Diagnostic]:
        diagnostics: List[Diagnostic] = []
        final_stage = doc.final_stage
        if not final_stage or final_stage.is_scratch:
            return diagnostics

        has_ports = len(final_stage.exposed_ports) > 0
        has_healthcheck = final_stage.has_healthcheck

        if has_ports and not has_healthcheck:
            diagnostics.append(
                Diagnostic(
                    rule_id=self.rule_id,
                    title=self.title,
                    message="Final container image has exposed services but lacks a HEALTHCHECK instruction.",
                    severity=self.severity,
                    line=final_stage.end_line,
                    stage_index=final_stage.index,
                    fixable=True,
                    suggestion="Define HEALTHCHECK --interval=30s --timeout=3s CMD curl -f http://localhost/ || exit 1",
                )
            )
        return diagnostics


class AptGetNoInstallRecommendsRule(BaseRule):
    """PERF001: apt-get install missing --no-install-recommends."""
    rule_id = "PERF001"
    title = "apt-get install Missing --no-install-recommends"
    severity = Severity.WARNING
    fixable = True

    def check(self, doc: Dockerfile) -> List[Diagnostic]:
        diagnostics: List[Diagnostic] = []
        install_pattern = re.compile(r"\bapt-get\s+install\b")
        for instr in doc.all_instructions:
            if instr.name == "RUN":
                if install_pattern.search(instr.arguments):
                    if "--no-install-recommends" not in instr.arguments:
                        diagnostics.append(
                            Diagnostic(
                                rule_id=self.rule_id,
                                title=self.title,
                                message="'apt-get install' without '--no-install-recommends' installs unneeded packages and inflates image size.",
                                severity=self.severity,
                                line=instr.start_line,
                                end_line=instr.end_line,
                                stage_index=instr.stage_index,
                                fixable=True,
                                suggestion="Add '--no-install-recommends' flag to apt-get install.",
                            )
                        )
        return diagnostics


class AptGetCacheUncleanedRule(BaseRule):
    """PERF002: apt-get cache not cleaned in same RUN instruction."""
    rule_id = "PERF002"
    title = "apt-get Package Cache Not Cleaned"
    severity = Severity.WARNING
    fixable = True

    def check(self, doc: Dockerfile) -> List[Diagnostic]:
        diagnostics: List[Diagnostic] = []
        apt_pattern = re.compile(r"\bapt-get\s+(install|update)\b")
        cleanup_pattern = re.compile(r"rm\s+-rf\s+/var/lib/apt/lists(/\*|\*|\s|$)")

        for instr in doc.all_instructions:
            if instr.name == "RUN":
                if apt_pattern.search(instr.arguments):
                    if not cleanup_pattern.search(instr.arguments):
                        diagnostics.append(
                            Diagnostic(
                                rule_id=self.rule_id,
                                title=self.title,
                                message="apt-get caches remain in layer. Clean with 'rm -rf /var/lib/apt/lists/*'.",
                                severity=self.severity,
                                line=instr.start_line,
                                end_line=instr.end_line,
                                stage_index=instr.stage_index,
                                fixable=True,
                                suggestion="Append '&& rm -rf /var/lib/apt/lists/*' to the RUN instruction.",
                            )
                        )
        return diagnostics


class AptGetUpdateAloneRule(BaseRule):
    """PERF003: apt-get update alone in separate RUN instruction."""
    rule_id = "PERF003"
    title = "apt-get update Executed Alone in RUN"
    severity = Severity.WARNING
    fixable = False

    def check(self, doc: Dockerfile) -> List[Diagnostic]:
        diagnostics: List[Diagnostic] = []
        update_pattern = re.compile(r"^\s*apt-get\s+update\s*(\s*-[a-zA-Z]+\s*)*$")

        for instr in doc.all_instructions:
            if instr.name == "RUN":
                cleaned = instr.arguments.strip()
                if update_pattern.match(cleaned):
                    diagnostics.append(
                        Diagnostic(
                            rule_id=self.rule_id,
                            title=self.title,
                            message="'apt-get update' alone in RUN causes caching issues. Combine with 'apt-get install'.",
                            severity=self.severity,
                            line=instr.start_line,
                            end_line=instr.end_line,
                            stage_index=instr.stage_index,
                            fixable=False,
                            suggestion="Combine 'apt-get update && apt-get install -y --no-install-recommends ...' in a single RUN instruction.",
                        )
                    )
        return diagnostics


class PipNoCacheRule(BaseRule):
    """PERF004: pip install without --no-cache-dir."""
    rule_id = "PERF004"
    title = "pip install Missing --no-cache-dir"
    severity = Severity.WARNING
    fixable = True

    def check(self, doc: Dockerfile) -> List[Diagnostic]:
        diagnostics: List[Diagnostic] = []
        pip_pattern = re.compile(r"\bpip\d*\s+install\b")

        for instr in doc.all_instructions:
            if instr.name == "RUN":
                if pip_pattern.search(instr.arguments):
                    if "--no-cache-dir" not in instr.arguments:
                        diagnostics.append(
                            Diagnostic(
                                rule_id=self.rule_id,
                                title=self.title,
                                message="'pip install' without '--no-cache-dir' stores wheel caches in container layer.",
                                severity=self.severity,
                                line=instr.start_line,
                                end_line=instr.end_line,
                                stage_index=instr.stage_index,
                                fixable=True,
                                suggestion="Add '--no-cache-dir' flag to pip install commands.",
                            )
                        )
        return diagnostics


class ApkNoCacheRule(BaseRule):
    """PERF005: Alpine apk add without --no-cache."""
    rule_id = "PERF005"
    title = "apk add Missing --no-cache"
    severity = Severity.WARNING
    fixable = True

    def check(self, doc: Dockerfile) -> List[Diagnostic]:
        diagnostics: List[Diagnostic] = []
        apk_pattern = re.compile(r"\bapk\s+add\b")
        apk_clean = re.compile(r"rm\s+-rf\s+/var/cache/apk")

        for instr in doc.all_instructions:
            if instr.name == "RUN":
                if apk_pattern.search(instr.arguments):
                    if "--no-cache" not in instr.arguments and not apk_clean.search(instr.arguments):
                        diagnostics.append(
                            Diagnostic(
                                rule_id=self.rule_id,
                                title=self.title,
                                message="'apk add' without '--no-cache' leaves package indices in image layer.",
                                severity=self.severity,
                                line=instr.start_line,
                                end_line=instr.end_line,
                                stage_index=instr.stage_index,
                                fixable=True,
                                suggestion="Add '--no-cache' flag to apk add.",
                            )
                        )
        return diagnostics


class AddInsteadOfCopyRule(BaseRule):
    """STYLE001: Prefer COPY over ADD for local files/directories."""
    rule_id = "STYLE001"
    title = "Use COPY Instead of ADD"
    severity = Severity.STYLE
    fixable = True

    def check(self, doc: Dockerfile) -> List[Diagnostic]:
        diagnostics: List[Diagnostic] = []
        for instr in doc.all_instructions:
            if instr.name == "ADD":
                args = instr.arguments.strip()
                # Parse flags if any (e.g. --chown=...)
                parts = args.split()
                sources: List[str] = []
                for p in parts[:-1]:
                    if not p.startswith("--"):
                        sources.append(p)

                # If source is remote URL or archive, ADD is legitimate
                is_legit = False
                for src in sources:
                    lower = src.lower()
                    if lower.startswith("http://") or lower.startswith("https://"):
                        is_legit = True
                        break
                    if any(lower.endswith(ext) for ext in ARCHIVE_EXTS):
                        is_legit = True
                        break

                if not is_legit:
                    diagnostics.append(
                        Diagnostic(
                            rule_id=self.rule_id,
                            title=self.title,
                            message="Use 'COPY' instead of 'ADD' for local files unless automatically extracting tar archives.",
                            severity=self.severity,
                            line=instr.start_line,
                            end_line=instr.end_line,
                            stage_index=instr.stage_index,
                            fixable=True,
                            suggestion="Replace 'ADD' with 'COPY'.",
                        )
                    )
        return diagnostics


class WorkdirRelativeRule(BaseRule):
    """STYLE002: WORKDIR should use absolute paths."""
    rule_id = "STYLE002"
    title = "Relative WORKDIR Path"
    severity = Severity.WARNING
    fixable = True

    def check(self, doc: Dockerfile) -> List[Diagnostic]:
        diagnostics: List[Diagnostic] = []
        for instr in doc.all_instructions:
            if instr.name == "WORKDIR":
                path = instr.arguments.strip()
                # Absolute if starts with /, \, or variable $ / %
                if path and not path.startswith(("/", "\\", "$")):
                    diagnostics.append(
                        Diagnostic(
                            rule_id=self.rule_id,
                            title=self.title,
                            message=f"WORKDIR path '{path}' is relative. Always use absolute paths for clarity.",
                            severity=self.severity,
                            line=instr.start_line,
                            end_line=instr.end_line,
                            stage_index=instr.stage_index,
                            fixable=True,
                            suggestion=f"Change to absolute path '/{path}'.",
                        )
                    )
        return diagnostics


class MultipleCmdOrEntrypointRule(BaseRule):
    """STYLE003: Multiple CMD or ENTRYPOINT instructions in a single stage."""
    rule_id = "STYLE003"
    title = "Multiple CMD or ENTRYPOINT in Same Stage"
    severity = Severity.WARNING
    fixable = True

    def check(self, doc: Dockerfile) -> List[Diagnostic]:
        diagnostics: List[Diagnostic] = []
        for stage in doc.stages:
            cmd_instructions = [i for i in stage.instructions if i.name == "CMD"]
            if len(cmd_instructions) > 1:
                # All except the last one are dead code
                for instr in cmd_instructions[:-1]:
                    diagnostics.append(
                        Diagnostic(
                            rule_id=self.rule_id,
                            title=self.title,
                            message="Multiple CMD instructions found in stage. Only the last CMD takes effect.",
                            severity=self.severity,
                            line=instr.start_line,
                            end_line=instr.end_line,
                            stage_index=stage.index,
                            fixable=True,
                            suggestion="Remove or comment out redundant earlier CMD instruction.",
                        )
                    )

            ep_instructions = [i for i in stage.instructions if i.name == "ENTRYPOINT"]
            if len(ep_instructions) > 1:
                for instr in ep_instructions[:-1]:
                    diagnostics.append(
                        Diagnostic(
                            rule_id=self.rule_id,
                            title=self.title,
                            message="Multiple ENTRYPOINT instructions found in stage. Only the last ENTRYPOINT takes effect.",
                            severity=self.severity,
                            line=instr.start_line,
                            end_line=instr.end_line,
                            stage_index=stage.index,
                            fixable=True,
                            suggestion="Remove or comment out redundant earlier ENTRYPOINT instruction.",
                        )
                    )
        return diagnostics


ALL_RULES: List[BaseRule] = [
    RootUserRule(),
    UnpinnedTagRule(),
    CurlPipeShellRule(),
    SecretInEnvRule(),
    SudoUsageRule(),
    MissingHealthcheckRule(),
    AptGetNoInstallRecommendsRule(),
    AptGetCacheUncleanedRule(),
    AptGetUpdateAloneRule(),
    PipNoCacheRule(),
    ApkNoCacheRule(),
    AddInsteadOfCopyRule(),
    WorkdirRelativeRule(),
    MultipleCmdOrEntrypointRule(),
]

RULE_REGISTRY = {r.rule_id: r for r in ALL_RULES}
