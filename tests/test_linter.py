"""Unit tests for linter functionality."""

from dockerfile_doctor.linter import lint_dockerfile_content
from dockerfile_doctor.models import Severity


def test_lint_clean_dockerfile():
    dockerfile = """FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
HEALTHCHECK --interval=30s CMD curl -f http://localhost:8000/ || exit 1
USER 10001
CMD ["python", "main.py"]
"""
    diags = lint_dockerfile_content(dockerfile)
    assert len(diags) == 0


def test_lint_dirty_dockerfile():
    dockerfile = """FROM python
WORKDIR app
ADD requirements.txt .
RUN sudo apt-get update
RUN pip install -r requirements.txt
CMD ["python", "app1.py"]
CMD ["python", "app2.py"]
"""
    diags = lint_dockerfile_content(dockerfile)
    rule_ids = {d.rule_id for d in diags}

    assert "SEC001" in rule_ids  # root user
    assert "SEC002" in rule_ids  # unpinned tag
    assert "SEC005" in rule_ids  # sudo
    assert "PERF004" in rule_ids  # pip no cache
    assert "STYLE001" in rule_ids  # ADD instead of COPY
    assert "STYLE002" in rule_ids  # relative workdir
    assert "STYLE003" in rule_ids  # multiple CMD


def test_lint_filtering():
    dockerfile = """FROM python:latest
WORKDIR relative
ADD file.txt /dest/
"""
    # Exclude all except STYLE002
    diags = lint_dockerfile_content(dockerfile, include_rules={"STYLE002"})
    assert len(diags) == 1
    assert diags[0].rule_id == "STYLE002"

    # Ignore STYLE002
    diags_ignored = lint_dockerfile_content(dockerfile, ignore_rules={"STYLE002"})
    assert not any(d.rule_id == "STYLE002" for d in diags_ignored)
