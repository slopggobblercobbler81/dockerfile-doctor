"""Unit tests for automated autofixer."""

from pathlib import Path
from dockerfile_doctor.fixer import fix_dockerfile, fix_dockerfile_content


def test_fix_add_to_copy():
    content = "FROM alpine:3.19\nADD config.yaml /etc/config.yaml\n"
    fixed, diff, fixes = fix_dockerfile_content(content, rules={"STYLE001"})
    assert "COPY config.yaml /etc/config.yaml" in fixed
    assert len(fixes) == 1
    assert fixes[0].rule_id == "STYLE001"
    assert "--- a/Dockerfile" in diff


def test_fix_workdir_relative():
    content = "FROM alpine:3.19\nWORKDIR app/src\n"
    fixed, diff, fixes = fix_dockerfile_content(content, rules={"STYLE002"})
    assert "WORKDIR /app/src" in fixed
    assert len(fixes) == 1
    assert fixes[0].rule_id == "STYLE002"


def test_fix_pip_no_cache():
    content = "FROM python:3.11-slim\nRUN pip install fastapi uvicorn\n"
    fixed, diff, fixes = fix_dockerfile_content(content, rules={"PERF004"})
    assert "pip install --no-cache-dir fastapi uvicorn" in fixed
    assert len(fixes) == 1


def test_fix_apk_no_cache():
    content = "FROM alpine:3.19\nRUN apk add curl git\n"
    fixed, diff, fixes = fix_dockerfile_content(content, rules={"PERF005"})
    assert "apk add --no-cache curl git" in fixed
    assert len(fixes) == 1


def test_fix_apt_get():
    content = "FROM ubuntu:22.04\nRUN apt-get update && apt-get install -y curl\n"
    fixed, diff, fixes = fix_dockerfile_content(content, rules={"PERF001", "PERF002"})
    assert "--no-install-recommends" in fixed
    assert "rm -rf /var/lib/apt/lists/*" in fixed
    assert len(fixes) >= 2


def test_fix_sudo_removal():
    content = "FROM ubuntu:22.04\nRUN sudo apt-get update\n"
    fixed, diff, fixes = fix_dockerfile_content(content, rules={"SEC005"})
    assert "RUN apt-get update" in fixed
    assert "sudo" not in fixed


def test_fix_root_user():
    content = "FROM python:3.11-slim\nWORKDIR /app\nCMD [\"python\", \"app.py\"]\n"
    fixed, diff, fixes = fix_dockerfile_content(content, rules={"SEC001"})
    assert "USER 10001" in fixed
    # USER should be inserted before CMD
    user_pos = fixed.find("USER 10001")
    cmd_pos = fixed.find("CMD")
    assert user_pos < cmd_pos


def test_fix_file_in_place(tmp_path: Path):
    df_path = tmp_path / "Dockerfile"
    df_path.write_text("FROM alpine:3.19\nWORKDIR myapp\nADD file.txt /dest/\n", encoding="utf-8")

    fixed, diff, fixes = fix_dockerfile(df_path, in_place=True)
    assert len(fixes) == 3
    disk_content = df_path.read_text(encoding="utf-8")
    assert "WORKDIR /myapp" in disk_content
    assert "COPY file.txt /dest/" in disk_content
    assert "USER 10001" in disk_content


def test_fix_healthcheck():
    content = "FROM alpine:3.19\nEXPOSE 8080\nUSER 10001\nCMD [\"/app\"]\n"
    fixed, diff, fixes = fix_dockerfile_content(content, rules={"SEC006"})
    assert "HEALTHCHECK" in fixed
    assert len(fixes) == 1
    assert fixes[0].rule_id == "SEC006"
