"""Integration and unit tests for CLI entry points."""

import json
from pathlib import Path
import pytest
from dockerfile_doctor.cli import main


def test_cli_version(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    captured = capsys.readouterr()
    assert "dockerfile-doctor 1.0.0" in captured.out


def test_cli_help(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--help"])
    assert exc.value.code == 0
    captured = capsys.readouterr()
    assert "lint" in captured.out
    assert "fix" in captured.out
    assert "scan" in captured.out


def test_cli_lint_clean(tmp_path: Path, capsys):
    df = tmp_path / "Dockerfile"
    df.write_text(
        "FROM alpine:3.19\nUSER 10001\nCMD [\"echo\", \"hello\"]\n",
        encoding="utf-8",
    )
    code = main(["lint", str(df)])
    assert code == 0
    captured = capsys.readouterr()
    assert "No Dockerfile issues found" in captured.out


def test_cli_lint_dirty(tmp_path: Path, capsys):
    df = tmp_path / "Dockerfile"
    df.write_text(
        "FROM alpine:latest\nWORKDIR app\nCMD [\"echo\", \"hi\"]\n",
        encoding="utf-8",
    )
    code = main(["lint", str(df)])
    assert code == 1  # Warnings found
    captured = capsys.readouterr()
    assert "SEC001" in captured.out or "SEC002" in captured.out or "STYLE002" in captured.out


def test_cli_lint_json(tmp_path: Path, capsys):
    df = tmp_path / "Dockerfile"
    df.write_text("FROM alpine:latest\n", encoding="utf-8")
    code = main(["lint", str(df), "--format", "json"])
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert "issues" in data
    assert data["total_issues"] > 0


def test_cli_lint_sarif(tmp_path: Path, capsys):
    df = tmp_path / "Dockerfile"
    df.write_text("FROM alpine:latest\n", encoding="utf-8")
    code = main(["lint", str(df), "--format", "sarif"])
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["version"] == "2.1.0"
    assert "runs" in data


def test_cli_fix_dry_run(tmp_path: Path, capsys):
    df = tmp_path / "Dockerfile"
    df.write_text("FROM alpine:3.19\nWORKDIR app\nADD file.txt /dest/\n", encoding="utf-8")
    code = main(["fix", str(df), "--dry-run"])
    assert code == 0
    captured = capsys.readouterr()
    assert "--- Unified Diff ---" in captured.out
    # Original file is unmodified
    assert "WORKDIR app" in df.read_text(encoding="utf-8")


def test_cli_fix_in_place(tmp_path: Path, capsys):
    df = tmp_path / "Dockerfile"
    df.write_text("FROM alpine:3.19\nWORKDIR app\nADD file.txt /dest/\n", encoding="utf-8")
    code = main(["fix", str(df), "-i"])
    assert code == 0
    content = df.read_text(encoding="utf-8")
    assert "WORKDIR /app" in content
    assert "COPY file.txt /dest/" in content


def test_cli_scan(tmp_path: Path, capsys):
    df = tmp_path / "Dockerfile"
    df.write_text("FROM alpine:3.19\nUSER 10001\nCMD [\"echo\", \"ok\"]\n", encoding="utf-8")
    code = main(["scan", str(df)])
    assert code == 0
    captured = capsys.readouterr()
    assert "Security Score : 100/100" in captured.out
    assert "Grade: A+" in captured.out


def test_cli_scan_fail_under(tmp_path: Path, capsys):
    df = tmp_path / "Dockerfile"
    df.write_text("FROM alpine:latest\nENV SECRET=1234567890\n", encoding="utf-8")
    code = main(["scan", str(df), "--fail-under", "95"])
    assert code == 1  # Score < 95


def test_cli_file_not_found(capsys):
    code = main(["lint", "nonexistent_dockerfile"])
    assert code == 2


def test_cli_lint_stdin(monkeypatch, capsys):
    import io
    monkeypatch.setattr("sys.stdin", io.StringIO("FROM alpine:3.19\nUSER 10001\n"))
    code = main(["lint", "-"])
    assert code == 0
    captured = capsys.readouterr()
    assert "No Dockerfile issues found" in captured.out


def test_cli_fix_stdin(monkeypatch, capsys):
    import io
    monkeypatch.setattr("sys.stdin", io.StringIO("FROM alpine:3.19\nWORKDIR app\n"))
    code = main(["fix", "-"])
    assert code == 0
    captured = capsys.readouterr()
    assert "--- a/<stdin>" in captured.out
    assert "+WORKDIR /app" in captured.out


def test_cli_scan_stdin(monkeypatch, capsys):
    import io
    monkeypatch.setattr("sys.stdin", io.StringIO("FROM alpine:3.19\nUSER 10001\n"))
    code = main(["scan", "-"])
    assert code == 0
    captured = capsys.readouterr()
    assert "DOCKERFILE SECURITY & ARCHITECTURE SCAN" in captured.out


def test_cli_scan_json(tmp_path: Path, capsys):
    df = tmp_path / "Dockerfile"
    df.write_text("FROM alpine:3.19\nUSER 10001\n", encoding="utf-8")
    code = main(["scan", str(df), "--format", "json"])
    assert code == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["security_score"] == 100
    assert data["grade"] == "A+"


def test_cli_scan_strict(tmp_path: Path):
    df = tmp_path / "Dockerfile"
    df.write_text("FROM alpine:latest\n", encoding="utf-8")
    code = main(["scan", str(df), "--strict"])
    assert code == 1


def test_cli_lint_strict(tmp_path: Path):
    df = tmp_path / "Dockerfile"
    df.write_text("FROM alpine:3.19\nUSER 10001\n", encoding="utf-8")
    code = main(["lint", str(df), "--strict"])
    assert code == 0


def test_cli_directory_path(tmp_path: Path, capsys):
    df = tmp_path / "Dockerfile"
    df.write_text("FROM alpine:3.19\nUSER 10001\n", encoding="utf-8")
    code = main(["lint", str(tmp_path)])
    assert code == 0
    captured = capsys.readouterr()
    assert "No Dockerfile issues found" in captured.out

