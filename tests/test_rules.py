"""Unit tests for individual dockerfile-doctor lint rules."""

from dockerfile_doctor.parser import parse_dockerfile_content
from dockerfile_doctor.rules import (
    AddInsteadOfCopyRule,
    ApkNoCacheRule,
    AptGetCacheUncleanedRule,
    AptGetNoInstallRecommendsRule,
    AptGetUpdateAloneRule,
    CurlPipeShellRule,
    MissingHealthcheckRule,
    MultipleCmdOrEntrypointRule,
    PipNoCacheRule,
    RootUserRule,
    SecretInEnvRule,
    SudoUsageRule,
    UnpinnedTagRule,
    WorkdirRelativeRule,
)


def test_sec001_root_user():
    rule = RootUserRule()

    # Insecure: no USER
    bad_doc = parse_dockerfile_content("FROM python:3.11-slim\nCMD [\"python\", \"app.py\"]")
    diags = rule.check(bad_doc)
    assert len(diags) == 1
    assert diags[0].rule_id == "SEC001"

    # Insecure: USER root
    bad_root_doc = parse_dockerfile_content("FROM python:3.11-slim\nUSER root\nCMD [\"python\", \"app.py\"]")
    assert len(rule.check(bad_root_doc)) == 1

    # Secure: USER appuser
    good_doc = parse_dockerfile_content("FROM python:3.11-slim\nUSER appuser\nCMD [\"python\", \"app.py\"]")
    assert len(rule.check(good_doc)) == 0


def test_sec002_unpinned_tag():
    rule = UnpinnedTagRule()

    # Missing tag
    doc1 = parse_dockerfile_content("FROM python\nRUN true")
    diags1 = rule.check(doc1)
    assert len(diags1) == 1
    assert "no tag specified" in diags1[0].message

    # Tag :latest
    doc2 = parse_dockerfile_content("FROM python:latest\nRUN true")
    diags2 = rule.check(doc2)
    assert len(diags2) == 1
    assert "uses mutable ':latest' tag" in diags2[0].message

    # Pinned tag: valid
    doc3 = parse_dockerfile_content("FROM python:3.11-slim\nRUN true")
    assert len(rule.check(doc3)) == 0


def test_sec003_curl_pipe_shell():
    rule = CurlPipeShellRule()

    bad_doc = parse_dockerfile_content("FROM alpine:3.19\nRUN curl -fsSL https://example.com/install.sh | sh")
    diags = rule.check(bad_doc)
    assert len(diags) == 1
    assert diags[0].rule_id == "SEC003"
    assert diags[0].cwe == "CWE-494"

    good_doc = parse_dockerfile_content("FROM alpine:3.19\nRUN curl -O https://example.com/file.tar.gz")
    assert len(rule.check(good_doc)) == 0


def test_sec004_secret_in_env():
    rule = SecretInEnvRule()

    bad_doc = parse_dockerfile_content("FROM alpine:3.19\nENV API_KEY=secret_token_123456789")
    diags = rule.check(bad_doc)
    assert len(diags) == 1
    assert diags[0].rule_id == "SEC004"
    assert diags[0].cwe == "CWE-798"

    good_doc = parse_dockerfile_content("FROM alpine:3.19\nENV PORT=8080\nENV ENV=production")
    assert len(rule.check(good_doc)) == 0


def test_sec005_sudo_usage():
    rule = SudoUsageRule()

    bad_doc = parse_dockerfile_content("FROM ubuntu:22.04\nRUN sudo apt-get update")
    diags = rule.check(bad_doc)
    assert len(diags) == 1
    assert diags[0].rule_id == "SEC005"

    good_doc = parse_dockerfile_content("FROM ubuntu:22.04\nRUN apt-get update")
    assert len(rule.check(good_doc)) == 0


def test_sec006_missing_healthcheck():
    rule = MissingHealthcheckRule()

    # Exposes port but no healthcheck
    bad_doc = parse_dockerfile_content("FROM python:3.11-slim\nEXPOSE 8080\nUSER nonroot\nCMD [\"python\", \"app.py\"]")
    diags = rule.check(bad_doc)
    assert len(diags) == 1
    assert diags[0].rule_id == "SEC006"

    # Has healthcheck
    good_doc = parse_dockerfile_content(
        "FROM python:3.11-slim\nEXPOSE 8080\nHEALTHCHECK CMD curl -f http://localhost:8080/ || exit 1\nUSER nonroot\nCMD [\"python\", \"app.py\"]"
    )
    assert len(rule.check(good_doc)) == 0


def test_perf001_apt_get_no_install_recommends():
    rule = AptGetNoInstallRecommendsRule()

    bad_doc = parse_dockerfile_content("FROM ubuntu:22.04\nRUN apt-get update && apt-get install -y curl")
    diags = rule.check(bad_doc)
    assert len(diags) == 1
    assert diags[0].rule_id == "PERF001"

    good_doc = parse_dockerfile_content("FROM ubuntu:22.04\nRUN apt-get update && apt-get install -y --no-install-recommends curl")
    assert len(rule.check(good_doc)) == 0


def test_perf002_apt_get_cache_uncleaned():
    rule = AptGetCacheUncleanedRule()

    bad_doc = parse_dockerfile_content("FROM ubuntu:22.04\nRUN apt-get update && apt-get install -y --no-install-recommends curl")
    diags = rule.check(bad_doc)
    assert len(diags) == 1
    assert diags[0].rule_id == "PERF002"

    good_doc = parse_dockerfile_content("FROM ubuntu:22.04\nRUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*")
    assert len(rule.check(good_doc)) == 0


def test_perf003_apt_get_update_alone():
    rule = AptGetUpdateAloneRule()

    bad_doc = parse_dockerfile_content("FROM ubuntu:22.04\nRUN apt-get update\nRUN apt-get install -y curl")
    diags = rule.check(bad_doc)
    assert len(diags) == 1
    assert diags[0].rule_id == "PERF003"


def test_perf004_pip_no_cache():
    rule = PipNoCacheRule()

    bad_doc = parse_dockerfile_content("FROM python:3.11-slim\nRUN pip install fastapi")
    diags = rule.check(bad_doc)
    assert len(diags) == 1
    assert diags[0].rule_id == "PERF004"

    good_doc = parse_dockerfile_content("FROM python:3.11-slim\nRUN pip install --no-cache-dir fastapi")
    assert len(rule.check(good_doc)) == 0


def test_perf005_apk_no_cache():
    rule = ApkNoCacheRule()

    bad_doc = parse_dockerfile_content("FROM alpine:3.19\nRUN apk add git")
    diags = rule.check(bad_doc)
    assert len(diags) == 1
    assert diags[0].rule_id == "PERF005"

    good_doc = parse_dockerfile_content("FROM alpine:3.19\nRUN apk add --no-cache git")
    assert len(rule.check(good_doc)) == 0


def test_style001_add_instead_of_copy():
    rule = AddInsteadOfCopyRule()

    # Local file with ADD
    bad_doc = parse_dockerfile_content("FROM alpine:3.19\nADD app.py /app/app.py")
    diags = rule.check(bad_doc)
    assert len(diags) == 1
    assert diags[0].rule_id == "STYLE001"

    # Tar archive with ADD is allowed
    tar_doc = parse_dockerfile_content("FROM alpine:3.19\nADD bundle.tar.gz /app/")
    assert len(rule.check(tar_doc)) == 0

    # URL with ADD is allowed
    url_doc = parse_dockerfile_content("FROM alpine:3.19\nADD https://example.com/file.txt /app/")
    assert len(rule.check(url_doc)) == 0


def test_style002_workdir_relative():
    rule = WorkdirRelativeRule()

    bad_doc = parse_dockerfile_content("FROM alpine:3.19\nWORKDIR app/src")
    diags = rule.check(bad_doc)
    assert len(diags) == 1
    assert diags[0].rule_id == "STYLE002"

    good_doc = parse_dockerfile_content("FROM alpine:3.19\nWORKDIR /app/src")
    assert len(rule.check(good_doc)) == 0


def test_style003_multiple_cmd():
    rule = MultipleCmdOrEntrypointRule()

    bad_doc = parse_dockerfile_content("FROM alpine:3.19\nCMD [\"echo\", \"1\"]\nCMD [\"echo\", \"2\"]")
    diags = rule.check(bad_doc)
    assert len(diags) == 1
    assert diags[0].rule_id == "STYLE003"
    assert diags[0].line == 2  # Flags the first redundant CMD
