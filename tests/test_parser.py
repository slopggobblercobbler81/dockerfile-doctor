"""Unit tests for Dockerfile parser."""

from dockerfile_doctor.parser import parse_dockerfile_content


def test_parse_simple_dockerfile():
    content = """FROM python:3.11-slim
WORKDIR /app
COPY . .
RUN pip install --no-cache-dir -r requirements.txt
USER 10001
CMD ["python", "app.py"]
"""
    doc = parse_dockerfile_content(content)
    assert len(doc.stages) == 1
    stage = doc.stages[0]
    assert stage.base_image == "python"
    assert stage.base_tag == "3.11-slim"
    assert stage.name is None
    assert len(stage.instructions) == 6
    assert stage.instructions[0].name == "FROM"
    assert stage.instructions[1].name == "WORKDIR"
    assert stage.instructions[1].arguments == "/app"
    assert stage.instructions[5].name == "CMD"
    assert stage.instructions[5].is_json_form


def test_parse_multistage():
    content = """# syntax=docker/dockerfile:1
FROM golang:1.22-alpine AS builder
WORKDIR /src
COPY . .
RUN go build -o /app/server .

FROM alpine:3.19 AS runner
WORKDIR /app
COPY --from=builder /app/server /app/server
USER 10001
ENTRYPOINT ["/app/server"]
"""
    doc = parse_dockerfile_content(content)
    assert doc.directives.get("syntax") == "docker/dockerfile:1"
    assert len(doc.stages) == 2

    builder = doc.stages[0]
    assert builder.name == "builder"
    assert builder.base_image == "golang"
    assert builder.base_tag == "1.22-alpine"

    runner = doc.stages[1]
    assert runner.name == "runner"
    assert runner.base_image == "alpine"
    assert runner.base_tag == "3.19"
    assert runner.has_user_instruction is True


def test_parse_line_continuations_and_comments():
    content = """FROM ubuntu:22.04
# Update system
RUN apt-get update && \\
    # install curl
    apt-get install -y curl && \\
    rm -rf /var/lib/apt/lists/*
WORKDIR /root
"""
    doc = parse_dockerfile_content(content)
    assert len(doc.stages) == 1
    run_inst = [i for i in doc.all_instructions if i.name == "RUN"][0]
    assert "apt-get update" in run_inst.arguments
    assert "rm -rf /var/lib/apt/lists/*" in run_inst.arguments
    assert run_inst.start_line == 3
    assert run_inst.end_line == 6


def test_parse_platform_and_digest():
    content = "FROM --platform=linux/amd64 node:20.10.0@sha256:abcdef123456 AS base"
    doc = parse_dockerfile_content(content)
    stage = doc.stages[0]
    assert stage.platform == "linux/amd64"
    assert stage.base_image == "node"
    assert stage.base_tag == "20.10.0"
    assert stage.base_digest == "sha256:abcdef123456"
    assert stage.name == "base"


def test_scratch_stage():
    content = "FROM scratch\nCOPY --from=0 /app /app\nUSER 1000\nENTRYPOINT [\"/app\"]"
    doc = parse_dockerfile_content(content)
    assert doc.stages[0].is_scratch is True
