"""Unit tests for multi-stage build validation and dependency graph."""

from dockerfile_doctor.multistage import build_stage_graph, validate_multistage
from dockerfile_doctor.parser import parse_dockerfile_content


def test_valid_multistage():
    content = """FROM golang:1.22-alpine AS builder
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
    diags = validate_multistage(doc)
    assert len(diags) == 0

    graph = build_stage_graph(doc)
    assert graph["stage_count"] == 2
    assert len(graph["edges"]) == 1
    assert graph["edges"][0]["from_stage"] == 0
    assert graph["edges"][0]["to_stage"] == 1


def test_ms001_missing_stage_reference():
    content = """FROM alpine:3.19 AS runner
COPY --from=nonexistent /file /file
"""
    doc = parse_dockerfile_content(content)
    diags = validate_multistage(doc)
    assert len(diags) == 1
    assert diags[0].rule_id == "MS001"
    assert "nonexistent" in diags[0].message


def test_ms002_forward_stage_reference():
    content = """FROM alpine:3.19 AS stage0
COPY --from=stage1 /data /data

FROM alpine:3.19 AS stage1
RUN touch /data
"""
    doc = parse_dockerfile_content(content)
    diags = validate_multistage(doc)
    assert any(d.rule_id == "MS002" for d in diags)


def test_ms003_unused_stage():
    content = """FROM alpine:3.19 AS unused_stage
RUN touch /temp

FROM alpine:3.19 AS final_stage
USER nonroot
CMD ["echo", "hello"]
"""
    doc = parse_dockerfile_content(content)
    diags = validate_multistage(doc)
    assert any(d.rule_id == "MS003" for d in diags)


def test_ms004_duplicate_stage_name():
    content = """FROM alpine:3.19 AS builder
RUN echo 1

FROM alpine:3.19 AS builder
RUN echo 2
"""
    doc = parse_dockerfile_content(content)
    diags = validate_multistage(doc)
    assert any(d.rule_id == "MS004" for d in diags)
