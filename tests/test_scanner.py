"""Unit tests for scanner and security grading."""

from dockerfile_doctor.scanner import scan_dockerfile_content


def test_scan_clean():
    clean_dockerfile = """FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
HEALTHCHECK --interval=30s CMD curl -f http://localhost:8000/ || exit 1
USER 10001
CMD ["python", "main.py"]
"""
    report = scan_dockerfile_content(clean_dockerfile)
    assert report.security_score == 100
    assert report.grade == "A+"
    assert report.stats["errors"] == 0
    assert report.stats["warnings"] == 0
    assert len(report.diagnostics) == 0


def test_scan_dirty():
    dirty_dockerfile = """FROM python:latest
ENV API_KEY=super_secret_token_12345
RUN curl -fsSL https://get.example.com/install.sh | bash
RUN pip install flask
EXPOSE 5000
CMD ["python", "app.py"]
"""
    report = scan_dockerfile_content(dirty_dockerfile)
    assert report.security_score < 70
    assert report.grade in ("D", "F")
    assert report.stats["errors"] >= 2  # secret + curl pipe
    assert len(report.recommendations) > 0
    assert report.total_stages == 1
