"""Tests for the Reporting modules."""

from pathlib import Path
from redops.core.context import Context
from redops.modules.reporting.markdown_report import (
    generate_exec_summary,
    build_executive_summary,
)


def test_build_executive_summary_basic():
    """Test building basic executive summary."""
    ctx = Context(target="example.com")
    ctx.add(
        "domain_profile",
        {"domain": "example.com", "dns_records": {"A": ["93.184.216.34"]}},
    )

    summary = build_executive_summary(ctx)

    assert isinstance(summary, str)
    assert len(summary) > 0
    assert "example.com" in summary.lower() or "executive" in summary.lower()


def test_build_executive_summary_with_findings():
    """Test building summary with findings."""
    ctx = Context(target="test.com")
    ctx.add(
        "finding_1",
        {
            "title": "Test Finding",
            "description": "Test description",
            "severity": "INFO",
        },
    )

    summary = build_executive_summary(ctx)

    assert isinstance(summary, str)
    assert len(summary) > 0


def test_generate_exec_summary_creates_file(tmp_path):
    """Test that executive summary generates a file."""
    ctx = Context(target="example.com")
    ctx.add("test_data", "test_value")

    result = generate_exec_summary(ctx, params={"output_dir": str(tmp_path)})

    assert result is not None
    assert "executive_summary_path" in result.data

    # Check file was created
    output_path = Path(result.data["executive_summary_path"])
    assert output_path.exists()
    assert output_path.suffix == ".md"


def test_generate_exec_summary_file_content(tmp_path):
    """Test that executive summary file has content."""
    ctx = Context(target="example.com")

    result = generate_exec_summary(ctx, params={"output_dir": str(tmp_path)})

    output_path = Path(result.data["executive_summary_path"])
    content = output_path.read_text()

    assert len(content) > 0


def test_generate_exec_summary_creates_directory(tmp_path):
    """Test that summary generation creates output directory if needed."""
    output_dir = tmp_path / "nested" / "output"

    ctx = Context(target="test.com")
    result = generate_exec_summary(ctx, params={"output_dir": str(output_dir)})

    assert output_dir.exists()
    assert "executive_summary_path" in result.data


def test_generate_exec_summary_default_path(tmp_path, monkeypatch):
    """Test executive summary with default output path."""
    # Change to tmp directory
    monkeypatch.chdir(tmp_path)

    ctx = Context(target="example.com")
    result = generate_exec_summary(ctx)

    assert "executive_summary_path" in result.data


def test_generate_exec_summary_logging(tmp_path):
    """Test that summary generation logs appropriately."""
    ctx = Context(target="example.com")
    result = generate_exec_summary(ctx, params={"output_dir": str(tmp_path)})

    info_logs = result.get_logs(level="INFO")
    assert len(info_logs) > 0
    assert any("executive summary" in log["message"].lower() for log in info_logs)


def test_generate_exec_summary_no_params(tmp_path, monkeypatch):
    """Test executive summary generation without params."""
    monkeypatch.chdir(tmp_path)

    ctx = Context(target="test.com")
    result = generate_exec_summary(ctx)

    assert result is not None
    assert "executive_summary_path" in result.data


def test_build_executive_summary_empty_context():
    """Test building summary with empty context."""
    ctx = Context()
    summary = build_executive_summary(ctx)

    assert isinstance(summary, str)
    # Should still produce some output even if minimal


def test_generate_exec_summary_filename_format(tmp_path):
    """Test that generated filename follows expected format."""
    ctx = Context(target="example.com")
    result = generate_exec_summary(ctx, params={"output_dir": str(tmp_path)})

    path = Path(result.data["executive_summary_path"])
    assert path.name.startswith("executive_summary_")
    assert path.suffix == ".md"
    # Check timestamp format in filename
    assert "_" in path.stem
