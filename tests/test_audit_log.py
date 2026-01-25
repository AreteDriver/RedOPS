"""Tests for audit log module."""

import pytest
import json
from unittest.mock import MagicMock, patch
from pathlib import Path
from datetime import datetime, timezone

from redops.modules.compliance.audit_log import (
    create_audit_entry,
    log_to_file,
    audit_pipeline_start,
    audit_pipeline_end,
)


class TestCreateAuditEntry:
    """Tests for create_audit_entry function."""

    def test_basic_entry(self):
        """Test creating basic audit entry."""
        entry = create_audit_entry(
            action="test_action",
            target="example.com"
        )

        assert entry["action"] == "test_action"
        assert entry["target"] == "example.com"
        assert entry["user"] == "system"
        assert entry["metadata"] == {}
        assert "timestamp" in entry

    def test_with_user(self):
        """Test entry with custom user."""
        entry = create_audit_entry(
            action="scan",
            target="example.com",
            user="admin"
        )

        assert entry["user"] == "admin"

    def test_with_metadata(self):
        """Test entry with metadata."""
        entry = create_audit_entry(
            action="scan",
            target="example.com",
            metadata={"preset": "full", "duration": 120}
        )

        assert entry["metadata"]["preset"] == "full"
        assert entry["metadata"]["duration"] == 120

    def test_timestamp_format(self):
        """Test timestamp is ISO format."""
        entry = create_audit_entry(
            action="test",
            target="target"
        )

        # Should be parseable as ISO format
        timestamp = entry["timestamp"]
        assert "T" in timestamp
        # Should be UTC
        assert timestamp.endswith("+00:00") or timestamp.endswith("Z")

    def test_none_metadata_becomes_empty_dict(self):
        """Test None metadata becomes empty dict."""
        entry = create_audit_entry(
            action="test",
            target="target",
            metadata=None
        )

        assert entry["metadata"] == {}


class TestLogToFile:
    """Tests for log_to_file function."""

    def test_creates_log_file(self, tmp_path):
        """Test log file creation."""
        log_file = tmp_path / "audit.log"

        entry = create_audit_entry(action="test", target="target")
        log_to_file(entry, log_file)

        assert log_file.exists()

    def test_writes_json_line(self, tmp_path):
        """Test writes JSON line."""
        log_file = tmp_path / "audit.log"

        entry = create_audit_entry(action="test", target="target")
        log_to_file(entry, log_file)

        content = log_file.read_text()
        parsed = json.loads(content.strip())
        assert parsed["action"] == "test"
        assert parsed["target"] == "target"

    def test_appends_to_existing(self, tmp_path):
        """Test appends to existing file."""
        log_file = tmp_path / "audit.log"

        entry1 = create_audit_entry(action="first", target="target1")
        entry2 = create_audit_entry(action="second", target="target2")

        log_to_file(entry1, log_file)
        log_to_file(entry2, log_file)

        lines = log_file.read_text().strip().split("\n")
        assert len(lines) == 2

        parsed1 = json.loads(lines[0])
        parsed2 = json.loads(lines[1])
        assert parsed1["action"] == "first"
        assert parsed2["action"] == "second"

    def test_creates_parent_directories(self, tmp_path):
        """Test creates parent directories."""
        log_file = tmp_path / "nested" / "path" / "audit.log"

        entry = create_audit_entry(action="test", target="target")
        log_to_file(entry, log_file)

        assert log_file.exists()
        assert (tmp_path / "nested" / "path").is_dir()

    def test_with_complex_metadata(self, tmp_path):
        """Test logging complex metadata."""
        log_file = tmp_path / "audit.log"

        entry = create_audit_entry(
            action="scan",
            target="example.com",
            metadata={
                "modules": ["dns", "tech", "vuln"],
                "nested": {"key": "value"},
                "count": 42,
            }
        )
        log_to_file(entry, log_file)

        parsed = json.loads(log_file.read_text().strip())
        assert parsed["metadata"]["modules"] == ["dns", "tech", "vuln"]
        assert parsed["metadata"]["nested"]["key"] == "value"


class TestAuditPipelineStart:
    """Tests for audit_pipeline_start function."""

    def test_returns_context(self):
        """Test returns context."""
        ctx = MagicMock()
        ctx.target = "example.com"
        ctx.get.return_value = None

        result = audit_pipeline_start(ctx)
        assert result == ctx

    def test_adds_audit_start(self):
        """Test adds audit_start to context."""
        ctx = MagicMock()
        ctx.target = "example.com"
        ctx.get.return_value = None

        audit_pipeline_start(ctx)

        ctx.add.assert_called()
        call_args = ctx.add.call_args[0]
        assert call_args[0] == "audit_start"
        assert isinstance(call_args[1], dict)
        assert call_args[1]["action"] == "pipeline_start"

    def test_logs_message(self):
        """Test logs info message."""
        ctx = MagicMock()
        ctx.target = "example.com"
        ctx.get.return_value = None

        audit_pipeline_start(ctx)

        ctx.log.assert_called()
        log_args = ctx.log.call_args
        assert "audit" in log_args[0][0].lower()
        assert log_args[1]["level"] == "INFO"

    def test_includes_pipeline_metadata(self):
        """Test includes pipeline name and version."""
        ctx = MagicMock()
        ctx.target = "example.com"

        def get_side_effect(key):
            if key == "pipeline_name":
                return "test_pipeline"
            if key == "pipeline_version":
                return "1.0"
            return None

        ctx.get.side_effect = get_side_effect

        audit_pipeline_start(ctx)

        call_args = ctx.add.call_args[0]
        entry = call_args[1]
        assert entry["metadata"]["pipeline"] == "test_pipeline"
        assert entry["metadata"]["version"] == "1.0"

    def test_handles_none_target(self):
        """Test handles None target."""
        ctx = MagicMock()
        ctx.target = None
        ctx.get.return_value = None

        audit_pipeline_start(ctx)

        call_args = ctx.add.call_args[0]
        entry = call_args[1]
        assert entry["target"] == "N/A"

    def test_writes_to_log_file(self, tmp_path):
        """Test writes to log file when specified."""
        log_file = tmp_path / "audit.log"

        ctx = MagicMock()
        ctx.target = "example.com"
        ctx.get.return_value = None

        audit_pipeline_start(ctx, {"log_file": str(log_file)})

        assert log_file.exists()
        parsed = json.loads(log_file.read_text().strip())
        assert parsed["action"] == "pipeline_start"

    def test_no_log_file_without_param(self, tmp_path):
        """Test no log file created without param."""
        ctx = MagicMock()
        ctx.target = "example.com"
        ctx.get.return_value = None

        audit_pipeline_start(ctx, {})

        # No file should be created
        assert not list(tmp_path.glob("*.log"))

    def test_handles_none_params(self):
        """Test handles None params."""
        ctx = MagicMock()
        ctx.target = "example.com"
        ctx.get.return_value = None

        result = audit_pipeline_start(ctx, None)
        assert result == ctx


class TestAuditPipelineEnd:
    """Tests for audit_pipeline_end function."""

    def test_returns_context(self):
        """Test returns context."""
        ctx = MagicMock()
        ctx.target = "example.com"
        ctx.get.return_value = None
        ctx.logs = []
        ctx.data = {}

        result = audit_pipeline_end(ctx)
        assert result == ctx

    def test_adds_audit_end(self):
        """Test adds audit_end to context."""
        ctx = MagicMock()
        ctx.target = "example.com"
        ctx.get.return_value = None
        ctx.logs = []
        ctx.data = {}

        audit_pipeline_end(ctx)

        ctx.add.assert_called()
        call_args = ctx.add.call_args[0]
        assert call_args[0] == "audit_end"
        assert isinstance(call_args[1], dict)
        assert call_args[1]["action"] == "pipeline_end"

    def test_logs_message(self):
        """Test logs info message."""
        ctx = MagicMock()
        ctx.target = "example.com"
        ctx.get.return_value = None
        ctx.logs = []
        ctx.data = {}

        audit_pipeline_end(ctx)

        ctx.log.assert_called()
        log_args = ctx.log.call_args
        assert "completed" in log_args[0][0].lower() or "audit" in log_args[0][0].lower()
        assert log_args[1]["level"] == "INFO"

    def test_includes_log_count(self):
        """Test includes log count in metadata."""
        ctx = MagicMock()
        ctx.target = "example.com"
        ctx.get.return_value = None
        ctx.logs = ["log1", "log2", "log3"]
        ctx.data = {}

        audit_pipeline_end(ctx)

        call_args = ctx.add.call_args[0]
        entry = call_args[1]
        assert entry["metadata"]["log_count"] == 3

    def test_includes_data_keys(self):
        """Test includes data keys in metadata."""
        ctx = MagicMock()
        ctx.target = "example.com"
        ctx.get.return_value = None
        ctx.logs = []
        ctx.data = {"domain_profile": {}, "tech_stack": {}, "findings": []}

        audit_pipeline_end(ctx)

        call_args = ctx.add.call_args[0]
        entry = call_args[1]
        assert "domain_profile" in entry["metadata"]["data_keys"]
        assert "tech_stack" in entry["metadata"]["data_keys"]
        assert "findings" in entry["metadata"]["data_keys"]

    def test_handles_none_target(self):
        """Test handles None target."""
        ctx = MagicMock()
        ctx.target = None
        ctx.get.return_value = None
        ctx.logs = []
        ctx.data = {}

        audit_pipeline_end(ctx)

        call_args = ctx.add.call_args[0]
        entry = call_args[1]
        assert entry["target"] == "N/A"

    def test_writes_to_log_file(self, tmp_path):
        """Test writes to log file when specified."""
        log_file = tmp_path / "audit.log"

        ctx = MagicMock()
        ctx.target = "example.com"
        ctx.get.return_value = None
        ctx.logs = []
        ctx.data = {}

        audit_pipeline_end(ctx, {"log_file": str(log_file)})

        assert log_file.exists()
        parsed = json.loads(log_file.read_text().strip())
        assert parsed["action"] == "pipeline_end"

    def test_handles_none_params(self):
        """Test handles None params."""
        ctx = MagicMock()
        ctx.target = "example.com"
        ctx.get.return_value = None
        ctx.logs = []
        ctx.data = {}

        result = audit_pipeline_end(ctx, None)
        assert result == ctx


class TestIntegration:
    """Integration tests for audit log module."""

    def test_full_audit_flow(self, tmp_path):
        """Test complete start-to-end audit flow."""
        log_file = tmp_path / "pipeline_audit.log"

        ctx = MagicMock()
        ctx.target = "example.com"

        def get_side_effect(key):
            if key == "pipeline_name":
                return "security_scan"
            if key == "pipeline_version":
                return "2.0"
            return None

        ctx.get.side_effect = get_side_effect
        ctx.logs = ["Starting scan...", "Scan complete"]
        ctx.data = {"findings": [1, 2, 3]}

        # Start
        params = {"log_file": str(log_file)}
        audit_pipeline_start(ctx, params)

        # End
        audit_pipeline_end(ctx, params)

        # Verify log file
        lines = log_file.read_text().strip().split("\n")
        assert len(lines) == 2

        start_entry = json.loads(lines[0])
        end_entry = json.loads(lines[1])

        assert start_entry["action"] == "pipeline_start"
        assert end_entry["action"] == "pipeline_end"
        assert end_entry["metadata"]["log_count"] == 2
        assert "findings" in end_entry["metadata"]["data_keys"]

    def test_multiple_pipelines(self, tmp_path):
        """Test auditing multiple pipelines."""
        log_file = tmp_path / "multi_audit.log"
        params = {"log_file": str(log_file)}

        for i in range(3):
            ctx = MagicMock()
            ctx.target = f"target{i}.com"
            ctx.get.return_value = f"pipeline_{i}"
            ctx.logs = []
            ctx.data = {}

            audit_pipeline_start(ctx, params)
            audit_pipeline_end(ctx, params)

        lines = log_file.read_text().strip().split("\n")
        assert len(lines) == 6  # 3 starts + 3 ends
