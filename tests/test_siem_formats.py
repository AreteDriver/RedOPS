"""Tests for SIEM export formats."""

import json
import pytest
from datetime import datetime, timezone

from redops.modules.export.siem.formats import (
    SecurityEvent,
    CEFExporter,
    LEEFExporter,
    SyslogExporter,
    JSONLExporter,
    SentinelExporter,
    export_to_cef,
    export_to_leef,
    export_to_syslog,
    export_to_jsonl,
    export_to_sentinel,
)


@pytest.fixture
def sample_event():
    """Create a sample security event."""
    return SecurityEvent(
        event_id="EVT-001",
        timestamp=datetime(2025, 1, 26, 12, 0, 0, tzinfo=timezone.utc),
        severity="high",
        event_type="vulnerability",
        target_host="example.com",
        target_ip="192.168.1.100",
        target_port=443,
        target_url="https://example.com/api/login",
        title="SQL Injection Detected",
        description="SQL injection vulnerability found in login endpoint",
        category="injection",
        technique_id="T1190",
        cve_id="CVE-2025-1234",
        tags=["sql", "injection", "critical-path"],
    )


@pytest.fixture
def multiple_events(sample_event):
    """Create multiple events with different severities."""
    return [
        sample_event,
        SecurityEvent(
            event_id="EVT-002",
            timestamp=datetime(2025, 1, 26, 12, 5, 0, tzinfo=timezone.utc),
            severity="medium",
            event_type="misconfiguration",
            target_host="api.example.com",
            title="Missing Security Headers",
            description="X-Frame-Options header not set",
            category="headers",
        ),
        SecurityEvent(
            event_id="EVT-003",
            timestamp=datetime(2025, 1, 26, 12, 10, 0, tzinfo=timezone.utc),
            severity="info",
            event_type="information",
            target_host="www.example.com",
            title="Server Version Disclosed",
            description="Server header reveals version information",
            category="information-disclosure",
        ),
    ]


class TestSecurityEvent:
    """Test SecurityEvent model."""

    def test_event_creation(self, sample_event):
        """Test event creation."""
        assert sample_event.event_id == "EVT-001"
        assert sample_event.severity == "high"
        assert sample_event.target_host == "example.com"

    def test_severity_numeric(self):
        """Test numeric severity conversion."""
        assert SecurityEvent(
            event_id="1",
            timestamp=datetime.now(timezone.utc),
            severity="critical",
            event_type="test",
        ).get_severity_numeric() == 10

        assert SecurityEvent(
            event_id="2",
            timestamp=datetime.now(timezone.utc),
            severity="info",
            event_type="test",
        ).get_severity_numeric() == 1


class TestCEFExporter:
    """Test CEF format exporter."""

    def test_export_single_event(self, sample_event):
        """Test single event export."""
        exporter = CEFExporter()
        result = exporter.export_event(sample_event)

        assert result.startswith("CEF:0|RedOPS|Security Assessment|")
        assert "EVT-001" in result
        assert "SQL Injection Detected" in result
        assert "|8|" in result  # High severity

    def test_export_contains_extensions(self, sample_event):
        """Test CEF extension fields."""
        exporter = CEFExporter()
        result = exporter.export_event(sample_event)

        assert "dhost=example.com" in result
        assert "dst=192.168.1.100" in result
        assert "dpt=443" in result
        assert "cs1=T1190" in result  # MITRE ATT&CK
        assert "cs2=CVE-2025-1234" in result  # CVE

    def test_export_multiple_events(self, multiple_events):
        """Test multiple events export."""
        exporter = CEFExporter()
        result = exporter.export_events(multiple_events)

        lines = result.split("\n")
        assert len(lines) == 3
        assert all(line.startswith("CEF:0") for line in lines)

    def test_escape_special_chars(self):
        """Test escaping of special characters."""
        exporter = CEFExporter()
        event = SecurityEvent(
            event_id="1",
            timestamp=datetime.now(timezone.utc),
            severity="high",
            event_type="test",
            title="Test|With|Pipes",
            description="Value=with=equals",
        )

        result = exporter.export_event(event)

        assert "Test\\|With\\|Pipes" in result
        assert "Value\\=with\\=equals" in result

    def test_convenience_function(self, multiple_events):
        """Test export_to_cef convenience function."""
        result = export_to_cef(multiple_events)
        assert result.count("CEF:0") == 3


class TestLEEFExporter:
    """Test LEEF format exporter."""

    def test_export_single_event(self, sample_event):
        """Test single event export."""
        exporter = LEEFExporter()
        result = exporter.export_event(sample_event)

        assert result.startswith("LEEF:2.0|RedOPS|Security Assessment|")
        assert "EVT-001" in result
        assert "\t" in result  # Tab delimiter for LEEF 2.0

    def test_export_contains_attributes(self, sample_event):
        """Test LEEF attributes."""
        exporter = LEEFExporter()
        result = exporter.export_event(sample_event)

        assert "dstHost=example.com" in result
        assert "dst=192.168.1.100" in result
        assert "dstPort=443" in result
        assert "sev=8" in result  # High severity
        assert "mitreAttackId=T1190" in result
        assert "cveId=CVE-2025-1234" in result

    def test_export_multiple_events(self, multiple_events):
        """Test multiple events export."""
        exporter = LEEFExporter()
        result = exporter.export_events(multiple_events)

        lines = result.split("\n")
        assert len(lines) == 3
        assert all(line.startswith("LEEF:2.0") for line in lines)

    def test_convenience_function(self, multiple_events):
        """Test export_to_leef convenience function."""
        result = export_to_leef(multiple_events)
        assert result.count("LEEF:2.0") == 3


class TestSyslogExporter:
    """Test RFC 5424 Syslog exporter."""

    def test_export_single_event(self, sample_event):
        """Test single event export."""
        exporter = SyslogExporter(app_name="RedOPS", hostname="scanner.local")
        result = exporter.export_event(sample_event)

        # RFC 5424 format check
        assert result.startswith("<")
        assert "RedOPS" in result
        assert "scanner.local" in result
        assert "SQL Injection Detected" in result

    def test_priority_calculation(self):
        """Test syslog priority calculation."""
        exporter = SyslogExporter()

        # Critical = facility(16) * 8 + severity(2) = 130
        critical_event = SecurityEvent(
            event_id="1",
            timestamp=datetime.now(timezone.utc),
            severity="critical",
            event_type="test",
            title="Critical",
        )
        result = exporter.export_event(critical_event)
        assert result.startswith("<130>")

        # Info = facility(16) * 8 + severity(6) = 134
        info_event = SecurityEvent(
            event_id="2",
            timestamp=datetime.now(timezone.utc),
            severity="info",
            event_type="test",
            title="Info",
        )
        result = exporter.export_event(info_event)
        assert result.startswith("<134>")

    def test_structured_data(self, sample_event):
        """Test syslog structured data."""
        exporter = SyslogExporter()
        result = exporter.export_event(sample_event)

        assert "[redops@32473" in result
        assert 'host="example.com"' in result
        assert 'mitre="T1190"' in result
        assert 'cve="CVE-2025-1234"' in result

    def test_convenience_function(self, multiple_events):
        """Test export_to_syslog convenience function."""
        result = export_to_syslog(multiple_events)
        lines = result.split("\n")
        assert len(lines) == 3


class TestJSONLExporter:
    """Test JSONL exporter."""

    def test_export_single_event(self, sample_event):
        """Test single event export."""
        exporter = JSONLExporter()
        result = exporter.export_event(sample_event)

        data = json.loads(result)
        assert data["event_id"] == "EVT-001"
        assert data["severity"] == "high"
        assert data["severity_numeric"] == 8
        assert data["target"]["host"] == "example.com"

    def test_export_with_epoch_timestamp(self, sample_event):
        """Test epoch timestamp format."""
        exporter = JSONLExporter(timestamp_format="epoch")
        result = exporter.export_event(sample_event)

        data = json.loads(result)
        assert isinstance(data["timestamp"], int)

    def test_export_with_epoch_ms_timestamp(self, sample_event):
        """Test epoch milliseconds timestamp format."""
        exporter = JSONLExporter(timestamp_format="epoch_ms")
        result = exporter.export_event(sample_event)

        data = json.loads(result)
        assert isinstance(data["timestamp"], int)
        assert data["timestamp"] > 1700000000000  # Sanity check

    def test_export_multiple_events(self, multiple_events):
        """Test JSONL multiple events."""
        exporter = JSONLExporter()
        result = exporter.export_events(multiple_events)

        lines = result.split("\n")
        assert len(lines) == 3

        for line in lines:
            data = json.loads(line)
            assert "event_id" in data
            assert "severity" in data

    def test_convenience_function(self, multiple_events):
        """Test export_to_jsonl convenience function."""
        result = export_to_jsonl(multiple_events)
        lines = result.split("\n")
        assert len(lines) == 3


class TestSentinelExporter:
    """Test Microsoft Sentinel exporter."""

    def test_export_single_event(self, sample_event):
        """Test single event export."""
        exporter = SentinelExporter()
        result = exporter.export_event(sample_event)

        assert result["EventId"] == "EVT-001"
        assert result["Severity"] == "High"
        assert result["SeverityLevel"] == 8
        assert result["TargetHost"] == "example.com"
        assert result["MITREAttackId"] == "T1190"
        assert result["CVEId"] == "CVE-2025-1234"

    def test_export_has_time_generated(self, sample_event):
        """Test TimeGenerated field."""
        exporter = SentinelExporter()
        result = exporter.export_event(sample_event)

        assert "TimeGenerated" in result
        assert result["TimeGenerated"].endswith("Z")

    def test_export_multiple_events(self, multiple_events):
        """Test Sentinel multiple events."""
        exporter = SentinelExporter()
        result = exporter.export_events(multiple_events)

        data = json.loads(result)
        assert isinstance(data, list)
        assert len(data) == 3

    def test_convenience_function(self, multiple_events):
        """Test export_to_sentinel convenience function."""
        result = export_to_sentinel(multiple_events)
        data = json.loads(result)
        assert len(data) == 3


class TestSeverityMapping:
    """Test severity mapping across formats."""

    @pytest.mark.parametrize("severity,cef_val,leef_val", [
        ("critical", "10", "10"),
        ("high", "8", "8"),
        ("medium", "5", "5"),
        ("low", "3", "3"),
        ("info", "1", "1"),
    ])
    def test_severity_consistency(self, severity, cef_val, leef_val):
        """Test severity is consistent across formats."""
        event = SecurityEvent(
            event_id="1",
            timestamp=datetime.now(timezone.utc),
            severity=severity,
            event_type="test",
            title="Test",
        )

        cef_result = CEFExporter().export_event(event)
        leef_result = LEEFExporter().export_event(event)

        assert f"|{cef_val}|" in cef_result
        assert f"sev={leef_val}" in leef_result
