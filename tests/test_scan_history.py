"""Tests for scan history module."""

import pytest
import tempfile
import os

from redops.core.scan_history import (
    ScanHistoryDB,
    ScanRecord,
    FindingRecord,
    get_history_db,
)


class TestScanHistoryDB:
    """Tests for ScanHistoryDB."""

    @pytest.fixture
    def db(self):
        """Create a temporary database for testing."""
        fd, path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        db = ScanHistoryDB(path)
        yield db
        # Cleanup
        os.unlink(path)

    def test_create_scan(self, db):
        """Test creating a scan."""
        scan_id = db.create_scan("example.com", "quick", {"source": "cli"})

        assert scan_id > 0

        scan = db.get_scan(scan_id)
        assert scan is not None
        assert scan.target == "example.com"
        assert scan.preset == "quick"
        assert scan.status == "running"
        assert scan.metadata == {"source": "cli"}

    def test_update_scan(self, db):
        """Test updating a scan."""
        scan_id = db.create_scan("example.com")

        db.update_scan(
            scan_id,
            status="completed",
            modules_run=["domain_profile", "exposure_scan"],
            findings_count=5,
            risk_score=7.5,
            duration_seconds=30.5,
        )

        scan = db.get_scan(scan_id)
        assert scan.status == "completed"
        assert scan.modules_run == ["domain_profile", "exposure_scan"]
        assert scan.findings_count == 5
        assert scan.risk_score == 7.5
        assert scan.duration_seconds == 30.5
        assert scan.completed_at is not None

    def test_update_scan_with_error(self, db):
        """Test updating scan with error."""
        scan_id = db.create_scan("example.com")

        db.update_scan(scan_id, status="failed", error="Connection timeout")

        scan = db.get_scan(scan_id)
        assert scan.status == "failed"
        assert scan.error == "Connection timeout"

    def test_list_scans(self, db):
        """Test listing scans."""
        db.create_scan("example.com")
        db.create_scan("test.org")
        db.create_scan("example.net")

        scans = db.list_scans()
        assert len(scans) == 3

    def test_list_scans_filter_by_target(self, db):
        """Test listing scans filtered by target."""
        db.create_scan("example.com")
        db.create_scan("test.org")
        db.create_scan("example.net")

        scans = db.list_scans(target="example")
        assert len(scans) == 2
        assert all("example" in s.target for s in scans)

    def test_list_scans_filter_by_status(self, db):
        """Test listing scans filtered by status."""
        scan1 = db.create_scan("example.com")
        db.create_scan("test.org")

        db.update_scan(scan1, status="completed")
        # scan2 stays as "running"

        scans = db.list_scans(status="completed")
        assert len(scans) == 1
        assert scans[0].target == "example.com"

    def test_list_scans_with_limit(self, db):
        """Test listing scans with limit."""
        for i in range(10):
            db.create_scan(f"target{i}.com")

        scans = db.list_scans(limit=5)
        assert len(scans) == 5

    def test_delete_scan(self, db):
        """Test deleting a scan."""
        scan_id = db.create_scan("example.com")
        assert db.get_scan(scan_id) is not None

        result = db.delete_scan(scan_id)
        assert result is True
        assert db.get_scan(scan_id) is None

    def test_delete_nonexistent_scan(self, db):
        """Test deleting a nonexistent scan."""
        result = db.delete_scan(99999)
        assert result is False

    def test_get_nonexistent_scan(self, db):
        """Test getting a nonexistent scan."""
        scan = db.get_scan(99999)
        assert scan is None


class TestFindings:
    """Tests for finding operations."""

    @pytest.fixture
    def db(self):
        """Create a temporary database for testing."""
        fd, path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        db = ScanHistoryDB(path)
        yield db
        os.unlink(path)

    def test_add_finding(self, db):
        """Test adding a finding."""
        scan_id = db.create_scan("example.com")

        finding_id = db.add_finding(
            scan_id=scan_id,
            module="exposure_scan",
            severity="high",
            title="Open SSH Port",
            description="Port 22 is publicly accessible",
            evidence="nmap scan results",
            remediation="Restrict SSH access to VPN",
        )

        assert finding_id > 0

    def test_get_findings(self, db):
        """Test getting findings for a scan."""
        scan_id = db.create_scan("example.com")

        db.add_finding(scan_id, "module_a", "critical", "Finding 1")
        db.add_finding(scan_id, "module_b", "high", "Finding 2")
        db.add_finding(scan_id, "module_a", "low", "Finding 3")

        findings = db.get_findings(scan_id)
        assert len(findings) == 3

        # Should be ordered by severity
        assert findings[0].severity == "critical"
        assert findings[1].severity == "high"
        assert findings[2].severity == "low"

    def test_get_findings_filter_by_severity(self, db):
        """Test getting findings filtered by severity."""
        scan_id = db.create_scan("example.com")

        db.add_finding(scan_id, "module_a", "critical", "Finding 1")
        db.add_finding(scan_id, "module_b", "high", "Finding 2")
        db.add_finding(scan_id, "module_a", "high", "Finding 3")

        findings = db.get_findings(scan_id, severity="high")
        assert len(findings) == 2
        assert all(f.severity == "high" for f in findings)

    def test_get_findings_filter_by_module(self, db):
        """Test getting findings filtered by module."""
        scan_id = db.create_scan("example.com")

        db.add_finding(scan_id, "module_a", "high", "Finding 1")
        db.add_finding(scan_id, "module_b", "high", "Finding 2")
        db.add_finding(scan_id, "module_a", "low", "Finding 3")

        findings = db.get_findings(scan_id, module="module_a")
        assert len(findings) == 2
        assert all(f.module == "module_a" for f in findings)

    def test_cascade_delete(self, db):
        """Test that deleting a scan also deletes its findings."""
        scan_id = db.create_scan("example.com")
        db.add_finding(scan_id, "module", "high", "Finding")

        # Verify finding exists
        assert len(db.get_findings(scan_id)) == 1

        # Delete scan
        db.delete_scan(scan_id)

        # Findings should be gone too
        assert len(db.get_findings(scan_id)) == 0


class TestScanData:
    """Tests for scan data operations."""

    @pytest.fixture
    def db(self):
        """Create a temporary database for testing."""
        fd, path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        db = ScanHistoryDB(path)
        yield db
        os.unlink(path)

    def test_store_and_get_scan_data(self, db):
        """Test storing and retrieving scan data."""
        scan_id = db.create_scan("example.com")

        db.store_scan_data(scan_id, "domain_info", {"registrar": "GoDaddy"})
        db.store_scan_data(scan_id, "tech_stack", ["nginx", "php"])

        data = db.get_scan_data(scan_id)
        assert data["domain_info"] == {"registrar": "GoDaddy"}
        assert data["tech_stack"] == ["nginx", "php"]

    def test_get_specific_scan_data(self, db):
        """Test getting specific scan data key."""
        scan_id = db.create_scan("example.com")

        db.store_scan_data(scan_id, "key1", "value1")
        db.store_scan_data(scan_id, "key2", "value2")

        data = db.get_scan_data(scan_id, "key1")
        assert data == {"key1": "value1"}

    def test_get_nonexistent_data(self, db):
        """Test getting nonexistent data key."""
        scan_id = db.create_scan("example.com")

        data = db.get_scan_data(scan_id, "nonexistent")
        assert data == {}


class TestStats:
    """Tests for statistics."""

    @pytest.fixture
    def db(self):
        """Create a temporary database for testing."""
        fd, path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        db = ScanHistoryDB(path)
        yield db
        os.unlink(path)

    def test_get_stats_empty(self, db):
        """Test stats on empty database."""
        stats = db.get_stats()

        assert stats["total_scans"] == 0
        assert stats["completed_scans"] == 0
        assert stats["total_findings"] == 0

    def test_get_stats_with_data(self, db):
        """Test stats with data."""
        scan1 = db.create_scan("example.com")
        db.create_scan("test.org")
        db.update_scan(scan1, status="completed")

        db.add_finding(scan1, "mod", "critical", "F1")
        db.add_finding(scan1, "mod", "high", "F2")
        db.add_finding(scan1, "mod", "high", "F3")

        stats = db.get_stats()

        assert stats["total_scans"] == 2
        assert stats["completed_scans"] == 1
        assert stats["total_findings"] == 3
        assert stats["findings_by_severity"]["critical"] == 1
        assert stats["findings_by_severity"]["high"] == 2


class TestDataclasses:
    """Tests for dataclasses."""

    def test_scan_record_to_dict(self):
        """Test ScanRecord serialization."""
        record = ScanRecord(
            id=1,
            target="example.com",
            preset="full",
            status="completed",
            modules_run=["a", "b"],
            findings_count=5,
        )
        data = record.to_dict()

        assert data["id"] == 1
        assert data["target"] == "example.com"
        assert data["modules_run"] == ["a", "b"]

    def test_finding_record_to_dict(self):
        """Test FindingRecord serialization."""
        record = FindingRecord(
            id=1,
            scan_id=10,
            module="test",
            severity="high",
            title="Test Finding",
        )
        data = record.to_dict()

        assert data["id"] == 1
        assert data["scan_id"] == 10
        assert data["severity"] == "high"


class TestGetHistoryDB:
    """Tests for get_history_db helper."""

    def test_get_default_db(self):
        """Test getting default database instance."""
        db = get_history_db()
        assert db is not None
        assert isinstance(db, ScanHistoryDB)

    def test_get_custom_db(self):
        """Test getting database with custom path."""
        fd, path = tempfile.mkstemp(suffix=".db")
        os.close(fd)

        try:
            db = get_history_db(path)
            assert db.db_path == path
        finally:
            os.unlink(path)
