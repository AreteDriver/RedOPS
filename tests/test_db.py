"""Tests for database module."""

import uuid
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from redops.db import (
    Base,
    User,
    APIKey,
    Scan,
    Finding,
    Schedule,
    Job,
    AuditLog,
    IntelCache,
    Report,
    ScanStatus,
    Severity,
    FindingStatus,
    UserRole,
    ScheduleStatus,
    JobStatus,
    DatabaseConfig,
    Database,
)


class TestEnums:
    """Test enum definitions."""

    def test_scan_status_values(self):
        """ScanStatus has expected values."""
        assert ScanStatus.PENDING.value == "pending"
        assert ScanStatus.RUNNING.value == "running"
        assert ScanStatus.COMPLETED.value == "completed"
        assert ScanStatus.FAILED.value == "failed"
        assert ScanStatus.CANCELLED.value == "cancelled"

    def test_severity_values(self):
        """Severity has expected values."""
        assert Severity.CRITICAL.value == "critical"
        assert Severity.HIGH.value == "high"
        assert Severity.MEDIUM.value == "medium"
        assert Severity.LOW.value == "low"
        assert Severity.INFO.value == "info"

    def test_finding_status_values(self):
        """FindingStatus has expected values."""
        assert FindingStatus.OPEN.value == "open"
        assert FindingStatus.CONFIRMED.value == "confirmed"
        assert FindingStatus.FALSE_POSITIVE.value == "false_positive"
        assert FindingStatus.ACCEPTED_RISK.value == "accepted_risk"
        assert FindingStatus.REMEDIATED.value == "remediated"

    def test_user_role_values(self):
        """UserRole has expected values."""
        assert UserRole.ADMIN.value == "admin"
        assert UserRole.USER.value == "user"
        assert UserRole.VIEWER.value == "viewer"
        assert UserRole.API.value == "api"

    def test_schedule_status_values(self):
        """ScheduleStatus has expected values."""
        assert ScheduleStatus.ACTIVE.value == "active"
        assert ScheduleStatus.PAUSED.value == "paused"
        assert ScheduleStatus.DISABLED.value == "disabled"
        assert ScheduleStatus.EXPIRED.value == "expired"

    def test_job_status_values(self):
        """JobStatus has expected values."""
        assert JobStatus.PENDING.value == "pending"
        assert JobStatus.RUNNING.value == "running"
        assert JobStatus.COMPLETED.value == "completed"
        assert JobStatus.FAILED.value == "failed"
        assert JobStatus.CANCELLED.value == "cancelled"
        assert JobStatus.TIMEOUT.value == "timeout"


class TestDatabaseConfig:
    """Test DatabaseConfig class."""

    def test_default_config(self):
        """Default config requires DATABASE_URL."""
        with patch.dict("os.environ", {"DATABASE_URL": "postgresql://test:test@localhost:5432/test"}):
            config = DatabaseConfig()
            assert "postgresql" in config.url
        assert config.pool_size == 5
        assert config.max_overflow == 10
        assert config.pool_timeout == 30
        assert config.pool_recycle == 1800
        assert config.echo is False

    def test_custom_config(self):
        """Custom config values are used."""
        config = DatabaseConfig(
            url="postgresql://custom:pass@host:5432/db",
            pool_size=10,
            max_overflow=20,
            pool_timeout=60,
            pool_recycle=3600,
            echo=True,
        )
        assert config.url == "postgresql://custom:pass@host:5432/db"
        assert config.pool_size == 10
        assert config.max_overflow == 20
        assert config.pool_timeout == 60
        assert config.pool_recycle == 3600
        assert config.echo is True

    def test_from_env(self):
        """Config from environment variables."""
        with patch.dict(
            "os.environ",
            {
                "DATABASE_URL": "postgresql://env:pass@localhost:5432/test",
                "DATABASE_POOL_SIZE": "15",
                "DATABASE_MAX_OVERFLOW": "25",
                "DATABASE_POOL_TIMEOUT": "45",
                "DATABASE_POOL_RECYCLE": "900",
                "DATABASE_ECHO": "true",
            },
        ):
            config = DatabaseConfig.from_env()
            assert config.url == "postgresql://env:pass@localhost:5432/test"
            assert config.pool_size == 15
            assert config.max_overflow == 25
            assert config.pool_timeout == 45
            assert config.pool_recycle == 900
            assert config.echo is True


class TestDatabase:
    """Test Database class."""

    @patch.dict("os.environ", {"DATABASE_URL": "postgresql://test:test@localhost:5432/test"})
    def test_engine_creation(self):
        """Engine is created lazily."""
        db = Database()
        assert db._engine is None
        # Access engine property - patch event.listens_for to avoid SQLAlchemy event issues with mock
        with patch("redops.db.connection.create_engine") as mock_create:
            with patch("redops.db.connection.event") as mock_event:
                mock_engine = MagicMock()
                mock_create.return_value = mock_engine
                mock_event.listens_for.return_value = lambda f: f
                _ = db.engine
                mock_create.assert_called_once()
        assert db._engine is not None

    @patch.dict("os.environ", {"DATABASE_URL": "postgresql://test:test@localhost:5432/test"})
    def test_session_factory_creation(self):
        """Session factory is created lazily."""
        db = Database()
        assert db._session_factory is None
        with patch("redops.db.connection.create_engine") as mock_create:
            with patch("redops.db.connection.event") as mock_event:
                mock_engine = MagicMock()
                mock_create.return_value = mock_engine
                mock_event.listens_for.return_value = lambda f: f
                with patch("redops.db.connection.sessionmaker") as mock_sessionmaker:
                    mock_sessionmaker.return_value = MagicMock()
                    _ = db.session_factory
                    mock_sessionmaker.assert_called_once()

    @patch.dict("os.environ", {"DATABASE_URL": "postgresql://test:test@localhost:5432/test"})
    def test_dispose(self):
        """Dispose clears engine and session factory."""
        db = Database()
        mock_engine = MagicMock()
        db._engine = mock_engine
        db._session_factory = MagicMock()

        db.dispose()

        mock_engine.dispose.assert_called_once()
        assert db._engine is None
        assert db._session_factory is None


class TestModels:
    """Test model definitions."""

    def test_user_model(self):
        """User model has expected columns."""
        assert hasattr(User, "id")
        assert hasattr(User, "username")
        assert hasattr(User, "email")
        assert hasattr(User, "password_hash")
        assert hasattr(User, "role")
        assert hasattr(User, "is_active")
        assert hasattr(User, "created_at")
        assert hasattr(User, "updated_at")

    def test_scan_model(self):
        """Scan model has expected columns."""
        assert hasattr(Scan, "id")
        assert hasattr(Scan, "target")
        assert hasattr(Scan, "pipeline")
        assert hasattr(Scan, "status")
        assert hasattr(Scan, "started_at")
        assert hasattr(Scan, "completed_at")
        assert hasattr(Scan, "created_at")
        assert hasattr(Scan, "findings")

    def test_finding_model(self):
        """Finding model has expected columns."""
        assert hasattr(Finding, "id")
        assert hasattr(Finding, "scan_id")
        assert hasattr(Finding, "title")
        assert hasattr(Finding, "description")
        assert hasattr(Finding, "severity")
        assert hasattr(Finding, "status")
        assert hasattr(Finding, "evidence")
        assert hasattr(Finding, "cvss_score")
        assert hasattr(Finding, "cve_ids")

    def test_schedule_model(self):
        """Schedule model has expected columns."""
        assert hasattr(Schedule, "id")
        assert hasattr(Schedule, "name")
        assert hasattr(Schedule, "target")
        assert hasattr(Schedule, "pipeline")
        assert hasattr(Schedule, "recurrence")
        assert hasattr(Schedule, "cron_expression")
        assert hasattr(Schedule, "status")
        assert hasattr(Schedule, "next_run")
        assert hasattr(Schedule, "last_run")
        assert hasattr(Schedule, "jobs")

    def test_job_model(self):
        """Job model has expected columns."""
        assert hasattr(Job, "id")
        assert hasattr(Job, "schedule_id")
        assert hasattr(Job, "scan_id")
        assert hasattr(Job, "status")
        assert hasattr(Job, "started_at")
        assert hasattr(Job, "completed_at")
        assert hasattr(Job, "retry_count")
        assert hasattr(Job, "error_message")

    def test_audit_log_model(self):
        """AuditLog model has expected columns."""
        assert hasattr(AuditLog, "id")
        assert hasattr(AuditLog, "user_id")
        assert hasattr(AuditLog, "action")
        assert hasattr(AuditLog, "resource_type")
        assert hasattr(AuditLog, "resource_id")
        assert hasattr(AuditLog, "details")
        assert hasattr(AuditLog, "ip_address")

    def test_intel_cache_model(self):
        """IntelCache model has expected columns."""
        assert hasattr(IntelCache, "id")
        assert hasattr(IntelCache, "source")
        assert hasattr(IntelCache, "indicator")
        assert hasattr(IntelCache, "indicator_type")
        assert hasattr(IntelCache, "data")
        assert hasattr(IntelCache, "expires_at")

    def test_report_model(self):
        """Report model has expected columns."""
        assert hasattr(Report, "id")
        assert hasattr(Report, "scan_id")
        assert hasattr(Report, "name")
        assert hasattr(Report, "report_type")
        assert hasattr(Report, "format")
        assert hasattr(Report, "file_path")
        assert hasattr(Report, "file_size")


class TestRelationships:
    """Test model relationships."""

    def test_user_has_api_keys_relationship(self):
        """User has api_keys relationship."""
        assert hasattr(User, "api_keys")

    def test_user_has_scans_relationship(self):
        """User has scans relationship."""
        assert hasattr(User, "scans")

    def test_scan_has_findings_relationship(self):
        """Scan has findings relationship."""
        assert hasattr(Scan, "findings")

    def test_scan_has_reports_relationship(self):
        """Scan has reports relationship."""
        assert hasattr(Scan, "reports")

    def test_finding_has_scan_relationship(self):
        """Finding has scan relationship."""
        assert hasattr(Finding, "scan")

    def test_schedule_has_jobs_relationship(self):
        """Schedule has jobs relationship."""
        assert hasattr(Schedule, "jobs")

    def test_job_has_schedule_relationship(self):
        """Job has schedule relationship."""
        assert hasattr(Job, "schedule")


class TestTableNames:
    """Test table names are correct."""

    def test_table_names(self):
        """All models have correct table names."""
        assert User.__tablename__ == "users"
        assert APIKey.__tablename__ == "api_keys"
        assert Scan.__tablename__ == "scans"
        assert Finding.__tablename__ == "findings"
        assert Schedule.__tablename__ == "schedules"
        assert Job.__tablename__ == "jobs"
        assert AuditLog.__tablename__ == "audit_logs"
        assert IntelCache.__tablename__ == "intel_cache"
        assert Report.__tablename__ == "reports"


class TestBase:
    """Test Base declarative class."""

    def test_base_is_declarative(self):
        """Base is a SQLAlchemy declarative base."""
        assert hasattr(Base, "metadata")
        assert hasattr(Base, "registry")
