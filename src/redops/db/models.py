"""
SQLAlchemy models for RedOPS.

Defines all database tables and relationships.
"""

from typing import Any
from datetime import datetime
from enum import Enum as PyEnum
import uuid

from sqlalchemy import (
    String,
    Text,
    Integer,
    Boolean,
    DateTime,
    ForeignKey,
    Enum,
    Numeric,
    Index,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import UUID, JSONB, INET
from sqlalchemy.orm import relationship, DeclarativeBase, Mapped, mapped_column
from sqlalchemy.sql import func


class Base(DeclarativeBase):
    """Base class for all models."""

    pass


# =============================================================================
# Enums
# =============================================================================


class ScanStatus(PyEnum):
    """Scan status values."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class Severity(PyEnum):
    """Finding severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingStatus(PyEnum):
    """Finding status values."""

    OPEN = "open"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    ACCEPTED_RISK = "accepted_risk"
    REMEDIATED = "remediated"


class UserRole(PyEnum):
    """User role types."""

    ADMIN = "admin"
    USER = "user"
    VIEWER = "viewer"
    API = "api"


class ScheduleStatus(PyEnum):
    """Schedule status values."""

    ACTIVE = "active"
    PAUSED = "paused"
    DISABLED = "disabled"
    EXPIRED = "expired"


class JobStatus(PyEnum):
    """Job status values."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMEOUT = "timeout"


# =============================================================================
# Core Models
# =============================================================================


class User(Base):
    """User account model."""

    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    username: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    email: Mapped[str] = mapped_column(String(256), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(256), nullable=False)
    full_name: Mapped[str | None] = mapped_column(String(256))
    role: Mapped[UserRole] = mapped_column(
        Enum(UserRole), default=UserRole.USER, nullable=False
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    last_login: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=func.now(), onupdate=func.now(), nullable=False
    )
    metadata_: Mapped[dict[str, Any]] = mapped_column(
        "metadata", JSONB, default=dict, nullable=False
    )

    # Relationships
    api_keys: Mapped[list["APIKey"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )
    scans: Mapped[list["Scan"]] = relationship(back_populates="created_by_user")
    schedules: Mapped[list["Schedule"]] = relationship(back_populates="created_by_user")

    __table_args__ = (
        Index("idx_users_username", "username"),
        Index("idx_users_email", "email"),
    )


class APIKey(Base):
    """API key model for authentication."""

    __tablename__ = "api_keys"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    key_hash: Mapped[str] = mapped_column(String(256), nullable=False)
    prefix: Mapped[str] = mapped_column(String(16), nullable=False)
    scopes: Mapped[list[str]] = mapped_column(JSONB, default=list, nullable=False)
    last_used: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=func.now(), nullable=False
    )

    # Relationships
    user: Mapped["User"] = relationship(back_populates="api_keys")

    __table_args__ = (
        Index("idx_api_keys_user_id", "user_id"),
        Index("idx_api_keys_prefix", "prefix"),
    )


class Scan(Base):
    """Security scan model."""

    __tablename__ = "scans"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    target: Mapped[str] = mapped_column(String(512), nullable=False)
    pipeline: Mapped[str] = mapped_column(String(128), nullable=False)
    status: Mapped[ScanStatus] = mapped_column(
        Enum(ScanStatus), default=ScanStatus.PENDING, nullable=False
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=func.now(), onupdate=func.now(), nullable=False
    )
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    metadata_: Mapped[dict[str, Any]] = mapped_column(
        "metadata", JSONB, default=dict, nullable=False
    )
    error_message: Mapped[str | None] = mapped_column(Text)

    # Relationships
    findings: Mapped[list["Finding"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )
    created_by_user: Mapped["User | None"] = relationship(back_populates="scans")
    reports: Mapped[list["Report"]] = relationship(back_populates="scan")

    __table_args__ = (
        Index("idx_scans_target", "target"),
        Index("idx_scans_status", "status"),
        Index("idx_scans_created_at", "created_at"),
        Index("idx_scans_pipeline", "pipeline"),
    )


class Finding(Base):
    """Security finding model."""

    __tablename__ = "findings"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False
    )
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    severity: Mapped[Severity] = mapped_column(Enum(Severity), nullable=False)
    module: Mapped[str | None] = mapped_column(String(128))
    category: Mapped[str | None] = mapped_column(String(128))
    evidence: Mapped[dict[str, Any]] = mapped_column(
        JSONB, default=dict, nullable=False
    )
    remediation: Mapped[str | None] = mapped_column(Text)
    references: Mapped[list[str]] = mapped_column(JSONB, default=list, nullable=False)
    cvss_score: Mapped[float | None] = mapped_column(Numeric(3, 1))
    cve_ids: Mapped[list[str]] = mapped_column(JSONB, default=list, nullable=False)
    status: Mapped[FindingStatus] = mapped_column(
        Enum(FindingStatus), default=FindingStatus.OPEN, nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=func.now(), onupdate=func.now(), nullable=False
    )
    metadata_: Mapped[dict[str, Any]] = mapped_column(
        "metadata", JSONB, default=dict, nullable=False
    )

    # Relationships
    scan: Mapped["Scan"] = relationship(back_populates="findings")

    __table_args__ = (
        Index("idx_findings_scan_id", "scan_id"),
        Index("idx_findings_severity", "severity"),
        Index("idx_findings_status", "status"),
        Index("idx_findings_module", "module"),
    )


# =============================================================================
# Scheduling Models
# =============================================================================


class Schedule(Base):
    """Scan schedule model."""

    __tablename__ = "schedules"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    name: Mapped[str] = mapped_column(String(256), nullable=False)
    target: Mapped[str] = mapped_column(String(512), nullable=False)
    pipeline: Mapped[str] = mapped_column(String(128), nullable=False)
    recurrence: Mapped[str] = mapped_column(String(32), default="daily", nullable=False)
    cron_expression: Mapped[str | None] = mapped_column(String(64))
    policy: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    status: Mapped[ScheduleStatus] = mapped_column(
        Enum(ScheduleStatus), default=ScheduleStatus.ACTIVE, nullable=False
    )
    next_run: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_run: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    run_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=func.now(), onupdate=func.now(), nullable=False
    )
    metadata_: Mapped[dict[str, Any]] = mapped_column(
        "metadata", JSONB, default=dict, nullable=False
    )

    # Relationships
    jobs: Mapped[list["Job"]] = relationship(back_populates="schedule")
    created_by_user: Mapped["User | None"] = relationship(back_populates="schedules")

    __table_args__ = (
        Index("idx_schedules_status", "status"),
        Index("idx_schedules_next_run", "next_run"),
    )


class Job(Base):
    """Scheduled job execution model."""

    __tablename__ = "jobs"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    schedule_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("schedules.id", ondelete="SET NULL")
    )
    scan_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scans.id", ondelete="SET NULL")
    )
    status: Mapped[JobStatus] = mapped_column(
        Enum(JobStatus), default=JobStatus.PENDING, nullable=False
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    retry_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    error_message: Mapped[str | None] = mapped_column(Text)
    result: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=func.now(), nullable=False
    )

    # Relationships
    schedule: Mapped["Schedule | None"] = relationship(back_populates="jobs")
    scan: Mapped["Scan | None"] = relationship()

    __table_args__ = (
        Index("idx_jobs_schedule_id", "schedule_id"),
        Index("idx_jobs_status", "status"),
        Index("idx_jobs_created_at", "created_at"),
    )


# =============================================================================
# Audit & Logging Models
# =============================================================================


class AuditLog(Base):
    """Audit log for tracking user actions."""

    __tablename__ = "audit_logs"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    resource_type: Mapped[str] = mapped_column(String(64), nullable=False)
    resource_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    details: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    ip_address: Mapped[str | None] = mapped_column(INET)
    user_agent: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=func.now(), nullable=False
    )

    __table_args__ = (
        Index("idx_audit_logs_user_id", "user_id"),
        Index("idx_audit_logs_action", "action"),
        Index("idx_audit_logs_resource", "resource_type", "resource_id"),
        Index("idx_audit_logs_created_at", "created_at"),
    )


# =============================================================================
# Cache Models
# =============================================================================


class IntelCache(Base):
    """Persistent cache for threat intelligence data."""

    __tablename__ = "intel_cache"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    source: Mapped[str] = mapped_column(String(64), nullable=False)
    indicator: Mapped[str] = mapped_column(String(512), nullable=False)
    indicator_type: Mapped[str] = mapped_column(String(32), nullable=False)
    data: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=func.now(), nullable=False
    )

    __table_args__ = (
        UniqueConstraint("source", "indicator", name="uq_intel_cache_source_indicator"),
        Index("idx_intel_cache_lookup", "source", "indicator"),
        Index("idx_intel_cache_expires", "expires_at"),
    )


# =============================================================================
# Report Models
# =============================================================================


class Report(Base):
    """Generated report model."""

    __tablename__ = "reports"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    scan_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("scans.id", ondelete="SET NULL")
    )
    name: Mapped[str] = mapped_column(String(256), nullable=False)
    report_type: Mapped[str] = mapped_column(String(64), nullable=False)
    format: Mapped[str] = mapped_column(String(32), default="pdf", nullable=False)
    file_path: Mapped[str | None] = mapped_column(String(512))
    file_size: Mapped[int | None] = mapped_column(Integer)
    generated_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=func.now(), nullable=False
    )
    metadata_: Mapped[dict[str, Any]] = mapped_column(
        "metadata", JSONB, default=dict, nullable=False
    )

    # Relationships
    scan: Mapped["Scan | None"] = relationship(back_populates="reports")

    __table_args__ = (
        Index("idx_reports_scan_id", "scan_id"),
        Index("idx_reports_created_at", "created_at"),
    )
