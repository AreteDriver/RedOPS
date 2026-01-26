"""
RedOPS Database Module.

Provides SQLAlchemy models, connection management, and migration support.
"""

from .models import (
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
)
from .connection import (
    Database,
    DatabaseConfig,
    get_database,
    get_session,
    session_scope,
    init_database,
)

__all__ = [
    # Base
    "Base",
    # Models
    "User",
    "APIKey",
    "Scan",
    "Finding",
    "Schedule",
    "Job",
    "AuditLog",
    "IntelCache",
    "Report",
    # Enums
    "ScanStatus",
    "Severity",
    "FindingStatus",
    "UserRole",
    "ScheduleStatus",
    "JobStatus",
    # Connection
    "Database",
    "DatabaseConfig",
    "get_database",
    "get_session",
    "session_scope",
    "init_database",
]
