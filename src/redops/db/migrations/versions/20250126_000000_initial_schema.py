"""Initial schema.

Revision ID: 001
Revises:
Create Date: 2025-01-26 00:00:00.000000

"""

from typing import Sequence

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Create initial database schema."""
    # Create enum types
    op.execute(
        "CREATE TYPE scanstatus AS ENUM ('pending', 'running', 'completed', 'failed', 'cancelled')"
    )
    op.execute(
        "CREATE TYPE severity AS ENUM ('critical', 'high', 'medium', 'low', 'info')"
    )
    op.execute(
        "CREATE TYPE findingstatus AS ENUM ('open', 'confirmed', 'false_positive', 'accepted_risk', 'remediated')"
    )
    op.execute("CREATE TYPE userrole AS ENUM ('admin', 'user', 'viewer', 'api')")
    op.execute(
        "CREATE TYPE schedulestatus AS ENUM ('active', 'paused', 'disabled', 'expired')"
    )
    op.execute(
        "CREATE TYPE jobstatus AS ENUM ('pending', 'running', 'completed', 'failed', 'cancelled', 'timeout')"
    )

    # Users table
    op.create_table(
        "users",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("username", sa.String(128), unique=True, nullable=False),
        sa.Column("email", sa.String(256), unique=True, nullable=False),
        sa.Column("password_hash", sa.String(256), nullable=False),
        sa.Column("full_name", sa.String(256)),
        sa.Column(
            "role",
            postgresql.ENUM(
                "admin", "user", "viewer", "api", name="userrole", create_type=False
            ),
            default="user",
            nullable=False,
        ),
        sa.Column("is_active", sa.Boolean, default=True, nullable=False),
        sa.Column("last_login", sa.DateTime(timezone=True)),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            onupdate=sa.func.now(),
            nullable=False,
        ),
        sa.Column("metadata", postgresql.JSONB, default={}, nullable=False),
    )
    op.create_index("idx_users_username", "users", ["username"])
    op.create_index("idx_users_email", "users", ["email"])

    # API Keys table
    op.create_table(
        "api_keys",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("key_hash", sa.String(256), nullable=False),
        sa.Column("prefix", sa.String(16), nullable=False),
        sa.Column("scopes", postgresql.JSONB, default=[], nullable=False),
        sa.Column("last_used", sa.DateTime(timezone=True)),
        sa.Column("expires_at", sa.DateTime(timezone=True)),
        sa.Column("is_active", sa.Boolean, default=True, nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )
    op.create_index("idx_api_keys_user_id", "api_keys", ["user_id"])
    op.create_index("idx_api_keys_prefix", "api_keys", ["prefix"])

    # Scans table
    op.create_table(
        "scans",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("target", sa.String(512), nullable=False),
        sa.Column("pipeline", sa.String(128), nullable=False),
        sa.Column(
            "status",
            postgresql.ENUM(
                "pending",
                "running",
                "completed",
                "failed",
                "cancelled",
                name="scanstatus",
                create_type=False,
            ),
            default="pending",
            nullable=False,
        ),
        sa.Column("started_at", sa.DateTime(timezone=True)),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            onupdate=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "created_by",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
        ),
        sa.Column("metadata", postgresql.JSONB, default={}, nullable=False),
        sa.Column("error_message", sa.Text),
    )
    op.create_index("idx_scans_target", "scans", ["target"])
    op.create_index("idx_scans_status", "scans", ["status"])
    op.create_index("idx_scans_created_at", "scans", ["created_at"])
    op.create_index("idx_scans_pipeline", "scans", ["pipeline"])

    # Findings table
    op.create_table(
        "findings",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "scan_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("scans.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("title", sa.String(512), nullable=False),
        sa.Column("description", sa.Text),
        sa.Column(
            "severity",
            postgresql.ENUM(
                "critical",
                "high",
                "medium",
                "low",
                "info",
                name="severity",
                create_type=False,
            ),
            nullable=False,
        ),
        sa.Column("module", sa.String(128)),
        sa.Column("category", sa.String(128)),
        sa.Column("evidence", postgresql.JSONB, default={}, nullable=False),
        sa.Column("remediation", sa.Text),
        sa.Column("references", postgresql.JSONB, default=[], nullable=False),
        sa.Column("cvss_score", sa.Numeric(3, 1)),
        sa.Column("cve_ids", postgresql.JSONB, default=[], nullable=False),
        sa.Column(
            "status",
            postgresql.ENUM(
                "open",
                "confirmed",
                "false_positive",
                "accepted_risk",
                "remediated",
                name="findingstatus",
                create_type=False,
            ),
            default="open",
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            onupdate=sa.func.now(),
            nullable=False,
        ),
        sa.Column("metadata", postgresql.JSONB, default={}, nullable=False),
    )
    op.create_index("idx_findings_scan_id", "findings", ["scan_id"])
    op.create_index("idx_findings_severity", "findings", ["severity"])
    op.create_index("idx_findings_status", "findings", ["status"])
    op.create_index("idx_findings_module", "findings", ["module"])

    # Schedules table
    op.create_table(
        "schedules",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(256), nullable=False),
        sa.Column("target", sa.String(512), nullable=False),
        sa.Column("pipeline", sa.String(128), nullable=False),
        sa.Column("recurrence", sa.String(32), default="daily", nullable=False),
        sa.Column("cron_expression", sa.String(64)),
        sa.Column("policy", postgresql.JSONB, default={}, nullable=False),
        sa.Column(
            "status",
            postgresql.ENUM(
                "active",
                "paused",
                "disabled",
                "expired",
                name="schedulestatus",
                create_type=False,
            ),
            default="active",
            nullable=False,
        ),
        sa.Column("next_run", sa.DateTime(timezone=True)),
        sa.Column("last_run", sa.DateTime(timezone=True)),
        sa.Column("run_count", sa.Integer, default=0, nullable=False),
        sa.Column(
            "created_by",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            onupdate=sa.func.now(),
            nullable=False,
        ),
        sa.Column("metadata", postgresql.JSONB, default={}, nullable=False),
    )
    op.create_index("idx_schedules_status", "schedules", ["status"])
    op.create_index("idx_schedules_next_run", "schedules", ["next_run"])

    # Jobs table
    op.create_table(
        "jobs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "schedule_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("schedules.id", ondelete="SET NULL"),
        ),
        sa.Column(
            "scan_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("scans.id", ondelete="SET NULL"),
        ),
        sa.Column(
            "status",
            postgresql.ENUM(
                "pending",
                "running",
                "completed",
                "failed",
                "cancelled",
                "timeout",
                name="jobstatus",
                create_type=False,
            ),
            default="pending",
            nullable=False,
        ),
        sa.Column("started_at", sa.DateTime(timezone=True)),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
        sa.Column("retry_count", sa.Integer, default=0, nullable=False),
        sa.Column("error_message", sa.Text),
        sa.Column("result", postgresql.JSONB, default={}, nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )
    op.create_index("idx_jobs_schedule_id", "jobs", ["schedule_id"])
    op.create_index("idx_jobs_status", "jobs", ["status"])
    op.create_index("idx_jobs_created_at", "jobs", ["created_at"])

    # Audit Logs table
    op.create_table(
        "audit_logs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
        ),
        sa.Column("action", sa.String(64), nullable=False),
        sa.Column("resource_type", sa.String(64), nullable=False),
        sa.Column("resource_id", postgresql.UUID(as_uuid=True)),
        sa.Column("details", postgresql.JSONB, default={}, nullable=False),
        sa.Column("ip_address", postgresql.INET),
        sa.Column("user_agent", sa.Text),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )
    op.create_index("idx_audit_logs_user_id", "audit_logs", ["user_id"])
    op.create_index("idx_audit_logs_action", "audit_logs", ["action"])
    op.create_index(
        "idx_audit_logs_resource", "audit_logs", ["resource_type", "resource_id"]
    )
    op.create_index("idx_audit_logs_created_at", "audit_logs", ["created_at"])

    # Intel Cache table
    op.create_table(
        "intel_cache",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("source", sa.String(64), nullable=False),
        sa.Column("indicator", sa.String(512), nullable=False),
        sa.Column("indicator_type", sa.String(32), nullable=False),
        sa.Column("data", postgresql.JSONB, nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True)),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.UniqueConstraint(
            "source", "indicator", name="uq_intel_cache_source_indicator"
        ),
    )
    op.create_index("idx_intel_cache_lookup", "intel_cache", ["source", "indicator"])
    op.create_index("idx_intel_cache_expires", "intel_cache", ["expires_at"])

    # Reports table
    op.create_table(
        "reports",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "scan_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("scans.id", ondelete="SET NULL"),
        ),
        sa.Column("name", sa.String(256), nullable=False),
        sa.Column("report_type", sa.String(64), nullable=False),
        sa.Column("format", sa.String(32), default="pdf", nullable=False),
        sa.Column("file_path", sa.String(512)),
        sa.Column("file_size", sa.Integer),
        sa.Column(
            "generated_by",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("metadata", postgresql.JSONB, default={}, nullable=False),
    )
    op.create_index("idx_reports_scan_id", "reports", ["scan_id"])
    op.create_index("idx_reports_created_at", "reports", ["created_at"])

    # Create updated_at trigger function
    op.execute("""
        CREATE OR REPLACE FUNCTION update_updated_at_column()
        RETURNS TRIGGER AS $$
        BEGIN
            NEW.updated_at = CURRENT_TIMESTAMP;
            RETURN NEW;
        END;
        $$ language 'plpgsql';
    """)

    # Add triggers to tables with updated_at
    for table in ["users", "scans", "findings", "schedules"]:
        op.execute(f"""
            CREATE TRIGGER update_{table}_updated_at
                BEFORE UPDATE ON {table}
                FOR EACH ROW
                EXECUTE FUNCTION update_updated_at_column();
        """)


def downgrade() -> None:
    """Drop all tables and types."""
    # Drop triggers first
    for table in ["users", "scans", "findings", "schedules"]:
        op.execute(f"DROP TRIGGER IF EXISTS update_{table}_updated_at ON {table}")

    # Drop trigger function
    op.execute("DROP FUNCTION IF EXISTS update_updated_at_column()")

    # Drop tables in reverse order of creation
    op.drop_table("reports")
    op.drop_table("intel_cache")
    op.drop_table("audit_logs")
    op.drop_table("jobs")
    op.drop_table("schedules")
    op.drop_table("findings")
    op.drop_table("scans")
    op.drop_table("api_keys")
    op.drop_table("users")

    # Drop enum types
    op.execute("DROP TYPE IF EXISTS jobstatus")
    op.execute("DROP TYPE IF EXISTS schedulestatus")
    op.execute("DROP TYPE IF EXISTS userrole")
    op.execute("DROP TYPE IF EXISTS findingstatus")
    op.execute("DROP TYPE IF EXISTS severity")
    op.execute("DROP TYPE IF EXISTS scanstatus")
