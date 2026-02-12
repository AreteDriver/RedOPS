"""
Tenant models for multi-tenant support.

Defines tenant configuration, quotas, and limits.
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import uuid4

logger = logging.getLogger(__name__)


class TenantStatus(Enum):
    """Tenant status."""

    ACTIVE = "active"
    SUSPENDED = "suspended"
    PENDING = "pending"
    DISABLED = "disabled"
    TRIAL = "trial"


class TenantTier(Enum):
    """Tenant subscription tier."""

    FREE = "free"
    STARTER = "starter"
    PROFESSIONAL = "professional"
    ENTERPRISE = "enterprise"
    CUSTOM = "custom"


@dataclass
class TenantQuota:
    """Resource quotas for a tenant."""

    max_scans_per_day: int = 10
    max_scans_per_month: int = 100
    max_targets: int = 50
    max_users: int = 5
    max_api_requests_per_minute: int = 60
    max_api_requests_per_day: int = 10000
    max_storage_mb: int = 1000
    max_report_retention_days: int = 30
    max_concurrent_scans: int = 2
    max_scheduled_scans: int = 5

    # Feature flags
    allow_api_access: bool = True
    allow_integrations: bool = False
    allow_custom_modules: bool = False
    allow_priority_support: bool = False

    @classmethod
    def for_tier(cls, tier: TenantTier) -> "TenantQuota":
        """Get default quota for a tier."""
        quotas = {
            TenantTier.FREE: cls(
                max_scans_per_day=5,
                max_scans_per_month=50,
                max_targets=10,
                max_users=2,
                max_api_requests_per_minute=30,
                max_api_requests_per_day=1000,
                max_storage_mb=100,
                max_report_retention_days=7,
                max_concurrent_scans=1,
                max_scheduled_scans=1,
                allow_api_access=False,
                allow_integrations=False,
            ),
            TenantTier.STARTER: cls(
                max_scans_per_day=20,
                max_scans_per_month=200,
                max_targets=50,
                max_users=5,
                max_api_requests_per_minute=60,
                max_api_requests_per_day=5000,
                max_storage_mb=500,
                max_report_retention_days=30,
                max_concurrent_scans=2,
                max_scheduled_scans=5,
                allow_api_access=True,
                allow_integrations=False,
            ),
            TenantTier.PROFESSIONAL: cls(
                max_scans_per_day=100,
                max_scans_per_month=1000,
                max_targets=200,
                max_users=20,
                max_api_requests_per_minute=120,
                max_api_requests_per_day=50000,
                max_storage_mb=5000,
                max_report_retention_days=90,
                max_concurrent_scans=5,
                max_scheduled_scans=20,
                allow_api_access=True,
                allow_integrations=True,
            ),
            TenantTier.ENTERPRISE: cls(
                max_scans_per_day=1000,
                max_scans_per_month=10000,
                max_targets=1000,
                max_users=100,
                max_api_requests_per_minute=600,
                max_api_requests_per_day=500000,
                max_storage_mb=50000,
                max_report_retention_days=365,
                max_concurrent_scans=20,
                max_scheduled_scans=100,
                allow_api_access=True,
                allow_integrations=True,
                allow_custom_modules=True,
                allow_priority_support=True,
            ),
        }
        return quotas.get(tier, cls())

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "max_scans_per_day": self.max_scans_per_day,
            "max_scans_per_month": self.max_scans_per_month,
            "max_targets": self.max_targets,
            "max_users": self.max_users,
            "max_api_requests_per_minute": self.max_api_requests_per_minute,
            "max_api_requests_per_day": self.max_api_requests_per_day,
            "max_storage_mb": self.max_storage_mb,
            "max_report_retention_days": self.max_report_retention_days,
            "max_concurrent_scans": self.max_concurrent_scans,
            "max_scheduled_scans": self.max_scheduled_scans,
            "allow_api_access": self.allow_api_access,
            "allow_integrations": self.allow_integrations,
            "allow_custom_modules": self.allow_custom_modules,
            "allow_priority_support": self.allow_priority_support,
        }


@dataclass
class TenantLimits:
    """Current resource usage for a tenant."""

    scans_today: int = 0
    scans_this_month: int = 0
    active_targets: int = 0
    active_users: int = 0
    api_requests_this_minute: int = 0
    api_requests_today: int = 0
    storage_used_mb: float = 0.0
    active_scans: int = 0
    scheduled_scans: int = 0

    last_reset_minute: datetime | None = None
    last_reset_day: datetime | None = None
    last_reset_month: datetime | None = None

    def check_quota(self, quota: TenantQuota, resource: str) -> bool:
        """Check if a quota would be exceeded."""
        checks = {
            "scan": self.scans_today < quota.max_scans_per_day,
            "scan_monthly": self.scans_this_month < quota.max_scans_per_month,
            "target": self.active_targets < quota.max_targets,
            "user": self.active_users < quota.max_users,
            "api_minute": self.api_requests_this_minute
            < quota.max_api_requests_per_minute,
            "api_daily": self.api_requests_today < quota.max_api_requests_per_day,
            "storage": self.storage_used_mb < quota.max_storage_mb,
            "concurrent_scan": self.active_scans < quota.max_concurrent_scans,
            "scheduled_scan": self.scheduled_scans < quota.max_scheduled_scans,
        }
        return checks.get(resource, True)

    def increment(self, resource: str, amount: int = 1) -> None:
        """Increment a resource counter."""
        if resource == "scan":
            self.scans_today += amount
            self.scans_this_month += amount
        elif resource == "api":
            self.api_requests_this_minute += amount
            self.api_requests_today += amount
        elif resource == "target":
            self.active_targets += amount
        elif resource == "user":
            self.active_users += amount
        elif resource == "active_scan":
            self.active_scans += amount
        elif resource == "scheduled_scan":
            self.scheduled_scans += amount

    def decrement(self, resource: str, amount: int = 1) -> None:
        """Decrement a resource counter."""
        if resource == "target":
            self.active_targets = max(0, self.active_targets - amount)
        elif resource == "user":
            self.active_users = max(0, self.active_users - amount)
        elif resource == "active_scan":
            self.active_scans = max(0, self.active_scans - amount)
        elif resource == "scheduled_scan":
            self.scheduled_scans = max(0, self.scheduled_scans - amount)

    def reset_minute(self) -> None:
        """Reset per-minute counters."""
        self.api_requests_this_minute = 0
        self.last_reset_minute = datetime.now(timezone.utc)

    def reset_day(self) -> None:
        """Reset daily counters."""
        self.scans_today = 0
        self.api_requests_today = 0
        self.last_reset_day = datetime.now(timezone.utc)

    def reset_month(self) -> None:
        """Reset monthly counters."""
        self.scans_this_month = 0
        self.last_reset_month = datetime.now(timezone.utc)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "scans_today": self.scans_today,
            "scans_this_month": self.scans_this_month,
            "active_targets": self.active_targets,
            "active_users": self.active_users,
            "api_requests_this_minute": self.api_requests_this_minute,
            "api_requests_today": self.api_requests_today,
            "storage_used_mb": self.storage_used_mb,
            "active_scans": self.active_scans,
            "scheduled_scans": self.scheduled_scans,
        }


@dataclass
class TenantConfig:
    """Tenant-specific configuration."""

    # Notification settings
    notification_email: str | None = None
    slack_webhook_url: str | None = None
    teams_webhook_url: str | None = None

    # Scan defaults
    default_scan_depth: str = "standard"
    default_modules: list[str] = field(default_factory=list)
    excluded_targets: list[str] = field(default_factory=list)

    # Branding
    logo_url: str | None = None
    primary_color: str = "#1a1a2e"
    company_name: str | None = None

    # Security settings
    require_mfa: bool = False
    allowed_ip_ranges: list[str] = field(default_factory=list)
    session_timeout_minutes: int = 60
    password_policy: dict[str, Any] = field(default_factory=dict)

    # Data retention
    finding_retention_days: int = 90
    scan_retention_days: int = 30
    audit_log_retention_days: int = 365

    # Custom settings
    custom_settings: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "notification_email": self.notification_email,
            "slack_webhook_url": self.slack_webhook_url,
            "teams_webhook_url": self.teams_webhook_url,
            "default_scan_depth": self.default_scan_depth,
            "default_modules": self.default_modules,
            "excluded_targets": self.excluded_targets,
            "logo_url": self.logo_url,
            "primary_color": self.primary_color,
            "company_name": self.company_name,
            "require_mfa": self.require_mfa,
            "allowed_ip_ranges": self.allowed_ip_ranges,
            "session_timeout_minutes": self.session_timeout_minutes,
            "finding_retention_days": self.finding_retention_days,
            "scan_retention_days": self.scan_retention_days,
            "audit_log_retention_days": self.audit_log_retention_days,
            "custom_settings": self.custom_settings,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "TenantConfig":
        """Create from dictionary."""
        return cls(
            notification_email=data.get("notification_email"),
            slack_webhook_url=data.get("slack_webhook_url"),
            teams_webhook_url=data.get("teams_webhook_url"),
            default_scan_depth=data.get("default_scan_depth", "standard"),
            default_modules=data.get("default_modules", []),
            excluded_targets=data.get("excluded_targets", []),
            logo_url=data.get("logo_url"),
            primary_color=data.get("primary_color", "#1a1a2e"),
            company_name=data.get("company_name"),
            require_mfa=data.get("require_mfa", False),
            allowed_ip_ranges=data.get("allowed_ip_ranges", []),
            session_timeout_minutes=data.get("session_timeout_minutes", 60),
            finding_retention_days=data.get("finding_retention_days", 90),
            scan_retention_days=data.get("scan_retention_days", 30),
            audit_log_retention_days=data.get("audit_log_retention_days", 365),
            custom_settings=data.get("custom_settings", {}),
        )


@dataclass
class Tenant:
    """Represents a tenant in the multi-tenant system."""

    id: str = field(default_factory=lambda: str(uuid4()))
    name: str = ""
    slug: str = ""  # URL-friendly identifier
    status: TenantStatus = TenantStatus.PENDING
    tier: TenantTier = TenantTier.FREE

    # Contact info
    owner_email: str = ""
    owner_name: str = ""
    billing_email: str | None = None

    # Timestamps
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    activated_at: datetime | None = None
    suspended_at: datetime | None = None
    trial_ends_at: datetime | None = None

    # Configuration
    config: TenantConfig = field(default_factory=TenantConfig)
    quota: TenantQuota = field(default_factory=TenantQuota)
    limits: TenantLimits = field(default_factory=TenantLimits)

    # Metadata
    metadata: dict[str, Any] = field(default_factory=dict)
    tags: set[str] = field(default_factory=set)

    def __post_init__(self):
        """Initialize slug if not provided."""
        if not self.slug and self.name:
            self.slug = self._generate_slug(self.name)
        if self.tier and not self.quota.max_scans_per_day:
            self.quota = TenantQuota.for_tier(self.tier)

    def _generate_slug(self, name: str) -> str:
        """Generate URL-friendly slug from name."""
        import re

        slug = name.lower()
        slug = re.sub(r"[^a-z0-9]+", "-", slug)
        slug = slug.strip("-")
        return slug

    def is_active(self) -> bool:
        """Check if tenant is active."""
        return self.status in (TenantStatus.ACTIVE, TenantStatus.TRIAL)

    def can_use_feature(self, feature: str) -> bool:
        """Check if tenant can use a feature."""
        feature_checks = {
            "api": self.quota.allow_api_access,
            "integrations": self.quota.allow_integrations,
            "custom_modules": self.quota.allow_custom_modules,
            "priority_support": self.quota.allow_priority_support,
        }
        return feature_checks.get(feature, True)

    def check_quota(self, resource: str) -> bool:
        """Check if quota allows the resource."""
        return self.limits.check_quota(self.quota, resource)

    def use_resource(self, resource: str, amount: int = 1) -> bool:
        """
        Try to use a resource.

        Returns:
            True if resource was available and used
        """
        if not self.check_quota(resource):
            return False
        self.limits.increment(resource, amount)
        return True

    def release_resource(self, resource: str, amount: int = 1) -> None:
        """Release a resource."""
        self.limits.decrement(resource, amount)

    def suspend(self, reason: str = "") -> None:
        """Suspend the tenant."""
        self.status = TenantStatus.SUSPENDED
        self.suspended_at = datetime.now(timezone.utc)
        if reason:
            self.metadata["suspension_reason"] = reason

    def activate(self) -> None:
        """Activate the tenant."""
        self.status = TenantStatus.ACTIVE
        self.activated_at = datetime.now(timezone.utc)
        self.suspended_at = None
        self.metadata.pop("suspension_reason", None)

    def upgrade_tier(self, new_tier: TenantTier) -> None:
        """Upgrade tenant tier."""
        self.tier = new_tier
        self.quota = TenantQuota.for_tier(new_tier)
        self.updated_at = datetime.now(timezone.utc)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "name": self.name,
            "slug": self.slug,
            "status": self.status.value,
            "tier": self.tier.value,
            "owner_email": self.owner_email,
            "owner_name": self.owner_name,
            "billing_email": self.billing_email,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "activated_at": self.activated_at.isoformat()
            if self.activated_at
            else None,
            "trial_ends_at": self.trial_ends_at.isoformat()
            if self.trial_ends_at
            else None,
            "config": self.config.to_dict(),
            "quota": self.quota.to_dict(),
            "limits": self.limits.to_dict(),
            "metadata": self.metadata,
            "tags": list(self.tags),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Tenant":
        """Create from dictionary."""
        tenant = cls(
            id=data.get("id", str(uuid4())),
            name=data.get("name", ""),
            slug=data.get("slug", ""),
            status=TenantStatus(data.get("status", "pending")),
            tier=TenantTier(data.get("tier", "free")),
            owner_email=data.get("owner_email", ""),
            owner_name=data.get("owner_name", ""),
            billing_email=data.get("billing_email"),
            metadata=data.get("metadata", {}),
            tags=set(data.get("tags", [])),
        )

        if data.get("config"):
            tenant.config = TenantConfig.from_dict(data["config"])

        if data.get("created_at"):
            tenant.created_at = datetime.fromisoformat(data["created_at"])

        return tenant
