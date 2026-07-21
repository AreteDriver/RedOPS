"""
Tenant manager for multi-tenant operations.

Handles tenant lifecycle, context management, and quota enforcement.
"""

from __future__ import annotations

import logging
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Callable

from .models import (
    Tenant,
    TenantConfig,
    TenantQuota,
    TenantStatus,
    TenantTier,
)

logger = logging.getLogger(__name__)

# Thread-local storage for current tenant
_tenant_context = threading.local()


def get_current_tenant() -> Tenant | None:
    """Get the current tenant from thread-local storage."""
    return getattr(_tenant_context, "tenant", None)


def set_current_tenant(tenant: Tenant | None) -> None:
    """Set the current tenant in thread-local storage."""
    _tenant_context.tenant = tenant


@contextmanager
def tenant_context(tenant: Tenant):
    """Context manager for tenant operations."""
    previous = get_current_tenant()
    set_current_tenant(tenant)
    try:
        yield tenant
    finally:
        set_current_tenant(previous)


class TenantBackend:
    """Abstract backend for tenant storage."""

    def get(self, tenant_id: str) -> Tenant | None:
        """Get tenant by ID."""
        raise NotImplementedError

    def get_by_slug(self, slug: str) -> Tenant | None:
        """Get tenant by slug."""
        raise NotImplementedError

    def list(self, status: TenantStatus | None = None) -> list[Tenant]:
        """List tenants."""
        raise NotImplementedError

    def save(self, tenant: Tenant) -> None:
        """Save tenant."""
        raise NotImplementedError

    def delete(self, tenant_id: str) -> bool:
        """Delete tenant."""
        raise NotImplementedError


class MemoryTenantBackend(TenantBackend):
    """In-memory tenant storage backend."""

    def __init__(self):
        self._tenants: dict[str, Tenant] = {}
        self._slug_index: dict[str, str] = {}
        self._lock = threading.Lock()

    def get(self, tenant_id: str) -> Tenant | None:
        """Get tenant by ID."""
        with self._lock:
            return self._tenants.get(tenant_id)

    def get_by_slug(self, slug: str) -> Tenant | None:
        """Get tenant by slug."""
        with self._lock:
            tenant_id = self._slug_index.get(slug)
            if tenant_id:
                return self._tenants.get(tenant_id)
            return None

    def list(self, status: TenantStatus | None = None) -> list[Tenant]:
        """List tenants."""
        with self._lock:
            tenants = list(self._tenants.values())
            if status:
                tenants = [t for t in tenants if t.status == status]
            return tenants

    def save(self, tenant: Tenant) -> None:
        """Save tenant."""
        with self._lock:
            # Remove old slug index if slug changed
            for slug, tid in list(self._slug_index.items()):
                if tid == tenant.id and slug != tenant.slug:
                    del self._slug_index[slug]

            self._tenants[tenant.id] = tenant
            self._slug_index[tenant.slug] = tenant.id

    def delete(self, tenant_id: str) -> bool:
        """Delete tenant."""
        with self._lock:
            tenant = self._tenants.get(tenant_id)
            if tenant:
                del self._tenants[tenant_id]
                self._slug_index.pop(tenant.slug, None)
                return True
            return False


class TenantManager:
    """
    Manages tenant lifecycle and operations.

    Provides:
    - Tenant CRUD operations
    - Quota enforcement
    - Context management
    - Event hooks
    """

    def __init__(self, backend: TenantBackend | None = None):
        """Initialize tenant manager."""
        self._backend = backend or MemoryTenantBackend()
        self._hooks: dict[str, list[Callable]] = {
            "before_create": [],
            "after_create": [],
            "before_update": [],
            "after_update": [],
            "before_delete": [],
            "after_delete": [],
            "on_suspend": [],
            "on_activate": [],
            "on_quota_exceeded": [],
        }
        self._lock = threading.Lock()

    def create_tenant(
        self,
        name: str,
        owner_email: str,
        owner_name: str = "",
        tier: TenantTier = TenantTier.FREE,
        slug: str | None = None,
        config: TenantConfig | None = None,
        **kwargs,
    ) -> Tenant:
        """
        Create a new tenant.

        Args:
            name: Tenant name
            owner_email: Owner email address
            owner_name: Owner name
            tier: Subscription tier
            slug: URL slug (auto-generated if not provided)
            config: Tenant configuration
            **kwargs: Additional tenant attributes

        Returns:
            Created tenant
        """
        tenant = Tenant(
            name=name,
            slug=slug or "",
            owner_email=owner_email,
            owner_name=owner_name,
            tier=tier,
            status=TenantStatus.PENDING,
            config=config or TenantConfig(),
            quota=TenantQuota.for_tier(tier),
            **kwargs,
        )

        # Run before hooks
        self._run_hooks("before_create", tenant)

        # Check for duplicate slug
        existing = self._backend.get_by_slug(tenant.slug)
        if existing:
            raise ValueError(f"Tenant with slug '{tenant.slug}' already exists")

        # Save tenant
        self._backend.save(tenant)
        logger.info(f"Created tenant: {tenant.name} ({tenant.id})")

        # Run after hooks
        self._run_hooks("after_create", tenant)

        return tenant

    def get_tenant(self, tenant_id: str) -> Tenant | None:
        """Get tenant by ID."""
        return self._backend.get(tenant_id)

    def get_tenant_by_slug(self, slug: str) -> Tenant | None:
        """Get tenant by slug."""
        return self._backend.get_by_slug(slug)

    def list_tenants(
        self,
        status: TenantStatus | None = None,
        tier: TenantTier | None = None,
    ) -> list[Tenant]:
        """
        List tenants with optional filtering.

        Args:
            status: Filter by status
            tier: Filter by tier

        Returns:
            List of tenants
        """
        tenants = self._backend.list(status)
        if tier:
            tenants = [t for t in tenants if t.tier == tier]
        return tenants

    def update_tenant(
        self,
        tenant_id: str,
        **updates,
    ) -> Tenant | None:
        """
        Update tenant attributes.

        Args:
            tenant_id: Tenant ID
            **updates: Attributes to update

        Returns:
            Updated tenant or None if not found
        """
        tenant = self._backend.get(tenant_id)
        if not tenant:
            return None

        # Run before hooks
        self._run_hooks("before_update", tenant, updates)

        # Apply updates
        for key, value in updates.items():
            if hasattr(tenant, key):
                setattr(tenant, key, value)

        tenant.updated_at = datetime.now(timezone.utc)

        # Save changes
        self._backend.save(tenant)

        # Run after hooks
        self._run_hooks("after_update", tenant)

        return tenant

    def delete_tenant(self, tenant_id: str) -> bool:
        """
        Delete a tenant.

        Args:
            tenant_id: Tenant ID

        Returns:
            True if deleted
        """
        tenant = self._backend.get(tenant_id)
        if not tenant:
            return False

        # Run before hooks
        self._run_hooks("before_delete", tenant)

        # Delete
        result = self._backend.delete(tenant_id)

        if result:
            logger.info(f"Deleted tenant: {tenant.name} ({tenant.id})")
            self._run_hooks("after_delete", tenant)

        return result

    def suspend_tenant(self, tenant_id: str, reason: str = "") -> Tenant | None:
        """
        Suspend a tenant.

        Args:
            tenant_id: Tenant ID
            reason: Suspension reason

        Returns:
            Updated tenant or None
        """
        tenant = self._backend.get(tenant_id)
        if not tenant:
            return None

        tenant.suspend(reason)
        self._backend.save(tenant)

        logger.warning(f"Suspended tenant: {tenant.name} - {reason}")
        self._run_hooks("on_suspend", tenant, reason)

        return tenant

    def activate_tenant(self, tenant_id: str) -> Tenant | None:
        """
        Activate a tenant.

        Args:
            tenant_id: Tenant ID

        Returns:
            Updated tenant or None
        """
        tenant = self._backend.get(tenant_id)
        if not tenant:
            return None

        tenant.activate()
        self._backend.save(tenant)

        logger.info(f"Activated tenant: {tenant.name}")
        self._run_hooks("on_activate", tenant)

        return tenant

    def upgrade_tier(
        self,
        tenant_id: str,
        new_tier: TenantTier,
    ) -> Tenant | None:
        """
        Upgrade tenant tier.

        Args:
            tenant_id: Tenant ID
            new_tier: New tier

        Returns:
            Updated tenant or None
        """
        tenant = self._backend.get(tenant_id)
        if not tenant:
            return None

        old_tier = tenant.tier
        tenant.upgrade_tier(new_tier)
        self._backend.save(tenant)

        logger.info(
            f"Upgraded tenant {tenant.name}: {old_tier.value} -> {new_tier.value}"
        )

        return tenant

    def check_quota(
        self,
        tenant_id: str,
        resource: str,
    ) -> bool:
        """
        Check if tenant can use a resource.

        Args:
            tenant_id: Tenant ID
            resource: Resource type

        Returns:
            True if resource is available
        """
        tenant = self._backend.get(tenant_id)
        if not tenant:
            return False

        if not tenant.is_active():
            return False

        return tenant.check_quota(resource)

    def use_resource(
        self,
        tenant_id: str,
        resource: str,
        amount: int = 1,
    ) -> bool:
        """
        Use a resource for a tenant.

        Args:
            tenant_id: Tenant ID
            resource: Resource type
            amount: Amount to use

        Returns:
            True if resource was available and used
        """
        tenant = self._backend.get(tenant_id)
        if not tenant:
            return False

        if not tenant.is_active():
            return False

        result = tenant.use_resource(resource, amount)

        if not result:
            self._run_hooks("on_quota_exceeded", tenant, resource)
            logger.warning(f"Quota exceeded for tenant {tenant.name}: {resource}")

        self._backend.save(tenant)
        return result

    def release_resource(
        self,
        tenant_id: str,
        resource: str,
        amount: int = 1,
    ) -> None:
        """
        Release a resource for a tenant.

        Args:
            tenant_id: Tenant ID
            resource: Resource type
            amount: Amount to release
        """
        tenant = self._backend.get(tenant_id)
        if tenant:
            tenant.release_resource(resource, amount)
            self._backend.save(tenant)

    def get_usage_stats(self, tenant_id: str) -> dict[str, Any] | None:
        """
        Get usage statistics for a tenant.

        Args:
            tenant_id: Tenant ID

        Returns:
            Usage statistics or None
        """
        tenant = self._backend.get(tenant_id)
        if not tenant:
            return None

        return {
            "tenant_id": tenant.id,
            "tenant_name": tenant.name,
            "tier": tenant.tier.value,
            "status": tenant.status.value,
            "limits": tenant.limits.to_dict(),
            "quota": tenant.quota.to_dict(),
            "usage_percentage": {
                "scans_daily": (
                    tenant.limits.scans_today / tenant.quota.max_scans_per_day * 100
                )
                if tenant.quota.max_scans_per_day
                else 0,
                "scans_monthly": (
                    tenant.limits.scans_this_month
                    / tenant.quota.max_scans_per_month
                    * 100
                )
                if tenant.quota.max_scans_per_month
                else 0,
                "storage": (
                    tenant.limits.storage_used_mb / tenant.quota.max_storage_mb * 100
                )
                if tenant.quota.max_storage_mb
                else 0,
                "targets": (
                    tenant.limits.active_targets / tenant.quota.max_targets * 100
                )
                if tenant.quota.max_targets
                else 0,
            },
        }

    def add_hook(self, event: str, callback: Callable) -> None:
        """Add an event hook."""
        if event in self._hooks:
            self._hooks[event].append(callback)

    def remove_hook(self, event: str, callback: Callable) -> None:
        """Remove an event hook."""
        if event in self._hooks and callback in self._hooks[event]:
            self._hooks[event].remove(callback)

    def _run_hooks(self, event: str, *args, **kwargs) -> None:
        """Run hooks for an event."""
        for callback in self._hooks.get(event, []):
            try:
                callback(*args, **kwargs)
            except (RuntimeError, ValueError, TypeError, OSError, ConnectionError) as e:
                logger.error(f"Hook error ({event}): {e}")


# Global tenant manager instance
_tenant_manager: TenantManager | None = None


def get_tenant_manager() -> TenantManager:
    """Get the global tenant manager."""
    global _tenant_manager
    if _tenant_manager is None:
        _tenant_manager = TenantManager()
    return _tenant_manager


def require_tenant(func: Callable) -> Callable:
    """
    Decorator to require a tenant context.

    Raises TenantRequired if no tenant is set.
    """
    from functools import wraps

    @wraps(func)
    def wrapper(*args, **kwargs):
        tenant = get_current_tenant()
        if not tenant:
            raise TenantRequired("No tenant context set")
        if not tenant.is_active():
            raise TenantInactive(f"Tenant '{tenant.name}' is not active")
        return func(*args, **kwargs)

    return wrapper


def require_quota(resource: str):
    """
    Decorator to check tenant quota before execution.

    Args:
        resource: Resource type to check
    """
    from functools import wraps

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            tenant = get_current_tenant()
            if not tenant:
                raise TenantRequired("No tenant context set")

            if not tenant.check_quota(resource):
                raise QuotaExceeded(f"Quota exceeded for resource: {resource}")

            return func(*args, **kwargs)

        return wrapper

    return decorator


class TenantRequired(Exception):
    """Raised when tenant context is required but not set."""

    pass


class TenantInactive(Exception):
    """Raised when tenant is not active."""

    pass


class QuotaExceeded(Exception):
    """Raised when tenant quota is exceeded."""

    pass
