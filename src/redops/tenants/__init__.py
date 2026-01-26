"""
Multi-tenant support for RedOPS.

Provides tenant isolation, configuration, and access control.
"""

from .models import (
    Tenant,
    TenantConfig,
    TenantStatus,
    TenantTier,
    TenantQuota,
    TenantLimits,
)
from .manager import (
    TenantManager,
    get_tenant_manager,
    get_current_tenant,
    set_current_tenant,
    tenant_context,
)
from .middleware import (
    TenantMiddleware,
    extract_tenant_from_request,
    TenantResolver,
    HeaderTenantResolver,
    SubdomainTenantResolver,
    PathTenantResolver,
)
from .isolation import (
    TenantIsolation,
    TenantDataStore,
    IsolatedStorage,
)

__all__ = [
    # Models
    "Tenant",
    "TenantConfig",
    "TenantStatus",
    "TenantTier",
    "TenantQuota",
    "TenantLimits",
    # Manager
    "TenantManager",
    "get_tenant_manager",
    "get_current_tenant",
    "set_current_tenant",
    "tenant_context",
    # Middleware
    "TenantMiddleware",
    "extract_tenant_from_request",
    "TenantResolver",
    "HeaderTenantResolver",
    "SubdomainTenantResolver",
    "PathTenantResolver",
    # Isolation
    "TenantIsolation",
    "TenantDataStore",
    "IsolatedStorage",
]
