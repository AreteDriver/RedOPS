"""
Tenant middleware for HTTP request handling.

Provides automatic tenant resolution and context injection.
"""

import logging
import re
from abc import ABC, abstractmethod
from typing import Any, Callable, Dict, List, Optional

from .manager import get_tenant_manager, set_current_tenant
from .models import Tenant

logger = logging.getLogger(__name__)


class TenantResolver(ABC):
    """Abstract base for tenant resolvers."""

    @abstractmethod
    def resolve(self, request: Any) -> Optional[str]:
        """
        Resolve tenant identifier from request.

        Args:
            request: HTTP request object

        Returns:
            Tenant ID or slug, or None if not found
        """
        pass


class HeaderTenantResolver(TenantResolver):
    """Resolves tenant from HTTP header."""

    def __init__(self, header_name: str = "X-Tenant-ID"):
        """
        Initialize header resolver.

        Args:
            header_name: Name of the header containing tenant ID
        """
        self.header_name = header_name

    def resolve(self, request: Any) -> Optional[str]:
        """Resolve tenant from header."""
        # Support different request objects
        if hasattr(request, "headers"):
            headers = request.headers
            if hasattr(headers, "get"):
                return headers.get(self.header_name)
            elif isinstance(headers, dict):
                return headers.get(self.header_name)
        return None


class SubdomainTenantResolver(TenantResolver):
    """Resolves tenant from subdomain."""

    def __init__(self, base_domain: str = "example.com"):
        """
        Initialize subdomain resolver.

        Args:
            base_domain: Base domain for the application
        """
        self.base_domain = base_domain

    def resolve(self, request: Any) -> Optional[str]:
        """Resolve tenant from subdomain."""
        host = None

        if hasattr(request, "url") and hasattr(request.url, "host"):
            host = request.url.host
        elif hasattr(request, "headers"):
            host = request.headers.get("host") or request.headers.get("Host")

        if not host:
            return None

        # Remove port if present
        host = host.split(":")[0]

        # Extract subdomain
        if host.endswith(f".{self.base_domain}"):
            subdomain = host[: -(len(self.base_domain) + 1)]
            if subdomain and subdomain != "www":
                return subdomain

        return None


class PathTenantResolver(TenantResolver):
    """Resolves tenant from URL path."""

    def __init__(self, prefix: str = "/t/"):
        """
        Initialize path resolver.

        Args:
            prefix: URL path prefix for tenant (e.g., /t/tenant-slug/)
        """
        self.prefix = prefix
        self.pattern = re.compile(rf"^{re.escape(prefix)}([^/]+)")

    def resolve(self, request: Any) -> Optional[str]:
        """Resolve tenant from path."""
        path = None

        if hasattr(request, "url") and hasattr(request.url, "path"):
            path = request.url.path
        elif hasattr(request, "path"):
            path = request.path

        if not path:
            return None

        match = self.pattern.match(path)
        if match:
            return match.group(1)

        return None


class APIKeyTenantResolver(TenantResolver):
    """Resolves tenant from API key."""

    def __init__(
        self,
        header_name: str = "X-API-Key",
        api_key_to_tenant: Optional[Dict[str, str]] = None,
    ):
        """
        Initialize API key resolver.

        Args:
            header_name: Name of the API key header
            api_key_to_tenant: Mapping of API keys to tenant IDs
        """
        self.header_name = header_name
        self._api_key_map = api_key_to_tenant or {}

    def add_mapping(self, api_key: str, tenant_id: str) -> None:
        """Add API key to tenant mapping."""
        self._api_key_map[api_key] = tenant_id

    def remove_mapping(self, api_key: str) -> None:
        """Remove API key mapping."""
        self._api_key_map.pop(api_key, None)

    def resolve(self, request: Any) -> Optional[str]:
        """Resolve tenant from API key."""
        api_key = None

        if hasattr(request, "headers"):
            headers = request.headers
            if hasattr(headers, "get"):
                api_key = headers.get(self.header_name)
            elif isinstance(headers, dict):
                api_key = headers.get(self.header_name)

        if api_key:
            return self._api_key_map.get(api_key)

        return None


class ChainedTenantResolver(TenantResolver):
    """Chains multiple resolvers, using first successful result."""

    def __init__(self, resolvers: Optional[List[TenantResolver]] = None):
        """Initialize with list of resolvers."""
        self.resolvers = resolvers or []

    def add_resolver(self, resolver: TenantResolver) -> None:
        """Add a resolver to the chain."""
        self.resolvers.append(resolver)

    def resolve(self, request: Any) -> Optional[str]:
        """Try each resolver in order."""
        for resolver in self.resolvers:
            result = resolver.resolve(request)
            if result:
                return result
        return None


def extract_tenant_from_request(
    request: Any,
    resolver: Optional[TenantResolver] = None,
) -> Optional[Tenant]:
    """
    Extract tenant from an HTTP request.

    Args:
        request: HTTP request object
        resolver: Tenant resolver to use

    Returns:
        Tenant if found, None otherwise
    """
    if resolver is None:
        resolver = ChainedTenantResolver([
            HeaderTenantResolver(),
            SubdomainTenantResolver(),
            PathTenantResolver(),
        ])

    tenant_identifier = resolver.resolve(request)
    if not tenant_identifier:
        return None

    manager = get_tenant_manager()

    # Try as ID first, then as slug
    tenant = manager.get_tenant(tenant_identifier)
    if not tenant:
        tenant = manager.get_tenant_by_slug(tenant_identifier)

    return tenant


# FastAPI/Starlette Middleware
try:
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.requests import Request
    from starlette.responses import JSONResponse

    class TenantMiddleware(BaseHTTPMiddleware):
        """
        ASGI middleware for tenant context injection.

        Resolves tenant from request and sets thread-local context.
        """

        def __init__(
            self,
            app,
            resolver: Optional[TenantResolver] = None,
            require_tenant: bool = False,
            exclude_paths: Optional[List[str]] = None,
        ):
            """
            Initialize middleware.

            Args:
                app: ASGI application
                resolver: Tenant resolver
                require_tenant: Whether to require tenant for all requests
                exclude_paths: Paths to exclude from tenant requirement
            """
            super().__init__(app)
            self.resolver = resolver or ChainedTenantResolver([
                HeaderTenantResolver(),
                SubdomainTenantResolver(),
                PathTenantResolver(),
            ])
            self.require_tenant = require_tenant
            self.exclude_paths = exclude_paths or [
                "/health",
                "/metrics",
                "/docs",
                "/openapi.json",
            ]

        async def dispatch(self, request: Request, call_next: Callable):
            """Process request with tenant context."""
            path = request.url.path

            # Skip excluded paths
            if any(path.startswith(p) for p in self.exclude_paths):
                return await call_next(request)

            # Resolve tenant
            tenant = extract_tenant_from_request(request, self.resolver)

            if tenant:
                if not tenant.is_active():
                    return JSONResponse(
                        status_code=403,
                        content={
                            "error": "tenant_inactive",
                            "message": "Tenant account is not active",
                        },
                    )

                # Set tenant context
                set_current_tenant(tenant)

                try:
                    # Add tenant info to request state
                    request.state.tenant = tenant
                    request.state.tenant_id = tenant.id

                    response = await call_next(request)

                    # Add tenant header to response
                    response.headers["X-Tenant-ID"] = tenant.id

                    return response
                finally:
                    set_current_tenant(None)

            elif self.require_tenant:
                return JSONResponse(
                    status_code=400,
                    content={
                        "error": "tenant_required",
                        "message": "Tenant identification required",
                    },
                )

            return await call_next(request)

except ImportError:
    # Starlette not available
    class TenantMiddleware:
        """Placeholder when Starlette is not installed."""

        def __init__(self, *args, **kwargs):
            raise ImportError("Install starlette to use TenantMiddleware")


# FastAPI Dependency
def get_tenant_dependency(
    resolver: Optional[TenantResolver] = None,
    required: bool = True,
) -> Callable:
    """
    Create a FastAPI dependency for tenant injection.

    Args:
        resolver: Tenant resolver to use
        required: Whether tenant is required

    Returns:
        FastAPI dependency function
    """
    if resolver is None:
        resolver = ChainedTenantResolver([
            HeaderTenantResolver(),
            SubdomainTenantResolver(),
            PathTenantResolver(),
        ])

    try:
        from fastapi import HTTPException, Request

        async def get_tenant(request: Request) -> Optional[Tenant]:
            tenant = extract_tenant_from_request(request, resolver)

            if tenant is None and required:
                raise HTTPException(
                    status_code=400,
                    detail="Tenant identification required",
                )

            if tenant and not tenant.is_active():
                raise HTTPException(
                    status_code=403,
                    detail="Tenant account is not active",
                )

            if tenant:
                set_current_tenant(tenant)
                request.state.tenant = tenant

            return tenant

        return get_tenant

    except ImportError:
        def get_tenant(*args, **kwargs):
            raise ImportError("Install fastapi to use get_tenant_dependency")

        return get_tenant
