"""
Tenant data isolation for multi-tenant support.
Provides isolated storage and data access patterns.
"""
from __future__ import annotations

import logging
import shutil
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import (
    Any,
    Callable,
    Generic,
    TypeVar,
)
from .manager import get_current_tenant
from .models import Tenant
logger = logging.getLogger(__name__)
T = TypeVar("T")
class TenantIsolation:
    """
    Utilities for tenant data isolation.
    Provides methods to ensure data is properly scoped to tenants.
    """
    @staticmethod
    def get_tenant_prefix(tenant: Tenant | None = None) -> str:
        """
        Get a prefix for tenant-scoped data.
        Args:
            tenant: Tenant (uses current if not provided)
        Returns:
            Prefix string
        """
        if tenant is None:
            tenant = get_current_tenant()
        if tenant:
            return f"tenant:{tenant.id}:"
        return "global:"
    @staticmethod
    def scope_key(key: str, tenant: Tenant | None = None) -> str:
        """
        Scope a key to a tenant.
        Args:
            key: Original key
            tenant: Tenant (uses current if not provided)
        Returns:
            Tenant-scoped key
        """
        prefix = TenantIsolation.get_tenant_prefix(tenant)
        return f"{prefix}{key}"
    @staticmethod
    def unscope_key(scoped_key: str) -> tuple:
        """
        Remove tenant scope from a key.
        Args:
            scoped_key: Scoped key
        Returns:
            Tuple of (tenant_id or None, original_key)
        """
        if scoped_key.startswith("tenant:"):
            parts = scoped_key.split(":", 2)
            if len(parts) >= 3:
                return parts[1], parts[2]
        elif scoped_key.startswith("global:"):
            return None, scoped_key[7:]
        return None, scoped_key
    @staticmethod
    def get_tenant_path(
        base_path: str,
        tenant: Tenant | None = None,
        create: bool = True,
    ) -> Path:
        """
        Get a tenant-isolated filesystem path.
        Args:
            base_path: Base storage path
            tenant: Tenant (uses current if not provided)
            create: Whether to create the directory
        Returns:
            Tenant-specific path
        """
        if tenant is None:
            tenant = get_current_tenant()
        base = Path(base_path)
        if tenant:
            path = base / "tenants" / tenant.id
        else:
            path = base / "shared"
        if create:
            path.mkdir(parents=True, exist_ok=True)
        return path
    @staticmethod
    def filter_for_tenant(
        items: list[dict[str, Any]],
        tenant_key: str = "tenant_id",
        tenant: Tenant | None = None,
    ) -> list[dict[str, Any]]:
        """
        Filter a list of items to only those belonging to a tenant.
        Args:
            items: List of items with tenant_id field
            tenant_key: Key containing tenant ID
            tenant: Tenant to filter for
        Returns:
            Filtered list
        """
        if tenant is None:
            tenant = get_current_tenant()
        if tenant is None:
            return items
        return [item for item in items if item.get(tenant_key) == tenant.id]
class TenantDataStore(Generic[T]):
    """
    Generic tenant-scoped data store.
    Provides isolated storage per tenant with a common interface.
    """
    def __init__(
        self,
        name: str,
        serializer: Callable[[T], dict] | None = None,
        deserializer: Callable[[dict], T] | None = None,
    ):
        """
        Initialize data store.
        Args:
            name: Store name
            serializer: Function to serialize items
            deserializer: Function to deserialize items
        """
        self.name = name
        self._data: dict[str, dict[str, T]] = {}  # tenant_id -> {key -> value}
        self._serializer = serializer or (lambda x: x)
        self._deserializer = deserializer or (lambda x: x)
        self._lock = threading.Lock()
    def _get_tenant_id(self, tenant: Tenant | None = None) -> str:
        """Get tenant ID, defaulting to current tenant."""
        if tenant:
            return tenant.id
        current = get_current_tenant()
        if current:
            return current.id
        return "_global_"
    def set(
        self,
        key: str,
        value: T,
        tenant: Tenant | None = None,
    ) -> None:
        """
        Set a value.
        Args:
            key: Item key
            value: Item value
            tenant: Tenant (uses current if not provided)
        """
        tenant_id = self._get_tenant_id(tenant)
        with self._lock:
            if tenant_id not in self._data:
                self._data[tenant_id] = {}
            self._data[tenant_id][key] = value
    def get(
        self,
        key: str,
        default: T | None = None,
        tenant: Tenant | None = None,
    ) -> T | None:
        """
        Get a value.
        Args:
            key: Item key
            default: Default value if not found
            tenant: Tenant (uses current if not provided)
        Returns:
            Value or default
        """
        tenant_id = self._get_tenant_id(tenant)
        with self._lock:
            tenant_data = self._data.get(tenant_id, {})
            return tenant_data.get(key, default)
    def delete(
        self,
        key: str,
        tenant: Tenant | None = None,
    ) -> bool:
        """
        Delete a value.
        Args:
            key: Item key
            tenant: Tenant (uses current if not provided)
        Returns:
            True if deleted
        """
        tenant_id = self._get_tenant_id(tenant)
        with self._lock:
            if tenant_id in self._data and key in self._data[tenant_id]:
                del self._data[tenant_id][key]
                return True
            return False
    def list(
        self,
        tenant: Tenant | None = None,
    ) -> list[T]:
        """
        List all values for a tenant.
        Args:
            tenant: Tenant (uses current if not provided)
        Returns:
            List of values
        """
        tenant_id = self._get_tenant_id(tenant)
        with self._lock:
            tenant_data = self._data.get(tenant_id, {})
            return list(tenant_data.values())
    def keys(
        self,
        tenant: Tenant | None = None,
    ) -> list[str]:
        """
        List all keys for a tenant.
        Args:
            tenant: Tenant (uses current if not provided)
        Returns:
            List of keys
        """
        tenant_id = self._get_tenant_id(tenant)
        with self._lock:
            tenant_data = self._data.get(tenant_id, {})
            return list(tenant_data.keys())
    def clear(
        self,
        tenant: Tenant | None = None,
    ) -> int:
        """
        Clear all data for a tenant.
        Args:
            tenant: Tenant (uses current if not provided)
        Returns:
            Number of items cleared
        """
        tenant_id = self._get_tenant_id(tenant)
        with self._lock:
            if tenant_id in self._data:
                count = len(self._data[tenant_id])
                self._data[tenant_id] = {}
                return count
            return 0
    def count(
        self,
        tenant: Tenant | None = None,
    ) -> int:
        """
        Count items for a tenant.
        Args:
            tenant: Tenant (uses current if not provided)
        Returns:
            Item count
        """
        tenant_id = self._get_tenant_id(tenant)
        with self._lock:
            tenant_data = self._data.get(tenant_id, {})
            return len(tenant_data)
class IsolatedStorage:
    """
    Filesystem-based isolated storage for tenants.
    Each tenant gets their own directory structure.
    """
    def __init__(self, base_path: str):
        """
        Initialize isolated storage.
        Args:
            base_path: Base path for storage
        """
        self.base_path = Path(base_path)
        self.base_path.mkdir(parents=True, exist_ok=True)
    def get_tenant_root(self, tenant: Tenant | None = None) -> Path:
        """
        Get the root directory for a tenant.
        Args:
            tenant: Tenant (uses current if not provided)
        Returns:
            Tenant root path
        """
        if tenant is None:
            tenant = get_current_tenant()
        if tenant:
            path = self.base_path / "tenants" / tenant.id
        else:
            path = self.base_path / "shared"
        path.mkdir(parents=True, exist_ok=True)
        return path
    def get_path(
        self,
        *path_parts: str,
        tenant: Tenant | None = None,
        create_parents: bool = True,
    ) -> Path:
        """
        Get a path within tenant storage.
        Args:
            *path_parts: Path components
            tenant: Tenant (uses current if not provided)
            create_parents: Whether to create parent directories
        Returns:
            Full path
        """
        root = self.get_tenant_root(tenant)
        path = root.joinpath(*path_parts)
        if create_parents:
            path.parent.mkdir(parents=True, exist_ok=True)
        return path
    def write(
        self,
        path: str,
        content: bytes,
        tenant: Tenant | None = None,
    ) -> Path:
        """
        Write content to tenant storage.
        Args:
            path: Relative path
            content: Content to write
            tenant: Tenant (uses current if not provided)
        Returns:
            Full path written to
        """
        full_path = self.get_path(path, tenant=tenant)
        full_path.write_bytes(content)
        return full_path
    def write_text(
        self,
        path: str,
        content: str,
        tenant: Tenant | None = None,
        encoding: str = "utf-8",
    ) -> Path:
        """
        Write text content to tenant storage.
        Args:
            path: Relative path
            content: Text content
            tenant: Tenant (uses current if not provided)
            encoding: Text encoding
        Returns:
            Full path written to
        """
        full_path = self.get_path(path, tenant=tenant)
        full_path.write_text(content, encoding=encoding)
        return full_path
    def read(
        self,
        path: str,
        tenant: Tenant | None = None,
    ) -> bytes | None:
        """
        Read content from tenant storage.
        Args:
            path: Relative path
            tenant: Tenant (uses current if not provided)
        Returns:
            Content or None if not found
        """
        full_path = self.get_path(path, tenant=tenant, create_parents=False)
        if full_path.exists():
            return full_path.read_bytes()
        return None
    def read_text(
        self,
        path: str,
        tenant: Tenant | None = None,
        encoding: str = "utf-8",
    ) -> str | None:
        """
        Read text content from tenant storage.
        Args:
            path: Relative path
            tenant: Tenant (uses current if not provided)
            encoding: Text encoding
        Returns:
            Text content or None if not found
        """
        full_path = self.get_path(path, tenant=tenant, create_parents=False)
        if full_path.exists():
            return full_path.read_text(encoding=encoding)
        return None
    def delete(
        self,
        path: str,
        tenant: Tenant | None = None,
    ) -> bool:
        """
        Delete a file from tenant storage.
        Args:
            path: Relative path
            tenant: Tenant (uses current if not provided)
        Returns:
            True if deleted
        """
        full_path = self.get_path(path, tenant=tenant, create_parents=False)
        if full_path.exists():
            if full_path.is_dir():
                shutil.rmtree(full_path)
            else:
                full_path.unlink()
            return True
        return False
    def list_files(
        self,
        path: str = "",
        pattern: str = "*",
        tenant: Tenant | None = None,
        recursive: bool = False,
    ) -> list[Path]:
        """
        List files in tenant storage.
        Args:
            path: Relative path
            pattern: Glob pattern
            tenant: Tenant (uses current if not provided)
            recursive: Whether to search recursively
        Returns:
            List of file paths
        """
        root = self.get_tenant_root(tenant)
        search_path = root / path if path else root
        if not search_path.exists():
            return []
        if recursive:
            return list(search_path.rglob(pattern))
        return list(search_path.glob(pattern))
    def get_usage(self, tenant: Tenant | None = None) -> dict[str, Any]:
        """
        Get storage usage statistics for a tenant.
        Args:
            tenant: Tenant (uses current if not provided)
        Returns:
            Usage statistics
        """
        root = self.get_tenant_root(tenant)
        total_size = 0
        file_count = 0
        for path in root.rglob("*"):
            if path.is_file():
                total_size += path.stat().st_size
                file_count += 1
        return {
            "total_bytes": total_size,
            "total_mb": total_size / (1024 * 1024),
            "file_count": file_count,
            "root_path": str(root),
        }
    def cleanup_tenant(self, tenant: Tenant) -> bool:
        """
        Clean up all storage for a tenant.
        Args:
            tenant: Tenant to clean up
        Returns:
            True if cleaned up
        """
        root = self.base_path / "tenants" / tenant.id
        if root.exists():
            shutil.rmtree(root)
            logger.info(f"Cleaned up storage for tenant: {tenant.id}")
            return True
        return False
class TenantAwareCache:
    """
    Tenant-aware caching layer.
    Ensures cache entries are isolated per tenant.
    """
    def __init__(
        self,
        backend: Any | None = None,
        default_ttl: int = 3600,
    ):
        """
        Initialize cache.
        Args:
            backend: Cache backend (defaults to in-memory)
            default_ttl: Default TTL in seconds
        """
        self._backend = backend
        self._default_ttl = default_ttl
        self._memory_cache: dict[str, dict[str, Any]] = {}
        self._lock = threading.Lock()
    def _get_scoped_key(self, key: str, tenant: Tenant | None = None) -> str:
        """Get tenant-scoped cache key."""
        return TenantIsolation.scope_key(key, tenant)
    def get(
        self,
        key: str,
        tenant: Tenant | None = None,
    ) -> Any | None:
        """
        Get a cached value.
        Args:
            key: Cache key
            tenant: Tenant (uses current if not provided)
        Returns:
            Cached value or None
        """
        scoped_key = self._get_scoped_key(key, tenant)
        with self._lock:
            entry = self._memory_cache.get(scoped_key)
            if entry:
                if entry["expires_at"] > datetime.now(timezone.utc):
                    return entry["value"]
                else:
                    del self._memory_cache[scoped_key]
            return None
    def set(
        self,
        key: str,
        value: Any,
        ttl: int | None = None,
        tenant: Tenant | None = None,
    ) -> None:
        """
        Set a cached value.
        Args:
            key: Cache key
            value: Value to cache
            ttl: TTL in seconds
            tenant: Tenant (uses current if not provided)
        """
        scoped_key = self._get_scoped_key(key, tenant)
        ttl = ttl or self._default_ttl
        from datetime import timedelta
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=ttl)
        with self._lock:
            self._memory_cache[scoped_key] = {
                "value": value,
                "expires_at": expires_at,
            }
    def delete(
        self,
        key: str,
        tenant: Tenant | None = None,
    ) -> bool:
        """
        Delete a cached value.
        Args:
            key: Cache key
            tenant: Tenant (uses current if not provided)
        Returns:
            True if deleted
        """
        scoped_key = self._get_scoped_key(key, tenant)
        with self._lock:
            if scoped_key in self._memory_cache:
                del self._memory_cache[scoped_key]
                return True
            return False
    def clear_tenant(self, tenant: Tenant | None = None) -> int:
        """
        Clear all cache entries for a tenant.
        Args:
            tenant: Tenant (uses current if not provided)
        Returns:
            Number of entries cleared
        """
        prefix = TenantIsolation.get_tenant_prefix(tenant)
        with self._lock:
            keys_to_delete = [
                k for k in self._memory_cache.keys() if k.startswith(prefix)
            ]
            for key in keys_to_delete:
                del self._memory_cache[key]
            return len(keys_to_delete)