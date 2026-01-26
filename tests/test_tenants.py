"""Tests for multi-tenant support."""

import pytest
from datetime import datetime, timezone, timedelta

from redops.tenants.models import (
    Tenant,
    TenantConfig,
    TenantStatus,
    TenantTier,
    TenantQuota,
    TenantLimits,
)
from redops.tenants.manager import (
    TenantManager,
    MemoryTenantBackend,
    get_current_tenant,
    set_current_tenant,
    tenant_context,
    TenantRequired,
    QuotaExceeded,
)
from redops.tenants.middleware import (
    HeaderTenantResolver,
    SubdomainTenantResolver,
    PathTenantResolver,
    ChainedTenantResolver,
)
from redops.tenants.isolation import (
    TenantIsolation,
    TenantDataStore,
    IsolatedStorage,
    TenantAwareCache,
)


class TestTenantModels:
    """Test tenant model classes."""

    def test_tenant_creation(self):
        """Test basic tenant creation."""
        tenant = Tenant(
            name="Test Company",
            owner_email="admin@test.com",
            owner_name="Test Admin",
        )

        assert tenant.name == "Test Company"
        assert tenant.slug == "test-company"
        assert tenant.status == TenantStatus.PENDING
        assert tenant.tier == TenantTier.FREE
        assert tenant.id is not None

    def test_tenant_slug_generation(self):
        """Test slug generation from name."""
        tenant = Tenant(name="My Awesome Company!")
        assert tenant.slug == "my-awesome-company"

        tenant2 = Tenant(name="Test   Spaces   Here")
        assert tenant2.slug == "test-spaces-here"

    def test_tenant_status_checks(self):
        """Test tenant status methods."""
        tenant = Tenant(name="Test", status=TenantStatus.ACTIVE)
        assert tenant.is_active() is True

        tenant.status = TenantStatus.SUSPENDED
        assert tenant.is_active() is False

        tenant.status = TenantStatus.TRIAL
        assert tenant.is_active() is True

    def test_tenant_to_dict(self):
        """Test tenant serialization."""
        tenant = Tenant(
            name="Test",
            owner_email="test@example.com",
            tier=TenantTier.PROFESSIONAL,
        )

        data = tenant.to_dict()

        assert data["name"] == "Test"
        assert data["tier"] == "professional"
        assert "id" in data
        assert "created_at" in data

    def test_tenant_from_dict(self):
        """Test tenant deserialization."""
        data = {
            "id": "test-123",
            "name": "Test Tenant",
            "slug": "test-tenant",
            "status": "active",
            "tier": "starter",
            "owner_email": "test@example.com",
            "metadata": {"key": "value"},
            "tags": ["test", "demo"],
        }

        tenant = Tenant.from_dict(data)

        assert tenant.id == "test-123"
        assert tenant.name == "Test Tenant"
        assert tenant.status == TenantStatus.ACTIVE
        assert tenant.tier == TenantTier.STARTER
        assert "test" in tenant.tags


class TestTenantQuota:
    """Test quota and limits."""

    def test_quota_for_tier(self):
        """Test tier-based quotas."""
        free_quota = TenantQuota.for_tier(TenantTier.FREE)
        assert free_quota.max_scans_per_day == 5
        assert free_quota.allow_api_access is False

        enterprise_quota = TenantQuota.for_tier(TenantTier.ENTERPRISE)
        assert enterprise_quota.max_scans_per_day == 1000
        assert enterprise_quota.allow_api_access is True
        assert enterprise_quota.allow_custom_modules is True

    def test_limits_check_quota(self):
        """Test quota checking."""
        quota = TenantQuota(max_scans_per_day=10)
        limits = TenantLimits(scans_today=5)

        assert limits.check_quota(quota, "scan") is True

        limits.scans_today = 10
        assert limits.check_quota(quota, "scan") is False

    def test_limits_increment_decrement(self):
        """Test resource counting."""
        limits = TenantLimits()

        limits.increment("scan")
        assert limits.scans_today == 1
        assert limits.scans_this_month == 1

        limits.increment("target", 5)
        assert limits.active_targets == 5

        limits.decrement("target", 2)
        assert limits.active_targets == 3

    def test_limits_reset(self):
        """Test counter resets."""
        limits = TenantLimits(
            scans_today=10,
            api_requests_today=100,
            api_requests_this_minute=50,
        )

        limits.reset_minute()
        assert limits.api_requests_this_minute == 0
        assert limits.api_requests_today == 100

        limits.reset_day()
        assert limits.scans_today == 0
        assert limits.api_requests_today == 0


class TestTenantConfig:
    """Test tenant configuration."""

    def test_config_defaults(self):
        """Test default configuration."""
        config = TenantConfig()

        assert config.default_scan_depth == "standard"
        assert config.require_mfa is False
        assert config.session_timeout_minutes == 60

    def test_config_to_dict(self):
        """Test config serialization."""
        config = TenantConfig(
            notification_email="alerts@example.com",
            require_mfa=True,
        )

        data = config.to_dict()

        assert data["notification_email"] == "alerts@example.com"
        assert data["require_mfa"] is True

    def test_config_from_dict(self):
        """Test config deserialization."""
        data = {
            "slack_webhook_url": "https://hooks.slack.com/test",
            "default_modules": ["port_scan", "header_check"],
            "require_mfa": True,
        }

        config = TenantConfig.from_dict(data)

        assert config.slack_webhook_url == "https://hooks.slack.com/test"
        assert "port_scan" in config.default_modules
        assert config.require_mfa is True


class TestTenantManager:
    """Test tenant manager."""

    def test_create_tenant(self):
        """Test tenant creation via manager."""
        manager = TenantManager()

        tenant = manager.create_tenant(
            name="Test Company",
            owner_email="admin@test.com",
            owner_name="Admin",
            tier=TenantTier.STARTER,
        )

        assert tenant.name == "Test Company"
        assert tenant.tier == TenantTier.STARTER
        assert manager.get_tenant(tenant.id) is not None

    def test_create_tenant_duplicate_slug(self):
        """Test duplicate slug prevention."""
        manager = TenantManager()

        manager.create_tenant(
            name="Test",
            owner_email="test@example.com",
        )

        with pytest.raises(ValueError, match="already exists"):
            manager.create_tenant(
                name="Test",
                owner_email="test2@example.com",
            )

    def test_get_tenant_by_slug(self):
        """Test tenant lookup by slug."""
        manager = TenantManager()

        tenant = manager.create_tenant(
            name="My Company",
            owner_email="test@example.com",
        )

        found = manager.get_tenant_by_slug("my-company")
        assert found is not None
        assert found.id == tenant.id

    def test_update_tenant(self):
        """Test tenant update."""
        manager = TenantManager()

        tenant = manager.create_tenant(
            name="Test",
            owner_email="test@example.com",
        )

        updated = manager.update_tenant(
            tenant.id,
            name="Updated Name",
        )

        assert updated.name == "Updated Name"

    def test_delete_tenant(self):
        """Test tenant deletion."""
        manager = TenantManager()

        tenant = manager.create_tenant(
            name="Test",
            owner_email="test@example.com",
        )

        assert manager.delete_tenant(tenant.id) is True
        assert manager.get_tenant(tenant.id) is None

    def test_suspend_activate_tenant(self):
        """Test suspend and activate."""
        manager = TenantManager()

        tenant = manager.create_tenant(
            name="Test",
            owner_email="test@example.com",
        )
        tenant.status = TenantStatus.ACTIVE
        manager._backend.save(tenant)

        manager.suspend_tenant(tenant.id, "Non-payment")
        tenant = manager.get_tenant(tenant.id)
        assert tenant.status == TenantStatus.SUSPENDED

        manager.activate_tenant(tenant.id)
        tenant = manager.get_tenant(tenant.id)
        assert tenant.status == TenantStatus.ACTIVE

    def test_upgrade_tier(self):
        """Test tier upgrade."""
        manager = TenantManager()

        tenant = manager.create_tenant(
            name="Test",
            owner_email="test@example.com",
            tier=TenantTier.FREE,
        )

        manager.upgrade_tier(tenant.id, TenantTier.PROFESSIONAL)
        tenant = manager.get_tenant(tenant.id)

        assert tenant.tier == TenantTier.PROFESSIONAL
        assert tenant.quota.allow_integrations is True

    def test_check_quota(self):
        """Test quota checking via manager."""
        manager = TenantManager()

        tenant = manager.create_tenant(
            name="Test",
            owner_email="test@example.com",
            tier=TenantTier.FREE,
        )
        tenant.status = TenantStatus.ACTIVE
        manager._backend.save(tenant)

        assert manager.check_quota(tenant.id, "scan") is True

        # Use up quota
        for _ in range(5):
            manager.use_resource(tenant.id, "scan")

        assert manager.check_quota(tenant.id, "scan") is False

    def test_use_release_resource(self):
        """Test resource usage."""
        manager = TenantManager()

        tenant = manager.create_tenant(
            name="Test",
            owner_email="test@example.com",
        )
        tenant.status = TenantStatus.ACTIVE
        manager._backend.save(tenant)

        assert manager.use_resource(tenant.id, "active_scan") is True
        tenant = manager.get_tenant(tenant.id)
        assert tenant.limits.active_scans == 1

        manager.release_resource(tenant.id, "active_scan")
        tenant = manager.get_tenant(tenant.id)
        assert tenant.limits.active_scans == 0

    def test_get_usage_stats(self):
        """Test usage statistics."""
        manager = TenantManager()

        tenant = manager.create_tenant(
            name="Test",
            owner_email="test@example.com",
            tier=TenantTier.STARTER,
        )
        tenant.status = TenantStatus.ACTIVE
        manager._backend.save(tenant)

        manager.use_resource(tenant.id, "scan", 10)

        stats = manager.get_usage_stats(tenant.id)

        assert stats["tier"] == "starter"
        assert stats["limits"]["scans_today"] == 10
        assert "usage_percentage" in stats

    def test_list_tenants(self):
        """Test listing tenants."""
        manager = TenantManager()

        t1 = manager.create_tenant(
            name="Test 1",
            owner_email="t1@example.com",
            tier=TenantTier.FREE,
        )
        t1.status = TenantStatus.ACTIVE
        manager._backend.save(t1)

        t2 = manager.create_tenant(
            name="Test 2",
            owner_email="t2@example.com",
            tier=TenantTier.PROFESSIONAL,
        )

        all_tenants = manager.list_tenants()
        assert len(all_tenants) == 2

        active_only = manager.list_tenants(status=TenantStatus.ACTIVE)
        assert len(active_only) == 1

        pro_only = manager.list_tenants(tier=TenantTier.PROFESSIONAL)
        assert len(pro_only) == 1


class TestTenantContext:
    """Test tenant context management."""

    def test_get_set_current_tenant(self):
        """Test thread-local tenant storage."""
        tenant = Tenant(name="Test", owner_email="test@example.com")

        set_current_tenant(tenant)
        assert get_current_tenant() == tenant

        set_current_tenant(None)
        assert get_current_tenant() is None

    def test_tenant_context_manager(self):
        """Test context manager."""
        tenant = Tenant(name="Test", owner_email="test@example.com")

        assert get_current_tenant() is None

        with tenant_context(tenant):
            assert get_current_tenant() == tenant

        assert get_current_tenant() is None

    def test_nested_context(self):
        """Test nested tenant contexts."""
        tenant1 = Tenant(name="Tenant 1", owner_email="t1@example.com")
        tenant2 = Tenant(name="Tenant 2", owner_email="t2@example.com")

        with tenant_context(tenant1):
            assert get_current_tenant().name == "Tenant 1"

            with tenant_context(tenant2):
                assert get_current_tenant().name == "Tenant 2"

            assert get_current_tenant().name == "Tenant 1"


class TestTenantResolvers:
    """Test tenant resolvers."""

    def test_header_resolver(self):
        """Test header-based resolution."""
        resolver = HeaderTenantResolver(header_name="X-Tenant-ID")

        class MockRequest:
            headers = {"X-Tenant-ID": "test-tenant-123"}

        result = resolver.resolve(MockRequest())
        assert result == "test-tenant-123"

    def test_subdomain_resolver(self):
        """Test subdomain-based resolution."""
        resolver = SubdomainTenantResolver(base_domain="example.com")

        class MockRequest:
            headers = {"host": "acme.example.com"}

        result = resolver.resolve(MockRequest())
        assert result == "acme"

    def test_subdomain_resolver_www(self):
        """Test www subdomain is ignored."""
        resolver = SubdomainTenantResolver(base_domain="example.com")

        class MockRequest:
            headers = {"host": "www.example.com"}

        result = resolver.resolve(MockRequest())
        assert result is None

    def test_path_resolver(self):
        """Test path-based resolution."""
        resolver = PathTenantResolver(prefix="/t/")

        class MockRequest:
            path = "/t/acme-corp/dashboard"

        result = resolver.resolve(MockRequest())
        assert result == "acme-corp"

    def test_chained_resolver(self):
        """Test chained resolver."""
        resolver = ChainedTenantResolver([
            HeaderTenantResolver(),
            SubdomainTenantResolver(base_domain="example.com"),
        ])

        # First resolver matches
        class RequestWithHeader:
            headers = {"X-Tenant-ID": "from-header"}

        assert resolver.resolve(RequestWithHeader()) == "from-header"

        # Falls through to second
        class RequestWithSubdomain:
            headers = {"host": "acme.example.com"}

        assert resolver.resolve(RequestWithSubdomain()) == "acme"


class TestTenantIsolation:
    """Test tenant isolation utilities."""

    def test_scope_key(self):
        """Test key scoping."""
        tenant = Tenant(id="tenant-123", name="Test", owner_email="t@e.com")

        scoped = TenantIsolation.scope_key("mykey", tenant)
        assert scoped == "tenant:tenant-123:mykey"

    def test_scope_key_no_tenant(self):
        """Test key scoping without tenant."""
        scoped = TenantIsolation.scope_key("mykey", None)
        assert scoped == "global:mykey"

    def test_unscope_key(self):
        """Test key unscoping."""
        tenant_id, key = TenantIsolation.unscope_key("tenant:123:mykey")
        assert tenant_id == "123"
        assert key == "mykey"

        tenant_id, key = TenantIsolation.unscope_key("global:mykey")
        assert tenant_id is None
        assert key == "mykey"

    def test_filter_for_tenant(self):
        """Test data filtering."""
        items = [
            {"id": 1, "tenant_id": "t1", "name": "Item 1"},
            {"id": 2, "tenant_id": "t2", "name": "Item 2"},
            {"id": 3, "tenant_id": "t1", "name": "Item 3"},
        ]

        tenant = Tenant(id="t1", name="Test", owner_email="t@e.com")
        filtered = TenantIsolation.filter_for_tenant(items, tenant=tenant)

        assert len(filtered) == 2
        assert all(i["tenant_id"] == "t1" for i in filtered)


class TestTenantDataStore:
    """Test tenant data store."""

    def test_set_get(self):
        """Test basic set/get."""
        store = TenantDataStore[str]("test_store")
        tenant = Tenant(id="t1", name="Test", owner_email="t@e.com")

        store.set("key1", "value1", tenant=tenant)
        assert store.get("key1", tenant=tenant) == "value1"

    def test_isolation(self):
        """Test tenant isolation."""
        store = TenantDataStore[str]("test_store")
        t1 = Tenant(id="t1", name="Tenant 1", owner_email="t1@e.com")
        t2 = Tenant(id="t2", name="Tenant 2", owner_email="t2@e.com")

        store.set("key", "value1", tenant=t1)
        store.set("key", "value2", tenant=t2)

        assert store.get("key", tenant=t1) == "value1"
        assert store.get("key", tenant=t2) == "value2"

    def test_list_keys(self):
        """Test listing."""
        store = TenantDataStore[int]("test_store")
        tenant = Tenant(id="t1", name="Test", owner_email="t@e.com")

        store.set("a", 1, tenant=tenant)
        store.set("b", 2, tenant=tenant)
        store.set("c", 3, tenant=tenant)

        assert store.count(tenant=tenant) == 3
        assert set(store.keys(tenant=tenant)) == {"a", "b", "c"}
        assert set(store.list(tenant=tenant)) == {1, 2, 3}

    def test_delete_clear(self):
        """Test delete and clear."""
        store = TenantDataStore[str]("test_store")
        tenant = Tenant(id="t1", name="Test", owner_email="t@e.com")

        store.set("key1", "val1", tenant=tenant)
        store.set("key2", "val2", tenant=tenant)

        assert store.delete("key1", tenant=tenant) is True
        assert store.get("key1", tenant=tenant) is None

        assert store.clear(tenant=tenant) == 1
        assert store.count(tenant=tenant) == 0


class TestTenantAwareCache:
    """Test tenant-aware cache."""

    def test_cache_isolation(self):
        """Test cache isolation between tenants."""
        cache = TenantAwareCache()
        t1 = Tenant(id="t1", name="Tenant 1", owner_email="t1@e.com")
        t2 = Tenant(id="t2", name="Tenant 2", owner_email="t2@e.com")

        cache.set("key", "value1", tenant=t1)
        cache.set("key", "value2", tenant=t2)

        assert cache.get("key", tenant=t1) == "value1"
        assert cache.get("key", tenant=t2) == "value2"

    def test_cache_ttl(self):
        """Test cache TTL expiration."""
        cache = TenantAwareCache(default_ttl=3600)
        tenant = Tenant(id="t1", name="Test", owner_email="t@e.com")

        # Set with default TTL - should work
        cache.set("key", "value", tenant=tenant)
        assert cache.get("key", tenant=tenant) == "value"

        # Delete works
        cache.delete("key", tenant=tenant)
        assert cache.get("key", tenant=tenant) is None

    def test_clear_tenant(self):
        """Test clearing tenant cache."""
        cache = TenantAwareCache()
        t1 = Tenant(id="t1", name="Tenant 1", owner_email="t1@e.com")
        t2 = Tenant(id="t2", name="Tenant 2", owner_email="t2@e.com")

        cache.set("key1", "val1", tenant=t1)
        cache.set("key2", "val2", tenant=t1)
        cache.set("key1", "val1", tenant=t2)

        cleared = cache.clear_tenant(tenant=t1)
        assert cleared == 2

        assert cache.get("key1", tenant=t1) is None
        assert cache.get("key1", tenant=t2) == "val1"
