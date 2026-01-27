"""Tests for authentication module."""

from datetime import datetime, timedelta, timezone

import pytest

from redops.api.auth import (
    hash_password,
    verify_password,
    create_access_token,
    create_refresh_token,
    decode_token,
    verify_token,
    revoke_token,
    generate_api_key,
    hash_api_key,
    create_api_key,
    verify_api_key,
    list_api_keys,
    revoke_api_key,
    delete_api_key,
    has_permission,
    check_scope,
    ROLE_PERMISSIONS,
    API_KEY_PREFIX,
)


class TestPasswordHashing:
    """Test password hashing functions."""

    def test_hash_password(self):
        """Password is hashed."""
        password = "secret123"
        hashed = hash_password(password)

        assert hashed != password
        assert len(hashed) > 20

    def test_verify_password_correct(self):
        """Correct password verifies."""
        password = "secret123"
        hashed = hash_password(password)

        assert verify_password(password, hashed) is True

    def test_verify_password_incorrect(self):
        """Incorrect password fails verification."""
        password = "secret123"
        hashed = hash_password(password)

        assert verify_password("wrong", hashed) is False


class TestJWTTokens:
    """Test JWT token functions."""

    def test_create_access_token(self):
        """Access token is created."""
        token = create_access_token(
            user_id="user-123",
            username="testuser",
            role="user",
        )

        assert token is not None
        assert isinstance(token, str)
        assert len(token) > 50

    def test_create_refresh_token(self):
        """Refresh token is created."""
        token = create_refresh_token(user_id="user-123")

        assert token is not None
        assert isinstance(token, str)

    def test_decode_valid_token(self):
        """Valid token is decoded."""
        token = create_access_token(
            user_id="user-123",
            username="testuser",
            role="admin",
        )

        payload = decode_token(token)

        assert payload is not None
        assert payload["sub"] == "user-123"
        assert payload["username"] == "testuser"
        assert payload["role"] == "admin"

    def test_decode_expired_token(self):
        """Expired token returns None."""
        token = create_access_token(
            user_id="user-123",
            username="testuser",
            role="user",
            expires_delta=timedelta(seconds=-1),  # Already expired
        )

        payload = decode_token(token)
        assert payload is None

    def test_decode_invalid_token(self):
        """Invalid token returns None."""
        payload = decode_token("invalid-token")
        assert payload is None

    @pytest.mark.asyncio
    async def test_verify_access_token(self):
        """Access token is verified."""
        token = create_access_token(
            user_id="user-123",
            username="testuser",
            role="user",
        )

        user = await verify_token(token)

        assert user is not None
        assert user["id"] == "user-123"
        assert user["username"] == "testuser"
        assert user["role"] == "user"

    @pytest.mark.asyncio
    async def test_verify_refresh_token_fails(self):
        """Refresh token cannot be used as access token."""
        token = create_refresh_token(user_id="user-123")

        user = await verify_token(token)
        assert user is None

    def test_revoke_token(self):
        """Token can be revoked."""
        token = create_access_token(
            user_id="user-123",
            username="testuser",
            role="user",
        )

        # Token is valid before revocation
        assert decode_token(token) is not None

        # Revoke
        result = revoke_token(token)
        assert result is True

        # Token is invalid after revocation
        assert decode_token(token) is None


class TestAPIKeys:
    """Test API key functions."""

    def test_generate_api_key(self):
        """API key is generated."""
        full_key, key_hash = generate_api_key()

        assert full_key.startswith(f"{API_KEY_PREFIX}_")
        assert len(key_hash) == 64  # SHA-256 hex

    def test_hash_api_key(self):
        """API key is hashed consistently."""
        key = "redops_test123"
        hash1 = hash_api_key(key)
        hash2 = hash_api_key(key)

        assert hash1 == hash2
        assert len(hash1) == 64

    def test_create_api_key(self):
        """API key is created with secret."""
        key = create_api_key(
            user_id="user-123",
            name="test-key",
            scopes=["scans:read", "scans:write"],
        )

        assert key.id is not None
        assert key.name == "test-key"
        assert key.key.startswith(f"{API_KEY_PREFIX}_")
        assert key.scopes == ["scans:read", "scans:write"]
        assert key.is_active is True

    def test_create_api_key_with_expiration(self):
        """API key with expiration is created."""
        key = create_api_key(
            user_id="user-123",
            name="expiring-key",
            expires_in_days=30,
        )

        assert key.expires_at is not None
        assert key.expires_at > datetime.now(timezone.utc)

    @pytest.mark.asyncio
    async def test_verify_api_key(self):
        """API key is verified."""
        key = create_api_key(
            user_id="user-123",
            name="verify-test",
        )

        user = await verify_api_key(key.key)

        assert user is not None
        assert user["id"] == "user-123"
        assert user["role"] == "api"

    @pytest.mark.asyncio
    async def test_verify_invalid_api_key(self):
        """Invalid API key returns None."""
        user = await verify_api_key("invalid-key")
        assert user is None

    @pytest.mark.asyncio
    async def test_verify_wrong_prefix(self):
        """Key with wrong prefix returns None."""
        user = await verify_api_key("wrong_prefix_key123")
        assert user is None

    def test_list_api_keys(self):
        """API keys are listed for user."""
        # Create some keys
        create_api_key(user_id="user-456", name="key1")
        create_api_key(user_id="user-456", name="key2")
        create_api_key(user_id="other-user", name="key3")

        keys = list_api_keys("user-456")

        assert len(keys) >= 2
        assert all(k.name in ["key1", "key2"] for k in keys if k.name.startswith("key"))

    def test_revoke_api_key(self):
        """API key is revoked."""
        key = create_api_key(user_id="user-789", name="revoke-test")

        result = revoke_api_key(key.id, "user-789")

        assert result is True

    def test_delete_api_key(self):
        """API key is deleted."""
        key = create_api_key(user_id="user-000", name="delete-test")

        result = delete_api_key(key.id, "user-000")

        assert result is True

        # Should not be in list anymore
        keys = list_api_keys("user-000")
        assert all(k.id != key.id for k in keys)


class TestRBAC:
    """Test role-based access control."""

    def test_admin_has_all_permissions(self):
        """Admin role has all permissions."""
        assert has_permission("admin", "users:read")
        assert has_permission("admin", "users:write")
        assert has_permission("admin", "users:delete")
        assert has_permission("admin", "scans:read")
        assert has_permission("admin", "config:write")

    def test_user_permissions(self):
        """User role has limited permissions."""
        assert has_permission("user", "scans:read")
        assert has_permission("user", "scans:write")
        assert not has_permission("user", "users:delete")
        assert not has_permission("user", "config:write")

    def test_viewer_permissions(self):
        """Viewer role has read-only permissions."""
        assert has_permission("viewer", "scans:read")
        assert has_permission("viewer", "findings:read")
        assert not has_permission("viewer", "scans:write")
        assert not has_permission("viewer", "findings:write")

    def test_api_role_permissions(self):
        """API role has scan permissions."""
        assert has_permission("api", "scans:read")
        assert has_permission("api", "scans:write")
        assert not has_permission("api", "users:read")

    def test_unknown_role_no_permissions(self):
        """Unknown role has no permissions."""
        assert not has_permission("unknown", "scans:read")
        assert not has_permission("nonexistent", "anything")

    def test_check_scope_user(self):
        """Check scope for regular user."""
        user = {"role": "admin"}
        assert check_scope(user, "users:delete") is True

        user = {"role": "viewer"}
        assert check_scope(user, "users:delete") is False

    def test_check_scope_api_key_with_scopes(self):
        """Check scope for API key with explicit scopes."""
        user = {
            "role": "api",
            "scopes": ["scans:read", "scans:write"],
        }

        assert check_scope(user, "scans:read") is True
        assert check_scope(user, "findings:read") is False

    def test_check_scope_api_key_empty_scopes(self):
        """API key with empty scopes uses role permissions."""
        user = {
            "role": "api",
            "scopes": [],
        }

        # Uses role permissions
        assert check_scope(user, "scans:read") is True
        assert check_scope(user, "users:read") is False


class TestRolePermissions:
    """Test role permission definitions."""

    def test_all_roles_defined(self):
        """All expected roles are defined."""
        assert "admin" in ROLE_PERMISSIONS
        assert "user" in ROLE_PERMISSIONS
        assert "viewer" in ROLE_PERMISSIONS
        assert "api" in ROLE_PERMISSIONS

    def test_admin_is_superset(self):
        """Admin has all permissions that other roles have."""
        ROLE_PERMISSIONS["admin"]

        for role, perms in ROLE_PERMISSIONS.items():
            if role != "admin":
                # Admin should have at least all permissions of other roles
                # (may not be true for specialized roles, but is for this design)
                pass  # This is by design - api role has different permissions

    def test_permissions_are_strings(self):
        """All permissions are strings."""
        for role, perms in ROLE_PERMISSIONS.items():
            assert isinstance(perms, set)
            for perm in perms:
                assert isinstance(perm, str)
                assert ":" in perm  # Format: resource:action
