"""Tests for the web authentication module."""

import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import patch, MagicMock

from redops.web.auth import (
    AuthConfig,
    AuthManager,
    AuthenticatedUser,
    SessionStore,
    generate_api_key,
    require_auth,
    optional_auth,
    set_auth_manager,
)


class TestAuthConfig:
    """Tests for AuthConfig."""

    def test_default_values(self):
        """Test default configuration values."""
        config = AuthConfig()

        assert config.enabled is False
        assert config.api_key is None
        assert config.admin_user == "admin"
        assert config.admin_password is None
        assert config.session_expiry_hours == 24
        assert "/api/health" in config.allowed_paths

    def test_from_env(self):
        """Test loading config from environment."""
        with patch.dict(
            "os.environ",
            {
                "REDOPS_AUTH_ENABLED": "true",
                "REDOPS_API_KEY": "test_key",
                "REDOPS_ADMIN_USER": "testuser",
                "REDOPS_ADMIN_PASSWORD": "testpass",
                "REDOPS_SESSION_EXPIRY_HOURS": "48",
            },
        ):
            config = AuthConfig.from_env()

            assert config.enabled is True
            assert config.api_key == "test_key"
            assert config.admin_user == "testuser"
            assert config.admin_password == "testpass"
            assert config.session_expiry_hours == 48

    def test_is_configured_when_disabled(self):
        """Test is_configured when auth is disabled."""
        config = AuthConfig(enabled=False)
        assert config.is_configured() is True

    def test_is_configured_with_api_key(self):
        """Test is_configured with API key."""
        config = AuthConfig(enabled=True, api_key="test_key")
        assert config.is_configured() is True

    def test_is_configured_with_password(self):
        """Test is_configured with admin password."""
        config = AuthConfig(enabled=True, admin_password="test_pass")
        assert config.is_configured() is True

    def test_is_configured_missing_credentials(self):
        """Test is_configured without credentials."""
        config = AuthConfig(enabled=True)
        assert config.is_configured() is False


class TestSessionStore:
    """Tests for SessionStore."""

    def test_create_session(self):
        """Test session creation."""
        store = SessionStore(secret="test_secret")

        token = store.create_session("testuser")

        assert token is not None
        assert len(token) > 20

    def test_validate_session(self):
        """Test session validation."""
        store = SessionStore(secret="test_secret")
        token = store.create_session("testuser")

        username = store.validate_session(token)

        assert username == "testuser"

    def test_validate_invalid_session(self):
        """Test validation of invalid session."""
        store = SessionStore(secret="test_secret")

        username = store.validate_session("invalid_token")

        assert username is None

    def test_validate_expired_session(self):
        """Test validation of expired session."""
        store = SessionStore(secret="test_secret", expiry_hours=0)
        token = store.create_session("testuser")

        # Force expiry by manipulating session
        session_id = store._hash_token(token)
        store._sessions[session_id]["expires_at"] = datetime.now(
            timezone.utc
        ) - timedelta(hours=1)

        username = store.validate_session(token)

        assert username is None
        assert session_id not in store._sessions  # Should be cleaned up

    def test_invalidate_session(self):
        """Test session invalidation."""
        store = SessionStore(secret="test_secret")
        token = store.create_session("testuser")

        result = store.invalidate_session(token)

        assert result is True
        assert store.validate_session(token) is None

    def test_invalidate_nonexistent_session(self):
        """Test invalidating nonexistent session."""
        store = SessionStore(secret="test_secret")

        result = store.invalidate_session("nonexistent")

        assert result is False

    def test_cleanup_expired(self):
        """Test expired session cleanup."""
        store = SessionStore(secret="test_secret")

        # Create sessions with past expiry
        for i in range(3):
            token = store.create_session(f"user{i}")
            session_id = store._hash_token(token)
            store._sessions[session_id]["expires_at"] = datetime.now(
                timezone.utc
            ) - timedelta(hours=1)

        # Add one valid session
        store.create_session("valid_user")

        removed = store.cleanup_expired()

        assert removed == 3
        assert len(store._sessions) == 1


class TestAuthManager:
    """Tests for AuthManager."""

    def test_init_with_config(self):
        """Test initialization with config."""
        config = AuthConfig(enabled=True, api_key="test_key")
        manager = AuthManager(config)

        assert manager.config.enabled is True
        assert manager.config.api_key == "test_key"

    def test_is_public_path(self):
        """Test public path detection."""
        manager = AuthManager(AuthConfig())

        assert manager.is_public_path("/api/health") is True
        assert manager.is_public_path("/api/docs") is True
        assert manager.is_public_path("/api/scans") is False

    def test_verify_api_key_valid(self):
        """Test valid API key verification."""
        config = AuthConfig(api_key="valid_key")
        manager = AuthManager(config)

        assert manager.verify_api_key("valid_key") is True

    def test_verify_api_key_invalid(self):
        """Test invalid API key verification."""
        config = AuthConfig(api_key="valid_key")
        manager = AuthManager(config)

        assert manager.verify_api_key("wrong_key") is False

    def test_verify_api_key_none_configured(self):
        """Test API key verification when none configured."""
        manager = AuthManager(AuthConfig())

        assert manager.verify_api_key("any_key") is False

    def test_verify_basic_auth_valid(self):
        """Test valid basic auth verification."""
        config = AuthConfig(admin_user="admin", admin_password="secret")
        manager = AuthManager(config)

        assert manager.verify_basic_auth("admin", "secret") is True

    def test_verify_basic_auth_wrong_username(self):
        """Test basic auth with wrong username."""
        config = AuthConfig(admin_user="admin", admin_password="secret")
        manager = AuthManager(config)

        assert manager.verify_basic_auth("wrong", "secret") is False

    def test_verify_basic_auth_wrong_password(self):
        """Test basic auth with wrong password."""
        config = AuthConfig(admin_user="admin", admin_password="secret")
        manager = AuthManager(config)

        assert manager.verify_basic_auth("admin", "wrong") is False

    def test_verify_basic_auth_none_configured(self):
        """Test basic auth when not configured."""
        manager = AuthManager(AuthConfig())

        assert manager.verify_basic_auth("admin", "any") is False

    def test_create_and_verify_session(self):
        """Test session creation and verification."""
        manager = AuthManager(AuthConfig())
        token = manager.create_session("testuser")

        username = manager.verify_session(token)

        assert username == "testuser"

    def test_logout(self):
        """Test logout invalidates session."""
        manager = AuthManager(AuthConfig())
        token = manager.create_session("testuser")

        result = manager.logout(token)

        assert result is True
        assert manager.verify_session(token) is None

    @pytest.mark.asyncio
    async def test_authenticate_with_api_key(self):
        """Test authentication with API key header."""
        config = AuthConfig(enabled=True, api_key="test_key")
        manager = AuthManager(config)

        request = MagicMock()
        request.headers = {"X-API-Key": "test_key"}
        request.cookies = {}

        user = await manager.authenticate(request)

        assert user is not None
        assert user.username == "api_user"
        assert user.auth_method == "api_key"

    @pytest.mark.asyncio
    async def test_authenticate_with_session(self):
        """Test authentication with session cookie."""
        manager = AuthManager(AuthConfig())
        token = manager.create_session("session_user")

        request = MagicMock()
        request.headers = {}
        request.cookies = {"redops_session": token}

        user = await manager.authenticate(request)

        assert user is not None
        assert user.username == "session_user"
        assert user.auth_method == "session"

    @pytest.mark.asyncio
    async def test_authenticate_with_basic_auth(self):
        """Test authentication with basic auth."""
        import base64

        config = AuthConfig(admin_user="admin", admin_password="secret")
        manager = AuthManager(config)

        credentials = base64.b64encode(b"admin:secret").decode("utf-8")
        request = MagicMock()
        request.headers = {"Authorization": f"Basic {credentials}"}
        request.cookies = {}

        user = await manager.authenticate(request)

        assert user is not None
        assert user.username == "admin"
        assert user.auth_method == "basic"

    @pytest.mark.asyncio
    async def test_authenticate_fails(self):
        """Test authentication failure."""
        config = AuthConfig(enabled=True, api_key="test_key")
        manager = AuthManager(config)

        request = MagicMock()
        request.headers = {"X-API-Key": "wrong_key"}
        request.cookies = {}

        user = await manager.authenticate(request)

        assert user is None


class TestRequireAuth:
    """Tests for require_auth dependency."""

    @pytest.mark.asyncio
    async def test_auth_disabled_returns_anonymous(self):
        """Test that disabled auth returns anonymous user."""
        config = AuthConfig(enabled=False)
        set_auth_manager(AuthManager(config))

        request = MagicMock()
        request.url.path = "/api/scans"

        user = await require_auth(request)

        assert user.username == "anonymous"
        assert user.auth_method == "none"

    @pytest.mark.asyncio
    async def test_public_path_returns_anonymous(self):
        """Test that public paths return anonymous user."""
        config = AuthConfig(enabled=True, api_key="key")
        set_auth_manager(AuthManager(config))

        request = MagicMock()
        request.url.path = "/api/health"
        request.headers = {}
        request.cookies = {}

        user = await require_auth(request)

        assert user.username == "anonymous"
        assert user.auth_method == "public"

    @pytest.mark.asyncio
    async def test_authenticated_request_succeeds(self):
        """Test that authenticated request succeeds."""
        config = AuthConfig(enabled=True, api_key="valid_key")
        set_auth_manager(AuthManager(config))

        request = MagicMock()
        request.url.path = "/api/scans"
        request.headers = {"X-API-Key": "valid_key"}
        request.cookies = {}

        user = await require_auth(request)

        assert user is not None
        assert user.auth_method == "api_key"

    @pytest.mark.asyncio
    async def test_unauthenticated_raises_401(self):
        """Test that unauthenticated request raises 401."""
        from fastapi import HTTPException

        config = AuthConfig(enabled=True, api_key="valid_key")
        set_auth_manager(AuthManager(config))

        request = MagicMock()
        request.url.path = "/api/scans"
        request.headers = {}
        request.cookies = {}

        with pytest.raises(HTTPException) as exc:
            await require_auth(request)

        assert exc.value.status_code == 401


class TestOptionalAuth:
    """Tests for optional_auth dependency."""

    @pytest.mark.asyncio
    async def test_auth_disabled_returns_anonymous(self):
        """Test that disabled auth returns anonymous."""
        config = AuthConfig(enabled=False)
        set_auth_manager(AuthManager(config))

        request = MagicMock()

        user = await optional_auth(request)

        assert user is not None
        assert user.auth_method == "none"

    @pytest.mark.asyncio
    async def test_authenticated_returns_user(self):
        """Test that authenticated request returns user."""
        config = AuthConfig(enabled=True, api_key="valid_key")
        set_auth_manager(AuthManager(config))

        request = MagicMock()
        request.headers = {"X-API-Key": "valid_key"}
        request.cookies = {}

        user = await optional_auth(request)

        assert user is not None
        assert user.auth_method == "api_key"

    @pytest.mark.asyncio
    async def test_unauthenticated_returns_none(self):
        """Test that unauthenticated request returns None."""
        config = AuthConfig(enabled=True, api_key="valid_key")
        set_auth_manager(AuthManager(config))

        request = MagicMock()
        request.headers = {}
        request.cookies = {}

        user = await optional_auth(request)

        assert user is None


class TestGenerateApiKey:
    """Tests for generate_api_key function."""

    def test_generates_unique_keys(self):
        """Test that each call generates a unique key."""
        keys = [generate_api_key() for _ in range(100)]

        assert len(set(keys)) == 100

    def test_key_format(self):
        """Test that keys have expected format."""
        key = generate_api_key()

        assert key.startswith("redops_")
        assert len(key) > 40

    def test_key_is_url_safe(self):
        """Test that keys are URL-safe."""
        key = generate_api_key()

        # URL-safe base64 uses only alphanumeric, -, and _
        import re

        assert re.match(r"^redops_[a-zA-Z0-9_-]+$", key)


class TestAuthenticatedUser:
    """Tests for AuthenticatedUser dataclass."""

    def test_creation(self):
        """Test user creation."""
        user = AuthenticatedUser(
            username="testuser",
            auth_method="api_key",
        )

        assert user.username == "testuser"
        assert user.auth_method == "api_key"
        assert user.authenticated_at is not None

    def test_authenticated_at_is_utc(self):
        """Test that authenticated_at is UTC."""
        user = AuthenticatedUser(
            username="test",
            auth_method="basic",
        )

        assert user.authenticated_at.tzinfo == timezone.utc
