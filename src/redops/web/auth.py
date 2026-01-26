"""
RedOPS Web Authentication Module.

Provides authentication mechanisms for the web dashboard and API:
- API Key authentication (for programmatic access)
- Basic authentication (for simple setups)
- Session-based authentication (for dashboard)
"""

import os
import secrets
import hashlib
import hmac
from datetime import datetime, timezone, timedelta
from typing import Optional
from dataclasses import dataclass, field

from fastapi import Request, HTTPException, Depends
from fastapi.security import APIKeyHeader, HTTPBasic, HTTPBasicCredentials


# Environment variables for configuration
ENV_AUTH_ENABLED = "REDOPS_AUTH_ENABLED"
ENV_API_KEY = "REDOPS_API_KEY"
ENV_ADMIN_USER = "REDOPS_ADMIN_USER"
ENV_ADMIN_PASSWORD = "REDOPS_ADMIN_PASSWORD"
ENV_SESSION_SECRET = "REDOPS_SESSION_SECRET"
ENV_SESSION_EXPIRY_HOURS = "REDOPS_SESSION_EXPIRY_HOURS"


@dataclass
class AuthConfig:
    """Authentication configuration."""

    enabled: bool = False
    api_key: Optional[str] = None
    admin_user: str = "admin"
    admin_password: Optional[str] = None
    session_secret: str = field(default_factory=lambda: secrets.token_hex(32))
    session_expiry_hours: int = 24
    allowed_paths: list = field(default_factory=lambda: [
        "/api/health",
        "/api/docs",
        "/api/redoc",
        "/openapi.json",
    ])

    @classmethod
    def from_env(cls) -> "AuthConfig":
        """Load configuration from environment variables."""
        return cls(
            enabled=os.environ.get(ENV_AUTH_ENABLED, "false").lower() == "true",
            api_key=os.environ.get(ENV_API_KEY),
            admin_user=os.environ.get(ENV_ADMIN_USER, "admin"),
            admin_password=os.environ.get(ENV_ADMIN_PASSWORD),
            session_secret=os.environ.get(ENV_SESSION_SECRET, secrets.token_hex(32)),
            session_expiry_hours=int(os.environ.get(ENV_SESSION_EXPIRY_HOURS, "24")),
        )

    def is_configured(self) -> bool:
        """Check if authentication is properly configured."""
        if not self.enabled:
            return True  # Not enabled means no config needed
        return bool(self.api_key or self.admin_password)


@dataclass
class AuthenticatedUser:
    """Represents an authenticated user."""

    username: str
    auth_method: str  # "api_key", "basic", "session"
    authenticated_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )


class SessionStore:
    """Simple in-memory session store."""

    def __init__(self, secret: str, expiry_hours: int = 24):
        self._sessions: dict[str, dict] = {}
        self._secret = secret
        self._expiry = timedelta(hours=expiry_hours)

    def create_session(self, username: str) -> str:
        """Create a new session and return the session token."""
        token = secrets.token_urlsafe(32)
        session_id = self._hash_token(token)

        self._sessions[session_id] = {
            "username": username,
            "created_at": datetime.now(timezone.utc),
            "expires_at": datetime.now(timezone.utc) + self._expiry,
        }

        return token

    def validate_session(self, token: str) -> Optional[str]:
        """Validate a session token and return the username if valid."""
        session_id = self._hash_token(token)
        session = self._sessions.get(session_id)

        if not session:
            return None

        if datetime.now(timezone.utc) > session["expires_at"]:
            del self._sessions[session_id]
            return None

        return session["username"]

    def invalidate_session(self, token: str) -> bool:
        """Invalidate a session."""
        session_id = self._hash_token(token)
        if session_id in self._sessions:
            del self._sessions[session_id]
            return True
        return False

    def cleanup_expired(self) -> int:
        """Remove expired sessions and return count of removed sessions."""
        now = datetime.now(timezone.utc)
        expired = [
            sid for sid, session in self._sessions.items()
            if now > session["expires_at"]
        ]
        for sid in expired:
            del self._sessions[sid]
        return len(expired)

    def _hash_token(self, token: str) -> str:
        """Hash a token for storage."""
        return hmac.new(
            self._secret.encode(),
            token.encode(),
            hashlib.sha256
        ).hexdigest()


class AuthManager:
    """
    Manages authentication for the RedOPS web interface.

    Supports:
    - API key authentication via X-API-Key header
    - HTTP Basic authentication
    - Session-based authentication with cookies
    """

    def __init__(self, config: Optional[AuthConfig] = None):
        self.config = config or AuthConfig.from_env()
        self.sessions = SessionStore(
            self.config.session_secret,
            self.config.session_expiry_hours,
        )

        # Security instances
        self._api_key_header = APIKeyHeader(
            name="X-API-Key",
            auto_error=False,
        )
        self._basic_auth = HTTPBasic(auto_error=False)

    def is_public_path(self, path: str) -> bool:
        """Check if a path is publicly accessible."""
        return any(path.startswith(allowed) for allowed in self.config.allowed_paths)

    def verify_api_key(self, api_key: str) -> bool:
        """Verify an API key."""
        if not self.config.api_key:
            return False
        return secrets.compare_digest(api_key, self.config.api_key)

    def verify_basic_auth(self, username: str, password: str) -> bool:
        """Verify basic auth credentials."""
        if not self.config.admin_password:
            return False

        username_match = secrets.compare_digest(username, self.config.admin_user)
        password_match = secrets.compare_digest(password, self.config.admin_password)

        return username_match and password_match

    def verify_session(self, token: str) -> Optional[str]:
        """Verify a session token and return username if valid."""
        return self.sessions.validate_session(token)

    def create_session(self, username: str) -> str:
        """Create a new session for a user."""
        return self.sessions.create_session(username)

    def logout(self, token: str) -> bool:
        """Invalidate a session."""
        return self.sessions.invalidate_session(token)

    async def authenticate(self, request: Request) -> Optional[AuthenticatedUser]:
        """
        Authenticate a request using available methods.

        Tries in order:
        1. API key header
        2. Session cookie
        3. Basic auth header

        Returns:
            AuthenticatedUser if authenticated, None otherwise
        """
        # Try API key
        api_key = request.headers.get("X-API-Key")
        if api_key and self.verify_api_key(api_key):
            return AuthenticatedUser(
                username="api_user",
                auth_method="api_key",
            )

        # Try session cookie
        session_token = request.cookies.get("redops_session")
        if session_token:
            username = self.verify_session(session_token)
            if username:
                return AuthenticatedUser(
                    username=username,
                    auth_method="session",
                )

        # Try basic auth
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Basic "):
            import base64
            try:
                credentials = base64.b64decode(auth_header[6:]).decode("utf-8")
                username, password = credentials.split(":", 1)
                if self.verify_basic_auth(username, password):
                    return AuthenticatedUser(
                        username=username,
                        auth_method="basic",
                    )
            except (ValueError, UnicodeDecodeError):
                pass

        return None


# Global auth manager instance
_auth_manager: Optional[AuthManager] = None


def get_auth_manager() -> AuthManager:
    """Get the global auth manager instance."""
    global _auth_manager
    if _auth_manager is None:
        _auth_manager = AuthManager()
    return _auth_manager


def set_auth_manager(manager: AuthManager) -> None:
    """Set the global auth manager instance."""
    global _auth_manager
    _auth_manager = manager


async def require_auth(request: Request) -> AuthenticatedUser:
    """
    FastAPI dependency that requires authentication.

    Use as a dependency in protected endpoints:

        @app.get("/api/protected")
        async def protected(user: AuthenticatedUser = Depends(require_auth)):
            return {"user": user.username}
    """
    auth_manager = get_auth_manager()

    # Check if auth is enabled
    if not auth_manager.config.enabled:
        return AuthenticatedUser(username="anonymous", auth_method="none")

    # Check if path is public
    if auth_manager.is_public_path(request.url.path):
        return AuthenticatedUser(username="anonymous", auth_method="public")

    # Authenticate
    user = await auth_manager.authenticate(request)
    if user is None:
        raise HTTPException(
            status_code=401,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Basic realm='RedOPS'"},
        )

    return user


async def optional_auth(request: Request) -> Optional[AuthenticatedUser]:
    """
    FastAPI dependency for optional authentication.

    Returns the authenticated user if available, None otherwise.
    Does not raise an error if not authenticated.
    """
    auth_manager = get_auth_manager()

    if not auth_manager.config.enabled:
        return AuthenticatedUser(username="anonymous", auth_method="none")

    return await auth_manager.authenticate(request)


def generate_api_key() -> str:
    """Generate a new random API key."""
    return f"redops_{secrets.token_urlsafe(32)}"
