"""
Authentication module for RedOPS API.

Provides JWT tokens, API key management, and RBAC.
"""

import hashlib
import hmac
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Optional
from uuid import uuid4

import bcrypt
import jwt
from pydantic import BaseModel, Field

# JWT configuration
JWT_SECRET_KEY = os.environ.get("REDOPS_JWT_SECRET")
if not JWT_SECRET_KEY:
    raise RuntimeError(
        "REDOPS_JWT_SECRET environment variable is required. "
        "Generate one with: python -c \"import secrets; print(secrets.token_urlsafe(64))\""
    )
JWT_ALGORITHM = "HS256"
JWT_ACCESS_TOKEN_EXPIRE_MINUTES = 30
JWT_REFRESH_TOKEN_EXPIRE_DAYS = 7

# API Key configuration
API_KEY_PREFIX = "redops"
API_KEY_LENGTH = 32


class Token(BaseModel):
    """Token response model."""

    access_token: str
    refresh_token: Optional[str] = None
    token_type: str = "bearer"
    expires_in: int


class TokenPayload(BaseModel):
    """JWT token payload."""

    sub: str  # Subject (user ID)
    username: str
    role: str
    exp: datetime
    iat: datetime
    jti: str  # JWT ID for revocation


class APIKeyCreate(BaseModel):
    """API key creation request."""

    name: str = Field(..., description="Key name for identification")
    scopes: list[str] = Field(default_factory=list, description="Allowed scopes")
    expires_in_days: Optional[int] = Field(None, description="Days until expiration")


class APIKeyResponse(BaseModel):
    """API key response model."""

    id: str
    name: str
    prefix: str
    scopes: list[str]
    created_at: datetime
    expires_at: Optional[datetime] = None
    last_used: Optional[datetime] = None
    is_active: bool = True


class APIKeyWithSecret(APIKeyResponse):
    """API key with the secret (only shown on creation)."""

    key: str = Field(..., description="Full API key (only shown once)")


# In-memory storage (use database in production)
_api_keys: dict[str, dict] = {}
_revoked_tokens: set[str] = set()


def hash_password(password: str) -> str:
    """Hash a password using bcrypt."""
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its bcrypt hash."""
    try:
        return bcrypt.checkpw(plain_password.encode(), hashed_password.encode())
    except (ValueError, TypeError):
        return False


def create_access_token(
    user_id: str,
    username: str,
    role: str,
    expires_delta: Optional[timedelta] = None,
) -> str:
    """Create a JWT access token.

    Args:
        user_id: User identifier
        username: Username
        role: User role
        expires_delta: Custom expiration time

    Returns:
        Encoded JWT token
    """
    now = datetime.now(timezone.utc)
    expire = now + (expires_delta or timedelta(minutes=JWT_ACCESS_TOKEN_EXPIRE_MINUTES))

    payload = {
        "sub": user_id,
        "username": username,
        "role": role,
        "exp": expire,
        "iat": now,
        "jti": str(uuid4()),
        "type": "access",
    }

    return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


def create_refresh_token(user_id: str) -> str:
    """Create a JWT refresh token.

    Args:
        user_id: User identifier

    Returns:
        Encoded JWT refresh token
    """
    now = datetime.now(timezone.utc)
    expire = now + timedelta(days=JWT_REFRESH_TOKEN_EXPIRE_DAYS)

    payload = {
        "sub": user_id,
        "exp": expire,
        "iat": now,
        "jti": str(uuid4()),
        "type": "refresh",
    }

    return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


def decode_token(token: str) -> Optional[dict]:
    """Decode and validate a JWT token.

    Args:
        token: JWT token string

    Returns:
        Token payload or None if invalid
    """
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])

        # Check if token is revoked
        if payload.get("jti") in _revoked_tokens:
            return None

        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


async def verify_token(token: str) -> Optional[dict]:
    """Verify an access token and return user info.

    Args:
        token: JWT access token

    Returns:
        User info dict or None
    """
    payload = decode_token(token)
    if not payload:
        return None

    if payload.get("type") != "access":
        return None

    return {
        "id": payload["sub"],
        "username": payload["username"],
        "role": payload["role"],
    }


def revoke_token(token: str) -> bool:
    """Revoke a JWT token.

    Args:
        token: JWT token to revoke

    Returns:
        True if revoked successfully
    """
    payload = decode_token(token)
    if payload and "jti" in payload:
        _revoked_tokens.add(payload["jti"])
        return True
    return False


def generate_api_key() -> tuple[str, str]:
    """Generate a new API key.

    Returns:
        Tuple of (full_key, key_hash)
    """
    # Generate random bytes
    random_bytes = secrets.token_bytes(API_KEY_LENGTH)
    key_secret = secrets.token_urlsafe(API_KEY_LENGTH)

    # Create full key with prefix
    full_key = f"{API_KEY_PREFIX}_{key_secret}"

    # Hash for storage
    key_hash = hashlib.sha256(full_key.encode()).hexdigest()

    return full_key, key_hash


def hash_api_key(key: str) -> str:
    """Hash an API key for storage.

    Args:
        key: Full API key

    Returns:
        SHA-256 hash of the key
    """
    return hashlib.sha256(key.encode()).hexdigest()


def create_api_key(
    user_id: str,
    name: str,
    scopes: Optional[list[str]] = None,
    expires_in_days: Optional[int] = None,
) -> APIKeyWithSecret:
    """Create a new API key.

    Args:
        user_id: Owner user ID
        name: Key name
        scopes: Allowed scopes
        expires_in_days: Days until expiration

    Returns:
        API key with secret (only returned on creation)
    """
    full_key, key_hash = generate_api_key()
    key_id = str(uuid4())
    now = datetime.now(timezone.utc)

    expires_at = None
    if expires_in_days:
        expires_at = now + timedelta(days=expires_in_days)

    # Extract prefix for display
    prefix = full_key[:12] + "..."

    key_data = {
        "id": key_id,
        "user_id": user_id,
        "name": name,
        "key_hash": key_hash,
        "prefix": prefix,
        "scopes": scopes or [],
        "created_at": now,
        "expires_at": expires_at,
        "last_used": None,
        "is_active": True,
    }

    _api_keys[key_id] = key_data

    return APIKeyWithSecret(
        id=key_id,
        name=name,
        prefix=prefix,
        scopes=scopes or [],
        created_at=now,
        expires_at=expires_at,
        last_used=None,
        is_active=True,
        key=full_key,
    )


async def verify_api_key(key: str) -> Optional[dict]:
    """Verify an API key and return user info.

    Args:
        key: Full API key

    Returns:
        User info dict or None
    """
    if not key.startswith(f"{API_KEY_PREFIX}_"):
        return None

    key_hash = hash_api_key(key)

    for key_data in _api_keys.values():
        if key_data["key_hash"] == key_hash:
            # Check if active
            if not key_data["is_active"]:
                return None

            # Check expiration
            if key_data["expires_at"]:
                if datetime.now(timezone.utc) > key_data["expires_at"]:
                    return None

            # Update last used
            key_data["last_used"] = datetime.now(timezone.utc)

            # Return user info
            # In production, would look up user from user_id
            return {
                "id": key_data["user_id"],
                "username": f"api_key_{key_data['name']}",
                "role": "api",
                "scopes": key_data["scopes"],
            }

    return None


def list_api_keys(user_id: str) -> list[APIKeyResponse]:
    """List API keys for a user.

    Args:
        user_id: User ID

    Returns:
        List of API keys (without secrets)
    """
    keys = []
    for key_data in _api_keys.values():
        if key_data["user_id"] == user_id:
            keys.append(
                APIKeyResponse(
                    id=key_data["id"],
                    name=key_data["name"],
                    prefix=key_data["prefix"],
                    scopes=key_data["scopes"],
                    created_at=key_data["created_at"],
                    expires_at=key_data["expires_at"],
                    last_used=key_data["last_used"],
                    is_active=key_data["is_active"],
                )
            )
    return keys


def revoke_api_key(key_id: str, user_id: str) -> bool:
    """Revoke an API key.

    Args:
        key_id: Key ID to revoke
        user_id: Owner user ID

    Returns:
        True if revoked successfully
    """
    if key_id in _api_keys:
        key_data = _api_keys[key_id]
        if key_data["user_id"] == user_id:
            key_data["is_active"] = False
            return True
    return False


def delete_api_key(key_id: str, user_id: str) -> bool:
    """Delete an API key.

    Args:
        key_id: Key ID to delete
        user_id: Owner user ID

    Returns:
        True if deleted successfully
    """
    if key_id in _api_keys:
        key_data = _api_keys[key_id]
        if key_data["user_id"] == user_id:
            del _api_keys[key_id]
            return True
    return False


# RBAC definitions
ROLE_PERMISSIONS = {
    "admin": {
        "users:read",
        "users:write",
        "users:delete",
        "scans:read",
        "scans:write",
        "scans:delete",
        "findings:read",
        "findings:write",
        "reports:read",
        "reports:write",
        "reports:delete",
        "schedules:read",
        "schedules:write",
        "schedules:delete",
        "api_keys:read",
        "api_keys:write",
        "config:read",
        "config:write",
    },
    "user": {
        "scans:read",
        "scans:write",
        "findings:read",
        "findings:write",
        "reports:read",
        "reports:write",
        "schedules:read",
        "schedules:write",
        "api_keys:read",
        "api_keys:write",
    },
    "viewer": {
        "scans:read",
        "findings:read",
        "reports:read",
        "schedules:read",
    },
    "api": {
        "scans:read",
        "scans:write",
        "findings:read",
        "reports:read",
    },
}


def has_permission(role: str, permission: str) -> bool:
    """Check if a role has a specific permission.

    Args:
        role: User role
        permission: Permission to check

    Returns:
        True if role has permission
    """
    role_perms = ROLE_PERMISSIONS.get(role, set())
    return permission in role_perms


def check_scope(user: dict, required_scope: str) -> bool:
    """Check if user has required scope.

    For API key users, checks against key scopes.
    For regular users, checks against role permissions.

    Args:
        user: User info dict
        required_scope: Required scope/permission

    Returns:
        True if user has scope
    """
    # API key users have explicit scopes
    if "scopes" in user:
        if not user["scopes"]:  # Empty scopes = all permissions for role
            return has_permission(user["role"], required_scope)
        return required_scope in user["scopes"]

    # Regular users use role permissions
    return has_permission(user["role"], required_scope)
