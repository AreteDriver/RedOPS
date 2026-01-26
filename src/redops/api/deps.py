"""
FastAPI dependencies for RedOPS.

Provides dependency injection for database sessions, authentication, etc.
"""

from typing import AsyncGenerator, Optional

from fastapi import Depends, HTTPException, Header, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session

security = HTTPBearer(auto_error=False)


async def get_db() -> AsyncGenerator[Session, None]:
    """Get database session dependency.

    Yields:
        Database session
    """
    from redops.db import get_database

    db = get_database()
    session = db.get_session()
    try:
        yield session
    finally:
        session.close()


async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
) -> dict:
    """Get the current authenticated user.

    Supports both Bearer token and API key authentication.

    Args:
        credentials: Bearer token credentials
        x_api_key: API key header

    Returns:
        User information dict

    Raises:
        HTTPException: If authentication fails
    """
    from redops.api.auth import verify_token, verify_api_key

    # Try Bearer token first
    if credentials:
        user = await verify_token(credentials.credentials)
        if user:
            return user

    # Try API key
    if x_api_key:
        user = await verify_api_key(x_api_key)
        if user:
            return user

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid authentication credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )


async def get_current_user_optional(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
) -> Optional[dict]:
    """Get the current user if authenticated, None otherwise.

    Args:
        credentials: Bearer token credentials
        x_api_key: API key header

    Returns:
        User information dict or None
    """
    try:
        return await get_current_user(credentials, x_api_key)
    except HTTPException:
        return None


def require_role(required_roles: list[str]):
    """Dependency to require specific roles.

    Args:
        required_roles: List of allowed roles

    Returns:
        Dependency function
    """
    async def role_checker(
        current_user: dict = Depends(get_current_user),
    ) -> dict:
        user_role = current_user.get("role", "viewer")
        if user_role not in required_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{user_role}' not authorized. Required: {required_roles}",
            )
        return current_user

    return role_checker


# Common role dependencies
require_admin = require_role(["admin"])
require_user = require_role(["admin", "user"])
require_viewer = require_role(["admin", "user", "viewer"])


class Pagination:
    """Pagination parameters dependency."""

    def __init__(
        self,
        skip: int = 0,
        limit: int = 100,
    ):
        self.skip = max(0, skip)
        self.limit = min(max(1, limit), 1000)


class ScanFilters:
    """Scan filtering parameters dependency."""

    def __init__(
        self,
        status: Optional[str] = None,
        target: Optional[str] = None,
        pipeline: Optional[str] = None,
    ):
        self.status = status
        self.target = target
        self.pipeline = pipeline
