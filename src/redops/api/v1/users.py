"""
Users API routes.
"""

from datetime import datetime, timezone
from typing import List, Optional
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict, EmailStr, Field

from ..deps import get_current_user, require_admin, Pagination

router = APIRouter()


class UserCreate(BaseModel):
    """Create user request."""

    username: str = Field(..., min_length=3, max_length=64)
    email: EmailStr
    password: str = Field(..., min_length=8)
    full_name: Optional[str] = None
    role: str = Field(default="user", description="Role: admin, user, viewer")

    model_config = ConfigDict(json_schema_extra={
        "example": {
            "username": "johndoe",
            "email": "john@example.com",
            "password": "securepassword123",
            "full_name": "John Doe",
            "role": "user",
        }
    })


class UserUpdate(BaseModel):
    """Update user request."""

    email: Optional[EmailStr] = None
    full_name: Optional[str] = None
    role: Optional[str] = None
    is_active: Optional[bool] = None


class UserResponse(BaseModel):
    """User response model."""

    id: str
    username: str
    email: str
    full_name: Optional[str] = None
    role: str
    is_active: bool = True
    last_login: Optional[datetime] = None
    created_at: datetime


class UserList(BaseModel):
    """Paginated user list response."""

    users: List[UserResponse]
    total: int
    skip: int
    limit: int


# In-memory storage
_users: dict[str, dict] = {
    "admin-user-id": {
        "id": "admin-user-id",
        "username": "admin",
        "email": "admin@example.com",
        "password_hash": "hashed_password",
        "full_name": "Admin User",
        "role": "admin",
        "is_active": True,
        "last_login": None,
        "created_at": datetime.now(timezone.utc),
    }
}


@router.get("/me", response_model=UserResponse)
async def get_current_user_info(
    current_user: dict = Depends(get_current_user),
):
    """Get current user information."""
    return UserResponse(**current_user)


@router.get("", response_model=UserList)
async def list_users(
    pagination: Pagination = Depends(),
    role: Optional[str] = None,
    is_active: Optional[bool] = None,
    current_user: dict = Depends(require_admin),
):
    """List all users (admin only)."""
    users = list(_users.values())

    if role:
        users = [u for u in users if u.get("role") == role]
    if is_active is not None:
        users = [u for u in users if u.get("is_active") == is_active]

    total = len(users)
    users = users[pagination.skip : pagination.skip + pagination.limit]

    return UserList(
        users=[UserResponse(**u) for u in users],
        total=total,
        skip=pagination.skip,
        limit=pagination.limit,
    )


@router.post("", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def create_user(
    user: UserCreate,
    current_user: dict = Depends(require_admin),
):
    """Create a new user (admin only)."""
    # Check for existing username
    for existing in _users.values():
        if existing["username"] == user.username:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Username already exists",
            )
        if existing["email"] == user.email:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Email already exists",
            )

    user_id = str(uuid4())
    now = datetime.now(timezone.utc)

    # In production, would hash password here
    user_data = {
        "id": user_id,
        "username": user.username,
        "email": user.email,
        "password_hash": f"hashed_{user.password}",
        "full_name": user.full_name,
        "role": user.role,
        "is_active": True,
        "last_login": None,
        "created_at": now,
    }

    _users[user_id] = user_data

    return UserResponse(**user_data)


@router.get("/{user_id}", response_model=UserResponse)
async def get_user(
    user_id: str,
    current_user: dict = Depends(require_admin),
):
    """Get user details (admin only)."""
    user = _users.get(user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User {user_id} not found",
        )

    return UserResponse(**user)


@router.patch("/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: str,
    update: UserUpdate,
    current_user: dict = Depends(require_admin),
):
    """Update a user (admin only)."""
    user = _users.get(user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User {user_id} not found",
        )

    if update.email is not None:
        user["email"] = update.email
    if update.full_name is not None:
        user["full_name"] = update.full_name
    if update.role is not None:
        valid_roles = ["admin", "user", "viewer"]
        if update.role not in valid_roles:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid role. Must be one of: {valid_roles}",
            )
        user["role"] = update.role
    if update.is_active is not None:
        user["is_active"] = update.is_active

    return UserResponse(**user)


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(
    user_id: str,
    current_user: dict = Depends(require_admin),
):
    """Delete a user (admin only)."""
    if user_id not in _users:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User {user_id} not found",
        )

    # Prevent deleting self
    if user_id == current_user.get("id"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete your own account",
        )

    del _users[user_id]
