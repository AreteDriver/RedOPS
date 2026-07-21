"""
Schedules API routes.
"""

from datetime import datetime, timezone
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field

from ..deps import get_current_user, Pagination

router = APIRouter()


class ScheduleCreate(BaseModel):
    """Create schedule request."""

    name: str = Field(..., description="Schedule name")
    target: str = Field(..., description="Target to scan")
    pipeline: str = Field(default="default", description="Scan pipeline")
    recurrence: str = Field(
        default="daily", description="Recurrence: daily, weekly, monthly, custom"
    )
    cron_expression: str | None = Field(
        None, description="Cron expression for custom schedules"
    )
    enabled: bool = Field(default=True, description="Enable or disable schedule")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "name": "Daily Production Scan",
                "target": "https://example.com",
                "pipeline": "web_security",
                "recurrence": "daily",
            }
        }
    )


class ScheduleUpdate(BaseModel):
    """Update schedule request."""

    name: str | None = None
    pipeline: str | None = None
    recurrence: str | None = None
    cron_expression: str | None = None
    status: str | None = Field(None, description="Status: active, paused, disabled")


class ScheduleResponse(BaseModel):
    """Schedule response model."""

    id: str
    name: str
    target: str
    pipeline: str
    recurrence: str
    cron_expression: str | None = None
    status: str
    next_run: datetime | None = None
    last_run: datetime | None = None
    run_count: int = 0
    created_at: datetime
    updated_at: datetime
    created_by: str | None = None


class ScheduleList(BaseModel):
    """Paginated schedule list response."""

    schedules: list[ScheduleResponse]
    total: int
    skip: int
    limit: int


# In-memory storage
_schedules: dict[str, dict] = {}

def _require_schedule_access(schedule_id: str, user: dict) -> dict:
    """Check schedule exists and user has access (owner or admin)."""
    schedule = _schedules.get(schedule_id)
    if not schedule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Schedule {schedule_id} not found",
        )
    username = user.get("username")
    role = user.get("role")
    if role != "admin" and schedule.get("created_by") != username:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied",
        )
    return schedule



@router.get("", response_model=ScheduleList)
async def list_schedules(
    pagination: Pagination = Depends(),
    status: str | None = None,
    target: str | None = None,
    current_user: dict = Depends(get_current_user),
):
    """List all schedules."""
    username = current_user.get("username")
    role = current_user.get("role")
    schedules = list(_schedules.values())

    # Ownership filter: non-admins only see their own schedules
    if role != "admin":
        schedules = [s for s in schedules if s.get("created_by") == username]

    if status:
        schedules = [s for s in schedules if s.get("status") == status]
    if target:
        schedules = [
            s for s in schedules if target.lower() in s.get("target", "").lower()
        ]

    total = len(schedules)
    schedules = schedules[pagination.skip : pagination.skip + pagination.limit]

    return ScheduleList(
        schedules=[ScheduleResponse(**s) for s in schedules],
        total=total,
        skip=pagination.skip,
        limit=pagination.limit,
    )


@router.post("", response_model=ScheduleResponse, status_code=status.HTTP_201_CREATED)
async def create_schedule(
    schedule: ScheduleCreate,
    current_user: dict = Depends(get_current_user),
):
    """Create a new scan schedule."""
    schedule_id = str(uuid4())
    now = datetime.now(timezone.utc)

    schedule_data = {
        "id": schedule_id,
        "name": schedule.name,
        "target": schedule.target,
        "pipeline": schedule.pipeline,
        "recurrence": schedule.recurrence,
        "cron_expression": schedule.cron_expression,
        "status": "active" if schedule.enabled else "paused",
        "next_run": now,  # Would be calculated based on recurrence
        "last_run": None,
        "run_count": 0,
        "created_at": now,
        "updated_at": now,
        "created_by": current_user.get("username"),
    }

    _schedules[schedule_id] = schedule_data

    return ScheduleResponse(**schedule_data)


@router.get("/{schedule_id}", response_model=ScheduleResponse)
async def get_schedule(
    schedule_id: str,
    current_user: dict = Depends(get_current_user),
):
    """Get schedule details."""
    schedule = _require_schedule_access(schedule_id, current_user)
    return ScheduleResponse(**schedule)


@router.patch("/{schedule_id}", response_model=ScheduleResponse)
async def update_schedule(
    schedule_id: str,
    update: ScheduleUpdate,
    current_user: dict = Depends(get_current_user),
):
    """Update a schedule."""
    schedule = _require_schedule_access(schedule_id, current_user)

    if update.name is not None:
        schedule["name"] = update.name
    if update.pipeline is not None:
        schedule["pipeline"] = update.pipeline
    if update.recurrence is not None:
        schedule["recurrence"] = update.recurrence
    if update.cron_expression is not None:
        schedule["cron_expression"] = update.cron_expression
    if update.status is not None:
        valid_statuses = ["active", "paused", "disabled"]
        if update.status not in valid_statuses:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid status. Must be one of: {valid_statuses}",
            )
        schedule["status"] = update.status

    schedule["updated_at"] = datetime.now(timezone.utc)

    return ScheduleResponse(**schedule)


@router.delete("/{schedule_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_schedule(
    schedule_id: str,
    current_user: dict = Depends(get_current_user),
):
    """Delete a schedule."""
    _require_schedule_access(schedule_id, current_user)
    del _schedules[schedule_id]


@router.post("/{schedule_id}/run")
async def trigger_schedule(
    schedule_id: str,
    current_user: dict = Depends(get_current_user),
):
    """Trigger a scheduled scan immediately."""
    schedule = _require_schedule_access(schedule_id, current_user)

    # In production, would create a scan from the schedule
    scan_id = str(uuid4())

    schedule["last_run"] = datetime.now(timezone.utc)
    schedule["run_count"] += 1

    return {
        "schedule_id": schedule_id,
        "scan_id": scan_id,
        "message": "Scan triggered successfully",
    }
