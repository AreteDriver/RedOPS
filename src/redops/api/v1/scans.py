"""
Scan API routes.
"""

from datetime import datetime, timezone
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field

from ..deps import get_current_user, Pagination, ScanFilters

router = APIRouter()


# Pydantic models
class ScanCreate(BaseModel):
    """Create scan request."""

    target: str = Field(..., description="Target URL, IP, or domain")
    pipeline: str = Field(default="default", description="Scan pipeline to use")
    modules: list[str] | None = Field(
        default=None, description="Specific modules to run"
    )
    options: dict | None = Field(default_factory=dict, description="Module options")
    tags: list[str] | None = Field(
        default_factory=list, description="Tags for organization"
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "target": "https://example.com",
                "pipeline": "web_security",
                "modules": ["ssl_check", "header_scan"],
                "tags": ["production", "q1-audit"],
            }
        }
    )


class ScanResponse(BaseModel):
    """Scan response model."""

    scan_id: str
    target: str
    pipeline: str
    status: str
    progress: int = 0
    started_at: datetime | None = None
    completed_at: datetime | None = None
    created_at: datetime
    created_by: str | None = None
    findings_count: int = 0
    metadata: dict = Field(default_factory=dict)


class ScanList(BaseModel):
    """Paginated scan list response."""

    scans: list[ScanResponse]
    total: int
    skip: int
    limit: int


class ScanCompareRequest(BaseModel):
    """Scan comparison request."""

    baseline_scan_id: str
    current_scan_id: str


# In-memory storage (replace with database in production)
_scans: dict[str, dict] = {}

def _require_scan_access(scan_id: str, user: dict) -> dict:
    """Check scan exists and user has access (owner or admin)."""
    scan = _scans.get(scan_id)
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan {scan_id} not found",
        )
    username = user.get("username")
    role = user.get("role")
    if role != "admin" and scan.get("created_by") != username:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied",
        )
    return scan



@router.get("", response_model=ScanList)
async def list_scans(
    pagination: Pagination = Depends(),
    filters: ScanFilters = Depends(),
    current_user: dict = Depends(get_current_user),
):
    """List all scans with optional filtering.

    - **status**: Filter by scan status (pending, running, completed, failed, cancelled)
    - **target**: Filter by target (partial match)
    - **pipeline**: Filter by pipeline name
    """
    username = current_user.get("username")
    role = current_user.get("role")
    scans = list(_scans.values())

    # Ownership filter: non-admins only see their own scans
    if role != "admin":
        scans = [s for s in scans if s.get("created_by") == username]

    # Apply filters
    if filters.status:
        scans = [s for s in scans if s.get("status") == filters.status]
    if filters.target:
        scans = [
            s for s in scans if filters.target.lower() in s.get("target", "").lower()
        ]
    if filters.pipeline:
        scans = [s for s in scans if s.get("pipeline") == filters.pipeline]

    total = len(scans)
    scans = scans[pagination.skip : pagination.skip + pagination.limit]

    return ScanList(
        scans=[ScanResponse(**s) for s in scans],
        total=total,
        skip=pagination.skip,
        limit=pagination.limit,
    )


@router.post("", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
async def create_scan(
    scan: ScanCreate,
    current_user: dict = Depends(get_current_user),
):
    """Create a new security scan.

    The scan will be queued for execution. Use the returned scan_id
    to check status and retrieve results.
    """
    scan_id = str(uuid4())
    now = datetime.now(timezone.utc)

    scan_data = {
        "scan_id": scan_id,
        "target": scan.target,
        "pipeline": scan.pipeline,
        "status": "pending",
        "progress": 0,
        "started_at": None,
        "completed_at": None,
        "created_at": now,
        "created_by": current_user.get("username"),
        "findings_count": 0,
        "metadata": {
            "modules": scan.modules,
            "options": scan.options,
            "tags": scan.tags,
        },
    }

    _scans[scan_id] = scan_data

    # In production, would queue scan for execution here

    return ScanResponse(**scan_data)


@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(
    scan_id: str,
    current_user: dict = Depends(get_current_user),
):
    """Get scan details by ID."""
    scan = _require_scan_access(scan_id, current_user)
    return ScanResponse(**scan)


@router.delete("/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_scan(
    scan_id: str,
    current_user: dict = Depends(get_current_user),
):
    """Delete a scan and its findings."""
    _require_scan_access(scan_id, current_user)
    del _scans[scan_id]


@router.post("/{scan_id}/cancel")
async def cancel_scan(
    scan_id: str,
    current_user: dict = Depends(get_current_user),
):
    """Cancel a running scan."""
    scan = _require_scan_access(scan_id, current_user)

    if scan["status"] not in ("pending", "running"):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Cannot cancel scan with status: {scan['status']}",
        )

    scan["status"] = "cancelled"
    scan["completed_at"] = datetime.now(timezone.utc)

    return {"scan_id": scan_id, "status": "cancelled"}


@router.post("/compare")
async def compare_scans(
    request: ScanCompareRequest,
    current_user: dict = Depends(get_current_user),
):
    """Compare two scans to identify changes.

    Returns new, resolved, and modified findings between the baseline
    and current scan.
    """
    baseline = _require_scan_access(request.baseline_scan_id, current_user)
    current = _require_scan_access(request.current_scan_id, current_user)

    # In production, would use ScanComparator here
    return {
        "baseline_scan_id": request.baseline_scan_id,
        "current_scan_id": request.current_scan_id,
        "summary": {
            "baseline_total": baseline.get("findings_count", 0),
            "current_total": current.get("findings_count", 0),
            "new": 0,
            "resolved": 0,
            "unchanged": 0,
            "modified": 0,
            "regressions": 0,
            "remediation_rate": 0.0,
        },
        "new_findings": [],
        "resolved_findings": [],
        "modified_findings": [],
        "unchanged_findings": [],
        "regression_findings": [],
    }
