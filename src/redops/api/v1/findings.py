"""
Findings API routes.
"""

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from ..deps import get_current_user, Pagination
from .scans import _scans

router = APIRouter()


class FindingResponse(BaseModel):
    """Finding response model."""

    id: str
    scan_id: str
    title: str
    description: str | None = None
    severity: str
    status: str = "open"
    module: str | None = None
    category: str | None = None
    cvss_score: float | None = None
    cve_ids: list[str] = Field(default_factory=list)
    evidence: dict = Field(default_factory=dict)
    remediation: str | None = None
    references: list[str] = Field(default_factory=list)
    created_at: datetime
    updated_at: datetime


class FindingUpdate(BaseModel):
    """Finding update request."""

    status: str | None = Field(
        None,
        description="Finding status: open, confirmed, false_positive, accepted_risk, remediated",
    )
    notes: str | None = None


class FindingList(BaseModel):
    """Paginated finding list response."""

    findings: list[FindingResponse]
    total: int
    skip: int
    limit: int


# In-memory storage
_findings: dict[str, dict] = {}

def _require_finding_access(finding_id: str, user: dict) -> dict:
    """Check finding exists and user has access via scan ownership (owner or admin)."""
    finding = _findings.get(finding_id)
    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Finding {finding_id} not found",
        )
    username = user.get("username")
    role = user.get("role")
    if role == "admin":
        return finding
    # Check scan ownership
    scan_id = finding.get("scan_id")
    scan = _scans.get(scan_id) if scan_id else None
    if scan and scan.get("created_by") == username:
        return finding
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Access denied",
    )



@router.get("", response_model=FindingList)
async def list_findings(
    pagination: Pagination = Depends(),
    scan_id: str | None = Query(None, description="Filter by scan ID"),
    severity: str | None = Query(None, description="Filter by severity"),
    status: str | None = Query(None, description="Filter by status"),
    module: str | None = Query(None, description="Filter by module"),
    current_user: dict = Depends(get_current_user),
):
    """List findings with optional filtering."""
    username = current_user.get("username")
    role = current_user.get("role")
    findings = list(_findings.values())

    # Ownership filter: non-admins only see findings from their own scans
    if role != "admin":
        allowed_scan_ids = {
            s["scan_id"] for s in _scans.values()
            if s.get("created_by") == username
        }
        findings = [f for f in findings if f.get("scan_id") in allowed_scan_ids]

    # Apply filters
    if scan_id:
        findings = [f for f in findings if f.get("scan_id") == scan_id]
    if severity:
        findings = [f for f in findings if f.get("severity") == severity]
    if status:
        findings = [f for f in findings if f.get("status") == status]
    if module:
        findings = [f for f in findings if f.get("module") == module]

    total = len(findings)
    findings = findings[pagination.skip : pagination.skip + pagination.limit]

    return FindingList(
        findings=[FindingResponse(**f) for f in findings],
        total=total,
        skip=pagination.skip,
        limit=pagination.limit,
    )


@router.get("/{finding_id}", response_model=FindingResponse)
async def get_finding(
    finding_id: str,
    current_user: dict = Depends(get_current_user),
):
    """Get finding details by ID."""
    finding = _require_finding_access(finding_id, current_user)
    return FindingResponse(**finding)


@router.patch("/{finding_id}", response_model=FindingResponse)
async def update_finding(
    finding_id: str,
    update: FindingUpdate,
    current_user: dict = Depends(get_current_user),
):
    """Update finding status or add notes."""
    finding = _require_finding_access(finding_id, current_user)

    if update.status:
        valid_statuses = [
            "open",
            "confirmed",
            "false_positive",
            "accepted_risk",
            "remediated",
        ]
        if update.status not in valid_statuses:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid status. Must be one of: {valid_statuses}",
            )
        finding["status"] = update.status

    finding["updated_at"] = datetime.now(timezone.utc)

    return FindingResponse(**finding)


@router.get("/severity/summary")
async def severity_summary(
    scan_id: str | None = Query(None, description="Filter by scan ID"),
    current_user: dict = Depends(get_current_user),
):
    """Get finding count by severity."""
    username = current_user.get("username")
    role = current_user.get("role")
    findings = list(_findings.values())

    # Ownership filter: non-admins only see findings from their own scans
    if role != "admin":
        allowed_scan_ids = {
            s["scan_id"] for s in _scans.values()
            if s.get("created_by") == username
        }
        findings = [f for f in findings if f.get("scan_id") in allowed_scan_ids]

    if scan_id:
        findings = [f for f in findings if f.get("scan_id") == scan_id]

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for finding in findings:
        severity = finding.get("severity", "").lower()
        if severity in counts:
            counts[severity] += 1

    return {
        "total": len(findings),
        "by_severity": counts,
    }
