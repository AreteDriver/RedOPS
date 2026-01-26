"""
Reports API routes.
"""

from datetime import datetime, timezone
from typing import List, Optional
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from ..deps import get_current_user, Pagination

router = APIRouter()


class ReportCreate(BaseModel):
    """Create report request."""

    scan_id: str = Field(..., description="Scan ID to generate report for")
    report_type: str = Field(
        default="executive",
        description="Report type: executive, detailed, compliance",
    )
    format: str = Field(default="pdf", description="Output format: pdf, html, markdown, json")
    title: Optional[str] = Field(None, description="Custom report title")
    organization: Optional[str] = Field(None, description="Organization name")
    options: Optional[dict] = Field(default_factory=dict, description="Report options")

    class Config:
        json_schema_extra = {
            "example": {
                "scan_id": "123e4567-e89b-12d3-a456-426614174000",
                "report_type": "executive",
                "format": "pdf",
                "title": "Q1 Security Assessment",
                "organization": "ACME Corp",
            }
        }


class ReportResponse(BaseModel):
    """Report response model."""

    report_id: str
    scan_id: str
    report_type: str
    format: str
    status: str
    file_path: Optional[str] = None
    file_size: Optional[int] = None
    created_at: datetime
    completed_at: Optional[datetime] = None
    metadata: dict = Field(default_factory=dict)


class ReportList(BaseModel):
    """Paginated report list response."""

    reports: List[ReportResponse]
    total: int
    skip: int
    limit: int


# In-memory storage
_reports: dict[str, dict] = {}


@router.get("", response_model=ReportList)
async def list_reports(
    pagination: Pagination = Depends(),
    scan_id: Optional[str] = None,
    report_type: Optional[str] = None,
    current_user: dict = Depends(get_current_user),
):
    """List generated reports."""
    reports = list(_reports.values())

    if scan_id:
        reports = [r for r in reports if r.get("scan_id") == scan_id]
    if report_type:
        reports = [r for r in reports if r.get("report_type") == report_type]

    total = len(reports)
    reports = reports[pagination.skip : pagination.skip + pagination.limit]

    return ReportList(
        reports=[ReportResponse(**r) for r in reports],
        total=total,
        skip=pagination.skip,
        limit=pagination.limit,
    )


@router.post("", response_model=ReportResponse, status_code=status.HTTP_202_ACCEPTED)
async def create_report(
    report: ReportCreate,
    current_user: dict = Depends(get_current_user),
):
    """Generate a report from scan results.

    The report generation is asynchronous. Poll the report status
    endpoint to check completion.
    """
    report_id = str(uuid4())
    now = datetime.now(timezone.utc)

    report_data = {
        "report_id": report_id,
        "scan_id": report.scan_id,
        "report_type": report.report_type,
        "format": report.format,
        "status": "generating",
        "file_path": None,
        "file_size": None,
        "created_at": now,
        "completed_at": None,
        "metadata": {
            "title": report.title,
            "organization": report.organization,
            "options": report.options,
            "generated_by": current_user.get("username"),
        },
    }

    _reports[report_id] = report_data

    # In production, would queue report generation here

    return ReportResponse(**report_data)


@router.get("/{report_id}", response_model=ReportResponse)
async def get_report(
    report_id: str,
    current_user: dict = Depends(get_current_user),
):
    """Get report status and metadata."""
    report = _reports.get(report_id)
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Report {report_id} not found",
        )

    return ReportResponse(**report)


@router.get("/{report_id}/download")
async def download_report(
    report_id: str,
    current_user: dict = Depends(get_current_user),
):
    """Download a generated report."""
    report = _reports.get(report_id)
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Report {report_id} not found",
        )

    if report["status"] != "completed":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Report is not ready. Status: {report['status']}",
        )

    # In production, would read from file storage
    # For now, return placeholder
    content = b"Report placeholder content"

    media_type = {
        "pdf": "application/pdf",
        "html": "text/html",
        "markdown": "text/markdown",
        "json": "application/json",
    }.get(report["format"], "application/octet-stream")

    return StreamingResponse(
        iter([content]),
        media_type=media_type,
        headers={
            "Content-Disposition": f"attachment; filename=report_{report_id}.{report['format']}"
        },
    )


@router.delete("/{report_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_report(
    report_id: str,
    current_user: dict = Depends(get_current_user),
):
    """Delete a generated report."""
    if report_id not in _reports:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Report {report_id} not found",
        )

    del _reports[report_id]
