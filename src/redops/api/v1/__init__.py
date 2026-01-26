"""
API v1 routes for RedOPS.
"""

from fastapi import APIRouter

from .scans import router as scans_router
from .findings import router as findings_router
from .reports import router as reports_router
from .schedules import router as schedules_router
from .users import router as users_router

router = APIRouter()

# Include all route modules
router.include_router(scans_router, prefix="/scans", tags=["Scans"])
router.include_router(findings_router, prefix="/findings", tags=["Findings"])
router.include_router(reports_router, prefix="/reports", tags=["Reports"])
router.include_router(schedules_router, prefix="/schedules", tags=["Schedules"])
router.include_router(users_router, prefix="/users", tags=["Users"])

__all__ = ["router"]
