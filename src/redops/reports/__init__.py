"""
RedOPS Report Generation Module.

Provides PDF report generation for scan results.
"""

from .generator import ReportGenerator, ReportConfig
from .templates.executive import ExecutiveSummaryReport
from .templates.detailed import DetailedFindingsReport
from .templates.compliance import ComplianceReport

__all__ = [
    "ReportGenerator",
    "ReportConfig",
    "ExecutiveSummaryReport",
    "DetailedFindingsReport",
    "ComplianceReport",
]
