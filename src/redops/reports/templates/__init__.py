"""Report templates for RedOPS."""

from .executive import ExecutiveSummaryReport
from .detailed import DetailedFindingsReport
from .compliance import ComplianceReport

__all__ = ["ExecutiveSummaryReport", "DetailedFindingsReport", "ComplianceReport"]
