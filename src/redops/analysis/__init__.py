"""
RedOPS Analysis Module.

Provides scan comparison, trend analysis, and remediation tracking.
"""

from .comparison import ScanComparator, ComparisonResult, FindingDiff
from .trends import TrendAnalyzer, TrendData, MetricType
from .remediation import RemediationTracker, RemediationStatus

__all__ = [
    "ScanComparator",
    "ComparisonResult",
    "FindingDiff",
    "TrendAnalyzer",
    "TrendData",
    "MetricType",
    "RemediationTracker",
    "RemediationStatus",
]
