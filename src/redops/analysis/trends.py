"""
Trend analysis for security metrics over time.

Analyzes historical scan data to identify patterns and trends.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional
import logging
import statistics

logger = logging.getLogger(__name__)


class MetricType(Enum):
    """Types of metrics to track."""

    TOTAL_FINDINGS = "total_findings"
    CRITICAL_FINDINGS = "critical_findings"
    HIGH_FINDINGS = "high_findings"
    MEDIUM_FINDINGS = "medium_findings"
    LOW_FINDINGS = "low_findings"
    INFO_FINDINGS = "info_findings"
    RISK_SCORE = "risk_score"
    SCAN_DURATION = "scan_duration"
    NEW_FINDINGS = "new_findings"
    RESOLVED_FINDINGS = "resolved_findings"
    REMEDIATION_RATE = "remediation_rate"
    MTTR = "mttr"


class TrendDirection(Enum):
    """Direction of a trend."""

    IMPROVING = "improving"
    DECLINING = "declining"
    STABLE = "stable"
    INSUFFICIENT_DATA = "insufficient_data"


@dataclass
class DataPoint:
    """Single data point in a time series."""

    timestamp: datetime
    value: float
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TrendData:
    """Trend analysis result for a metric."""

    metric: MetricType
    data_points: List[DataPoint] = field(default_factory=list)
    current_value: Optional[float] = None
    previous_value: Optional[float] = None
    average: Optional[float] = None
    min_value: Optional[float] = None
    max_value: Optional[float] = None
    std_dev: Optional[float] = None
    trend_direction: TrendDirection = TrendDirection.INSUFFICIENT_DATA
    percent_change: Optional[float] = None
    forecast_next: Optional[float] = None

    def add_point(self, timestamp: datetime, value: float, **metadata) -> None:
        """Add a data point."""
        self.data_points.append(DataPoint(timestamp, value, metadata))
        self._recalculate()

    def _recalculate(self) -> None:
        """Recalculate statistics."""
        if not self.data_points:
            return

        # Sort by timestamp
        self.data_points.sort(key=lambda p: p.timestamp)

        values = [p.value for p in self.data_points]

        self.current_value = values[-1]
        self.previous_value = values[-2] if len(values) > 1 else None
        self.average = statistics.mean(values)
        self.min_value = min(values)
        self.max_value = max(values)

        if len(values) > 1:
            self.std_dev = statistics.stdev(values)
            self._calculate_trend()
            self._calculate_change()
            self._forecast()

    def _calculate_trend(self) -> None:
        """Calculate trend direction."""
        if len(self.data_points) < 3:
            self.trend_direction = TrendDirection.INSUFFICIENT_DATA
            return

        # Use simple linear regression
        values = [p.value for p in self.data_points[-10:]]  # Last 10 points
        n = len(values)
        x = list(range(n))

        x_mean = sum(x) / n
        y_mean = sum(values) / n

        numerator = sum((xi - x_mean) * (yi - y_mean) for xi, yi in zip(x, values))
        denominator = sum((xi - x_mean) ** 2 for xi in x)

        if denominator == 0:
            self.trend_direction = TrendDirection.STABLE
            return

        slope = numerator / denominator

        # Determine direction based on slope relative to values
        threshold = self.average * 0.05 if self.average else 0.1

        if slope < -threshold:
            # For most metrics, decreasing is good
            if self.metric in (
                MetricType.REMEDIATION_RATE,
                MetricType.RESOLVED_FINDINGS,
            ):
                self.trend_direction = TrendDirection.DECLINING
            else:
                self.trend_direction = TrendDirection.IMPROVING
        elif slope > threshold:
            if self.metric in (
                MetricType.REMEDIATION_RATE,
                MetricType.RESOLVED_FINDINGS,
            ):
                self.trend_direction = TrendDirection.IMPROVING
            else:
                self.trend_direction = TrendDirection.DECLINING
        else:
            self.trend_direction = TrendDirection.STABLE

    def _calculate_change(self) -> None:
        """Calculate percent change."""
        if self.previous_value and self.current_value:
            if self.previous_value != 0:
                self.percent_change = (
                    (self.current_value - self.previous_value) / self.previous_value
                ) * 100

    def _forecast(self) -> None:
        """Simple forecast for next value."""
        if len(self.data_points) < 2:
            return

        # Simple moving average forecast
        recent = [p.value for p in self.data_points[-3:]]
        self.forecast_next = sum(recent) / len(recent)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "metric": self.metric.value,
            "current_value": self.current_value,
            "previous_value": self.previous_value,
            "average": round(self.average, 2) if self.average else None,
            "min": self.min_value,
            "max": self.max_value,
            "std_dev": round(self.std_dev, 2) if self.std_dev else None,
            "trend": self.trend_direction.value,
            "percent_change": round(self.percent_change, 2)
            if self.percent_change
            else None,
            "forecast": round(self.forecast_next, 2) if self.forecast_next else None,
            "data_points": [
                {"timestamp": p.timestamp.isoformat(), "value": p.value}
                for p in self.data_points
            ],
        }


@dataclass
class TrendReport:
    """Complete trend analysis report."""

    target: str
    period_start: datetime
    period_end: datetime
    scan_count: int
    metrics: Dict[MetricType, TrendData] = field(default_factory=dict)
    alerts: List[str] = field(default_factory=list)

    def get_metric(self, metric: MetricType) -> Optional[TrendData]:
        """Get trend data for a specific metric."""
        return self.metrics.get(metric)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "target": self.target,
            "period_start": self.period_start.isoformat(),
            "period_end": self.period_end.isoformat(),
            "scan_count": self.scan_count,
            "metrics": {m.value: t.to_dict() for m, t in self.metrics.items()},
            "alerts": self.alerts,
        }


class TrendAnalyzer:
    """Analyze trends in security metrics over time.

    Processes historical scan data to identify patterns,
    calculate statistics, and generate trend reports.
    """

    # Risk score weights by severity
    RISK_WEIGHTS = {
        "critical": 40,
        "high": 25,
        "medium": 10,
        "low": 3,
        "info": 1,
    }

    def __init__(
        self,
        alert_thresholds: Optional[Dict[str, float]] = None,
        comparison_window_days: int = 30,
    ):
        """
        Initialize analyzer.

        Args:
            alert_thresholds: Thresholds for generating alerts
            comparison_window_days: Window for trend comparison
        """
        self.alert_thresholds = alert_thresholds or {
            "critical_increase": 0,  # Any new critical finding
            "risk_score_increase": 20,  # 20% increase in risk score
            "finding_increase": 50,  # 50% increase in total findings
        }
        self.comparison_window_days = comparison_window_days

    def analyze(
        self,
        scans: List[Dict[str, Any]],
        target: Optional[str] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
    ) -> TrendReport:
        """
        Analyze trends from scan history.

        Args:
            scans: List of scan result dictionaries
            target: Filter by target (optional)
            start_date: Start of analysis period
            end_date: End of analysis period

        Returns:
            TrendReport with analyzed metrics
        """
        # Filter and sort scans
        filtered_scans = self._filter_scans(scans, target, start_date, end_date)

        if not filtered_scans:
            return TrendReport(
                target=target or "all",
                period_start=start_date or datetime.now() - timedelta(days=30),
                period_end=end_date or datetime.now(),
                scan_count=0,
            )

        # Initialize trend data for each metric
        metrics = {metric: TrendData(metric=metric) for metric in MetricType}

        # Process each scan
        for scan in filtered_scans:
            scan_time = self._parse_date(
                scan.get("started_at", scan.get("completed_at"))
            )
            findings = scan.get("findings", [])

            # Count by severity
            severity_counts = self._count_by_severity(findings)

            # Calculate risk score
            risk_score = self._calculate_risk_score(severity_counts)

            # Add data points
            metrics[MetricType.TOTAL_FINDINGS].add_point(
                scan_time, len(findings), scan_id=scan.get("scan_id")
            )
            metrics[MetricType.CRITICAL_FINDINGS].add_point(
                scan_time, severity_counts.get("critical", 0)
            )
            metrics[MetricType.HIGH_FINDINGS].add_point(
                scan_time, severity_counts.get("high", 0)
            )
            metrics[MetricType.MEDIUM_FINDINGS].add_point(
                scan_time, severity_counts.get("medium", 0)
            )
            metrics[MetricType.LOW_FINDINGS].add_point(
                scan_time, severity_counts.get("low", 0)
            )
            metrics[MetricType.INFO_FINDINGS].add_point(
                scan_time, severity_counts.get("info", 0)
            )
            metrics[MetricType.RISK_SCORE].add_point(scan_time, risk_score)

            # Scan duration if available
            if scan.get("completed_at") and scan.get("started_at"):
                start = self._parse_date(scan["started_at"])
                end = self._parse_date(scan["completed_at"])
                duration = (end - start).total_seconds() / 60  # Minutes
                metrics[MetricType.SCAN_DURATION].add_point(scan_time, duration)

        # Determine analysis period
        timestamps = [
            self._parse_date(s.get("started_at"))
            for s in filtered_scans
            if s.get("started_at")
        ]
        period_start = (
            min(timestamps) if timestamps else datetime.now() - timedelta(days=30)
        )
        period_end = max(timestamps) if timestamps else datetime.now()

        # Create report
        report = TrendReport(
            target=target or filtered_scans[0].get("target", "unknown"),
            period_start=period_start,
            period_end=period_end,
            scan_count=len(filtered_scans),
            metrics=metrics,
        )

        # Generate alerts
        report.alerts = self._generate_alerts(metrics)

        logger.info(
            f"Trend analysis complete: {len(filtered_scans)} scans, "
            f"{len(report.alerts)} alerts"
        )

        return report

    def analyze_comparison_series(
        self,
        comparisons: List[Dict[str, Any]],
    ) -> TrendReport:
        """
        Analyze trends from scan comparisons.

        Args:
            comparisons: List of comparison results

        Returns:
            TrendReport with comparison metrics
        """
        metrics = {metric: TrendData(metric=metric) for metric in MetricType}

        for comp in comparisons:
            comp_time = self._parse_date(comp.get("current_date"))

            summary = comp.get("summary", {})

            metrics[MetricType.NEW_FINDINGS].add_point(comp_time, summary.get("new", 0))
            metrics[MetricType.RESOLVED_FINDINGS].add_point(
                comp_time, summary.get("resolved", 0)
            )
            metrics[MetricType.REMEDIATION_RATE].add_point(
                comp_time, summary.get("remediation_rate", 0)
            )
            metrics[MetricType.TOTAL_FINDINGS].add_point(
                comp_time, summary.get("current_total", 0)
            )

        timestamps = [self._parse_date(c.get("current_date")) for c in comparisons]

        return TrendReport(
            target=comparisons[0].get("target", "unknown")
            if comparisons
            else "unknown",
            period_start=min(timestamps) if timestamps else datetime.now(),
            period_end=max(timestamps) if timestamps else datetime.now(),
            scan_count=len(comparisons),
            metrics=metrics,
            alerts=self._generate_alerts(metrics),
        )

    def _filter_scans(
        self,
        scans: List[Dict[str, Any]],
        target: Optional[str],
        start_date: Optional[datetime],
        end_date: Optional[datetime],
    ) -> List[Dict[str, Any]]:
        """Filter scans by criteria."""
        filtered = []

        for scan in scans:
            # Filter by target
            if target and scan.get("target") != target:
                continue

            # Filter by date
            scan_date = self._parse_date(
                scan.get("started_at", scan.get("completed_at"))
            )
            if start_date and scan_date < start_date:
                continue
            if end_date and scan_date > end_date:
                continue

            # Only completed scans
            if scan.get("status") not in ("completed", "finished"):
                continue

            filtered.append(scan)

        # Sort by date
        filtered.sort(key=lambda s: self._parse_date(s.get("started_at", "")))

        return filtered

    def _count_by_severity(self, findings: List[Dict[str, Any]]) -> Dict[str, int]:
        """Count findings by severity."""
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for finding in findings:
            severity = finding.get("severity", "").lower()
            if severity in counts:
                counts[severity] += 1
        return counts

    def _calculate_risk_score(self, severity_counts: Dict[str, int]) -> float:
        """Calculate risk score from severity counts."""
        score = sum(
            severity_counts.get(sev, 0) * weight
            for sev, weight in self.RISK_WEIGHTS.items()
        )
        return min(100, score)  # Cap at 100

    def _generate_alerts(self, metrics: Dict[MetricType, TrendData]) -> List[str]:
        """Generate alerts based on thresholds."""
        alerts = []

        # Critical findings increased
        critical = metrics.get(MetricType.CRITICAL_FINDINGS)
        if critical and critical.current_value and critical.previous_value:
            if critical.current_value > critical.previous_value:
                increase = critical.current_value - critical.previous_value
                alerts.append(
                    f"ALERT: {int(increase)} new critical finding(s) detected"
                )

        # Risk score increased significantly
        risk = metrics.get(MetricType.RISK_SCORE)
        if risk and risk.percent_change:
            threshold = self.alert_thresholds.get("risk_score_increase", 20)
            if risk.percent_change > threshold:
                alerts.append(
                    f"ALERT: Risk score increased by {risk.percent_change:.1f}%"
                )

        # Total findings increased significantly
        total = metrics.get(MetricType.TOTAL_FINDINGS)
        if total and total.percent_change:
            threshold = self.alert_thresholds.get("finding_increase", 50)
            if total.percent_change > threshold:
                alerts.append(
                    f"ALERT: Total findings increased by {total.percent_change:.1f}%"
                )

        # Declining trend in resolved findings
        resolved = metrics.get(MetricType.RESOLVED_FINDINGS)
        if resolved and resolved.trend_direction == TrendDirection.DECLINING:
            alerts.append("WARNING: Remediation velocity is declining")

        return alerts

    def _parse_date(self, date_value: Any) -> datetime:
        """Parse date from various formats."""
        if isinstance(date_value, datetime):
            return date_value
        if isinstance(date_value, str):
            try:
                return datetime.fromisoformat(date_value.replace("Z", "+00:00"))
            except ValueError:
                pass
        return datetime.now()

    def generate_summary(self, report: TrendReport) -> str:
        """Generate a text summary of trend analysis."""
        lines = [
            "Trend Analysis Summary",
            "=" * 50,
            f"Target: {report.target}",
            f"Period: {report.period_start.strftime('%Y-%m-%d')} to "
            f"{report.period_end.strftime('%Y-%m-%d')}",
            f"Scans Analyzed: {report.scan_count}",
            "",
        ]

        # Key metrics
        key_metrics = [
            MetricType.TOTAL_FINDINGS,
            MetricType.CRITICAL_FINDINGS,
            MetricType.HIGH_FINDINGS,
            MetricType.RISK_SCORE,
        ]

        for metric_type in key_metrics:
            metric = report.get_metric(metric_type)
            if metric and metric.current_value is not None:
                trend_icon = {
                    TrendDirection.IMPROVING: "↓",
                    TrendDirection.DECLINING: "↑",
                    TrendDirection.STABLE: "→",
                    TrendDirection.INSUFFICIENT_DATA: "?",
                }.get(metric.trend_direction, "?")

                lines.append(
                    f"{metric_type.value.replace('_', ' ').title()}: "
                    f"{metric.current_value:.0f} {trend_icon}"
                )

                if metric.percent_change is not None:
                    change_str = (
                        f"+{metric.percent_change:.1f}%"
                        if metric.percent_change > 0
                        else f"{metric.percent_change:.1f}%"
                    )
                    lines.append(f"  Change: {change_str} (vs previous)")

                if metric.average is not None:
                    lines.append(f"  Average: {metric.average:.1f}")

        # Alerts
        if report.alerts:
            lines.extend(["", "Alerts:"])
            for alert in report.alerts:
                lines.append(f"  {alert}")

        return "\n".join(lines)

    def export_for_chart(
        self,
        report: TrendReport,
        metric: MetricType,
    ) -> Dict[str, List[Any]]:
        """
        Export metric data in chart-friendly format.

        Returns:
            Dictionary with 'labels' and 'values' lists
        """
        trend_data = report.get_metric(metric)
        if not trend_data:
            return {"labels": [], "values": []}

        return {
            "labels": [
                p.timestamp.strftime("%Y-%m-%d") for p in trend_data.data_points
            ],
            "values": [p.value for p in trend_data.data_points],
            "metric": metric.value,
            "trend": trend_data.trend_direction.value,
        }
