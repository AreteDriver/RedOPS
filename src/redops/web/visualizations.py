"""
Dashboard visualizations for RedOPS.

Provides chart data generation and visualization components for the web dashboard.
"""

from typing import Dict, Any, List
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass, field
from collections import Counter
import json


@dataclass
class ChartData:
    """Generic chart data structure."""

    chart_type: str  # bar, line, pie, doughnut, radar
    labels: List[str]
    datasets: List[Dict[str, Any]]
    title: str = ""
    options: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "type": self.chart_type,
            "data": {
                "labels": self.labels,
                "datasets": self.datasets,
            },
            "options": self.options,
            "title": self.title,
        }

    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict())


class SeverityDistributionChart:
    """
    Generates severity distribution charts.

    Shows the breakdown of findings by severity level.
    """

    COLORS = {
        "critical": "#dc3545",  # Red
        "high": "#fd7e14",  # Orange
        "medium": "#ffc107",  # Yellow
        "low": "#28a745",  # Green
        "info": "#17a2b8",  # Cyan
    }

    def __init__(self, findings: List[Dict[str, Any]]):
        """
        Initialize with findings data.

        Args:
            findings: List of finding dictionaries
        """
        self.findings = findings

    def generate(self, chart_type: str = "doughnut") -> ChartData:
        """
        Generate the severity distribution chart.

        Args:
            chart_type: Type of chart (doughnut, pie, bar)

        Returns:
            ChartData for the visualization
        """
        # Count by severity
        severity_counts = Counter(f.get("severity", "unknown") for f in self.findings)

        # Order by severity
        severity_order = ["critical", "high", "medium", "low", "info"]
        labels = []
        data = []
        colors = []

        for severity in severity_order:
            count = severity_counts.get(severity, 0)
            if count > 0:
                labels.append(severity.capitalize())
                data.append(count)
                colors.append(self.COLORS.get(severity, "#6c757d"))

        # Add unknown if present
        unknown_count = severity_counts.get("unknown", 0)
        if unknown_count > 0:
            labels.append("Unknown")
            data.append(unknown_count)
            colors.append("#6c757d")

        return ChartData(
            chart_type=chart_type,
            labels=labels,
            datasets=[
                {
                    "data": data,
                    "backgroundColor": colors,
                    "borderWidth": 1,
                }
            ],
            title="Findings by Severity",
            options={
                "responsive": True,
                "plugins": {
                    "legend": {"position": "right"},
                    "title": {"display": True, "text": "Findings by Severity"},
                },
            },
        )


class ModuleDistributionChart:
    """
    Generates module distribution charts.

    Shows which modules produced findings.
    """

    def __init__(self, findings: List[Dict[str, Any]]):
        """
        Initialize with findings data.

        Args:
            findings: List of finding dictionaries
        """
        self.findings = findings

    def generate(self, max_modules: int = 10) -> ChartData:
        """
        Generate the module distribution chart.

        Args:
            max_modules: Maximum number of modules to show

        Returns:
            ChartData for the visualization
        """
        # Count by module
        module_counts = Counter(f.get("module", "unknown") for f in self.findings)

        # Get top modules
        top_modules = module_counts.most_common(max_modules)

        labels = [m[0].split(".")[-1] for m in top_modules]  # Short names
        data = [m[1] for m in top_modules]

        return ChartData(
            chart_type="bar",
            labels=labels,
            datasets=[
                {
                    "label": "Findings",
                    "data": data,
                    "backgroundColor": "#007bff",
                    "borderWidth": 1,
                }
            ],
            title="Findings by Module",
            options={
                "responsive": True,
                "plugins": {
                    "legend": {"display": False},
                    "title": {"display": True, "text": "Findings by Module"},
                },
                "scales": {
                    "y": {"beginAtZero": True},
                },
            },
        )


class TimelineChart:
    """
    Generates timeline charts.

    Shows findings or scans over time.
    """

    def __init__(self, items: List[Dict[str, Any]], timestamp_key: str = "timestamp"):
        """
        Initialize with timestamped items.

        Args:
            items: List of items with timestamps
            timestamp_key: Key for timestamp field
        """
        self.items = items
        self.timestamp_key = timestamp_key

    def generate(self, period: str = "day", days: int = 7) -> ChartData:
        """
        Generate the timeline chart.

        Args:
            period: Aggregation period (hour, day, week)
            days: Number of days to include

        Returns:
            ChartData for the visualization
        """
        now = datetime.now(timezone.utc)
        start = now - timedelta(days=days)

        # Parse timestamps and filter
        parsed_items = []
        for item in self.items:
            ts = item.get(self.timestamp_key)
            if ts:
                if isinstance(ts, str):
                    try:
                        ts = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                    except ValueError:
                        continue
                if ts >= start:
                    parsed_items.append((ts, item))

        # Generate time buckets
        if period == "hour":
            bucket_format = "%Y-%m-%d %H:00"
            label_format = "%H:00"
        elif period == "week":
            bucket_format = "%Y-W%W"
            label_format = "Week %W"
        else:  # day
            bucket_format = "%Y-%m-%d"
            label_format = "%b %d"

        # Count items per bucket
        bucket_counts: Dict[str, int] = {}
        for ts, item in parsed_items:
            bucket = ts.strftime(bucket_format)
            bucket_counts[bucket] = bucket_counts.get(bucket, 0) + 1

        # Generate all buckets for the period
        labels = []
        data = []
        current = start
        while current <= now:
            bucket = current.strftime(bucket_format)
            labels.append(current.strftime(label_format))
            data.append(bucket_counts.get(bucket, 0))

            if period == "hour":
                current += timedelta(hours=1)
            elif period == "week":
                current += timedelta(weeks=1)
            else:
                current += timedelta(days=1)

        return ChartData(
            chart_type="line",
            labels=labels,
            datasets=[
                {
                    "label": "Count",
                    "data": data,
                    "fill": True,
                    "borderColor": "#007bff",
                    "backgroundColor": "rgba(0, 123, 255, 0.1)",
                    "tension": 0.4,
                }
            ],
            title=f"Activity Over Time ({days} days)",
            options={
                "responsive": True,
                "plugins": {
                    "legend": {"display": False},
                    "title": {"display": True, "text": "Activity Over Time"},
                },
                "scales": {
                    "y": {"beginAtZero": True},
                },
            },
        )


class RiskScoreGauge:
    """
    Generates risk score gauge visualization.

    Shows overall risk score as a gauge/speedometer.
    """

    def __init__(self, findings: List[Dict[str, Any]]):
        """
        Initialize with findings data.

        Args:
            findings: List of finding dictionaries
        """
        self.findings = findings

    def calculate_score(self) -> int:
        """
        Calculate overall risk score (0-100).

        Returns:
            Risk score
        """
        if not self.findings:
            return 0

        # Severity weights
        weights = {
            "critical": 40,
            "high": 25,
            "medium": 15,
            "low": 5,
            "info": 1,
        }

        total_weight = 0
        for finding in self.findings:
            severity = finding.get("severity", "info")
            total_weight += weights.get(severity, 1)

        # Cap at 100
        return min(100, total_weight)

    def generate(self) -> Dict[str, Any]:
        """
        Generate the risk score gauge data.

        Returns:
            Gauge configuration data
        """
        score = self.calculate_score()

        # Determine color based on score
        if score >= 80:
            color = "#dc3545"  # Red
            label = "Critical"
        elif score >= 60:
            color = "#fd7e14"  # Orange
            label = "High"
        elif score >= 40:
            color = "#ffc107"  # Yellow
            label = "Medium"
        elif score >= 20:
            color = "#28a745"  # Green
            label = "Low"
        else:
            color = "#17a2b8"  # Cyan
            label = "Minimal"

        return {
            "type": "gauge",
            "value": score,
            "max": 100,
            "color": color,
            "label": label,
            "title": "Risk Score",
            "zones": [
                {"min": 0, "max": 20, "color": "#17a2b8"},
                {"min": 20, "max": 40, "color": "#28a745"},
                {"min": 40, "max": 60, "color": "#ffc107"},
                {"min": 60, "max": 80, "color": "#fd7e14"},
                {"min": 80, "max": 100, "color": "#dc3545"},
            ],
        }


class ThreatIntelSummary:
    """
    Generates threat intelligence summary visualization.

    Aggregates and visualizes threat intel data.
    """

    def __init__(self, intel_results: Dict[str, Any]):
        """
        Initialize with threat intel results.

        Args:
            intel_results: Dictionary of intel results from context
        """
        self.intel_results = intel_results

    def generate(self) -> Dict[str, Any]:
        """
        Generate the threat intel summary.

        Returns:
            Summary data with charts
        """
        summary = {
            "sources_queried": [],
            "total_hits": 0,
            "malicious_indicators": [],
            "reputation_scores": {},
        }

        # Process each intel source
        if "greynoise_result" in self.intel_results:
            gn = self.intel_results["greynoise_result"]
            summary["sources_queried"].append("GreyNoise")
            if gn.get("noise"):
                summary["total_hits"] += 1

        if "abuseipdb_result" in self.intel_results:
            ab = self.intel_results["abuseipdb_result"]
            summary["sources_queried"].append("AbuseIPDB")
            score = ab.get("data", {}).get("abuseConfidenceScore", 0)
            summary["reputation_scores"]["AbuseIPDB"] = score
            if score > 50:
                summary["malicious_indicators"].append(
                    f"AbuseIPDB: {score}% confidence"
                )

        if "urlhaus_result" in self.intel_results:
            uh = self.intel_results["urlhaus_result"]
            summary["sources_queried"].append("URLhaus")
            if uh.get("query_status") == "listed":
                summary["total_hits"] += 1
                summary["malicious_indicators"].append("URLhaus: Listed as malicious")

        if "urlscan_result" in self.intel_results:
            us = self.intel_results["urlscan_result"]
            summary["sources_queried"].append("URLScan.io")
            analysis = us.get("analysis", {})
            if analysis.get("is_malicious"):
                summary["total_hits"] += 1
                summary["malicious_indicators"].append(
                    f"URLScan: {analysis.get('verdict')}"
                )

        if "otx_indicator" in self.intel_results:
            otx = self.intel_results["otx_indicator"]
            summary["sources_queried"].append("AlienVault OTX")
            analysis = otx.get("analysis", {})
            if analysis.get("is_malicious"):
                summary["total_hits"] += 1
                summary["malicious_indicators"].append(
                    f"OTX: {analysis.get('pulse_count', 0)} pulses"
                )

        # Generate radar chart for reputation scores
        if summary["reputation_scores"]:
            summary["reputation_chart"] = ChartData(
                chart_type="radar",
                labels=list(summary["reputation_scores"].keys()),
                datasets=[
                    {
                        "label": "Reputation Score",
                        "data": list(summary["reputation_scores"].values()),
                        "fill": True,
                        "backgroundColor": "rgba(255, 99, 132, 0.2)",
                        "borderColor": "rgb(255, 99, 132)",
                    }
                ],
                title="Reputation Scores",
            ).to_dict()

        return summary


class ScanSummaryDashboard:
    """
    Generates a complete scan summary dashboard.

    Combines multiple visualizations into a cohesive dashboard.
    """

    def __init__(self, context_data: Dict[str, Any]):
        """
        Initialize with context data from a scan.

        Args:
            context_data: Full context data dictionary
        """
        self.context_data = context_data

    def _extract_findings(self) -> List[Dict[str, Any]]:
        """Extract findings from context data."""
        findings = []
        for key, value in self.context_data.items():
            if key.startswith("finding_") and isinstance(value, dict):
                findings.append(value)
        return findings

    def generate(self) -> Dict[str, Any]:
        """
        Generate the complete dashboard data.

        Returns:
            Dashboard configuration with all visualizations
        """
        findings = self._extract_findings()

        dashboard = {
            "summary": {
                "total_findings": len(findings),
                "critical": sum(1 for f in findings if f.get("severity") == "critical"),
                "high": sum(1 for f in findings if f.get("severity") == "high"),
                "medium": sum(1 for f in findings if f.get("severity") == "medium"),
                "low": sum(1 for f in findings if f.get("severity") == "low"),
                "target": self.context_data.get("target"),
                "pipeline": self.context_data.get("pipeline_name"),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
            "charts": {},
        }

        # Severity distribution
        if findings:
            severity_chart = SeverityDistributionChart(findings)
            dashboard["charts"]["severity"] = severity_chart.generate().to_dict()

            # Module distribution
            module_chart = ModuleDistributionChart(findings)
            dashboard["charts"]["modules"] = module_chart.generate().to_dict()

            # Risk score
            risk_gauge = RiskScoreGauge(findings)
            dashboard["charts"]["risk_score"] = risk_gauge.generate()

        # Threat intel summary
        intel_results = {
            k: v
            for k, v in self.context_data.items()
            if k.endswith("_result") or k.endswith("_indicator")
        }
        if intel_results:
            intel_summary = ThreatIntelSummary(intel_results)
            dashboard["threat_intel"] = intel_summary.generate()

        return dashboard


def generate_dashboard_html(dashboard_data: Dict[str, Any]) -> str:
    """
    Generate HTML for the dashboard.

    Args:
        dashboard_data: Dashboard data from ScanSummaryDashboard

    Returns:
        HTML string for the dashboard
    """
    summary = dashboard_data.get("summary", {})
    charts = dashboard_data.get("charts", {})

    html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>RedOPS Scan Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 20px; background: #f5f5f5; }}
        .dashboard {{ max-width: 1400px; margin: 0 auto; }}
        .header {{ background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; }}
        .header h1 {{ margin: 0 0 10px 0; }}
        .summary-cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 20px; }}
        .card {{ background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); text-align: center; }}
        .card.critical {{ border-left: 4px solid #dc3545; }}
        .card.high {{ border-left: 4px solid #fd7e14; }}
        .card.medium {{ border-left: 4px solid #ffc107; }}
        .card.low {{ border-left: 4px solid #28a745; }}
        .card .count {{ font-size: 2.5rem; font-weight: bold; }}
        .card .label {{ color: #666; text-transform: uppercase; font-size: 0.9rem; }}
        .charts {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(400px, 1fr)); gap: 20px; }}
        .chart-container {{ background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .gauge-container {{ text-align: center; }}
        .gauge-value {{ font-size: 3rem; font-weight: bold; }}
        .gauge-label {{ color: #666; }}
    </style>
</head>
<body>
    <div class="dashboard">
        <div class="header">
            <h1>Security Scan Results</h1>
            <p>Target: {summary.get("target", "N/A")} | Pipeline: {summary.get("pipeline", "N/A")}</p>
        </div>

        <div class="summary-cards">
            <div class="card">
                <div class="count">{summary.get("total_findings", 0)}</div>
                <div class="label">Total Findings</div>
            </div>
            <div class="card critical">
                <div class="count" style="color: #dc3545;">{summary.get("critical", 0)}</div>
                <div class="label">Critical</div>
            </div>
            <div class="card high">
                <div class="count" style="color: #fd7e14;">{summary.get("high", 0)}</div>
                <div class="label">High</div>
            </div>
            <div class="card medium">
                <div class="count" style="color: #ffc107;">{summary.get("medium", 0)}</div>
                <div class="label">Medium</div>
            </div>
            <div class="card low">
                <div class="count" style="color: #28a745;">{summary.get("low", 0)}</div>
                <div class="label">Low</div>
            </div>
        </div>

        <div class="charts">
            <div class="chart-container">
                <canvas id="severityChart"></canvas>
            </div>
            <div class="chart-container">
                <canvas id="modulesChart"></canvas>
            </div>
        </div>
    </div>

    <script>
        const severityData = {json.dumps(charts.get("severity", {}))};
        const modulesData = {json.dumps(charts.get("modules", {}))};

        if (severityData.data) {{
            new Chart(document.getElementById('severityChart'), severityData);
        }}
        if (modulesData.data) {{
            new Chart(document.getElementById('modulesChart'), modulesData);
        }}
    </script>
</body>
</html>
"""
    return html
