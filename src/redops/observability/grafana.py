"""
Grafana dashboard configuration for RedOPS.

Provides pre-built dashboards for monitoring RedOPS operations.
"""

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class GrafanaPanel:
    """Represents a Grafana dashboard panel."""

    title: str
    panel_type: str  # graph, gauge, stat, table, etc.
    gridPos: Dict[str, int]
    targets: List[Dict[str, Any]] = field(default_factory=list)
    options: Dict[str, Any] = field(default_factory=dict)
    fieldConfig: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to Grafana panel format."""
        return {
            "title": self.title,
            "type": self.panel_type,
            "gridPos": self.gridPos,
            "targets": self.targets,
            "options": self.options,
            "fieldConfig": self.fieldConfig,
        }


@dataclass
class GrafanaDashboard:
    """Represents a Grafana dashboard."""

    title: str
    uid: str
    tags: List[str] = field(default_factory=list)
    panels: List[GrafanaPanel] = field(default_factory=list)
    refresh: str = "30s"
    time_from: str = "now-1h"
    time_to: str = "now"
    timezone: str = "browser"

    def to_dict(self) -> Dict[str, Any]:
        """Convert to Grafana dashboard format."""
        return {
            "uid": self.uid,
            "title": self.title,
            "tags": self.tags,
            "timezone": self.timezone,
            "refresh": self.refresh,
            "time": {
                "from": self.time_from,
                "to": self.time_to,
            },
            "panels": [
                {**p.to_dict(), "id": i + 1}
                for i, p in enumerate(self.panels)
            ],
            "schemaVersion": 38,
            "version": 1,
        }

    def to_json(self, pretty: bool = True) -> str:
        """Convert to JSON string."""
        if pretty:
            return json.dumps(self.to_dict(), indent=2)
        return json.dumps(self.to_dict())


def create_prometheus_target(
    expr: str,
    legend_format: str = "",
    ref_id: str = "A",
) -> Dict[str, Any]:
    """Create a Prometheus query target."""
    return {
        "datasource": {"type": "prometheus", "uid": "${datasource}"},
        "expr": expr,
        "legendFormat": legend_format,
        "refId": ref_id,
    }


def create_redops_overview_dashboard() -> GrafanaDashboard:
    """Create the main RedOPS overview dashboard."""
    panels = [
        # Row 1: Key Stats
        GrafanaPanel(
            title="Total Scans",
            panel_type="stat",
            gridPos={"x": 0, "y": 0, "w": 6, "h": 4},
            targets=[create_prometheus_target(
                'sum(redops_scans_total)',
                "Total Scans"
            )],
            options={
                "colorMode": "value",
                "graphMode": "area",
                "justifyMode": "auto",
                "orientation": "auto",
            },
            fieldConfig={
                "defaults": {
                    "color": {"mode": "thresholds"},
                    "thresholds": {
                        "mode": "absolute",
                        "steps": [
                            {"color": "green", "value": None},
                        ]
                    },
                }
            },
        ),
        GrafanaPanel(
            title="Active Scans",
            panel_type="stat",
            gridPos={"x": 6, "y": 0, "w": 6, "h": 4},
            targets=[create_prometheus_target(
                'redops_active_scans',
                "Active"
            )],
            options={
                "colorMode": "value",
                "graphMode": "none",
            },
            fieldConfig={
                "defaults": {
                    "color": {"mode": "thresholds"},
                    "thresholds": {
                        "mode": "absolute",
                        "steps": [
                            {"color": "green", "value": None},
                            {"color": "yellow", "value": 5},
                            {"color": "red", "value": 10},
                        ]
                    },
                }
            },
        ),
        GrafanaPanel(
            title="Total Findings",
            panel_type="stat",
            gridPos={"x": 12, "y": 0, "w": 6, "h": 4},
            targets=[create_prometheus_target(
                'sum(redops_findings_total)',
                "Findings"
            )],
            options={"colorMode": "value"},
            fieldConfig={
                "defaults": {
                    "color": {"mode": "thresholds"},
                    "thresholds": {
                        "mode": "absolute",
                        "steps": [
                            {"color": "green", "value": None},
                            {"color": "yellow", "value": 100},
                            {"color": "orange", "value": 500},
                            {"color": "red", "value": 1000},
                        ]
                    },
                }
            },
        ),
        GrafanaPanel(
            title="Error Rate",
            panel_type="stat",
            gridPos={"x": 18, "y": 0, "w": 6, "h": 4},
            targets=[create_prometheus_target(
                'sum(rate(redops_errors_total[5m]))',
                "Errors/sec"
            )],
            options={"colorMode": "value"},
            fieldConfig={
                "defaults": {
                    "unit": "ops",
                    "color": {"mode": "thresholds"},
                    "thresholds": {
                        "mode": "absolute",
                        "steps": [
                            {"color": "green", "value": None},
                            {"color": "yellow", "value": 0.1},
                            {"color": "red", "value": 1},
                        ]
                    },
                }
            },
        ),

        # Row 2: Scan Metrics
        GrafanaPanel(
            title="Scan Rate",
            panel_type="timeseries",
            gridPos={"x": 0, "y": 4, "w": 12, "h": 8},
            targets=[
                create_prometheus_target(
                    'sum(rate(redops_scans_total[5m])) by (status)',
                    "{{status}}"
                ),
            ],
            options={
                "legend": {"displayMode": "list", "placement": "bottom"},
            },
            fieldConfig={
                "defaults": {
                    "custom": {
                        "drawStyle": "line",
                        "lineInterpolation": "smooth",
                        "fillOpacity": 10,
                    },
                    "unit": "ops",
                }
            },
        ),
        GrafanaPanel(
            title="Scan Duration Distribution",
            panel_type="histogram",
            gridPos={"x": 12, "y": 4, "w": 12, "h": 8},
            targets=[create_prometheus_target(
                'redops_scan_duration_seconds_bucket',
                "{{le}}"
            )],
            options={
                "legend": {"displayMode": "list"},
            },
            fieldConfig={
                "defaults": {
                    "unit": "s",
                }
            },
        ),

        # Row 3: Findings
        GrafanaPanel(
            title="Findings by Severity",
            panel_type="piechart",
            gridPos={"x": 0, "y": 12, "w": 8, "h": 8},
            targets=[create_prometheus_target(
                'sum(redops_findings_total) by (severity)',
                "{{severity}}"
            )],
            options={
                "legend": {"displayMode": "table", "placement": "right"},
                "pieType": "donut",
            },
        ),
        GrafanaPanel(
            title="Findings by Module",
            panel_type="barchart",
            gridPos={"x": 8, "y": 12, "w": 8, "h": 8},
            targets=[create_prometheus_target(
                'sum(redops_findings_total) by (module)',
                "{{module}}"
            )],
            options={
                "orientation": "horizontal",
            },
        ),
        GrafanaPanel(
            title="Findings Over Time",
            panel_type="timeseries",
            gridPos={"x": 16, "y": 12, "w": 8, "h": 8},
            targets=[create_prometheus_target(
                'sum(rate(redops_findings_total[5m])) by (severity)',
                "{{severity}}"
            )],
            options={
                "legend": {"displayMode": "list", "placement": "bottom"},
            },
            fieldConfig={
                "defaults": {
                    "custom": {
                        "drawStyle": "bars",
                        "stacking": {"mode": "normal"},
                    },
                    "unit": "short",
                }
            },
        ),

        # Row 4: API Metrics
        GrafanaPanel(
            title="API Request Rate",
            panel_type="timeseries",
            gridPos={"x": 0, "y": 20, "w": 12, "h": 8},
            targets=[
                create_prometheus_target(
                    'sum(rate(redops_api_requests_total[5m])) by (method)',
                    "{{method}}"
                ),
            ],
            options={
                "legend": {"displayMode": "list", "placement": "bottom"},
            },
            fieldConfig={
                "defaults": {
                    "unit": "reqps",
                }
            },
        ),
        GrafanaPanel(
            title="API Latency (p95)",
            panel_type="timeseries",
            gridPos={"x": 12, "y": 20, "w": 12, "h": 8},
            targets=[create_prometheus_target(
                'histogram_quantile(0.95, sum(rate(redops_api_request_duration_seconds_bucket[5m])) by (le, endpoint))',
                "{{endpoint}}"
            )],
            options={
                "legend": {"displayMode": "list", "placement": "bottom"},
            },
            fieldConfig={
                "defaults": {
                    "unit": "s",
                }
            },
        ),

        # Row 5: Pipeline Metrics
        GrafanaPanel(
            title="Pipeline Steps",
            panel_type="timeseries",
            gridPos={"x": 0, "y": 28, "w": 12, "h": 8},
            targets=[create_prometheus_target(
                'sum(rate(redops_pipeline_steps_total[5m])) by (step, status)',
                "{{step}} ({{status}})"
            )],
            fieldConfig={
                "defaults": {
                    "unit": "ops",
                }
            },
        ),
        GrafanaPanel(
            title="Step Duration by Module",
            panel_type="timeseries",
            gridPos={"x": 12, "y": 28, "w": 12, "h": 8},
            targets=[create_prometheus_target(
                'histogram_quantile(0.95, sum(rate(redops_step_duration_seconds_bucket[5m])) by (le, module))',
                "{{module}}"
            )],
            fieldConfig={
                "defaults": {
                    "unit": "s",
                }
            },
        ),
    ]

    return GrafanaDashboard(
        title="RedOPS Overview",
        uid="redops-overview",
        tags=["redops", "security", "monitoring"],
        panels=panels,
    )


def create_redops_alerts_dashboard() -> GrafanaDashboard:
    """Create the RedOPS alerts dashboard."""
    panels = [
        GrafanaPanel(
            title="Critical Findings (Last 24h)",
            panel_type="stat",
            gridPos={"x": 0, "y": 0, "w": 8, "h": 4},
            targets=[create_prometheus_target(
                'sum(increase(redops_findings_total{severity="critical"}[24h]))',
                "Critical"
            )],
            fieldConfig={
                "defaults": {
                    "color": {"mode": "thresholds"},
                    "thresholds": {
                        "mode": "absolute",
                        "steps": [
                            {"color": "green", "value": None},
                            {"color": "red", "value": 1},
                        ]
                    },
                }
            },
        ),
        GrafanaPanel(
            title="High Findings (Last 24h)",
            panel_type="stat",
            gridPos={"x": 8, "y": 0, "w": 8, "h": 4},
            targets=[create_prometheus_target(
                'sum(increase(redops_findings_total{severity="high"}[24h]))',
                "High"
            )],
            fieldConfig={
                "defaults": {
                    "color": {"mode": "thresholds"},
                    "thresholds": {
                        "mode": "absolute",
                        "steps": [
                            {"color": "green", "value": None},
                            {"color": "orange", "value": 5},
                            {"color": "red", "value": 20},
                        ]
                    },
                }
            },
        ),
        GrafanaPanel(
            title="Scan Failures (Last 1h)",
            panel_type="stat",
            gridPos={"x": 16, "y": 0, "w": 8, "h": 4},
            targets=[create_prometheus_target(
                'sum(increase(redops_scans_total{status="failure"}[1h]))',
                "Failures"
            )],
            fieldConfig={
                "defaults": {
                    "color": {"mode": "thresholds"},
                    "thresholds": {
                        "mode": "absolute",
                        "steps": [
                            {"color": "green", "value": None},
                            {"color": "yellow", "value": 1},
                            {"color": "red", "value": 5},
                        ]
                    },
                }
            },
        ),
        GrafanaPanel(
            title="Error Timeline",
            panel_type="timeseries",
            gridPos={"x": 0, "y": 4, "w": 24, "h": 8},
            targets=[create_prometheus_target(
                'sum(rate(redops_errors_total[5m])) by (type, module)',
                "{{type}} ({{module}})"
            )],
            fieldConfig={
                "defaults": {
                    "custom": {
                        "drawStyle": "line",
                        "lineWidth": 2,
                    },
                }
            },
        ),
    ]

    return GrafanaDashboard(
        title="RedOPS Alerts",
        uid="redops-alerts",
        tags=["redops", "security", "alerts"],
        panels=panels,
        refresh="10s",
    )


# Pre-built dashboards
DASHBOARDS = {
    "overview": create_redops_overview_dashboard,
    "alerts": create_redops_alerts_dashboard,
}


def get_dashboard(name: str) -> Optional[GrafanaDashboard]:
    """Get a pre-built dashboard by name."""
    factory = DASHBOARDS.get(name)
    if factory:
        return factory()
    return None


def get_all_dashboards() -> Dict[str, GrafanaDashboard]:
    """Get all pre-built dashboards."""
    return {name: factory() for name, factory in DASHBOARDS.items()}


def export_dashboards(output_dir: str = "./dashboards") -> List[str]:
    """Export all dashboards to JSON files."""
    import os
    from pathlib import Path

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    files = []
    for name, dashboard in get_all_dashboards().items():
        file_path = output_path / f"{name}.json"
        with open(file_path, "w") as f:
            f.write(dashboard.to_json())
        files.append(str(file_path))

    return files
