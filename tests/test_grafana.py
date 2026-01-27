"""Tests for Grafana dashboard configuration."""

import json

from redops.observability.grafana import (
    GrafanaPanel,
    GrafanaDashboard,
    create_prometheus_target,
    create_redops_overview_dashboard,
    create_redops_alerts_dashboard,
    get_dashboard,
    get_all_dashboards,
    DASHBOARDS,
)


class TestGrafanaPanel:
    """Test Grafana panel creation."""

    def test_panel_creation(self):
        """Test basic panel creation."""
        panel = GrafanaPanel(
            title="Test Panel",
            panel_type="stat",
            gridPos={"x": 0, "y": 0, "w": 6, "h": 4},
        )

        assert panel.title == "Test Panel"
        assert panel.panel_type == "stat"

    def test_panel_with_targets(self):
        """Test panel with query targets."""
        panel = GrafanaPanel(
            title="Scans",
            panel_type="timeseries",
            gridPos={"x": 0, "y": 0, "w": 12, "h": 8},
            targets=[
                create_prometheus_target("sum(redops_scans_total)", "Total"),
            ],
        )

        assert len(panel.targets) == 1
        assert "redops_scans_total" in panel.targets[0]["expr"]

    def test_panel_to_dict(self):
        """Test panel serialization."""
        panel = GrafanaPanel(
            title="Test",
            panel_type="gauge",
            gridPos={"x": 0, "y": 0, "w": 6, "h": 4},
            options={"orientation": "horizontal"},
        )

        data = panel.to_dict()

        assert data["title"] == "Test"
        assert data["type"] == "gauge"
        assert data["gridPos"]["w"] == 6
        assert data["options"]["orientation"] == "horizontal"


class TestGrafanaDashboard:
    """Test Grafana dashboard creation."""

    def test_dashboard_creation(self):
        """Test basic dashboard creation."""
        dashboard = GrafanaDashboard(
            title="Test Dashboard",
            uid="test-dash",
            tags=["test"],
        )

        assert dashboard.title == "Test Dashboard"
        assert dashboard.uid == "test-dash"
        assert "test" in dashboard.tags

    def test_dashboard_with_panels(self):
        """Test dashboard with panels."""
        panels = [
            GrafanaPanel(
                title="Panel 1",
                panel_type="stat",
                gridPos={"x": 0, "y": 0, "w": 6, "h": 4},
            ),
            GrafanaPanel(
                title="Panel 2",
                panel_type="timeseries",
                gridPos={"x": 6, "y": 0, "w": 6, "h": 4},
            ),
        ]

        dashboard = GrafanaDashboard(
            title="Test",
            uid="test",
            panels=panels,
        )

        assert len(dashboard.panels) == 2

    def test_dashboard_to_dict(self):
        """Test dashboard serialization."""
        dashboard = GrafanaDashboard(
            title="Test Dashboard",
            uid="test-uid",
            tags=["redops", "security"],
            refresh="30s",
            time_from="now-1h",
            time_to="now",
        )

        data = dashboard.to_dict()

        assert data["uid"] == "test-uid"
        assert data["title"] == "Test Dashboard"
        assert data["refresh"] == "30s"
        assert data["time"]["from"] == "now-1h"
        assert data["schemaVersion"] == 38

    def test_dashboard_panel_ids(self):
        """Test panels get sequential IDs."""
        panels = [
            GrafanaPanel(
                title=f"Panel {i}",
                panel_type="stat",
                gridPos={"x": 0, "y": i * 4, "w": 6, "h": 4},
            )
            for i in range(3)
        ]

        dashboard = GrafanaDashboard(
            title="Test",
            uid="test",
            panels=panels,
        )

        data = dashboard.to_dict()

        assert data["panels"][0]["id"] == 1
        assert data["panels"][1]["id"] == 2
        assert data["panels"][2]["id"] == 3

    def test_dashboard_to_json(self):
        """Test JSON export."""
        dashboard = GrafanaDashboard(
            title="Test",
            uid="test",
            panels=[
                GrafanaPanel(
                    title="P1",
                    panel_type="stat",
                    gridPos={"x": 0, "y": 0, "w": 6, "h": 4},
                ),
            ],
        )

        json_str = dashboard.to_json(pretty=True)
        data = json.loads(json_str)

        assert data["title"] == "Test"
        assert len(data["panels"]) == 1


class TestPrometheusTarget:
    """Test Prometheus target creation."""

    def test_basic_target(self):
        """Test basic target creation."""
        target = create_prometheus_target(
            expr="sum(redops_scans_total)",
            legend_format="Total Scans",
        )

        assert target["expr"] == "sum(redops_scans_total)"
        assert target["legendFormat"] == "Total Scans"
        assert target["refId"] == "A"

    def test_custom_ref_id(self):
        """Test custom ref ID."""
        target = create_prometheus_target(
            expr="rate(requests[5m])",
            ref_id="B",
        )

        assert target["refId"] == "B"


class TestBuiltInDashboards:
    """Test pre-built dashboards."""

    def test_overview_dashboard(self):
        """Test RedOPS overview dashboard."""
        dashboard = create_redops_overview_dashboard()

        assert dashboard.title == "RedOPS Overview"
        assert dashboard.uid == "redops-overview"
        assert "redops" in dashboard.tags
        assert len(dashboard.panels) > 0

    def test_overview_has_key_metrics(self):
        """Test overview has expected panels."""
        dashboard = create_redops_overview_dashboard()
        titles = [p.title for p in dashboard.panels]

        assert "Total Scans" in titles
        assert "Active Scans" in titles
        assert "Total Findings" in titles
        assert "Error Rate" in titles

    def test_alerts_dashboard(self):
        """Test RedOPS alerts dashboard."""
        dashboard = create_redops_alerts_dashboard()

        assert dashboard.title == "RedOPS Alerts"
        assert dashboard.uid == "redops-alerts"
        assert dashboard.refresh == "10s"  # Faster refresh for alerts

    def test_alerts_has_key_panels(self):
        """Test alerts dashboard has expected panels."""
        dashboard = create_redops_alerts_dashboard()
        titles = [p.title for p in dashboard.panels]

        assert "Critical Findings (Last 24h)" in titles
        assert "High Findings (Last 24h)" in titles
        assert "Scan Failures (Last 1h)" in titles

    def test_get_dashboard(self):
        """Test getting dashboard by name."""
        overview = get_dashboard("overview")
        assert overview is not None
        assert overview.uid == "redops-overview"

        alerts = get_dashboard("alerts")
        assert alerts is not None
        assert alerts.uid == "redops-alerts"

        unknown = get_dashboard("nonexistent")
        assert unknown is None

    def test_get_all_dashboards(self):
        """Test getting all dashboards."""
        dashboards = get_all_dashboards()

        assert "overview" in dashboards
        assert "alerts" in dashboards
        assert len(dashboards) == len(DASHBOARDS)

    def test_dashboards_are_valid_json(self):
        """Test all dashboards produce valid JSON."""
        for name, dashboard in get_all_dashboards().items():
            json_str = dashboard.to_json()
            data = json.loads(json_str)

            assert "uid" in data
            assert "title" in data
            assert "panels" in data
            assert isinstance(data["panels"], list)


class TestDashboardExport:
    """Test dashboard export functionality."""

    def test_dashboard_json_is_importable(self):
        """Test exported JSON matches Grafana format."""
        dashboard = create_redops_overview_dashboard()
        data = json.loads(dashboard.to_json())

        # Required Grafana fields
        assert "uid" in data
        assert "title" in data
        assert "schemaVersion" in data
        assert "panels" in data
        assert "time" in data

        # Panels have required fields
        for panel in data["panels"]:
            assert "id" in panel
            assert "title" in panel
            assert "type" in panel
            assert "gridPos" in panel

    def test_panel_positions_valid(self):
        """Test panel grid positions are valid."""
        dashboard = create_redops_overview_dashboard()

        for panel in dashboard.panels:
            pos = panel.gridPos
            assert pos["x"] >= 0
            assert pos["y"] >= 0
            assert pos["w"] > 0
            assert pos["h"] > 0
            assert pos["x"] + pos["w"] <= 24  # Grafana max width
