"""Tests for RedOPS Web UI."""

import pytest

# Skip all tests if fastapi not installed
pytest.importorskip("fastapi")


class TestWebApp:
    """Test web application."""

    @pytest.fixture
    def client(self):
        """Create test client."""
        from fastapi.testclient import TestClient
        from redops.web.app import create_app

        app = create_app()
        return TestClient(app)

    def test_health_check(self, client):
        """Test health endpoint."""
        response = client.get("/api/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "version" in data
        assert "timestamp" in data

    def test_list_presets(self, client):
        """Test presets endpoint."""
        response = client.get("/api/settings/presets")
        assert response.status_code == 200
        data = response.json()
        assert "presets" in data
        preset_ids = [p["id"] for p in data["presets"]]
        assert "quick" in preset_ids
        assert "recon" in preset_ids
        assert "full" in preset_ids

    def test_list_providers(self, client):
        """Test providers endpoint."""
        response = client.get("/api/settings/providers")
        assert response.status_code == 200
        data = response.json()
        assert "providers" in data
        provider_ids = [p["id"] for p in data["providers"]]
        assert "openai" in provider_ids
        assert "anthropic" in provider_ids

    def test_list_scans_empty(self, client):
        """Test listing scans when empty."""
        response = client.get("/api/scans")
        assert response.status_code == 200
        # May have scans from other tests, just verify response format
        assert isinstance(response.json(), list)

    def test_get_scan_not_found(self, client):
        """Test getting non-existent scan."""
        response = client.get("/api/scans/nonexistent")
        assert response.status_code == 404

    def test_dashboard_html(self, client):
        """Test dashboard returns HTML."""
        response = client.get("/")
        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]
        assert "RedOPS" in response.text

    def test_start_scan(self, client):
        """Test starting a scan."""
        response = client.post(
            "/api/scans",
            json={"target": "example.com", "preset": "quick"},
        )
        assert response.status_code == 200
        data = response.json()
        assert "scan_id" in data
        assert data["target"] == "example.com"
        assert data["preset"] == "quick"
        assert data["status"] == "pending"
