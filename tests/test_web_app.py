"""Tests for web app module."""

import pytest
from unittest.mock import MagicMock, patch, AsyncMock

# Import FastAPI test client
try:
    from fastapi.testclient import TestClient
    from fastapi import FastAPI
    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False

# Skip all tests if fastapi not available
pytestmark = pytest.mark.skipif(not HAS_FASTAPI, reason="fastapi not installed")

from redops.web.app import (
    create_app,
    ScanRequest,
    ScanResponse,
    ScanStatus,
    AIRequest,
    AIResponse,
    HealthResponse,
)


class TestModels:
    """Tests for Pydantic models."""

    def test_scan_request(self):
        """Test ScanRequest model."""
        req = ScanRequest(target="example.com")
        assert req.target == "example.com"
        assert req.preset == "quick"  # default
        assert req.modules is None

    def test_scan_request_with_preset(self):
        """Test ScanRequest with preset."""
        req = ScanRequest(target="example.com", preset="full")
        assert req.preset == "full"

    def test_scan_request_with_modules(self):
        """Test ScanRequest with specific modules."""
        req = ScanRequest(target="example.com", modules=["domain", "tech"])
        assert req.modules == ["domain", "tech"]

    def test_scan_response(self):
        """Test ScanResponse model."""
        resp = ScanResponse(
            scan_id="scan-123",
            status="running",
            target="example.com",
            preset="quick",
            started_at="2024-01-15T10:00:00Z",
            message="Scan started"
        )
        assert resp.scan_id == "scan-123"
        assert resp.status == "running"

    def test_scan_status(self):
        """Test ScanStatus model."""
        status = ScanStatus(
            scan_id="scan-123",
            status="running",
            target="example.com",
            preset="quick",
            started_at="2024-01-15T10:00:00Z",
            progress=50,
            current_module="domain_scan"
        )
        assert status.progress == 50
        assert status.current_module == "domain_scan"

    def test_ai_request(self):
        """Test AIRequest model."""
        req = AIRequest(action="analyze")
        assert req.action == "analyze"
        assert req.query is None

    def test_ai_response(self):
        """Test AIResponse model."""
        resp = AIResponse(
            action="analyze",
            result="Analysis complete",
            provider="openai",
            model="gpt-4"
        )
        assert resp.action == "analyze"
        assert resp.result == "Analysis complete"

    def test_health_response(self):
        """Test HealthResponse model."""
        resp = HealthResponse(
            status="healthy",
            version="1.0.0",
            timestamp="2024-01-15T10:00:00Z"
        )
        assert resp.status == "healthy"


class TestCreateApp:
    """Tests for create_app function."""

    def test_creates_app(self):
        """Test app creation."""
        app = create_app()
        assert isinstance(app, FastAPI)

    def test_app_has_title(self):
        """Test app has title."""
        app = create_app()
        assert app.title == "RedOPS API"

    def test_app_has_cors(self):
        """Test app has CORS middleware."""
        app = create_app()
        # CORS middleware is added
        assert len(app.user_middleware) > 0


class TestHealthEndpoint:
    """Tests for health endpoint."""

    def test_health_check(self):
        """Test health check endpoint."""
        app = create_app()
        client = TestClient(app)

        response = client.get("/api/health")

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "version" in data
        assert "timestamp" in data


class TestScanEndpoints:
    """Tests for scan endpoints."""

    def test_start_scan(self):
        """Test starting a scan."""
        app = create_app()
        client = TestClient(app)

        response = client.post("/api/scans", json={
            "target": "example.com",
            "preset": "quick"
        })

        assert response.status_code == 200
        data = response.json()
        assert "scan_id" in data
        assert data["status"] in ["pending", "running"]
        assert data["target"] == "example.com"

    def test_start_scan_with_modules(self):
        """Test starting scan with specific modules."""
        app = create_app()
        client = TestClient(app)

        response = client.post("/api/scans", json={
            "target": "example.com",
            "modules": ["domain", "tech"]
        })

        assert response.status_code == 200

    def test_start_scan_invalid_target(self):
        """Test starting scan with invalid request."""
        app = create_app()
        client = TestClient(app)

        response = client.post("/api/scans", json={})

        assert response.status_code == 422  # Validation error

    def test_get_scan_status(self):
        """Test getting scan status."""
        app = create_app()
        client = TestClient(app)

        # First start a scan
        start_response = client.post("/api/scans", json={
            "target": "example.com"
        })
        scan_id = start_response.json()["scan_id"]

        # Then get status
        response = client.get(f"/api/scans/{scan_id}")

        assert response.status_code == 200
        data = response.json()
        assert data["scan_id"] == scan_id

    def test_get_nonexistent_scan(self):
        """Test getting nonexistent scan."""
        app = create_app()
        client = TestClient(app)

        response = client.get("/api/scans/nonexistent-scan-id")

        assert response.status_code == 404

    def test_list_scans(self):
        """Test listing scans."""
        app = create_app()
        client = TestClient(app)

        # Start a scan first
        client.post("/api/scans", json={"target": "example.com"})

        response = client.get("/api/scans")

        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)

    def test_get_scan_results(self):
        """Test getting scan results."""
        app = create_app()
        client = TestClient(app)

        # First start a scan
        start_response = client.post("/api/scans", json={
            "target": "example.com"
        })
        scan_id = start_response.json()["scan_id"]

        response = client.get(f"/api/scans/{scan_id}/results")

        # 400 because scan not completed yet
        assert response.status_code in [200, 400, 404]


class TestAIEndpoints:
    """Tests for AI endpoints."""

    def test_ai_analyze(self):
        """Test AI analyze endpoint."""
        app = create_app()
        client = TestClient(app)

        # First need a scan
        start_response = client.post("/api/scans", json={
            "target": "example.com"
        })
        scan_id = start_response.json()["scan_id"]

        response = client.post("/api/ai", json={
            "action": "analyze",
            "scan_id": scan_id
        })

        # May return 200, 404, or 503 (AI not available)
        assert response.status_code in [200, 404, 503, 400]

    def test_ai_explain(self):
        """Test AI explain endpoint."""
        app = create_app()
        client = TestClient(app)

        response = client.post("/api/ai", json={
            "action": "explain",
            "query": "What is SQL injection?"
        })

        # May return 200 or 503 (AI not available)
        assert response.status_code in [200, 503, 400]


class TestStaticAssets:
    """Tests for static assets."""

    def test_docs_available(self):
        """Test API docs are available."""
        app = create_app()
        client = TestClient(app)

        response = client.get("/api/docs")

        assert response.status_code == 200

    def test_openapi_schema(self):
        """Test OpenAPI schema is available."""
        app = create_app()
        client = TestClient(app)

        response = client.get("/openapi.json")

        assert response.status_code == 200
        data = response.json()
        assert "openapi" in data
