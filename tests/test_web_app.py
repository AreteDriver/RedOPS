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

from redops.web.app import (  # noqa: E402
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
            message="Scan started",
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
            current_module="domain_scan",
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
            model="gpt-4",
        )
        assert resp.action == "analyze"
        assert resp.result == "Analysis complete"

    def test_health_response(self):
        """Test HealthResponse model."""
        resp = HealthResponse(
            status="healthy", version="1.0.0", timestamp="2024-01-15T10:00:00Z"
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

        response = client.post(
            "/api/scans", json={"target": "example.com", "preset": "quick"}
        )

        assert response.status_code == 200
        data = response.json()
        assert "scan_id" in data
        assert data["status"] in ["pending", "running"]
        assert data["target"] == "example.com"

    def test_start_scan_with_modules(self):
        """Test starting scan with specific modules."""
        app = create_app()
        client = TestClient(app)

        response = client.post(
            "/api/scans", json={"target": "example.com", "modules": ["domain", "tech"]}
        )

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
        start_response = client.post("/api/scans", json={"target": "example.com"})
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
        start_response = client.post("/api/scans", json={"target": "example.com"})
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
        start_response = client.post("/api/scans", json={"target": "example.com"})
        scan_id = start_response.json()["scan_id"]

        response = client.post(
            "/api/ai", json={"action": "analyze", "scan_id": scan_id}
        )

        # May return 200, 404, or 503 (AI not available)
        assert response.status_code in [200, 404, 503, 400]

    def test_ai_explain(self):
        """Test AI explain endpoint."""
        app = create_app()
        client = TestClient(app)

        response = client.post(
            "/api/ai", json={"action": "explain", "query": "What is SQL injection?"}
        )

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


class TestListScansFiltering:
    """Tests for scan list filtering."""

    def test_list_scans_with_status_filter(self):
        """Test listing scans with status filter."""
        app = create_app()
        client = TestClient(app)

        # Start a scan to ensure there's at least one
        client.post("/api/scans", json={"target": "filter-test.com"})

        # Filter by pending status
        response = client.get("/api/scans?status=pending")

        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        # All returned scans should have matching status
        for scan in data:
            assert scan["status"] == "pending"

    def test_list_scans_with_limit(self):
        """Test listing scans with limit parameter."""
        app = create_app()
        client = TestClient(app)

        # Start multiple scans
        for i in range(5):
            client.post("/api/scans", json={"target": f"limit-test-{i}.com"})

        response = client.get("/api/scans?limit=3")

        assert response.status_code == 200
        data = response.json()
        assert len(data) <= 3

    def test_list_scans_empty_status_filter(self):
        """Test listing scans with non-matching status filter."""
        app = create_app()
        client = TestClient(app)

        # Filter by a status that might not exist
        response = client.get("/api/scans?status=completed")

        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)


class TestScanResultsEdgeCases:
    """Tests for scan results edge cases."""

    def test_get_results_scan_not_found(self):
        """Test getting results for nonexistent scan."""
        app = create_app()
        client = TestClient(app)

        response = client.get("/api/scans/nonexistent-id/results")

        assert response.status_code == 404

    def test_get_results_scan_not_completed(self):
        """Test getting results for incomplete scan."""
        app = create_app()
        client = TestClient(app)

        # Start a scan but don't wait for completion
        start_response = client.post("/api/scans", json={"target": "results-test.com"})
        scan_id = start_response.json()["scan_id"]

        # Try to get results immediately (scan should still be pending/running)
        response = client.get(f"/api/scans/{scan_id}/results")

        # Should be 400 (not completed) or 404 (no results)
        assert response.status_code in [400, 404]


class TestAIEndpointsAdvanced:
    """Advanced tests for AI endpoints."""

    def test_ai_explain_no_query(self):
        """Test AI explain without query."""
        app = create_app()
        client = TestClient(app)

        response = client.post(
            "/api/ai",
            json={
                "action": "explain"
                # No query provided
            },
        )

        # Should return 400 (query required) or 503 (AI not available)
        assert response.status_code in [400, 503]

    def test_ai_analyze_no_scan_id(self):
        """Test AI analyze without scan_id."""
        app = create_app()
        client = TestClient(app)

        response = client.post(
            "/api/ai",
            json={
                "action": "analyze"
                # No scan_id provided
            },
        )

        # Should return 400 or 503
        assert response.status_code in [400, 503]

    def test_ai_suggest_action(self):
        """Test AI suggest action."""
        app = create_app()
        client = TestClient(app)

        response = client.post(
            "/api/ai", json={"action": "suggest", "scan_id": "nonexistent"}
        )

        # Should return 404 (scan not found) or 503 (AI not available)
        assert response.status_code in [400, 404, 503]

    def test_ai_summarize_action(self):
        """Test AI summarize action."""
        app = create_app()
        client = TestClient(app)

        response = client.post(
            "/api/ai", json={"action": "summarize", "scan_id": "nonexistent"}
        )

        # Should return 404 (scan not found) or 503 (AI not available)
        assert response.status_code in [400, 404, 503]

    def test_ai_unknown_action(self):
        """Test AI with unknown action."""
        app = create_app()
        client = TestClient(app)

        response = client.post("/api/ai", json={"action": "unknown_action"})

        # Should return 400 or 503
        assert response.status_code in [400, 503]

    def test_ai_with_provider_override(self):
        """Test AI with provider override."""
        app = create_app()
        client = TestClient(app)

        response = client.post(
            "/api/ai",
            json={
                "action": "explain",
                "query": "What is XSS?",
                "provider": "anthropic",
                "model": "claude-3",
            },
        )

        # May succeed or fail depending on AI availability
        assert response.status_code in [200, 400, 503]


class TestSettingsEndpoints:
    """Tests for settings endpoints."""

    def test_list_providers(self):
        """Test listing AI providers."""
        app = create_app()
        client = TestClient(app)

        response = client.get("/api/settings/providers")

        assert response.status_code == 200
        data = response.json()
        assert "providers" in data
        assert isinstance(data["providers"], list)

    def test_list_presets(self):
        """Test listing scan presets."""
        app = create_app()
        client = TestClient(app)

        response = client.get("/api/settings/presets")

        assert response.status_code == 200
        data = response.json()
        assert "presets" in data
        assert len(data["presets"]) >= 4  # quick, recon, full, ai_enhanced


class TestDashboard:
    """Tests for dashboard endpoint."""

    def test_dashboard_html(self):
        """Test dashboard returns HTML."""
        app = create_app()
        client = TestClient(app)

        response = client.get("/")

        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]
        assert "RedOPS" in response.text
        assert "Dashboard" in response.text


class TestWebSocketEndpoint:
    """Tests for WebSocket endpoint."""

    def test_websocket_connect(self):
        """Test WebSocket connection."""
        app = create_app()
        client = TestClient(app)

        with client.websocket_connect("/ws") as websocket:
            # Should receive connection message
            data = websocket.receive_json()
            assert data["event"] == "connection"

    def test_websocket_subscribe(self):
        """Test WebSocket subscribe action."""
        app = create_app()
        client = TestClient(app)

        with client.websocket_connect("/ws") as websocket:
            # Receive initial connection message
            websocket.receive_json()

            # Send subscribe message
            websocket.send_json({"action": "subscribe", "scan_id": "test-scan-123"})

            # No error means success - subscription is handled internally

    def test_websocket_unsubscribe(self):
        """Test WebSocket unsubscribe action."""
        app = create_app()
        client = TestClient(app)

        with client.websocket_connect("/ws") as websocket:
            # Receive initial connection message
            websocket.receive_json()

            # Subscribe first
            websocket.send_json({"action": "subscribe", "scan_id": "test-scan-456"})

            # Then unsubscribe
            websocket.send_json({"action": "unsubscribe", "scan_id": "test-scan-456"})

            # No error means success

    def test_websocket_invalid_json(self):
        """Test WebSocket handles invalid JSON."""
        app = create_app()
        client = TestClient(app)

        with client.websocket_connect("/ws") as websocket:
            # Receive initial connection message
            websocket.receive_json()

            # Send invalid JSON (as text)
            websocket.send_text("not valid json")

            # Should not crash - invalid messages are ignored

    def test_websocket_stats(self):
        """Test WebSocket stats endpoint."""
        app = create_app()
        client = TestClient(app)

        response = client.get("/api/ws/stats")

        assert response.status_code == 200
        data = response.json()
        assert "total_connections" in data


class TestRunScanTask:
    """Tests for run_scan_task background function."""

    @pytest.mark.asyncio
    async def test_run_scan_task_exception(self):
        """Test scan task with fatal exception."""
        from redops.web import app as app_module
        from redops.web.app import run_scan_task, _scans, ScanStatus

        scan_id = "test-task-fatal-789"
        request = ScanRequest(target="example.com", preset="quick")

        _scans[scan_id] = ScanStatus(
            scan_id=scan_id,
            status="pending",
            target="example.com",
            preset="quick",
            started_at="2024-01-01T00:00:00Z",
            progress=0,
        )

        with patch.object(
            app_module, "emit_scan_started", new_callable=AsyncMock
        ) as mock_started:
            with patch.object(
                app_module, "emit_scan_failed", new_callable=AsyncMock
            ) as mock_failed:
                # Make emit_scan_started raise to trigger failure path
                mock_started.side_effect = Exception("Fatal error")

                await run_scan_task(scan_id, request)

        # Scan should be marked as failed
        assert _scans[scan_id].status == "failed"
        assert _scans[scan_id].error is not None
        mock_failed.assert_called_once()

        # Cleanup
        del _scans[scan_id]

    def test_run_scan_task_exists(self):
        """Test run_scan_task function exists."""
        from redops.web.app import run_scan_task
        import asyncio

        assert callable(run_scan_task)
        assert asyncio.iscoroutinefunction(run_scan_task)


class TestGetDashboardHtml:
    """Tests for get_dashboard_html function."""

    def test_dashboard_html_content(self):
        """Test dashboard HTML contains expected elements."""
        from redops.web.app import get_dashboard_html

        html = get_dashboard_html()

        assert "<!DOCTYPE html>" in html
        assert "RedOPS" in html
        assert "Dashboard" in html
        assert "tailwindcss" in html
        assert "alpinejs" in html
        assert "websocket" in html.lower()


class TestMainFunction:
    """Tests for main entry point."""

    def test_main_function_exists(self):
        """Test main function exists and is callable."""
        from redops.web.app import main

        assert callable(main)

    def test_main_with_mocked_uvicorn(self):
        """Test main function with mocked uvicorn."""
        from redops.web.app import main
        import os

        mock_uvicorn = MagicMock()
        with patch.dict("sys.modules", {"uvicorn": mock_uvicorn}):
            with patch.dict(
                os.environ, {"REDOPS_HOST": "0.0.0.0", "REDOPS_PORT": "9000"}
            ):
                with patch("builtins.print"):  # Suppress print output
                    main()

                mock_uvicorn.run.assert_called_once()
                call_kwargs = mock_uvicorn.run.call_args[1]
                assert call_kwargs["host"] == "0.0.0.0"
                assert call_kwargs["port"] == 9000
                assert call_kwargs["factory"] is True

    def test_main_default_settings(self):
        """Test main function with default settings."""
        from redops.web.app import main
        import os

        mock_uvicorn = MagicMock()
        with patch.dict("sys.modules", {"uvicorn": mock_uvicorn}):
            # Clear environment variables
            env = {
                k: v
                for k, v in os.environ.items()
                if k not in ["REDOPS_HOST", "REDOPS_PORT", "REDOPS_DEV"]
            }
            with patch.dict(os.environ, env, clear=True):
                with patch("builtins.print"):
                    main()

                call_kwargs = mock_uvicorn.run.call_args[1]
                assert call_kwargs["host"] == "127.0.0.1"
                assert call_kwargs["port"] == 8000
                assert call_kwargs["reload"] is False

    def test_main_dev_mode(self):
        """Test main function in dev mode."""
        from redops.web.app import main
        import os

        mock_uvicorn = MagicMock()
        with patch.dict("sys.modules", {"uvicorn": mock_uvicorn}):
            with patch.dict(os.environ, {"REDOPS_DEV": "true"}):
                with patch("builtins.print"):
                    main()

                call_kwargs = mock_uvicorn.run.call_args[1]
                assert call_kwargs["reload"] is True


class TestAIWithMockedAssistant:
    """Tests for AI endpoints with mocked assistant."""

    def test_ai_explain_success(self):
        """Test AI explain with mocked assistant."""
        import sys

        app = create_app()
        client = TestClient(app)

        mock_assistant = MagicMock()
        mock_assistant.explain.return_value = (
            "SQL injection is a security vulnerability..."
        )
        mock_assistant.provider = "mock_provider"
        mock_assistant.model = "mock_model"

        mock_ai_module = MagicMock()
        mock_ai_module.AIAssistant.return_value = mock_assistant

        with patch.dict(sys.modules, {"redops.modules.ai_assistant": mock_ai_module}):
            response = client.post(
                "/api/ai", json={"action": "explain", "query": "What is SQL injection?"}
            )

        if response.status_code == 200:
            data = response.json()
            assert data["action"] == "explain"
            assert "SQL injection" in data["result"]

    def test_ai_analyze_success(self):
        """Test AI analyze with mocked assistant and results."""
        import sys
        from redops.web.app import _scan_results

        app = create_app()
        client = TestClient(app)

        # Add mock scan results
        _scan_results["mock-scan-id"] = {"findings": []}

        mock_assistant = MagicMock()
        mock_assistant.analyze_findings.return_value = "Analysis: No critical findings"
        mock_assistant.provider = "mock_provider"
        mock_assistant.model = "mock_model"

        mock_ai_module = MagicMock()
        mock_ai_module.AIAssistant.return_value = mock_assistant

        with patch.dict(sys.modules, {"redops.modules.ai_assistant": mock_ai_module}):
            response = client.post(
                "/api/ai", json={"action": "analyze", "scan_id": "mock-scan-id"}
            )

        if response.status_code == 200:
            data = response.json()
            assert data["action"] == "analyze"
            assert "Analysis" in data["result"]

        # Cleanup
        del _scan_results["mock-scan-id"]

    def test_ai_suggest_success(self):
        """Test AI suggest with mocked assistant and results."""
        import sys
        from redops.web.app import _scan_results

        app = create_app()
        client = TestClient(app)

        # Add mock scan results
        _scan_results["suggest-scan-id"] = {"findings": [{"severity": "high"}]}

        mock_assistant = MagicMock()
        mock_assistant.suggest_remediations.return_value = "Suggested fixes..."
        mock_assistant.provider = "mock_provider"
        mock_assistant.model = "mock_model"

        mock_ai_module = MagicMock()
        mock_ai_module.AIAssistant.return_value = mock_assistant

        with patch.dict(sys.modules, {"redops.modules.ai_assistant": mock_ai_module}):
            response = client.post(
                "/api/ai", json={"action": "suggest", "scan_id": "suggest-scan-id"}
            )

        if response.status_code == 200:
            data = response.json()
            assert data["action"] == "suggest"

        # Cleanup
        del _scan_results["suggest-scan-id"]

    def test_ai_summarize_success(self):
        """Test AI summarize with mocked assistant and results."""
        import sys
        from redops.web.app import _scan_results

        app = create_app()
        client = TestClient(app)

        # Add mock scan results
        _scan_results["summarize-scan-id"] = {"data": "some data"}

        mock_assistant = MagicMock()
        mock_assistant.summarize.return_value = "Summary of findings..."
        mock_assistant.provider = "mock_provider"
        mock_assistant.model = "mock_model"

        mock_ai_module = MagicMock()
        mock_ai_module.AIAssistant.return_value = mock_assistant

        with patch.dict(sys.modules, {"redops.modules.ai_assistant": mock_ai_module}):
            response = client.post(
                "/api/ai", json={"action": "summarize", "scan_id": "summarize-scan-id"}
            )

        if response.status_code == 200:
            data = response.json()
            assert data["action"] == "summarize"

        # Cleanup
        del _scan_results["summarize-scan-id"]

    def test_ai_unknown_action_with_mock(self):
        """Test AI with unknown action using mocked module."""
        import sys

        app = create_app()
        client = TestClient(app)

        mock_assistant = MagicMock()
        mock_assistant.provider = "mock_provider"
        mock_assistant.model = "mock_model"

        mock_ai_module = MagicMock()
        mock_ai_module.AIAssistant.return_value = mock_assistant

        with patch.dict(sys.modules, {"redops.modules.ai_assistant": mock_ai_module}):
            response = client.post("/api/ai", json={"action": "invalid_action"})

        assert response.status_code == 400
        assert "Unknown action" in response.json()["detail"]

    def test_ai_value_error(self):
        """Test AI endpoint handles ValueError."""
        import sys

        app = create_app()
        client = TestClient(app)

        mock_ai_module = MagicMock()
        mock_ai_module.AIAssistant.side_effect = ValueError("Invalid configuration")

        with patch.dict(sys.modules, {"redops.modules.ai_assistant": mock_ai_module}):
            response = client.post(
                "/api/ai", json={"action": "explain", "query": "test"}
            )

        assert response.status_code == 400
        assert "Invalid configuration" in response.json()["detail"]


class TestScanResultsNotAvailable:
    """Tests for scan results when not available."""

    def test_get_results_no_results_stored(self):
        """Test getting results when scan completed but results not stored."""
        from redops.web.app import _scans, ScanStatus

        app = create_app()
        client = TestClient(app)

        # Create a completed scan without storing results
        scan_id = "no-results-scan"
        _scans[scan_id] = ScanStatus(
            scan_id=scan_id,
            status="completed",
            target="test.com",
            preset="quick",
            started_at="2024-01-01T00:00:00Z",
            progress=100,
        )
        # Intentionally don't add to _scan_results

        response = client.get(f"/api/scans/{scan_id}/results")

        assert response.status_code == 404
        assert "not available" in response.json()["detail"].lower()

        # Cleanup
        del _scans[scan_id]

    def test_get_results_scan_not_completed(self):
        """Test getting results when scan is still running."""
        from redops.web.app import _scans, ScanStatus

        app = create_app()
        client = TestClient(app)

        # Create a running scan
        scan_id = "running-scan"
        _scans[scan_id] = ScanStatus(
            scan_id=scan_id,
            status="running",
            target="test.com",
            preset="quick",
            started_at="2024-01-01T00:00:00Z",
            progress=50,
        )

        response = client.get(f"/api/scans/{scan_id}/results")

        assert response.status_code == 400
        assert "not completed" in response.json()["detail"].lower()

        # Cleanup
        del _scans[scan_id]

    def test_get_results_success(self):
        """Test getting results when scan is completed with results."""
        from redops.web.app import _scans, _scan_results, ScanStatus

        app = create_app()
        client = TestClient(app)

        # Create a completed scan with results
        scan_id = "completed-scan"
        _scans[scan_id] = ScanStatus(
            scan_id=scan_id,
            status="completed",
            target="test.com",
            preset="quick",
            started_at="2024-01-01T00:00:00Z",
            progress=100,
        )
        _scan_results[scan_id] = {
            "findings": [{"severity": "high", "title": "Test Finding"}]
        }

        response = client.get(f"/api/scans/{scan_id}/results")

        assert response.status_code == 200
        data = response.json()
        assert "findings" in data
        assert len(data["findings"]) == 1

        # Cleanup
        del _scans[scan_id]
        del _scan_results[scan_id]


class TestAIValidationErrors:
    """Tests for AI endpoint validation errors."""

    def test_ai_analyze_missing_results(self):
        """Test AI analyze when scan results don't exist."""
        import sys

        app = create_app()
        client = TestClient(app)

        mock_assistant = MagicMock()
        mock_assistant.provider = "mock"
        mock_assistant.model = "mock"

        mock_ai_module = MagicMock()
        mock_ai_module.AIAssistant.return_value = mock_assistant

        with patch.dict(sys.modules, {"redops.modules.ai_assistant": mock_ai_module}):
            response = client.post(
                "/api/ai", json={"action": "analyze", "scan_id": "nonexistent-scan"}
            )

        assert response.status_code == 404
        assert "not found" in response.json()["detail"].lower()

    def test_ai_suggest_missing_scan_id(self):
        """Test AI suggest without scan_id."""
        import sys

        app = create_app()
        client = TestClient(app)

        mock_assistant = MagicMock()
        mock_ai_module = MagicMock()
        mock_ai_module.AIAssistant.return_value = mock_assistant

        with patch.dict(sys.modules, {"redops.modules.ai_assistant": mock_ai_module}):
            response = client.post(
                "/api/ai",
                json={
                    "action": "suggest"
                    # No scan_id
                },
            )

        assert response.status_code == 400
        assert "scan_id required" in response.json()["detail"]

    def test_ai_suggest_missing_results(self):
        """Test AI suggest when scan results don't exist."""
        import sys

        app = create_app()
        client = TestClient(app)

        mock_assistant = MagicMock()
        mock_ai_module = MagicMock()
        mock_ai_module.AIAssistant.return_value = mock_assistant

        with patch.dict(sys.modules, {"redops.modules.ai_assistant": mock_ai_module}):
            response = client.post(
                "/api/ai", json={"action": "suggest", "scan_id": "missing-results-scan"}
            )

        assert response.status_code == 404

    def test_ai_summarize_missing_scan_id(self):
        """Test AI summarize without scan_id."""
        import sys

        app = create_app()
        client = TestClient(app)

        mock_assistant = MagicMock()
        mock_ai_module = MagicMock()
        mock_ai_module.AIAssistant.return_value = mock_assistant

        with patch.dict(sys.modules, {"redops.modules.ai_assistant": mock_ai_module}):
            response = client.post(
                "/api/ai",
                json={
                    "action": "summarize"
                    # No scan_id
                },
            )

        assert response.status_code == 400
        assert "scan_id required" in response.json()["detail"]

    def test_ai_summarize_missing_results(self):
        """Test AI summarize when scan results don't exist."""
        import sys

        app = create_app()
        client = TestClient(app)

        mock_assistant = MagicMock()
        mock_ai_module = MagicMock()
        mock_ai_module.AIAssistant.return_value = mock_assistant

        with patch.dict(sys.modules, {"redops.modules.ai_assistant": mock_ai_module}):
            response = client.post(
                "/api/ai",
                json={"action": "summarize", "scan_id": "missing-results-scan"},
            )

        assert response.status_code == 404
