"""
Tests for RedOPS API Server.
"""

import json
import pytest

from redops.api.server import (
    APIError,
    APIRequest,
    APIResponse,
    APIServer,
    HTTPMethod,
    HTTPStatus,
    Route,
    Router,
    create_api_server,
)


class TestHTTPMethod:
    """Tests for HTTPMethod enum."""

    def test_methods_exist(self):
        """Test all HTTP methods exist."""
        assert HTTPMethod.GET.value == "GET"
        assert HTTPMethod.POST.value == "POST"
        assert HTTPMethod.PUT.value == "PUT"
        assert HTTPMethod.PATCH.value == "PATCH"
        assert HTTPMethod.DELETE.value == "DELETE"
        assert HTTPMethod.OPTIONS.value == "OPTIONS"


class TestHTTPStatus:
    """Tests for HTTPStatus enum."""

    def test_success_codes(self):
        """Test success status codes."""
        assert HTTPStatus.OK.value == 200
        assert HTTPStatus.CREATED.value == 201
        assert HTTPStatus.ACCEPTED.value == 202
        assert HTTPStatus.NO_CONTENT.value == 204

    def test_client_error_codes(self):
        """Test client error status codes."""
        assert HTTPStatus.BAD_REQUEST.value == 400
        assert HTTPStatus.UNAUTHORIZED.value == 401
        assert HTTPStatus.FORBIDDEN.value == 403
        assert HTTPStatus.NOT_FOUND.value == 404
        assert HTTPStatus.METHOD_NOT_ALLOWED.value == 405

    def test_server_error_codes(self):
        """Test server error status codes."""
        assert HTTPStatus.INTERNAL_ERROR.value == 500
        assert HTTPStatus.SERVICE_UNAVAILABLE.value == 503


class TestAPIRequest:
    """Tests for APIRequest dataclass."""

    def test_basic_request(self):
        """Test basic request creation."""
        request = APIRequest(
            method="GET",
            path="/api/v1/scans",
            headers={"Content-Type": "application/json"},
            query_params={},
            path_params={},
        )

        assert request.method == "GET"
        assert request.path == "/api/v1/scans"
        assert request.headers == {"Content-Type": "application/json"}
        assert request.body is None

    def test_request_with_body(self):
        """Test request with body."""
        request = APIRequest(
            method="POST",
            path="/api/v1/scans",
            headers={},
            query_params={},
            path_params={},
            body={"target": "example.com"},
        )

        assert request.body == {"target": "example.com"}

    def test_request_has_id(self):
        """Test request has unique ID."""
        request1 = APIRequest(
            method="GET",
            path="/test",
            headers={},
            query_params={},
            path_params={},
        )
        request2 = APIRequest(
            method="GET",
            path="/test",
            headers={},
            query_params={},
            path_params={},
        )

        assert request1.request_id != request2.request_id


class TestAPIResponse:
    """Tests for APIResponse dataclass."""

    def test_default_response(self):
        """Test default response values."""
        response = APIResponse()

        assert response.status == 200
        assert response.body is None
        assert response.headers == {}

    def test_response_with_body(self):
        """Test response with body."""
        response = APIResponse(
            status=200,
            body={"message": "success"},
        )

        assert response.body == {"message": "success"}

    def test_to_json_dict(self):
        """Test converting dict body to JSON."""
        response = APIResponse(body={"key": "value"})

        json_str = response.to_json()
        parsed = json.loads(json_str)

        assert parsed == {"key": "value"}

    def test_to_json_list(self):
        """Test converting list body to JSON."""
        response = APIResponse(body=[1, 2, 3])

        json_str = response.to_json()
        parsed = json.loads(json_str)

        assert parsed == [1, 2, 3]

    def test_to_json_none(self):
        """Test converting None body to JSON."""
        response = APIResponse(body=None)

        assert response.to_json() == ""

    def test_to_json_string(self):
        """Test string body passthrough."""
        response = APIResponse(body="raw string")

        assert response.to_json() == "raw string"


class TestAPIError:
    """Tests for APIError dataclass."""

    def test_basic_error(self):
        """Test basic error creation."""
        error = APIError(
            error="not_found",
            message="Resource not found",
            status=404,
        )

        assert error.error == "not_found"
        assert error.message == "Resource not found"
        assert error.status == 404

    def test_error_to_dict(self):
        """Test converting error to dict."""
        error = APIError(
            error="bad_request",
            message="Invalid input",
            status=400,
            request_id="req-123",
        )

        result = error.to_dict()

        assert result["error"] == "bad_request"
        assert result["message"] == "Invalid input"
        assert result["status"] == 400
        assert result["request_id"] == "req-123"

    def test_error_with_details(self):
        """Test error with details."""
        error = APIError(
            error="validation_error",
            message="Validation failed",
            status=422,
            details={"field": "target", "reason": "required"},
        )

        result = error.to_dict()

        assert result["details"] == {"field": "target", "reason": "required"}


class TestRoute:
    """Tests for Route class."""

    def test_simple_route(self):
        """Test simple route matching."""
        route = Route("/api/v1/scans", lambda r: None, ["GET"])

        assert route.match("/api/v1/scans") == {}
        assert route.match("/api/v1/other") is None

    def test_route_with_param(self):
        """Test route with path parameter."""
        route = Route("/api/v1/scans/{scan_id}", lambda r: None, ["GET"])

        result = route.match("/api/v1/scans/123")
        assert result == {"scan_id": "123"}

        result = route.match("/api/v1/scans/abc-def-456")
        assert result == {"scan_id": "abc-def-456"}

    def test_route_multiple_params(self):
        """Test route with multiple parameters."""
        route = Route("/api/v1/{resource}/{id}", lambda r: None, ["GET"])

        result = route.match("/api/v1/scans/123")
        assert result == {"resource": "scans", "id": "123"}

    def test_route_no_match_different_path(self):
        """Test route doesn't match different path."""
        route = Route("/api/v1/scans", lambda r: None, ["GET"])

        assert route.match("/api/v1/modules") is None


class TestRouter:
    """Tests for Router class."""

    def test_add_route(self):
        """Test adding routes."""
        router = Router()
        router.add_route("/test", lambda r: None, ["GET"])

        assert len(router.routes) == 1

    def test_match_route(self):
        """Test matching routes."""
        router = Router()

        def handler(r):
            return APIResponse(body={"matched": True})

        router.add_route("/test", handler, ["GET"])

        match = router.match("/test", "GET")

        assert match is not None
        assert match.handler == handler

    def test_match_with_params(self):
        """Test matching routes with parameters."""
        router = Router()
        router.add_route("/items/{id}", lambda r: None, ["GET"])

        match = router.match("/items/456", "GET")

        assert match is not None
        assert match.path_params == {"id": "456"}

    def test_no_match_wrong_method(self):
        """Test no match for wrong method."""
        router = Router()
        router.add_route("/test", lambda r: None, ["GET"])

        match = router.match("/test", "POST")

        assert match is None

    def test_decorator_get(self):
        """Test @router.get decorator."""
        router = Router()

        @router.get("/items")
        def list_items(request):
            return APIResponse(body=[])

        assert len(router.routes) == 1
        assert router.routes[0].methods == ["GET"]

    def test_decorator_post(self):
        """Test @router.post decorator."""
        router = Router()

        @router.post("/items")
        def create_item(request):
            return APIResponse(body={})

        assert len(router.routes) == 1
        assert router.routes[0].methods == ["POST"]


class TestAPIServer:
    """Tests for APIServer class."""

    @pytest.fixture
    def server(self):
        """Create a test server."""
        return APIServer(host="127.0.0.1", port=0)

    def test_initialization(self, server):
        """Test server initialization."""
        assert server.host == "127.0.0.1"
        assert server.VERSION == "1.0.0"
        assert len(server.router.routes) > 0

    def test_health_endpoint(self, server):
        """Test health check endpoint."""
        request = APIRequest(
            method="GET",
            path="/health",
            headers={},
            query_params={},
            path_params={},
        )

        response = server.handle_request(request)

        assert response.status == 200
        body = json.loads(response.to_json())
        assert body["status"] == "healthy"
        assert "version" in body

    def test_info_endpoint(self, server):
        """Test API info endpoint."""
        request = APIRequest(
            method="GET",
            path="/api/v1/info",
            headers={},
            query_params={},
            path_params={},
        )

        response = server.handle_request(request)

        assert response.status == 200
        body = json.loads(response.to_json())
        assert body["name"] == "RedOPS API"
        assert "endpoints" in body

    def test_openapi_spec(self, server):
        """Test OpenAPI specification endpoint."""
        request = APIRequest(
            method="GET",
            path="/api/v1/openapi.json",
            headers={},
            query_params={},
            path_params={},
        )

        response = server.handle_request(request)

        assert response.status == 200
        body = json.loads(response.to_json())
        assert body["openapi"] == "3.0.3"
        assert "paths" in body
        assert "components" in body

    def test_list_scans_empty(self, server):
        """Test listing scans when empty."""
        request = APIRequest(
            method="GET",
            path="/api/v1/scans",
            headers={},
            query_params={},
            path_params={},
        )

        response = server.handle_request(request)

        assert response.status == 200
        body = json.loads(response.to_json())
        assert body["scans"] == []
        assert body["total"] == 0

    def test_create_scan(self, server):
        """Test creating a scan."""
        request = APIRequest(
            method="POST",
            path="/api/v1/scans",
            headers={},
            query_params={},
            path_params={},
            body={"target": "example.com", "preset": "quick"},
        )

        response = server.handle_request(request)

        assert response.status == 201
        body = json.loads(response.to_json())
        assert "id" in body
        assert body["target"] == "example.com"
        assert body["preset"] == "quick"
        assert body["status"] == "pending"

    def test_create_scan_missing_target(self, server):
        """Test creating scan without target."""
        request = APIRequest(
            method="POST",
            path="/api/v1/scans",
            headers={},
            query_params={},
            path_params={},
            body={"preset": "quick"},
        )

        response = server.handle_request(request)

        assert response.status == 400
        body = json.loads(response.to_json())
        assert body["error"] == "missing_target"

    def test_create_scan_no_body(self, server):
        """Test creating scan without body."""
        request = APIRequest(
            method="POST",
            path="/api/v1/scans",
            headers={},
            query_params={},
            path_params={},
            body=None,
        )

        response = server.handle_request(request)

        assert response.status == 400
        body = json.loads(response.to_json())
        assert body["error"] == "missing_body"

    def test_get_scan(self, server):
        """Test getting a scan."""
        # First create a scan
        create_request = APIRequest(
            method="POST",
            path="/api/v1/scans",
            headers={},
            query_params={},
            path_params={},
            body={"target": "test.com"},
        )
        create_response = server.handle_request(create_request)
        scan_id = json.loads(create_response.to_json())["id"]

        # Then get it
        get_request = APIRequest(
            method="GET",
            path=f"/api/v1/scans/{scan_id}",
            headers={},
            query_params={},
            path_params={},
        )

        response = server.handle_request(get_request)

        assert response.status == 200
        body = json.loads(response.to_json())
        assert body["id"] == scan_id
        assert body["target"] == "test.com"

    def test_get_scan_not_found(self, server):
        """Test getting nonexistent scan."""
        request = APIRequest(
            method="GET",
            path="/api/v1/scans/nonexistent-id",
            headers={},
            query_params={},
            path_params={},
        )

        response = server.handle_request(request)

        assert response.status == 404
        body = json.loads(response.to_json())
        assert body["error"] == "scan_not_found"

    def test_delete_scan(self, server):
        """Test deleting a scan."""
        # Create a scan
        create_request = APIRequest(
            method="POST",
            path="/api/v1/scans",
            headers={},
            query_params={},
            path_params={},
            body={"target": "delete-me.com"},
        )
        create_response = server.handle_request(create_request)
        scan_id = json.loads(create_response.to_json())["id"]

        # Delete it
        delete_request = APIRequest(
            method="DELETE",
            path=f"/api/v1/scans/{scan_id}",
            headers={},
            query_params={},
            path_params={},
        )

        response = server.handle_request(delete_request)

        assert response.status == 204

    def test_delete_scan_not_found(self, server):
        """Test deleting nonexistent scan."""
        request = APIRequest(
            method="DELETE",
            path="/api/v1/scans/nonexistent",
            headers={},
            query_params={},
            path_params={},
        )

        response = server.handle_request(request)

        assert response.status == 404

    def test_get_scan_status(self, server):
        """Test getting scan status."""
        # Create a scan
        create_request = APIRequest(
            method="POST",
            path="/api/v1/scans",
            headers={},
            query_params={},
            path_params={},
            body={"target": "status.com"},
        )
        create_response = server.handle_request(create_request)
        scan_id = json.loads(create_response.to_json())["id"]

        # Get status
        status_request = APIRequest(
            method="GET",
            path=f"/api/v1/scans/{scan_id}/status",
            headers={},
            query_params={},
            path_params={},
        )

        response = server.handle_request(status_request)

        assert response.status == 200
        body = json.loads(response.to_json())
        assert body["id"] == scan_id
        assert body["status"] == "pending"
        assert body["progress"] == 0

    def test_cancel_scan(self, server):
        """Test cancelling a scan."""
        # Create a scan
        create_request = APIRequest(
            method="POST",
            path="/api/v1/scans",
            headers={},
            query_params={},
            path_params={},
            body={"target": "cancel.com"},
        )
        create_response = server.handle_request(create_request)
        scan_id = json.loads(create_response.to_json())["id"]

        # Cancel it
        cancel_request = APIRequest(
            method="POST",
            path=f"/api/v1/scans/{scan_id}/cancel",
            headers={},
            query_params={},
            path_params={},
        )

        response = server.handle_request(cancel_request)

        assert response.status == 200
        body = json.loads(response.to_json())
        assert body["status"] == "cancelled"

    def test_list_modules(self, server):
        """Test listing modules."""
        request = APIRequest(
            method="GET",
            path="/api/v1/modules",
            headers={},
            query_params={},
            path_params={},
        )

        response = server.handle_request(request)

        assert response.status == 200
        body = json.loads(response.to_json())
        assert "modules" in body
        assert len(body["modules"]) > 0
        assert any(m["name"] == "domain_profile" for m in body["modules"])

    def test_get_module(self, server):
        """Test getting a module."""
        request = APIRequest(
            method="GET",
            path="/api/v1/modules/domain_profile",
            headers={},
            query_params={},
            path_params={},
        )

        response = server.handle_request(request)

        assert response.status == 200
        body = json.loads(response.to_json())
        assert body["name"] == "domain_profile"
        assert "options" in body

    def test_get_module_not_found(self, server):
        """Test getting nonexistent module."""
        request = APIRequest(
            method="GET",
            path="/api/v1/modules/nonexistent",
            headers={},
            query_params={},
            path_params={},
        )

        response = server.handle_request(request)

        assert response.status == 404

    def test_list_presets(self, server):
        """Test listing presets."""
        request = APIRequest(
            method="GET",
            path="/api/v1/presets",
            headers={},
            query_params={},
            path_params={},
        )

        response = server.handle_request(request)

        assert response.status == 200
        body = json.loads(response.to_json())
        assert "presets" in body
        assert any(p["name"] == "quick" for p in body["presets"])
        assert any(p["name"] == "full" for p in body["presets"])

    def test_get_preset(self, server):
        """Test getting a preset."""
        request = APIRequest(
            method="GET",
            path="/api/v1/presets/quick",
            headers={},
            query_params={},
            path_params={},
        )

        response = server.handle_request(request)

        assert response.status == 200
        body = json.loads(response.to_json())
        assert body["name"] == "quick"
        assert "modules" in body

    def test_get_preset_not_found(self, server):
        """Test getting nonexistent preset."""
        request = APIRequest(
            method="GET",
            path="/api/v1/presets/nonexistent",
            headers={},
            query_params={},
            path_params={},
        )

        response = server.handle_request(request)

        assert response.status == 404

    def test_get_config(self, server):
        """Test getting configuration."""
        request = APIRequest(
            method="GET",
            path="/api/v1/config",
            headers={},
            query_params={},
            path_params={},
        )

        response = server.handle_request(request)

        assert response.status == 200
        body = json.loads(response.to_json())
        assert "output" in body
        assert "network" in body
        assert "cache" in body

    def test_update_config(self, server):
        """Test updating configuration."""
        request = APIRequest(
            method="PATCH",
            path="/api/v1/config",
            headers={},
            query_params={},
            path_params={},
            body={"network": {"timeout": 60}},
        )

        response = server.handle_request(request)

        assert response.status == 200

    def test_update_config_no_body(self, server):
        """Test updating config without body."""
        request = APIRequest(
            method="PATCH",
            path="/api/v1/config",
            headers={},
            query_params={},
            path_params={},
            body=None,
        )

        response = server.handle_request(request)

        assert response.status == 400

    def test_not_found_path(self, server):
        """Test 404 for unknown path."""
        request = APIRequest(
            method="GET",
            path="/api/v1/unknown",
            headers={},
            query_params={},
            path_params={},
        )

        response = server.handle_request(request)

        assert response.status == 404
        body = json.loads(response.to_json())
        assert body["error"] == "not_found"

    def test_method_not_allowed(self, server):
        """Test 405 for wrong method."""
        request = APIRequest(
            method="PUT",
            path="/api/v1/scans",
            headers={},
            query_params={},
            path_params={},
        )

        response = server.handle_request(request)

        assert response.status == 405

    def test_list_scans_with_pagination(self, server):
        """Test listing scans with pagination."""
        # Create some scans
        for i in range(5):
            create_request = APIRequest(
                method="POST",
                path="/api/v1/scans",
                headers={},
                query_params={},
                path_params={},
                body={"target": f"test{i}.com"},
            )
            server.handle_request(create_request)

        # List with pagination
        request = APIRequest(
            method="GET",
            path="/api/v1/scans",
            headers={},
            query_params={"limit": ["2"], "offset": ["1"]},
            path_params={},
        )

        response = server.handle_request(request)

        assert response.status == 200
        body = json.loads(response.to_json())
        assert len(body["scans"]) == 2
        assert body["limit"] == 2
        assert body["offset"] == 1

    def test_generate_report(self, server):
        """Test generating a report."""
        # Create a scan
        create_request = APIRequest(
            method="POST",
            path="/api/v1/scans",
            headers={},
            query_params={},
            path_params={},
            body={"target": "report.com"},
        )
        create_response = server.handle_request(create_request)
        scan_id = json.loads(create_response.to_json())["id"]

        # Generate report
        report_request = APIRequest(
            method="POST",
            path=f"/api/v1/reports/{scan_id}",
            headers={},
            query_params={},
            path_params={},
            body={"format": "html"},
        )

        response = server.handle_request(report_request)

        assert response.status == 202
        body = json.loads(response.to_json())
        assert "id" in body
        assert body["format"] == "html"


class TestCreateAPIServer:
    """Tests for create_api_server function."""

    def test_create_default(self):
        """Test creating server with defaults."""
        server = create_api_server()

        assert server.host == "127.0.0.1"
        assert server.port == 8080

    def test_create_custom(self):
        """Test creating server with custom settings."""
        server = create_api_server(host="0.0.0.0", port=9000)

        assert server.host == "0.0.0.0"
        assert server.port == 9000


class TestAPIServerIntegration:
    """Integration tests for API server."""

    def test_scan_workflow(self):
        """Test complete scan workflow."""
        server = APIServer()

        # 1. Create scan
        create_request = APIRequest(
            method="POST",
            path="/api/v1/scans",
            headers={},
            query_params={},
            path_params={},
            body={"target": "workflow.com", "preset": "full"},
        )
        create_response = server.handle_request(create_request)
        assert create_response.status == 201
        scan = json.loads(create_response.to_json())
        scan_id = scan["id"]

        # 2. Check status
        status_request = APIRequest(
            method="GET",
            path=f"/api/v1/scans/{scan_id}/status",
            headers={},
            query_params={},
            path_params={},
        )
        status_response = server.handle_request(status_request)
        assert status_response.status == 200

        # 3. Cancel scan
        cancel_request = APIRequest(
            method="POST",
            path=f"/api/v1/scans/{scan_id}/cancel",
            headers={},
            query_params={},
            path_params={},
        )
        cancel_response = server.handle_request(cancel_request)
        assert cancel_response.status == 200

        # 4. Delete scan
        delete_request = APIRequest(
            method="DELETE",
            path=f"/api/v1/scans/{scan_id}",
            headers={},
            query_params={},
            path_params={},
        )
        delete_response = server.handle_request(delete_request)
        assert delete_response.status == 204

        # 5. Verify deleted
        get_request = APIRequest(
            method="GET",
            path=f"/api/v1/scans/{scan_id}",
            headers={},
            query_params={},
            path_params={},
        )
        get_response = server.handle_request(get_request)
        assert get_response.status == 404
