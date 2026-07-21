"""
RESTful API Server for RedOPS.

Provides programmatic access to RedOPS functionality via HTTP API.
"""

import hashlib
import json
import logging
import os
import re
import secrets
import threading
import traceback
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Callable
from urllib.parse import parse_qs, urlparse

logger = logging.getLogger(__name__)


class HTTPMethod(Enum):
    """HTTP methods."""

    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"
    OPTIONS = "OPTIONS"


class HTTPStatus(Enum):
    """HTTP status codes."""

    OK = 200
    CREATED = 201
    ACCEPTED = 202
    NO_CONTENT = 204
    BAD_REQUEST = 400
    UNAUTHORIZED = 401
    FORBIDDEN = 403
    NOT_FOUND = 404
    METHOD_NOT_ALLOWED = 405
    CONFLICT = 409
    UNPROCESSABLE_ENTITY = 422
    TOO_MANY_REQUESTS = 429
    INTERNAL_ERROR = 500
    SERVICE_UNAVAILABLE = 503


@dataclass
class APIRequest:
    """Represents an API request."""

    method: str
    path: str
    headers: dict[str, str]
    query_params: dict[str, list[str]]
    path_params: dict[str, str]
    body: dict | list | None = None
    client_address: tuple[str, int] | None = None
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))


@dataclass
class APIResponse:
    """Represents an API response."""

    status: int = 200
    body: dict | list | str | None = None
    headers: dict[str, str] = field(default_factory=dict)

    def to_json(self) -> str:
        """Convert body to JSON string."""
        if self.body is None:
            return ""
        if isinstance(self.body, str):
            return self.body
        return json.dumps(self.body, default=str)


@dataclass
class RouteMatch:
    """Result of matching a route."""

    handler: Callable
    path_params: dict[str, str]
    methods: list[str]


@dataclass
class APIError:
    """Standard API error response."""

    error: str
    message: str
    status: int
    details: dict | None = None
    request_id: str | None = None

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        result = {
            "error": self.error,
            "message": self.message,
            "status": self.status,
        }
        if self.details:
            result["details"] = self.details
        if self.request_id:
            result["request_id"] = self.request_id
        return result


class Route:
    """Represents an API route."""

    def __init__(
        self,
        path: str,
        handler: Callable,
        methods: list[str] | None = None,
        auth_required: bool = False,
        rate_limit: int | None = None,
    ):
        self.path = path
        self.handler = handler
        self.methods = methods or ["GET"]
        self.auth_required = auth_required
        self.rate_limit = rate_limit

        # Convert path pattern to regex
        # /scans/{scan_id} -> /scans/(?P<scan_id>[^/]+)
        pattern = re.sub(r"\{(\w+)\}", r"(?P<\1>[^/]+)", path)
        self.pattern = re.compile(f"^{pattern}$")

    def match(self, path: str) -> dict[str, str] | None:
        """
        Check if path matches this route.

        Returns:
            Path parameters if match, None otherwise
        """
        match = self.pattern.match(path)
        if match:
            return match.groupdict()
        return None


class Router:
    """Routes requests to handlers."""

    def __init__(self):
        self.routes: list[Route] = []
        self.middleware: list[Callable] = []

    def add_route(
        self,
        path: str,
        handler: Callable,
        methods: list[str] | None = None,
        **kwargs,
    ) -> None:
        """Add a route."""
        self.routes.append(Route(path, handler, methods, **kwargs))

    def add_middleware(self, middleware: Callable) -> None:
        """Add middleware."""
        self.middleware.append(middleware)

    def get(self, path: str, **kwargs) -> Callable:
        """Decorator for GET routes."""

        def decorator(handler: Callable) -> Callable:
            self.add_route(path, handler, ["GET"], **kwargs)
            return handler

        return decorator

    def post(self, path: str, **kwargs) -> Callable:
        """Decorator for POST routes."""

        def decorator(handler: Callable) -> Callable:
            self.add_route(path, handler, ["POST"], **kwargs)
            return handler

        return decorator

    def put(self, path: str, **kwargs) -> Callable:
        """Decorator for PUT routes."""

        def decorator(handler: Callable) -> Callable:
            self.add_route(path, handler, ["PUT"], **kwargs)
            return handler

        return decorator

    def delete(self, path: str, **kwargs) -> Callable:
        """Decorator for DELETE routes."""

        def decorator(handler: Callable) -> Callable:
            self.add_route(path, handler, ["DELETE"], **kwargs)
            return handler

        return decorator

    def match(self, path: str, method: str) -> RouteMatch | None:
        """Find matching route for path and method."""
        for route in self.routes:
            path_params = route.match(path)
            if path_params is not None:
                if method in route.methods:
                    return RouteMatch(route.handler, path_params, route.methods)
                elif method == "OPTIONS":
                    return RouteMatch(
                        lambda req: APIResponse(status=204),
                        path_params,
                        route.methods,
                    )
        return None


class APIServer:
    """
    RedOPS API Server.

    Provides RESTful endpoints for programmatic access.
    """

    VERSION = "1.0.0"
    API_PREFIX = "/api/v1"

    MAX_BODY_SIZE = 1024 * 1024  # 1MB

    # Public paths that do not require authentication
    PUBLIC_PATHS = {"/health", "/api/v1/openapi.json"}

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 8080,
        api_key: str | None = None,
    ):
        self.host = host
        self.port = port
        self.router = Router()
        self._server: HTTPServer | None = None
        self._thread: threading.Thread | None = None

        # API key for authentication (falls back to env var)
        self._api_key = api_key or os.environ.get("REDOPS_API_KEY")
        if not self._api_key:
            logger.warning(
                "SECURITY WARNING: No API key configured. "
                "Set REDOPS_API_KEY to secure this API server."
            )

        # In-memory storage for demo
        self._scans: dict[str, dict] = {}
        self._jobs: dict[str, dict] = {}

        # Register routes
        self._register_routes()

    def _register_routes(self) -> None:
        """Register all API routes."""
        # Health & Info
        self.router.add_route("/health", self._health, ["GET"])
        self.router.add_route("/api/v1/info", self._info, ["GET"])
        self.router.add_route("/api/v1/openapi.json", self._openapi_spec, ["GET"])

        # Scans
        self.router.add_route("/api/v1/scans", self._list_scans, ["GET"])
        self.router.add_route("/api/v1/scans", self._create_scan, ["POST"])
        self.router.add_route("/api/v1/scans/{scan_id}", self._get_scan, ["GET"])
        self.router.add_route("/api/v1/scans/{scan_id}", self._delete_scan, ["DELETE"])
        self.router.add_route(
            "/api/v1/scans/{scan_id}/status", self._get_scan_status, ["GET"]
        )
        self.router.add_route(
            "/api/v1/scans/{scan_id}/results", self._get_scan_results, ["GET"]
        )
        self.router.add_route(
            "/api/v1/scans/{scan_id}/cancel", self._cancel_scan, ["POST"]
        )

        # Modules
        self.router.add_route("/api/v1/modules", self._list_modules, ["GET"])
        self.router.add_route(
            "/api/v1/modules/{module_name}", self._get_module, ["GET"]
        )

        # Presets
        self.router.add_route("/api/v1/presets", self._list_presets, ["GET"])
        self.router.add_route(
            "/api/v1/presets/{preset_name}", self._get_preset, ["GET"]
        )

        # Reports
        self.router.add_route("/api/v1/reports", self._list_reports, ["GET"])
        self.router.add_route(
            "/api/v1/reports/{scan_id}", self._generate_report, ["POST"]
        )
        self.router.add_route("/api/v1/reports/{report_id}", self._get_report, ["GET"])

        # Config
        self.router.add_route("/api/v1/config", self._get_config, ["GET"])
        self.router.add_route("/api/v1/config", self._update_config, ["PATCH"])

    # Health & Info Handlers
    def _health(self, request: APIRequest) -> APIResponse:
        """Health check endpoint."""
        return APIResponse(
            body={
                "status": "healthy",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "version": self.VERSION,
            }
        )

    def _info(self, request: APIRequest) -> APIResponse:
        """API information endpoint."""
        return APIResponse(
            body={
                "name": "RedOPS API",
                "version": self.VERSION,
                "description": "RESTful API for RedOPS security intelligence framework",
                "endpoints": {
                    "scans": f"{self.API_PREFIX}/scans",
                    "modules": f"{self.API_PREFIX}/modules",
                    "presets": f"{self.API_PREFIX}/presets",
                    "reports": f"{self.API_PREFIX}/reports",
                    "config": f"{self.API_PREFIX}/config",
                },
                "documentation": f"{self.API_PREFIX}/openapi.json",
            }
        )

    def _openapi_spec(self, request: APIRequest) -> APIResponse:
        """OpenAPI specification."""
        return APIResponse(body=self._generate_openapi_spec())

    # Scan Handlers
    def _list_scans(self, request: APIRequest) -> APIResponse:
        """List all scans."""
        # Parse query params
        status = request.query_params.get("status", [None])[0]
        limit = int(request.query_params.get("limit", ["100"])[0])
        offset = int(request.query_params.get("offset", ["0"])[0])

        scans = list(self._scans.values())

        # Filter by status
        if status:
            scans = [s for s in scans if s.get("status") == status]

        # Paginate
        total = len(scans)
        scans = scans[offset : offset + limit]

        return APIResponse(
            body={
                "scans": scans,
                "total": total,
                "limit": limit,
                "offset": offset,
            }
        )

    def _create_scan(self, request: APIRequest) -> APIResponse:
        """Create a new scan."""
        if not request.body:
            return self._error_response(
                HTTPStatus.BAD_REQUEST,
                "missing_body",
                "Request body is required",
                request.request_id,
            )

        target = request.body.get("target")
        if not target:
            return self._error_response(
                HTTPStatus.BAD_REQUEST,
                "missing_target",
                "Target is required",
                request.request_id,
            )

        scan_id = str(uuid.uuid4())
        scan = {
            "id": scan_id,
            "target": target,
            "preset": request.body.get("preset", "quick"),
            "modules": request.body.get("modules", []),
            "options": request.body.get("options", {}),
            "status": "pending",
            "progress": 0,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "started_at": None,
            "completed_at": None,
            "results": None,
            "error": None,
        }

        self._scans[scan_id] = scan

        return APIResponse(
            status=HTTPStatus.CREATED.value,
            body=scan,
            headers={"Location": f"{self.API_PREFIX}/scans/{scan_id}"},
        )

    def _get_scan(self, request: APIRequest) -> APIResponse:
        """Get a specific scan."""
        scan_id = request.path_params.get("scan_id")
        scan = self._scans.get(scan_id)

        if not scan:
            return self._error_response(
                HTTPStatus.NOT_FOUND,
                "scan_not_found",
                f"Scan {scan_id} not found",
                request.request_id,
            )

        return APIResponse(body=scan)

    def _delete_scan(self, request: APIRequest) -> APIResponse:
        """Delete a scan."""
        scan_id = request.path_params.get("scan_id")

        if scan_id not in self._scans:
            return self._error_response(
                HTTPStatus.NOT_FOUND,
                "scan_not_found",
                f"Scan {scan_id} not found",
                request.request_id,
            )

        del self._scans[scan_id]
        return APIResponse(status=HTTPStatus.NO_CONTENT.value)

    def _get_scan_status(self, request: APIRequest) -> APIResponse:
        """Get scan status."""
        scan_id = request.path_params.get("scan_id")
        scan = self._scans.get(scan_id)

        if not scan:
            return self._error_response(
                HTTPStatus.NOT_FOUND,
                "scan_not_found",
                f"Scan {scan_id} not found",
                request.request_id,
            )

        return APIResponse(
            body={
                "id": scan_id,
                "status": scan["status"],
                "progress": scan["progress"],
                "started_at": scan["started_at"],
                "completed_at": scan["completed_at"],
                "error": scan["error"],
            }
        )

    def _get_scan_results(self, request: APIRequest) -> APIResponse:
        """Get scan results."""
        scan_id = request.path_params.get("scan_id")
        scan = self._scans.get(scan_id)

        if not scan:
            return self._error_response(
                HTTPStatus.NOT_FOUND,
                "scan_not_found",
                f"Scan {scan_id} not found",
                request.request_id,
            )

        if scan["status"] != "completed":
            return self._error_response(
                HTTPStatus.BAD_REQUEST,
                "scan_not_complete",
                f"Scan {scan_id} is not complete (status: {scan['status']})",
                request.request_id,
            )

        return APIResponse(
            body={
                "id": scan_id,
                "results": scan["results"],
                "completed_at": scan["completed_at"],
            }
        )

    def _cancel_scan(self, request: APIRequest) -> APIResponse:
        """Cancel a running scan."""
        scan_id = request.path_params.get("scan_id")
        scan = self._scans.get(scan_id)

        if not scan:
            return self._error_response(
                HTTPStatus.NOT_FOUND,
                "scan_not_found",
                f"Scan {scan_id} not found",
                request.request_id,
            )

        if scan["status"] not in ("pending", "running"):
            return self._error_response(
                HTTPStatus.CONFLICT,
                "cannot_cancel",
                f"Cannot cancel scan with status: {scan['status']}",
                request.request_id,
            )

        scan["status"] = "cancelled"
        scan["completed_at"] = datetime.now(timezone.utc).isoformat()

        return APIResponse(body={"id": scan_id, "status": "cancelled"})

    # Module Handlers
    def _list_modules(self, request: APIRequest) -> APIResponse:
        """List available modules."""
        modules = [
            {
                "name": "domain_profile",
                "description": "Domain profiling and WHOIS lookup",
                "category": "recon",
                "enabled": True,
            },
            {
                "name": "tech_stack",
                "description": "Technology stack detection",
                "category": "recon",
                "enabled": True,
            },
            {
                "name": "social_osint",
                "description": "Social media OSINT",
                "category": "osint",
                "enabled": True,
            },
            {
                "name": "exposure_scan",
                "description": "Exposure and vulnerability scanning",
                "category": "security",
                "enabled": True,
            },
            {
                "name": "infrastructure",
                "description": "Infrastructure analysis",
                "category": "recon",
                "enabled": True,
            },
            {
                "name": "threat_intel",
                "description": "Threat intelligence gathering",
                "category": "intel",
                "enabled": True,
            },
            {
                "name": "compliance",
                "description": "Compliance checking",
                "category": "compliance",
                "enabled": True,
            },
            {
                "name": "correlation",
                "description": "Finding correlation engine",
                "category": "analysis",
                "enabled": True,
            },
            {
                "name": "executive_report",
                "description": "Executive summary generation",
                "category": "reporting",
                "enabled": True,
            },
        ]

        return APIResponse(body={"modules": modules, "total": len(modules)})

    def _get_module(self, request: APIRequest) -> APIResponse:
        """Get module details."""
        module_name = request.path_params.get("module_name")

        modules = {
            "domain_profile": {
                "name": "domain_profile",
                "description": "Domain profiling and WHOIS lookup",
                "category": "recon",
                "enabled": True,
                "options": {
                    "include_whois": {"type": "boolean", "default": True},
                    "include_dns": {"type": "boolean", "default": True},
                },
            },
            "tech_stack": {
                "name": "tech_stack",
                "description": "Technology stack detection",
                "category": "recon",
                "enabled": True,
                "options": {
                    "deep_scan": {"type": "boolean", "default": False},
                },
            },
        }

        module = modules.get(module_name)
        if not module:
            return self._error_response(
                HTTPStatus.NOT_FOUND,
                "module_not_found",
                f"Module {module_name} not found",
                request.request_id,
            )

        return APIResponse(body=module)

    # Preset Handlers
    def _list_presets(self, request: APIRequest) -> APIResponse:
        """List available presets."""
        presets = [
            {
                "name": "quick",
                "description": "Quick reconnaissance scan",
                "modules": ["domain_profile", "tech_stack", "exposure_scan"],
            },
            {
                "name": "full",
                "description": "Comprehensive security assessment",
                "modules": [
                    "domain_profile",
                    "tech_stack",
                    "social_osint",
                    "exposure_scan",
                    "infrastructure",
                    "threat_intel",
                    "compliance",
                    "correlation",
                    "executive_report",
                ],
            },
            {
                "name": "recon",
                "description": "Reconnaissance focused scan",
                "modules": ["domain_profile", "tech_stack", "infrastructure"],
            },
            {
                "name": "compliance",
                "description": "Compliance-focused assessment",
                "modules": ["compliance", "exposure_scan"],
            },
            {
                "name": "threat_intel",
                "description": "Threat intelligence gathering",
                "modules": ["threat_intel", "correlation"],
            },
        ]

        return APIResponse(body={"presets": presets, "total": len(presets)})

    def _get_preset(self, request: APIRequest) -> APIResponse:
        """Get preset details."""
        preset_name = request.path_params.get("preset_name")

        presets = {
            "quick": {
                "name": "quick",
                "description": "Quick reconnaissance scan",
                "modules": ["domain_profile", "tech_stack", "exposure_scan"],
                "estimated_duration": "1-2 minutes",
            },
            "full": {
                "name": "full",
                "description": "Comprehensive security assessment",
                "modules": [
                    "domain_profile",
                    "tech_stack",
                    "social_osint",
                    "exposure_scan",
                    "infrastructure",
                    "threat_intel",
                    "compliance",
                    "correlation",
                    "executive_report",
                ],
                "estimated_duration": "5-10 minutes",
            },
        }

        preset = presets.get(preset_name)
        if not preset:
            return self._error_response(
                HTTPStatus.NOT_FOUND,
                "preset_not_found",
                f"Preset {preset_name} not found",
                request.request_id,
            )

        return APIResponse(body=preset)

    # Report Handlers
    def _list_reports(self, request: APIRequest) -> APIResponse:
        """List generated reports."""
        return APIResponse(body={"reports": [], "total": 0})

    def _generate_report(self, request: APIRequest) -> APIResponse:
        """Generate a report for a scan."""
        scan_id = request.path_params.get("scan_id")
        scan = self._scans.get(scan_id)

        if not scan:
            return self._error_response(
                HTTPStatus.NOT_FOUND,
                "scan_not_found",
                f"Scan {scan_id} not found",
                request.request_id,
            )

        format_type = "json"
        if request.body:
            format_type = request.body.get("format", "json")

        report_id = str(uuid.uuid4())
        report = {
            "id": report_id,
            "scan_id": scan_id,
            "format": format_type,
            "status": "generating",
            "created_at": datetime.now(timezone.utc).isoformat(),
        }

        return APIResponse(
            status=HTTPStatus.ACCEPTED.value,
            body=report,
            headers={"Location": f"{self.API_PREFIX}/reports/{report_id}"},
        )

    def _get_report(self, request: APIRequest) -> APIResponse:
        """Get a generated report."""
        report_id = request.path_params.get("report_id")

        return self._error_response(
            HTTPStatus.NOT_FOUND,
            "report_not_found",
            f"Report {report_id} not found",
            request.request_id,
        )

    # Config Handlers
    def _get_config(self, request: APIRequest) -> APIResponse:
        """Get current configuration."""
        return APIResponse(
            body={
                "output": {
                    "directory": "./output",
                    "format": "json",
                },
                "network": {
                    "timeout": 30,
                    "rate_limit": 1.0,
                },
                "cache": {
                    "enabled": True,
                    "ttl_seconds": 3600,
                },
            }
        )

    def _update_config(self, request: APIRequest) -> APIResponse:
        """Update configuration."""
        if not request.body:
            return self._error_response(
                HTTPStatus.BAD_REQUEST,
                "missing_body",
                "Request body is required",
                request.request_id,
            )

        # In real implementation, would update config manager
        return APIResponse(body={"message": "Configuration updated"})

    # Helper Methods
    def _error_response(
        self,
        status: HTTPStatus,
        error: str,
        message: str,
        request_id: str | None = None,
        details: dict | None = None,
    ) -> APIResponse:
        """Create an error response."""
        return APIResponse(
            status=status.value,
            body=APIError(
                error=error,
                message=message,
                status=status.value,
                details=details,
                request_id=request_id,
            ).to_dict(),
        )

    def _generate_openapi_spec(self) -> dict:
        """Generate OpenAPI specification."""
        return {
            "openapi": "3.0.3",
            "info": {
                "title": "RedOPS API",
                "description": "RESTful API for RedOPS security intelligence framework",
                "version": self.VERSION,
                "contact": {
                    "name": "RedOPS Team",
                },
                "license": {
                    "name": "MIT",
                },
            },
            "servers": [
                {
                    "url": f"http://{self.host}:{self.port}{self.API_PREFIX}",
                    "description": "Local development server",
                },
            ],
            "paths": {
                "/scans": {
                    "get": {
                        "summary": "List scans",
                        "operationId": "listScans",
                        "tags": ["Scans"],
                        "parameters": [
                            {
                                "name": "status",
                                "in": "query",
                                "schema": {"type": "string"},
                            },
                            {
                                "name": "limit",
                                "in": "query",
                                "schema": {"type": "integer", "default": 100},
                            },
                            {
                                "name": "offset",
                                "in": "query",
                                "schema": {"type": "integer", "default": 0},
                            },
                        ],
                        "responses": {
                            "200": {
                                "description": "List of scans",
                                "content": {
                                    "application/json": {
                                        "schema": {
                                            "$ref": "#/components/schemas/ScanList"
                                        },
                                    },
                                },
                            },
                        },
                    },
                    "post": {
                        "summary": "Create a new scan",
                        "operationId": "createScan",
                        "tags": ["Scans"],
                        "requestBody": {
                            "required": True,
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "$ref": "#/components/schemas/CreateScan"
                                    },
                                },
                            },
                        },
                        "responses": {
                            "201": {
                                "description": "Scan created",
                                "content": {
                                    "application/json": {
                                        "schema": {"$ref": "#/components/schemas/Scan"},
                                    },
                                },
                            },
                        },
                    },
                },
                "/scans/{scan_id}": {
                    "get": {
                        "summary": "Get scan details",
                        "operationId": "getScan",
                        "tags": ["Scans"],
                        "parameters": [
                            {
                                "name": "scan_id",
                                "in": "path",
                                "required": True,
                                "schema": {"type": "string", "format": "uuid"},
                            },
                        ],
                        "responses": {
                            "200": {
                                "description": "Scan details",
                                "content": {
                                    "application/json": {
                                        "schema": {"$ref": "#/components/schemas/Scan"},
                                    },
                                },
                            },
                            "404": {
                                "description": "Scan not found",
                                "content": {
                                    "application/json": {
                                        "schema": {
                                            "$ref": "#/components/schemas/Error"
                                        },
                                    },
                                },
                            },
                        },
                    },
                    "delete": {
                        "summary": "Delete a scan",
                        "operationId": "deleteScan",
                        "tags": ["Scans"],
                        "parameters": [
                            {
                                "name": "scan_id",
                                "in": "path",
                                "required": True,
                                "schema": {"type": "string", "format": "uuid"},
                            },
                        ],
                        "responses": {
                            "204": {"description": "Scan deleted"},
                            "404": {"description": "Scan not found"},
                        },
                    },
                },
                "/modules": {
                    "get": {
                        "summary": "List available modules",
                        "operationId": "listModules",
                        "tags": ["Modules"],
                        "responses": {
                            "200": {
                                "description": "List of modules",
                                "content": {
                                    "application/json": {
                                        "schema": {
                                            "$ref": "#/components/schemas/ModuleList"
                                        },
                                    },
                                },
                            },
                        },
                    },
                },
                "/presets": {
                    "get": {
                        "summary": "List available presets",
                        "operationId": "listPresets",
                        "tags": ["Presets"],
                        "responses": {
                            "200": {
                                "description": "List of presets",
                                "content": {
                                    "application/json": {
                                        "schema": {
                                            "$ref": "#/components/schemas/PresetList"
                                        },
                                    },
                                },
                            },
                        },
                    },
                },
            },
            "components": {
                "schemas": {
                    "Scan": {
                        "type": "object",
                        "properties": {
                            "id": {"type": "string", "format": "uuid"},
                            "target": {"type": "string"},
                            "preset": {"type": "string"},
                            "modules": {"type": "array", "items": {"type": "string"}},
                            "status": {
                                "type": "string",
                                "enum": [
                                    "pending",
                                    "running",
                                    "completed",
                                    "failed",
                                    "cancelled",
                                ],
                            },
                            "progress": {
                                "type": "integer",
                                "minimum": 0,
                                "maximum": 100,
                            },
                            "created_at": {"type": "string", "format": "date-time"},
                            "started_at": {"type": "string", "format": "date-time"},
                            "completed_at": {"type": "string", "format": "date-time"},
                        },
                    },
                    "CreateScan": {
                        "type": "object",
                        "required": ["target"],
                        "properties": {
                            "target": {"type": "string"},
                            "preset": {"type": "string", "default": "quick"},
                            "modules": {"type": "array", "items": {"type": "string"}},
                            "options": {"type": "object"},
                        },
                    },
                    "ScanList": {
                        "type": "object",
                        "properties": {
                            "scans": {
                                "type": "array",
                                "items": {"$ref": "#/components/schemas/Scan"},
                            },
                            "total": {"type": "integer"},
                            "limit": {"type": "integer"},
                            "offset": {"type": "integer"},
                        },
                    },
                    "Module": {
                        "type": "object",
                        "properties": {
                            "name": {"type": "string"},
                            "description": {"type": "string"},
                            "category": {"type": "string"},
                            "enabled": {"type": "boolean"},
                        },
                    },
                    "ModuleList": {
                        "type": "object",
                        "properties": {
                            "modules": {
                                "type": "array",
                                "items": {"$ref": "#/components/schemas/Module"},
                            },
                            "total": {"type": "integer"},
                        },
                    },
                    "Preset": {
                        "type": "object",
                        "properties": {
                            "name": {"type": "string"},
                            "description": {"type": "string"},
                            "modules": {"type": "array", "items": {"type": "string"}},
                        },
                    },
                    "PresetList": {
                        "type": "object",
                        "properties": {
                            "presets": {
                                "type": "array",
                                "items": {"$ref": "#/components/schemas/Preset"},
                            },
                            "total": {"type": "integer"},
                        },
                    },
                    "Error": {
                        "type": "object",
                        "properties": {
                            "error": {"type": "string"},
                            "message": {"type": "string"},
                            "status": {"type": "integer"},
                            "request_id": {"type": "string"},
                        },
                    },
                },
                "securitySchemes": {
                    "ApiKeyAuth": {
                        "type": "apiKey",
                        "in": "header",
                        "name": "X-API-Key",
                    },
                },
            },
        }

    def _authenticate_request(self, request: APIRequest) -> APIResponse | None:
        """Authenticate a request via X-API-Key header.

        Returns None if authenticated or path is public.
        Returns an error response if authentication fails.
        """
        # Public paths do not require authentication
        if request.path in self.PUBLIC_PATHS:
            return None

        # If no API key is configured, allow all requests (warned in __init__)
        if not self._api_key:
            return None

        provided_key = request.headers.get("X-API-Key", "")
        if secrets.compare_digest(provided_key, self._api_key):
            return None

        return self._error_response(
            HTTPStatus.UNAUTHORIZED,
            "unauthorized",
            "Authentication required. Provide a valid X-API-Key header.",
            request.request_id,
        )

    def handle_request(self, request: APIRequest) -> APIResponse:
        """Handle an incoming request."""
        # Authenticate
        auth_error = self._authenticate_request(request)
        if auth_error is not None:
            return auth_error

        # Match route
        match = self.router.match(request.path, request.method)

        if not match:
            # Check if path exists with different method
            for route in self.router.routes:
                if route.match(request.path) is not None:
                    return self._error_response(
                        HTTPStatus.METHOD_NOT_ALLOWED,
                        "method_not_allowed",
                        f"Method {request.method} not allowed",
                        request.request_id,
                    )

            return self._error_response(
                HTTPStatus.NOT_FOUND,
                "not_found",
                f"Path {request.path} not found",
                request.request_id,
            )

        request.path_params = match.path_params

        try:
            return match.handler(request)
        except Exception as e:
            logger.error(
                "Unhandled exception in API handler: %s\n%s",
                e,
                traceback.format_exc(),
            )
            return self._error_response(
                HTTPStatus.INTERNAL_ERROR,
                "internal_error",
                "An internal server error occurred.",
                request.request_id,
            )

    def start(self, blocking: bool = True) -> None:
        """Start the API server."""
        handler = self._create_handler()
        self._server = HTTPServer((self.host, self.port), handler)

        if blocking:
            self._server.serve_forever()
        else:
            self._thread = threading.Thread(target=self._server.serve_forever)
            self._thread.daemon = True
            self._thread.start()

    def stop(self) -> None:
        """Stop the API server."""
        if self._server:
            self._server.shutdown()
            self._server = None
        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None

    def _create_handler(self) -> type:
        """Create HTTP request handler class."""
        server = self

        class RequestHandler(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args) -> None:
                pass  # Suppress default logging

            def _handle(self, method: str) -> None:
                # Parse request
                parsed = urlparse(self.path)
                query_params = parse_qs(parsed.query)

                # Read body if present (enforce size limit)
                body = None
                content_length = self.headers.get("Content-Length")
                if content_length:
                    size = int(content_length)
                    if size > server.MAX_BODY_SIZE:
                        self.send_response(413)
                        self.send_header("Content-Type", "application/json")
                        self.end_headers()
                        error_body = json.dumps(
                            {
                                "error": "payload_too_large",
                                "message": f"Request body exceeds maximum size of {server.MAX_BODY_SIZE} bytes",
                                "status": 413,
                            }
                        )
                        self.wfile.write(error_body.encode("utf-8"))
                        return

                    raw_body = self.rfile.read(size)
                    if raw_body:
                        try:
                            body = json.loads(raw_body.decode("utf-8"))
                        except json.JSONDecodeError:
                            pass

                request = APIRequest(
                    method=method,
                    path=parsed.path,
                    headers=dict(self.headers),
                    query_params=query_params,
                    path_params={},
                    body=body,
                    client_address=self.client_address,
                )

                response = server.handle_request(request)

                # Send response
                self.send_response(response.status)
                self.send_header("Content-Type", "application/json")
                for key, value in response.headers.items():
                    self.send_header(key, value)
                self.end_headers()

                body_bytes = response.to_json().encode("utf-8")
                if body_bytes:
                    self.wfile.write(body_bytes)

            def do_GET(self) -> None:
                self._handle("GET")

            def do_POST(self) -> None:
                self._handle("POST")

            def do_PUT(self) -> None:
                self._handle("PUT")

            def do_PATCH(self) -> None:
                self._handle("PATCH")

            def do_DELETE(self) -> None:
                self._handle("DELETE")

            def do_OPTIONS(self) -> None:
                self._handle("OPTIONS")

        return RequestHandler


# Convenience functions
def create_api_server(host: str = "127.0.0.1", port: int = 8080) -> APIServer:
    """Create an API server instance."""
    return APIServer(host, port)


def run_api_server(host: str = "127.0.0.1", port: int = 8080) -> None:
    """Run the API server (blocking)."""
    server = create_api_server(host, port)
    print(f"Starting RedOPS API server on http://{host}:{port}")
    server.start(blocking=True)
