"""
RedOPS Web UI - FastAPI application.

Provides a REST API and web dashboard for RedOPS functionality.
"""

import os
from datetime import datetime, timezone
from typing import Any

from fastapi import (
    FastAPI,
    HTTPException,
    BackgroundTasks,
    Query,
    WebSocket,
    WebSocketDisconnect,
    Depends,
    Response,
    Request,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from redops.web.websocket import (
    manager as ws_manager,
    emit_scan_started,
    emit_scan_progress,
    emit_module_start,
    emit_module_end,
    emit_scan_completed,
    emit_scan_failed,
)
from redops.web.auth import (
    AuthConfig,
    AuthManager,
    AuthenticatedUser,
    require_auth,
    optional_auth,
    get_auth_manager,
    set_auth_manager,
    generate_api_key,
)

from redops.core.exceptions import RedOpsError, ModuleError
from redops.main import __version__
from redops.analysis.comparison import ScanComparator
from redops.web.store import ScanStore


# Request/Response models
class ScanRequest(BaseModel):
    """Request model for starting a scan."""

    target: str = Field(..., description="Target domain or URL")
    preset: str = Field(
        default="quick", description="Scan preset (quick, recon, full, ai_enhanced)"
    )
    modules: list[str] | None = Field(
        default=None, description="Specific modules to run"
    )


class ScanResponse(BaseModel):
    """Response model for scan operations."""

    scan_id: str
    status: str
    target: str
    preset: str
    started_at: str
    message: str


class ScanStatus(BaseModel):
    """Status of a scan."""

    scan_id: str
    status: str  # pending, running, completed, failed
    target: str
    preset: str
    started_at: str
    completed_at: str | None = None
    progress: int = 0
    current_module: str | None = None
    results_path: str | None = None
    error: str | None = None


class ScanCompareRequest(BaseModel):
    """Request model for scan comparison."""

    baseline_scan_id: str = Field(..., description="Baseline scan ID")
    current_scan_id: str = Field(..., description="Current scan ID")


class FindingTriageUpdate(BaseModel):
    """Request model for updating finding triage status."""

    status: str = Field(
        ..., description="Triage status: open, false_positive, accepted_risk"
    )
    notes: str | None = Field(default=None, description="Triage notes")
    assignee: str | None = Field(default=None, description="Assigned user")


class AIRequest(BaseModel):
    """Request model for AI operations."""

    action: str = Field(
        ..., description="AI action (analyze, explain, suggest, summarize)"
    )
    query: str | None = Field(default=None, description="Query for explain action")
    scan_id: str | None = Field(default=None, description="Scan ID for analysis")
    provider: str | None = Field(default=None, description="AI provider override")
    model: str | None = Field(default=None, description="Model override")
    budget_limit: float | None = Field(
        default=None, ge=0, description="Max estimated USD spend for this call"
    )


class AICostMetrics(BaseModel):
    """Cost metrics for an AI call."""

    calls: int
    input_tokens: int
    output_tokens: int
    estimated_cost_usd: float
    budget_limit_usd: float | None = None
    budget_remaining_usd: float | None = None


class AIResponse(BaseModel):
    """Response model for AI operations."""

    action: str
    result: str
    provider: str
    model: str
    cost: AICostMetrics | None = None


class HealthResponse(BaseModel):
    """Health check response."""

    status: str
    version: str
    timestamp: str
    auth_enabled: bool = False


class LoginRequest(BaseModel):
    """Request model for login."""

    username: str = Field(..., description="Username")
    password: str = Field(..., description="Password")


class LoginResponse(BaseModel):
    """Response model for login."""

    success: bool
    message: str
    username: str | None = None


class AuthStatusResponse(BaseModel):
    """Response model for auth status check."""

    authenticated: bool
    username: str | None = None
    auth_method: str | None = None
    auth_enabled: bool


# Scan storage backend (memory or Redis) — singleton per process
_scan_store = ScanStore.get_instance()


class _ScanDictProxy:
    """Backward-compatible proxy for `_scans` dict access."""

    def __getitem__(self, key: str) -> ScanStatus:
        val = _scan_store.get_scan(key)
        if val is None:
            raise KeyError(key)
        return val

    def __setitem__(self, key: str, value: ScanStatus) -> None:
        _scan_store.set_scan(key, value)

    def __contains__(self, key: str) -> bool:
        return _scan_store.get_scan(key) is not None

    def __delitem__(self, key: str) -> None:
        # No-op: store has no delete API; clear() resets everything
        pass

    def get(self, key: str, default: Any = None) -> Any:
        val = _scan_store.get_scan(key)
        return val if val is not None else default

    def values(self):
        return _scan_store.list_scans()

    def clear(self) -> None:
        _scan_store.clear()


class _ResultsDictProxy:
    """Backward-compatible proxy for `_scan_results` dict access."""

    def __getitem__(self, key: str) -> dict:
        val = _scan_store.get_results(key)
        if val is None:
            raise KeyError(key)
        return val

    def __setitem__(self, key: str, value: dict) -> None:
        _scan_store.set_results(key, value)

    def __contains__(self, key: str) -> bool:
        return _scan_store.get_results(key) is not None

    def __delitem__(self, key: str) -> None:
        pass

    def get(self, key: str, default: Any = None) -> Any:
        val = _scan_store.get_results(key)
        return val if val is not None else default

    def clear(self) -> None:
        _scan_store.clear()


class _TriageDictProxy:
    """Backward-compatible proxy for `_finding_triage` dict access."""

    def __getitem__(self, key: str) -> dict:
        val = _scan_store.get_triage(key)
        if val is None:
            raise KeyError(key)
        return val

    def __setitem__(self, key: str, value: dict) -> None:
        _scan_store.set_triage(key, value)

    def __contains__(self, key: str) -> bool:
        return _scan_store.get_triage(key) is not None

    def __delitem__(self, key: str) -> None:
        pass

    def get(self, key: str, default: Any = None) -> Any:
        val = _scan_store.get_triage(key)
        return val if val is not None else default

    def clear(self) -> None:
        _scan_store.clear()


class _BaselinesDictProxy:
    """Backward-compatible proxy for `_baselines` dict access."""

    def __getitem__(self, key: str) -> str:
        val = _scan_store.get_baseline(key)
        if val is None:
            raise KeyError(key)
        return val

    def __setitem__(self, key: str, value: str) -> None:
        _scan_store.set_baseline(key, value)

    def __contains__(self, key: str) -> bool:
        return _scan_store.get_baseline(key) is not None

    def __delitem__(self, key: str) -> None:
        pass

    def get(self, key: str, default: Any = None) -> Any:
        val = _scan_store.get_baseline(key)
        return val if val is not None else default

    def clear(self) -> None:
        _scan_store.clear()


class _AICostTrackerProxy:
    """Backward-compatible proxy for `_ai_cost_tracker` dict access."""

    def __getitem__(self, key: str) -> Any:
        return _scan_store.get_ai_costs()[key]

    def __setitem__(self, key: str, value: Any) -> None:
        costs = {key: value}
        _scan_store.increment_ai_costs(costs)

    def clear(self) -> None:
        _scan_store.clear()


# Backward-compatible module-level proxies (tests import these directly)
_scans = _ScanDictProxy()
_scan_results = _ResultsDictProxy()
_finding_triage = _TriageDictProxy()
_baselines = _BaselinesDictProxy()
_ai_cost_tracker = _AICostTrackerProxy()


def create_app(auth_config: AuthConfig | None = None) -> FastAPI:
    """Create and configure the FastAPI application."""
    app = FastAPI(
        title="RedOPS API",
        description="REST API for RedOPS security assessment framework",
        version=__version__,
        docs_url="/api/docs",
        redoc_url="/api/redoc",
    )

    # Initialize auth manager
    if auth_config:
        set_auth_manager(AuthManager(auth_config))

    # CORS middleware
    cors_origins = os.environ.get("REDOPS_CORS_ORIGINS", "http://localhost:8000").split(
        ","
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # CSRF protection: require X-Requested-With header on state-changing requests
    # using session cookies. Cross-origin requests cannot set custom headers
    # without a CORS preflight, preventing CSRF attacks.
    @app.middleware("http")
    async def csrf_protection(request: Request, call_next):
        if request.method in ("POST", "PUT", "DELETE", "PATCH"):
            has_session_cookie = "redops_session" in request.cookies
            has_csrf_header = request.headers.get("X-Requested-With") == "RedOPS"
            has_api_key = "x-api-key" in request.headers
            # Only enforce for session-based auth (not API key auth or login)
            if has_session_cookie and not has_csrf_header and not has_api_key:
                if not request.url.path.endswith("/login"):
                    from fastapi.responses import JSONResponse

                    return JSONResponse(
                        status_code=403,
                        content={
                            "error": "CSRF validation failed. Include X-Requested-With: RedOPS header."
                        },
                    )
        return await call_next(request)

    # Health check (public)
    @app.get("/api/health", response_model=HealthResponse, tags=["System"])
    async def health_check():
        """Check API health status."""
        auth_manager = get_auth_manager()
        return HealthResponse(
            status="healthy",
            version=__version__,
            timestamp=datetime.now(timezone.utc).isoformat() + "Z",
            auth_enabled=auth_manager.config.enabled,
        )

    # Authentication endpoints
    @app.get("/api/auth/status", response_model=AuthStatusResponse, tags=["Auth"])
    async def auth_status(user: AuthenticatedUser | None = Depends(optional_auth)):
        """Check current authentication status."""
        auth_manager = get_auth_manager()
        if user and user.auth_method != "none":
            return AuthStatusResponse(
                authenticated=True,
                username=user.username,
                auth_method=user.auth_method,
                auth_enabled=auth_manager.config.enabled,
            )
        return AuthStatusResponse(
            authenticated=False,
            auth_enabled=auth_manager.config.enabled,
        )

    @app.post("/api/auth/login", response_model=LoginResponse, tags=["Auth"])
    async def login(request: LoginRequest, response: Response):
        """Login with username and password."""
        auth_manager = get_auth_manager()

        if not auth_manager.config.enabled:
            return LoginResponse(
                success=True,
                message="Authentication not enabled",
                username="anonymous",
            )

        if auth_manager.verify_basic_auth(request.username, request.password):
            # Create session and set cookie
            token = auth_manager.create_session(request.username)
            is_https = os.environ.get("REDOPS_HTTPS", "false").lower() == "true"
            response.set_cookie(
                key="redops_session",
                value=token,
                httponly=True,
                secure=is_https,
                samesite="lax",
                max_age=auth_manager.config.session_expiry_hours * 3600,
            )
            return LoginResponse(
                success=True,
                message="Login successful",
                username=request.username,
            )

        raise HTTPException(status_code=401, detail="Invalid credentials")

    @app.post("/api/auth/logout", response_model=LoginResponse, tags=["Auth"])
    async def logout(request: Request, response: Response):
        """Logout and invalidate session."""
        auth_manager = get_auth_manager()

        token = request.cookies.get("redops_session")
        if token:
            auth_manager.logout(token)

        response.delete_cookie(key="redops_session")

        return LoginResponse(
            success=True,
            message="Logged out successfully",
        )

    @app.post("/api/auth/generate-api-key", tags=["Auth"])
    async def generate_new_api_key(user: AuthenticatedUser = Depends(require_auth)):
        """Generate a new API key (requires admin auth)."""
        if user.auth_method == "none":
            raise HTTPException(
                status_code=403,
                detail="Authentication must be enabled to generate API keys",
            )
        return {"api_key": generate_api_key()}

    # Scan endpoints (protected)
    @app.post("/api/scans", response_model=ScanResponse, tags=["Scans"])
    async def start_scan(
        request: ScanRequest,
        background_tasks: BackgroundTasks,
        user: AuthenticatedUser = Depends(require_auth),
    ):
        """Start a new security scan."""
        import uuid

        scan_id = str(uuid.uuid4())[:8]
        now = datetime.now(timezone.utc).isoformat() + "Z"

        # Create scan status
        status = ScanStatus(
            scan_id=scan_id,
            status="pending",
            target=request.target,
            preset=request.preset,
            started_at=now,
            progress=0,
        )
        _scan_store.set_scan(scan_id, status)

        # Run scan in background
        background_tasks.add_task(run_scan_task, scan_id, request)

        return ScanResponse(
            scan_id=scan_id,
            status="pending",
            target=request.target,
            preset=request.preset,
            started_at=now,
            message=f"Scan started with preset '{request.preset}'",
        )

    @app.get("/api/scans", response_model=list[ScanStatus], tags=["Scans"])
    async def list_scans(
        status: str | None = Query(None, description="Filter by status"),
        search: str | None = Query(None, description="Search target or scan ID"),
        sort: str = Query("started_at_desc", description="Sort field and direction"),
        limit: int = Query(20, ge=1, le=100, description="Max results"),
        user: AuthenticatedUser = Depends(require_auth),
    ):
        """List all scans with optional filtering, search, and sorting."""
        scans = _scan_store.list_scans()
        if status:
            scans = [s for s in scans if s.status == status]
        if search:
            q = search.lower()
            scans = [s for s in scans if q in s.target.lower() or q in s.scan_id.lower()]
        # Sorting
        reverse = sort.endswith("_desc")
        sort_key = sort.removesuffix("_desc").removesuffix("_asc") if "_" in sort else sort
        if sort_key == "target":
            scans = sorted(scans, key=lambda s: s.target.lower(), reverse=reverse)
        elif sort_key == "status":
            scans = sorted(scans, key=lambda s: s.status, reverse=reverse)
        elif sort_key == "progress":
            scans = sorted(scans, key=lambda s: s.progress, reverse=reverse)
        else:
            scans = sorted(scans, key=lambda s: s.started_at or "", reverse=reverse)
        return scans[:limit]

    @app.get("/api/scans/{scan_id}", response_model=ScanStatus, tags=["Scans"])
    async def get_scan(scan_id: str, user: AuthenticatedUser = Depends(require_auth)):
        """Get scan status by ID."""
        scan = _scan_store.get_scan(scan_id)
        if scan is None:
            raise HTTPException(status_code=404, detail="Scan not found")
        return scan

    def _merge_triage_into_findings(scan_id: str, data: Any) -> Any:
        """Recursively merge triage state into finding dicts within results."""
        if isinstance(data, list):
            return [_merge_triage_into_findings(scan_id, item) for item in data]
        if isinstance(data, dict):
            merged = {k: _merge_triage_into_findings(scan_id, v) for k, v in data.items()}
            if "severity" in merged:
                fid = merged.get("id", "") or merged.get("title", "") or ""
                triage = _scan_store.get_triage(f"{scan_id}:{fid}")
                if triage:
                    merged["triage"] = triage
            return merged
        return data

    def _collect_findings(data: Any, findings: list[dict] | None = None) -> list[dict]:
        """Recursively collect all dicts that look like findings (have severity)."""
        if findings is None:
            findings = []
        if isinstance(data, list):
            for item in data:
                _collect_findings(item, findings)
        elif isinstance(data, dict):
            if "severity" in data:
                findings.append(data)
            for v in data.values():
                _collect_findings(v, findings)
        return findings

    @app.get("/api/scans/{scan_id}/results", tags=["Scans"])
    async def get_scan_results(
        scan_id: str, user: AuthenticatedUser = Depends(require_auth)
    ):
        """Get scan results."""
        scan = _scan_store.get_scan(scan_id)
        if scan is None:
            raise HTTPException(status_code=404, detail="Scan not found")
        if scan.status != "completed":
            raise HTTPException(status_code=400, detail="Scan not completed")
        raw = _scan_store.get_results(scan_id)
        if raw is None:
            raise HTTPException(status_code=404, detail="Results not available")
        merged = _merge_triage_into_findings(scan_id, raw)
        # Normalize findings into an array for dashboard charts / UI
        if isinstance(merged, dict) and "findings" not in merged:
            merged = {**merged, "findings": _collect_findings(merged)}
        # Attach delta info if a baseline exists for this target
        target = scan.target
        baseline_scan_id = _scan_store.get_baseline(target)
        if baseline_scan_id and baseline_scan_id != scan_id:
            baseline_data = _scan_store.get_results(baseline_scan_id)
            if baseline_data is not None:
                baseline_findings = []
                current_findings = []
                for key, value in baseline_data.items():
                    if isinstance(value, dict) and (key.startswith("finding_") or "severity" in value):
                        baseline_findings.append(value)
                for key, value in raw.items():
                    if isinstance(value, dict) and (key.startswith("finding_") or "severity" in value):
                        current_findings.append(value)
                comparator = ScanComparator()
                delta = comparator.compare(
                    {"scan_id": baseline_scan_id, "findings": baseline_findings},
                    {"scan_id": scan_id, "findings": current_findings},
                )
                merged["_delta"] = {
                    "has_baseline": True,
                    "baseline_scan_id": baseline_scan_id,
                    **delta.to_dict(include_findings=True),
                }
        return merged

    @app.post("/api/scans/compare", tags=["Scans"])
    async def compare_scans(
        request: ScanCompareRequest, user: AuthenticatedUser = Depends(require_auth)
    ):
        """Compare two scans to identify changes."""
        baseline_data = _scan_store.get_results(request.baseline_scan_id)
        if baseline_data is None:
            raise HTTPException(status_code=404, detail="Baseline scan results not found")
        current_data = _scan_store.get_results(request.current_scan_id)
        if current_data is None:
            raise HTTPException(status_code=404, detail="Current scan results not found")

        # Build findings lists from ctx.data format (keys like finding_xxx)
        baseline_findings = []
        current_findings = []
        for key, value in baseline_data.items():
            if isinstance(value, dict) and (key.startswith("finding_") or "severity" in value):
                baseline_findings.append(value)
        for key, value in current_data.items():
            if isinstance(value, dict) and (key.startswith("finding_") or "severity" in value):
                current_findings.append(value)

        comparator = ScanComparator()
        result = comparator.compare(
            {"scan_id": request.baseline_scan_id, "findings": baseline_findings},
            {"scan_id": request.current_scan_id, "findings": current_findings},
        )
        return result.to_dict(include_findings=True)

    @app.post("/api/scans/{scan_id}/findings/{finding_id}/triage", tags=["Scans"])
    async def update_finding_triage(
        scan_id: str,
        finding_id: str,
        request: FindingTriageUpdate,
        user: AuthenticatedUser = Depends(require_auth),
    ):
        """Update triage status for a finding."""
        if _scan_store.get_scan(scan_id) is None:
            raise HTTPException(status_code=404, detail="Scan not found")
        valid_statuses = {"open", "false_positive", "accepted_risk"}
        if request.status not in valid_statuses:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid status. Must be one of: {', '.join(valid_statuses)}",
            )
        key = f"{scan_id}:{finding_id}"
        triage = {
            "status": request.status,
            "notes": request.notes or "",
            "assignee": request.assignee or "",
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "updated_by": user.username,
        }
        _scan_store.set_triage(key, triage)
        return {"success": True, "triage": triage}

    _MITRE_TACTICS_ORDER = [
        "Reconnaissance", "Resource Development", "Initial Access", "Execution",
        "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
        "Discovery", "Lateral Movement", "Collection", "Command and Control",
        "Exfiltration", "Impact",
    ]

    @app.get("/api/scans/{scan_id}/mitre", tags=["Scans"])
    async def get_scan_mitre(
        scan_id: str, user: AuthenticatedUser = Depends(require_auth)
    ):
        """Get MITRE ATT&CK coverage for a scan."""
        scan = _scan_store.get_scan(scan_id)
        if scan is None:
            raise HTTPException(status_code=404, detail="Scan not found")
        data = _scan_store.get_results(scan_id) or {}
        mitre_mapping = data.get("mitre_mapping", {}) if isinstance(data, dict) else {}
        mitre_techniques = set(data.get("mitre_techniques_used", [])) if isinstance(data, dict) else set()

        matrix = {}
        for technique_id, technique_info in mitre_mapping.items():
            if isinstance(technique_info, dict):
                tactic = technique_info.get("tactic", "Unknown")
                name = technique_info.get("name", technique_id)
            else:
                tactic = "Unknown"
                name = technique_id
            matrix.setdefault(tactic, []).append({"id": technique_id, "name": name})
        if not matrix and mitre_techniques:
            matrix["Identified Techniques"] = [{"id": t, "name": t} for t in sorted(mitre_techniques)]

        total_techniques = sum(len(v) for v in matrix.values())
        tactics_covered = len([t for t in matrix if matrix.get(t)])
        return {
            "matrix": matrix,
            "tactics_order": _MITRE_TACTICS_ORDER,
            "total_techniques": total_techniques,
            "tactics_covered": tactics_covered,
        }

    @app.get("/api/scans/{scan_id}/navigator-layer", tags=["Scans"])
    async def get_scan_navigator_layer(
        scan_id: str, user: AuthenticatedUser = Depends(require_auth)
    ):
        """Export MITRE ATT&CK Navigator layer JSON for a scan."""
        scan = _scan_store.get_scan(scan_id)
        if scan is None:
            raise HTTPException(status_code=404, detail="Scan not found")
        data = _scan_store.get_results(scan_id)
        if data is None:
            raise HTTPException(status_code=404, detail="Results not available")
        techniques = set(data.get("mitre_techniques_used", [])) if isinstance(data, dict) else set()
        if not techniques and isinstance(data, dict):
            for key, value in data.items():
                if isinstance(value, dict) and "mitre_techniques" in value:
                    techniques.update(value.get("mitre_techniques", []))
        from redops.modules.simulation.mitre_mapping import generate_navigator_layer

        layer = generate_navigator_layer(
            techniques,
            name=f"RedOPS Scan {scan_id}",
            description=f"ATT&CK coverage for target: {scan.target}",
        )
        return Response(
            content=__import__("json").dumps(layer, indent=2),
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="navigator-layer-{scan_id}.json"'},
        )

    @app.get("/api/scans/{scan_id}/attack-graph", tags=["Scans"])
    async def get_scan_attack_graph(
        scan_id: str, user: AuthenticatedUser = Depends(require_auth)
    ):
        """Return attack graph data for a scan in Cytoscape.js format."""
        scan = _scan_store.get_scan(scan_id)
        if scan is None:
            raise HTTPException(status_code=404, detail="Scan not found")
        data = _scan_store.get_results(scan_id)
        if data is None:
            raise HTTPException(status_code=404, detail="Results not available")
        if not isinstance(data, dict):
            raise HTTPException(status_code=404, detail="No graph data available")

        # Extract attack paths and chains from scan results
        attack_paths = data.get("attack_paths", [])
        attack_chains = data.get("attack_chains_raw", [])
        summary = data.get("attack_path_summary", {})

        # Build Cytoscape.js elements
        elements = []
        seen_nodes = set()

        for chain in attack_chains:
            path = chain.get("path", [])
            for i, node_id in enumerate(path):
                if node_id not in seen_nodes:
                    seen_nodes.add(node_id)
                    elements.append(
                        {
                            "data": {
                                "id": node_id,
                                "label": node_id,
                                "type": "entry" if i == 0 else ("target" if i == len(path) - 1 else "intermediate"),
                            },
                            "group": "nodes",
                        }
                    )
                if i < len(path) - 1:
                    elements.append(
                        {
                            "data": {
                                "id": f"{node_id}->{path[i + 1]}",
                                "source": node_id,
                                "target": path[i + 1],
                                "type": "attack-step",
                            },
                            "group": "edges",
                        }
                    )

        return {
            "elements": elements,
            "summary": summary,
            "attack_paths": attack_paths,
        }

    @app.post("/api/scans/{scan_id}/baseline", tags=["Scans"])
    async def set_scan_baseline(
        scan_id: str, user: AuthenticatedUser = Depends(require_auth)
    ):
        """Set a scan as the baseline for its target."""
        scan = _scan_store.get_scan(scan_id)
        if scan is None:
            raise HTTPException(status_code=404, detail="Scan not found")
        if scan.status != "completed":
            raise HTTPException(status_code=400, detail="Scan not completed")
        _scan_store.set_baseline(scan.target, scan_id)
        return {
            "success": True,
            "scan_id": scan_id,
            "target": scan.target,
            "message": f"Baseline set for {scan.target}",
        }

    @app.get("/api/scans/{scan_id}/delta", tags=["Scans"])
    async def get_scan_delta(
        scan_id: str, user: AuthenticatedUser = Depends(require_auth)
    ):
        """Get delta between this scan and the baseline for its target."""
        scan = _scan_store.get_scan(scan_id)
        if scan is None:
            raise HTTPException(status_code=404, detail="Scan not found")
        baseline_scan_id = _scan_store.get_baseline(scan.target)
        if not baseline_scan_id:
            return {"has_baseline": False, "message": "No baseline set for this target"}
        baseline_data = _scan_store.get_results(baseline_scan_id)
        if baseline_data is None:
            raise HTTPException(status_code=404, detail="Baseline scan results not found")
        current_data = _scan_store.get_results(scan_id)
        if current_data is None:
            raise HTTPException(status_code=404, detail="Current scan results not found")

        baseline_findings = []
        current_findings = []
        for key, value in baseline_data.items():
            if isinstance(value, dict) and (key.startswith("finding_") or "severity" in value):
                baseline_findings.append(value)
        for key, value in current_data.items():
            if isinstance(value, dict) and (key.startswith("finding_") or "severity" in value):
                current_findings.append(value)

        comparator = ScanComparator()
        result = comparator.compare(
            {"scan_id": baseline_scan_id, "findings": baseline_findings},
            {"scan_id": scan_id, "findings": current_findings},
        )
        return {
            "has_baseline": True,
            "baseline_scan_id": baseline_scan_id,
            "current_scan_id": scan_id,
            "delta": result.to_dict(include_findings=True),
        }

    # AI endpoints (protected)
    @app.post("/api/ai", response_model=AIResponse, tags=["AI"])
    async def ai_action(
        request: AIRequest, user: AuthenticatedUser = Depends(require_auth)
    ):
        """Perform AI-assisted analysis."""
        try:
            from redops.modules.ai_assistant import AIAssistant

            assistant = AIAssistant(
                provider=request.provider,
                model=request.model,
                budget_limit=request.budget_limit,
            )

            if request.action == "explain":
                if not request.query:
                    raise HTTPException(
                        status_code=400, detail="Query required for explain action"
                    )
                result = assistant.explain(request.query)
            elif request.action == "analyze":
                if not request.scan_id:
                    raise HTTPException(
                        status_code=400, detail="scan_id required for analyze action"
                    )
                results = _scan_store.get_results(request.scan_id)
                if results is None:
                    raise HTTPException(
                        status_code=404, detail="Scan results not found"
                    )
                result = assistant.analyze_findings(results)
            elif request.action == "suggest":
                if not request.scan_id:
                    raise HTTPException(
                        status_code=400, detail="scan_id required for suggest action"
                    )
                results = _scan_store.get_results(request.scan_id)
                if results is None:
                    raise HTTPException(
                        status_code=404, detail="Scan results not found"
                    )
                result = assistant.suggest_remediations(results)
            elif request.action == "summarize":
                if not request.scan_id:
                    raise HTTPException(
                        status_code=400, detail="scan_id required for summarize action"
                    )
                results = _scan_store.get_results(request.scan_id)
                if results is None:
                    raise HTTPException(
                        status_code=404, detail="Scan results not found"
                    )
                result = assistant.summarize(results)
            else:
                raise HTTPException(
                    status_code=400, detail=f"Unknown action: {request.action}"
                )

            # Merge per-call cost into global tracker
            metrics = assistant.get_cost_metrics()
            _scan_store.increment_ai_costs(metrics)

            return AIResponse(
                action=request.action,
                result=result,
                provider=assistant.provider,
                model=assistant.model,
                cost=AICostMetrics(
                    calls=metrics["calls"],
                    input_tokens=metrics["input_tokens"],
                    output_tokens=metrics["output_tokens"],
                    estimated_cost_usd=metrics["estimated_cost_usd"],
                    budget_limit_usd=metrics["budget_limit_usd"],
                    budget_remaining_usd=metrics["budget_remaining_usd"],
                ),
            )

        except ImportError as e:
            raise HTTPException(status_code=503, detail=f"AI not available: {e}")
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
        except RuntimeError as e:
            raise HTTPException(status_code=429, detail=str(e))
        except HTTPException:
            raise
        except (ConnectionError, TimeoutError, OSError, TypeError) as e:
            raise HTTPException(status_code=503, detail=f"AI service error: {e}")

    # Settings endpoints
    @app.get("/api/settings/providers", tags=["Settings"])
    async def list_providers():
        """List available AI providers."""
        from redops.cli.settings import AI_PROVIDERS

        return {
            "providers": [
                {
                    "id": pid,
                    "name": info["name"],
                    "models": info["models"],
                    "default_model": info["default_model"],
                }
                for pid, info in AI_PROVIDERS.items()
            ]
        }

    @app.get("/api/settings/presets", tags=["Settings"])
    async def list_presets():
        """List available scan presets."""
        return {
            "presets": [
                {
                    "id": "quick",
                    "name": "Quick Scan",
                    "description": "Fast reconnaissance with basic modules",
                },
                {
                    "id": "recon",
                    "name": "Full Reconnaissance",
                    "description": "Comprehensive reconnaissance without AI",
                },
                {
                    "id": "full",
                    "name": "Full Assessment",
                    "description": "Complete security assessment",
                },
                {
                    "id": "ai_enhanced",
                    "name": "AI-Enhanced",
                    "description": "Full assessment with AI analysis",
                },
            ]
        }

    @app.get("/api/settings/ai-cost", tags=["Settings"])
    async def get_ai_cost_metrics(user: AuthenticatedUser = Depends(require_auth)):
        """Return global AI cost metrics."""
        costs = _scan_store.get_ai_costs()
        return {
            "calls": costs["calls"],
            "input_tokens": costs["input_tokens"],
            "output_tokens": costs["output_tokens"],
            "estimated_cost_usd": round(costs["estimated_cost_usd"], 6),
        }

    # Dashboard HTML
    @app.get("/", response_class=HTMLResponse, tags=["Dashboard"])
    async def dashboard():
        """Serve the web dashboard."""
        return get_dashboard_html()

    # WebSocket endpoint
    @app.websocket("/ws")
    async def websocket_endpoint(websocket: WebSocket):
        """
        WebSocket endpoint for real-time updates.

        Clients receive events:
        - scan_started: When a new scan begins
        - scan_progress: Periodic progress updates
        - scan_module_start/end: Module lifecycle events
        - scan_completed: When scan finishes successfully
        - scan_failed: When scan fails

        Clients can send:
        - {"action": "subscribe", "scan_id": "xxx"}: Subscribe to specific scan
        - {"action": "unsubscribe", "scan_id": "xxx"}: Unsubscribe from scan
        """
        # Authenticate WebSocket connection
        auth_manager = get_auth_manager()
        if auth_manager.config.enabled:
            session_token = websocket.cookies.get("redops_session")
            if not session_token or not auth_manager.validate_session(session_token):
                await websocket.close(code=4001, reason="Authentication required")
                return
        await ws_manager.connect(websocket)
        try:
            while True:
                data = await websocket.receive_text()
                try:
                    import json

                    message = json.loads(data)
                    action = message.get("action")

                    if action == "subscribe" and "scan_id" in message:
                        ws_manager.subscribe_to_scan(websocket, message["scan_id"])
                    elif action == "unsubscribe" and "scan_id" in message:
                        ws_manager.unsubscribe_from_scan(websocket, message["scan_id"])

                except (json.JSONDecodeError, KeyError):
                    pass  # Ignore invalid messages

        except WebSocketDisconnect:
            ws_manager.disconnect(websocket)

    # WebSocket stats endpoint
    @app.get("/api/ws/stats", tags=["WebSocket"])
    async def websocket_stats():
        """Get WebSocket connection statistics."""
        return ws_manager.get_stats()

    return app


async def run_scan_task(scan_id: str, request: ScanRequest):
    """Background task to run a scan."""
    import asyncio

    try:
        scan = _scan_store.get_scan(scan_id)
        if scan is None:
            return
        scan.status = "running"
        scan.progress = 0
        _scan_store.set_scan(scan_id, scan)

        # Emit scan started event
        await emit_scan_started(scan_id, request.target, request.preset)

        # Simulate scan progress (replace with actual scan in production)
        from redops.core.context import Context
        from redops.modules import recon

        ctx = Context(target=request.target)

        modules = [
            ("profile_domain", recon.profile_domain),
            ("fingerprint", recon.fingerprint),
        ]

        for i, (name, module_fn) in enumerate(modules):
            scan.current_module = name
            progress = int((i / len(modules)) * 100)
            scan.progress = progress
            _scan_store.set_scan(scan_id, scan)

            # Emit progress and module start
            await emit_scan_progress(scan_id, progress, name)
            await emit_module_start(scan_id, name)

            success = True
            try:
                ctx = module_fn(ctx)
            except (RedOpsError, RuntimeError, ImportError, TypeError, ValueError) as e:
                ctx.log(f"Module {name} failed: {e}", level="ERROR")
                success = False

            # Emit module end
            await emit_module_end(scan_id, name, success)

            await asyncio.sleep(0.5)  # Yield to event loop

        # Store results
        _scan_store.set_results(scan_id, ctx.data)
        scan.status = "completed"
        scan.progress = 100
        scan.completed_at = datetime.now(timezone.utc).isoformat() + "Z"
        scan.current_module = None
        _scan_store.set_scan(scan_id, scan)

        # Emit completion
        await emit_scan_completed(scan_id, len(ctx.data))

    except Exception as e:  # Worker safety net — prevents unhandled exceptions from killing the background task
        scan = _scan_store.get_scan(scan_id)
        if scan is not None:
            scan.status = "failed"
            scan.error = str(e)
            _scan_store.set_scan(scan_id, scan)
        await emit_scan_failed(scan_id, str(e))


def get_dashboard_html() -> str:
    """Generate the dashboard HTML."""
    return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>RedOPS Dashboard</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://unpkg.com/alpinejs@3.x.x/dist/cdn.min.js" defer></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
</head>
<body class="bg-gray-900 text-gray-100 min-h-screen">
    <a href="#main-content" class="sr-only focus:not-sr-only focus:absolute focus:top-4 focus:left-4 focus:z-50 focus:bg-gray-800 focus:text-white focus:px-4 focus:py-2 focus:rounded">Skip to main content</a>
    <div x-data="dashboard()" x-init="init()" id="main-content" tabindex="-1">
        <!-- Live region for screen reader announcements -->
        <div aria-live="assertive" aria-atomic="true" class="sr-only" x-text="srAnnouncement"></div>

        <!-- Header -->
        <header class="bg-gray-800 border-b border-gray-700 px-6 py-4" role="banner">
            <div class="flex items-center justify-between">
                <div class="flex items-center space-x-3">
                    <span class="text-2xl" aria-hidden="true">🔴</span>
                    <h1 class="text-xl font-bold text-red-500">RedOPS</h1>
                    <span class="text-gray-500 text-sm" x-text="'v' + version" aria-label="Version"></span>
                </div>
                <div class="flex items-center space-x-4">
                    <span class="text-sm" :class="wsStatus === 'Connected' ? 'text-green-400' : 'text-yellow-400'" x-text="'WS: ' + wsStatus" aria-live="polite" aria-label="WebSocket status"></span>
                    <span class="text-sm text-gray-400" x-text="health" aria-label="API health"></span>
                    <!-- Auth status -->
                    <template x-if="authEnabled && authenticated">
                        <div class="flex items-center space-x-2">
                            <span class="text-sm text-green-400" x-text="'User: ' + username"></span>
                            <button @click="logout()" class="text-xs text-gray-400 hover:text-gray-200 px-3 h-11 border border-gray-600 rounded inline-flex items-center focus:outline-none focus:ring-2 focus:ring-red-500 focus:ring-offset-2 focus:ring-offset-gray-800">Logout</button>
                        </div>
                    </template>
                </div>
            </div>
        </header>

        <!-- Login Modal -->
        <template x-if="authEnabled && !authenticated && showLogin">
            <div class="fixed inset-0 bg-black/50 flex items-center justify-center z-50" role="dialog" aria-modal="true" aria-label="Login dialog"
                x-trap.noscroll.inert="showLogin" @keydown.escape.window="showLogin = false">
                <div class="bg-gray-800 rounded-lg p-6 sm:p-8 w-full max-w-sm shadow-xl" role="document">
                    <h2 class="text-xl font-bold mb-6 text-center" id="login-title">Login to RedOPS</h2>
                    <form @submit.prevent="login()" aria-labelledby="login-title">
                        <div class="mb-4">
                            <label for="login-username" class="block text-sm text-gray-400 mb-2">Username</label>
                            <input id="login-username" type="text" x-model="loginForm.username" required
                                class="w-full bg-gray-700 border border-gray-600 rounded px-4 py-2 focus:outline-none focus:ring-2 focus:ring-red-500 focus:border-red-500 h-11">
                        </div>
                        <div class="mb-6">
                            <label for="login-password" class="block text-sm text-gray-400 mb-2">Password</label>
                            <input id="login-password" type="password" x-model="loginForm.password" required
                                class="w-full bg-gray-700 border border-gray-600 rounded px-4 py-2 focus:outline-none focus:ring-2 focus:ring-red-500 focus:border-red-500 h-11">
                        </div>
                        <p x-show="loginError" class="text-red-400 text-sm mb-4" x-text="loginError" role="alert" aria-live="assertive"></p>
                        <button type="submit" :disabled="loggingIn"
                            class="w-full bg-red-600 hover:bg-red-700 disabled:bg-gray-600 py-2 rounded font-medium transition h-11 focus:outline-none focus:ring-2 focus:ring-red-500 focus:ring-offset-2 focus:ring-offset-gray-800">
                            <span x-show="!loggingIn">Login</span>
                            <span x-show="loggingIn">Logging in...</span>
                        </button>
                    </form>
                </div>
            </div>
        </template>

        <div class="container mx-auto px-4 sm:px-6 py-8">
            <!-- New Scan Form -->
            <div class="bg-gray-800 rounded-lg p-6 mb-8" role="region" aria-label="New scan">
                <h2 class="text-lg font-semibold mb-4" id="new-scan-title">New Scan</h2>
                <form @submit.prevent="startScan()" class="flex flex-wrap gap-4" aria-labelledby="new-scan-title">
                    <label for="scan-target" class="sr-only">Target</label>
                    <input id="scan-target" type="text" x-model="newScan.target" placeholder="Target (e.g., example.com)"
                        class="w-full sm:flex-1 sm:min-w-0 min-w-0 bg-gray-700 border border-gray-600 rounded px-4 py-2 focus:outline-none focus:ring-2 focus:ring-red-500 focus:border-red-500 h-11">
                    <label for="scan-preset" class="sr-only">Preset</label>
                    <select id="scan-preset" x-model="newScan.preset" class="w-full sm:w-auto bg-gray-700 border border-gray-600 rounded px-4 py-2 h-11 focus:outline-none focus:ring-2 focus:ring-red-500 focus:border-red-500">
                        <template x-for="preset in presets" :key="preset.id">
                            <option :value="preset.id" x-text="preset.name"></option>
                        </template>
                    </select>
                    <button type="submit" :disabled="!newScan.target || scanning"
                        class="bg-red-600 hover:bg-red-700 disabled:bg-gray-600 px-6 py-2 rounded font-medium transition h-11 w-full sm:w-auto focus:outline-none focus:ring-2 focus:ring-red-500 focus:ring-offset-2 focus:ring-offset-gray-800"
                        aria-label="Start scan">
                        <span x-show="!scanning">Start Scan</span>
                        <span x-show="scanning">Starting...</span>
                    </button>
                </form>
            </div>

            <!-- Scans List -->
            <div class="bg-gray-800 rounded-lg p-6 mb-8" role="region" aria-label="Recent scans">
                <div class="flex items-center justify-between mb-4">
                    <h2 class="text-lg font-semibold" id="scans-title">Recent Scans</h2>
                    <div class="flex items-center gap-2">
                        <button x-show="selectedForCompare.length === 2" @click="compareSelectedScans()"
                            :disabled="comparing"
                            class="bg-red-600 hover:bg-red-700 disabled:bg-gray-600 px-4 py-2 rounded text-sm font-medium transition h-11 inline-flex items-center focus:outline-none focus:ring-2 focus:ring-red-500 focus:ring-offset-2 focus:ring-offset-gray-800"
                            aria-label="Compare selected scans">
                            <span x-show="!comparing">Compare Selected</span>
                            <span x-show="comparing">Comparing...</span>
                        </button>
                        <button @click="loadScans()" class="text-sm text-gray-400 hover:text-gray-200 h-11 px-3 inline-flex items-center focus:outline-none focus:ring-2 focus:ring-red-500 rounded"
                            aria-label="Refresh scans list">Refresh</button>
                    </div>
                </div>
                <!-- Filter / Search / Sort controls -->
                <div class="flex flex-wrap gap-3 mb-4">
                    <div class="flex-1 min-w-[12rem]">
                        <label for="scan-search" class="sr-only">Search scans</label>
                        <input id="scan-search" type="text" x-model="scanFilter.search" @input.debounce.300ms="loadScans()"
                            placeholder="Search target or ID..."
                            class="w-full bg-gray-700 border border-gray-600 rounded px-4 py-2 focus:outline-none focus:ring-2 focus:ring-red-500 focus:border-red-500 h-11 text-sm">
                    </div>
                    <div class="w-40">
                        <label for="scan-status-filter" class="sr-only">Filter by status</label>
                        <select id="scan-status-filter" x-model="scanFilter.status" @change="loadScans()"
                            class="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 h-11 text-sm focus:outline-none focus:ring-2 focus:ring-red-500 focus:border-red-500">
                            <option value="">All Statuses</option>
                            <option value="pending">Pending</option>
                            <option value="running">Running</option>
                            <option value="completed">Completed</option>
                            <option value="failed">Failed</option>
                        </select>
                    </div>
                    <div class="w-48">
                        <label for="scan-sort" class="sr-only">Sort by</label>
                        <select id="scan-sort" x-model="scanFilter.sort" @change="loadScans()"
                            class="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 h-11 text-sm focus:outline-none focus:ring-2 focus:ring-red-500 focus:border-red-500">
                            <option value="started_at_desc">Started (newest)</option>
                            <option value="started_at_asc">Started (oldest)</option>
                            <option value="target_asc">Target (A–Z)</option>
                            <option value="target_desc">Target (Z–A)</option>
                            <option value="status_asc">Status (A–Z)</option>
                            <option value="status_desc">Status (Z–A)</option>
                            <option value="progress_desc">Progress (high–low)</option>
                            <option value="progress_asc">Progress (low–high)</option>
                        </select>
                    </div>
                </div>
                <!-- Desktop table -->
                <div class="hidden md:block overflow-x-auto">
                    <table class="w-full" aria-labelledby="scans-title">
                        <thead>
                            <tr class="text-left text-gray-400 text-sm border-b border-gray-700">
                                <th scope="col" class="pb-3"><span class="sr-only">Compare</span></th>
                                <th scope="col" class="pb-3">ID</th>
                                <th scope="col" class="pb-3">Target</th>
                                <th scope="col" class="pb-3">Preset</th>
                                <th scope="col" class="pb-3">Status</th>
                                <th scope="col" class="pb-3">Progress</th>
                                <th scope="col" class="pb-3">Started</th>
                                <th scope="col" class="pb-3">Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            <template x-for="scan in scans" :key="scan.scan_id">
                                <tr class="border-b border-gray-700/50">
                                    <td class="py-3">
                                        <input type="checkbox" :checked="isSelectedForCompare(scan.scan_id)"
                                            @click="toggleCompareSelection(scan.scan_id)"
                                            :aria-label="'Select scan ' + scan.scan_id + ' for comparison'"
                                            class="h-4 w-4 rounded border-gray-600 bg-gray-700 text-red-600 focus:ring-red-500">
                                    </td>
                                    <td class="py-3 font-mono text-sm" x-text="scan.scan_id"></td>
                                    <td class="py-3" x-text="scan.target"></td>
                                    <td class="py-3 capitalize" x-text="scan.preset"></td>
                                    <td class="py-3">
                                        <span :class="statusClass(scan.status)" class="px-2 py-1 rounded text-xs font-medium"
                                            x-text="scan.status"></span>
                                    </td>
                                    <td class="py-3">
                                        <div class="w-24 bg-gray-700 rounded-full h-2 mb-1">
                                            <div class="bg-red-500 h-2 rounded-full transition-all" :style="'width: ' + scan.progress + '%'"></div>
                                        </div>
                                        <div x-show="scan.status === 'running' && scan.current_module"
                                            class="text-[10px] text-gray-400 truncate w-24"
                                            x-text="scan.current_module"></div>
                                    </td>
                                    <td class="py-3 text-sm text-gray-400" x-text="formatDate(scan.started_at)"></td>
                                    <td class="py-3">
                                        <div class="flex items-center gap-1">
                                            <button x-show="scan.status === 'completed'" @click="viewResults(scan.scan_id)"
                                                class="text-red-400 hover:text-red-300 text-sm h-11 px-3 inline-flex items-center justify-center focus:outline-none focus:ring-2 focus:ring-red-500 rounded"
                                                :aria-label="'View results for scan ' + scan.scan_id">View</button>
                                            <button x-show="scan.status === 'completed'" @click="setBaseline(scan.scan_id)"
                                                class="text-gray-400 hover:text-gray-200 text-sm h-11 px-3 inline-flex items-center justify-center focus:outline-none focus:ring-2 focus:ring-red-500 rounded"
                                                :aria-label="'Set scan ' + scan.scan_id + ' as baseline'">Baseline</button>
                                        </div>
                                    </td>
                                </tr>
                            </template>
                            <tr x-show="scans.length === 0">
                                <td colspan="8" class="py-8 text-center text-gray-500">No scans yet. Start one above.</td>
                            </tr>
                        </tbody>
                    </table>
                </div>
                <!-- Mobile cards -->
                <div class="md:hidden space-y-3">
                    <template x-for="scan in scans" :key="scan.scan_id">
                        <div class="bg-gray-700/50 rounded-lg p-4 space-y-2">
                            <div class="flex items-center justify-between">
                                <span class="font-mono text-sm text-gray-300" x-text="scan.scan_id"></span>
                                <div class="flex items-center gap-2">
                                    <span :class="statusClass(scan.status)" class="px-2 py-1 rounded text-xs font-medium" x-text="scan.status"></span>
                                    <input type="checkbox" :checked="isSelectedForCompare(scan.scan_id)"
                                        @click="toggleCompareSelection(scan.scan_id)"
                                        :aria-label="'Select scan ' + scan.scan_id + ' for comparison'"
                                        class="h-4 w-4 rounded border-gray-600 bg-gray-700 text-red-600 focus:ring-red-500">
                                </div>
                            </div>
                            <div class="text-sm" x-text="scan.target"></div>
                            <div class="flex items-center justify-between text-sm text-gray-400">
                                <span class="capitalize" x-text="scan.preset"></span>
                                <span x-text="formatDate(scan.started_at)"></span>
                            </div>
                            <div class="w-full bg-gray-700 rounded-full h-2">
                                <div class="bg-red-500 h-2 rounded-full transition-all" :style="'width: ' + scan.progress + '%'"></div>
                            </div>
                            <div x-show="scan.status === 'running' && scan.current_module"
                                class="text-[10px] text-gray-400 truncate"
                                x-text="scan.current_module"></div>
                            <div class="flex flex-col sm:flex-row justify-end gap-2">
                                <button x-show="scan.status === 'completed'" @click="viewResults(scan.scan_id)"
                                    class="text-red-400 hover:text-red-300 text-sm h-11 px-3 inline-flex items-center justify-center focus:outline-none focus:ring-2 focus:ring-red-500 rounded"
                                    :aria-label="'View results for scan ' + scan.scan_id">View Results</button>
                                <button x-show="scan.status === 'completed'" @click="setBaseline(scan.scan_id)"
                                    class="text-gray-400 hover:text-gray-200 text-sm h-11 px-3 inline-flex items-center justify-center focus:outline-none focus:ring-2 focus:ring-red-500 rounded"
                                    :aria-label="'Set scan ' + scan.scan_id + ' as baseline'">Set Baseline</button>
                            </div>
                        </div>
                    </template>
                    <div x-show="scans.length === 0" class="py-8 text-center text-gray-500">No scans yet. Start one above.</div>
                </div>
            </div>

            <!-- Comparison Results Panel -->
            <div x-show="showCompare" @keydown.escape.window="closeCompare()" class="bg-gray-800 rounded-lg p-6 mb-8" role="region" aria-label="Scan comparison results" tabindex="0">
                <div class="flex items-center justify-between mb-4">
                    <h2 class="text-lg font-semibold" id="compare-title">Scan Comparison</h2>
                    <button @click="closeCompare()" class="text-gray-400 hover:text-gray-200 focus:outline-none focus:ring-2 focus:ring-red-500 rounded h-11 w-11 inline-flex items-center justify-center" aria-label="Close comparison panel">&times;</button>
                </div>
                <div x-show="comparing" class="py-8 text-center text-gray-500">Comparing scans...</div>
                <div x-show="!comparing && compareResults">
                    <!-- Summary stats -->
                    <div class="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3 mb-6">
                        <div class="bg-gray-700/50 rounded-lg p-3 text-center">
                            <div class="text-2xl font-bold text-green-400" x-text="compareResults.total_new || 0"></div>
                            <div class="text-xs text-gray-400">New</div>
                        </div>
                        <div class="bg-gray-700/50 rounded-lg p-3 text-center">
                            <div class="text-2xl font-bold text-blue-400" x-text="compareResults.total_resolved || 0"></div>
                            <div class="text-xs text-gray-400">Resolved</div>
                        </div>
                        <div class="bg-gray-700/50 rounded-lg p-3 text-center">
                            <div class="text-2xl font-bold text-yellow-400" x-text="compareResults.total_modified || 0"></div>
                            <div class="text-xs text-gray-400">Modified</div>
                        </div>
                        <div class="bg-gray-700/50 rounded-lg p-3 text-center">
                            <div class="text-2xl font-bold text-red-400" x-text="compareResults.total_regression || 0"></div>
                            <div class="text-xs text-gray-400">Regression</div>
                        </div>
                        <div class="bg-gray-700/50 rounded-lg p-3 text-center">
                            <div class="text-2xl font-bold text-gray-300" x-text="compareResults.total_unchanged || 0"></div>
                            <div class="text-xs text-gray-400">Unchanged</div>
                        </div>
                    </div>
                    <!-- New findings -->
                    <div x-show="compareResults.new_findings && compareResults.new_findings.length > 0" class="mb-4">
                        <h3 class="text-sm font-medium text-gray-400 mb-2">New Findings</h3>
                        <div class="space-y-2">
                            <template x-for="diff in compareResults.new_findings" :key="diff.current_finding.id">
                                <div class="bg-gray-700/30 rounded p-3 flex items-center justify-between">
                                    <div>
                                        <div class="font-medium text-sm" x-text="diff.current_finding.title"></div>
                                        <div class="text-xs text-gray-400" x-text="diff.current_finding.module + ' / ' + diff.current_finding.category"></div>
                                    </div>
                                    <span class="px-2 py-1 rounded text-xs font-medium"
                                        :class="severityClass(diff.current_finding.severity)"
                                        x-text="diff.current_finding.severity"></span>
                                </div>
                            </template>
                        </div>
                    </div>
                    <!-- Resolved findings -->
                    <div x-show="compareResults.resolved_findings && compareResults.resolved_findings.length > 0" class="mb-4">
                        <h3 class="text-sm font-medium text-gray-400 mb-2">Resolved Findings</h3>
                        <div class="space-y-2">
                            <template x-for="diff in compareResults.resolved_findings" :key="diff.previous_finding.id">
                                <div class="bg-gray-700/30 rounded p-3 flex items-center justify-between">
                                    <div>
                                        <div class="font-medium text-sm" x-text="diff.previous_finding.title"></div>
                                        <div class="text-xs text-gray-400" x-text="diff.previous_finding.module + ' / ' + diff.previous_finding.category"></div>
                                    </div>
                                    <span class="px-2 py-1 rounded text-xs font-medium bg-green-900 text-green-300">Resolved</span>
                                </div>
                            </template>
                        </div>
                    </div>
                    <!-- Modified findings -->
                    <div x-show="compareResults.modified_findings && compareResults.modified_findings.length > 0" class="mb-4">
                        <h3 class="text-sm font-medium text-gray-400 mb-2">Modified Findings</h3>
                        <div class="space-y-2">
                            <template x-for="diff in compareResults.modified_findings" :key="diff.current_finding.id">
                                <div class="bg-gray-700/30 rounded p-3 flex items-center justify-between">
                                    <div>
                                        <div class="font-medium text-sm" x-text="diff.current_finding.title"></div>
                                        <div class="text-xs text-gray-400" x-text="'Changes: ' + (diff.changes ? diff.changes.join(', ') : '')"></div>
                                    </div>
                                    <span class="px-2 py-1 rounded text-xs font-medium"
                                        :class="severityClass(diff.current_finding.severity)"
                                        x-text="diff.current_finding.severity"></span>
                                </div>
                            </template>
                        </div>
                    </div>
                    <!-- Regression findings -->
                    <div x-show="compareResults.regression_findings && compareResults.regression_findings.length > 0" class="mb-4">
                        <h3 class="text-sm font-medium text-gray-400 mb-2">Regressions</h3>
                        <div class="space-y-2">
                            <template x-for="diff in compareResults.regression_findings" :key="diff.current_finding.id">
                                <div class="bg-gray-700/30 rounded p-3 flex items-center justify-between">
                                    <div>
                                        <div class="font-medium text-sm" x-text="diff.current_finding.title"></div>
                                        <div class="text-xs text-gray-400" x-text="diff.current_finding.module + ' / ' + diff.current_finding.category"></div>
                                    </div>
                                    <span class="px-2 py-1 rounded text-xs font-medium"
                                        :class="severityClass(diff.current_finding.severity)"
                                        x-text="diff.current_finding.severity"></span>
                                </div>
                            </template>
                        </div>
                    </div>
                    <!-- Empty state -->
                    <div x-show="(!compareResults.new_findings || compareResults.new_findings.length === 0) &&
                                  (!compareResults.resolved_findings || compareResults.resolved_findings.length === 0) &&
                                  (!compareResults.modified_findings || compareResults.modified_findings.length === 0) &&
                                  (!compareResults.regression_findings || compareResults.regression_findings.length === 0)"
                        class="py-8 text-center text-gray-500">
                        No differences detected between the two scans.
                    </div>
                </div>
            </div>

            <!-- Results Panel -->
            <div x-show="selectedScan" @keydown.escape.window="selectedScan = null" class="bg-gray-800 rounded-lg p-6" role="region" aria-label="Scan results" tabindex="0">
                <div class="flex flex-col sm:flex-row sm:items-center justify-between mb-4 gap-2">
                    <h2 class="text-lg font-semibold" id="results-title">Scan Results: <span x-text="selectedScan"></span></h2>
                    <button @click="selectedScan = null" class="text-gray-400 hover:text-gray-200 focus:outline-none focus:ring-2 focus:ring-red-500 rounded h-11 w-11 inline-flex items-center justify-center self-end"
                        aria-label="Close results panel">&times;</button>
                </div>
                <!-- Severity Chart -->
                <div class="mb-6" x-show="results && results.findings && results.findings.length > 0">
                    <h3 class="text-sm font-medium text-gray-400 mb-2">Severity Distribution</h3>
                    <div class="h-64">
                        <canvas id="severityChart"></canvas>
                    </div>
                </div>
                <!-- Module Distribution Chart -->
                <div class="mb-6" x-show="results && results.findings && results.findings.length > 0">
                    <h3 class="text-sm font-medium text-gray-400 mb-2">Findings by Module</h3>
                    <div class="h-64">
                        <canvas id="moduleChart"></canvas>
                    </div>
                </div>
                <!-- Risk Score Gauge -->
                <div class="mb-6" x-show="results && results.findings && results.findings.length > 0">
                    <h3 class="text-sm font-medium text-gray-400 mb-2">Risk Score</h3>
                    <div class="h-48">
                        <canvas id="riskGauge"></canvas>
                    </div>
                </div>
                <!-- Timeline Chart -->
                <div class="mb-6" x-show="results && results.findings && results.findings.length > 0">
                    <h3 class="text-sm font-medium text-gray-400 mb-2">Findings Timeline</h3>
                    <div class="h-64">
                        <canvas id="timelineChart"></canvas>
                    </div>
                </div>
                <!-- MITRE ATT&CK Heatmap -->
                <div class="mb-6" x-show="mitreData && mitreData.total_techniques > 0">
                    <div class="flex items-center justify-between mb-2">
                        <h3 class="text-sm font-medium text-gray-400">MITRE ATT&CK Coverage</h3>
                        <span class="text-xs text-gray-400"><span x-text="mitreData.total_techniques"></span> techniques across <span x-text="mitreData.tactics_covered"></span> tactics</span>
                    </div>
                    <div class="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 xl:grid-cols-5 gap-2">
                        <template x-for="tactic in mitreData.tactics_order" :key="tactic">
                            <div x-show="mitreData.matrix[tactic] && mitreData.matrix[tactic].length > 0"
                                class="bg-gray-700/30 rounded p-2">
                                <div class="text-xs font-medium text-gray-300 mb-1 truncate" x-text="tactic"></div>
                                <div class="flex flex-wrap gap-1">
                                    <template x-for="tech in mitreData.matrix[tactic]" :key="tech.id">
                                        <span class="px-1.5 py-0.5 rounded text-[10px] font-mono bg-red-900 text-red-200"
                                            :title="tech.name"
                                            x-text="tech.id"></span>
                                    </template>
                                </div>
                            </div>
                        </template>
                        <div x-show="mitreData.matrix['Unknown'] && mitreData.matrix['Unknown'].length > 0"
                            class="bg-gray-700/30 rounded p-2">
                            <div class="text-xs font-medium text-gray-300 mb-1">Other</div>
                            <div class="flex flex-wrap gap-1">
                                <template x-for="tech in mitreData.matrix['Unknown']" :key="tech.id">
                                    <span class="px-1.5 py-0.5 rounded text-[10px] font-mono bg-gray-600 text-gray-200"
                                        :title="tech.name"
                                        x-text="tech.id"></span>
                                </template>
                            </div>
                        </div>
                    </div>
                </div>
                <!-- Delta Summary -->
                <div x-show="results && results._delta && results._delta.has_baseline" class="mb-6 bg-gray-700/30 rounded-lg p-4">
                    <div class="flex items-center justify-between mb-2">
                        <h3 class="text-sm font-medium text-gray-300">Delta vs Baseline</h3>
                        <span class="text-xs text-gray-400">Baseline: <span x-text="results._delta.baseline_scan_id"></span></span>
                    </div>
                    <div class="grid grid-cols-2 sm:grid-cols-4 gap-2">
                        <div class="bg-gray-800/50 rounded p-2 text-center">
                            <div class="text-lg font-bold text-green-400" x-text="results._delta.summary ? results._delta.summary.new : 0"></div>
                            <div class="text-[10px] text-gray-400">New</div>
                        </div>
                        <div class="bg-gray-800/50 rounded p-2 text-center">
                            <div class="text-lg font-bold text-blue-400" x-text="results._delta.summary ? results._delta.summary.resolved : 0"></div>
                            <div class="text-[10px] text-gray-400">Resolved</div>
                        </div>
                        <div class="bg-gray-800/50 rounded p-2 text-center">
                            <div class="text-lg font-bold text-yellow-400" x-text="results._delta.summary ? results._delta.summary.modified : 0"></div>
                            <div class="text-[10px] text-gray-400">Modified</div>
                        </div>
                        <div class="bg-gray-800/50 rounded p-2 text-center">
                            <div class="text-lg font-bold text-gray-300" x-text="results._delta.summary ? results._delta.summary.unchanged : 0"></div>
                            <div class="text-[10px] text-gray-400">Unchanged</div>
                        </div>
                    </div>
                </div>
                <!-- Findings List with Triage -->
                <div x-show="results && results.findings && results.findings.length > 0">
                    <div class="flex items-center justify-between mb-4">
                        <h3 class="text-sm font-medium text-gray-400">Findings (<span x-text="results.findings.length"></span>)</h3>
                        <div class="flex gap-2 text-xs">
                            <span class="px-2 py-1 rounded bg-gray-700 text-gray-300">Open: <span x-text="triageCount('open')"></span></span>
                            <span class="px-2 py-1 rounded bg-yellow-900 text-yellow-300">FP: <span x-text="triageCount('false_positive')"></span></span>
                            <span class="px-2 py-1 rounded bg-blue-900 text-blue-300">Accepted: <span x-text="triageCount('accepted_risk')"></span></span>
                        </div>
                    </div>
                    <div class="space-y-3">
                        <template x-for="finding in results.findings" :key="finding.id || finding.title">
                            <div class="bg-gray-700/30 rounded p-4">
                                <div class="flex items-start justify-between gap-3 mb-2">
                                    <div class="flex-1 min-w-0">
                                        <div class="flex items-center gap-2 mb-1">
                                            <span class="px-2 py-0.5 rounded text-xs font-medium"
                                                :class="severityClass(finding.severity)"
                                                x-text="finding.severity"></span>
                                            <span x-show="results._delta && results._delta.new_findings && results._delta.new_findings.some(f => f.fingerprint === finding.fingerprint || f.title === finding.title)"
                                                class="px-2 py-0.5 rounded text-xs font-medium bg-green-900/60 text-green-300 border border-green-700"
                                                role="status" aria-label="New finding since baseline">New</span>
                                            <span class="font-medium text-sm truncate" x-text="finding.title"></span>
                                        </div>
                                        <div class="text-xs text-gray-400"
                                            x-text="(finding.module || '') + (finding.category ? ' / ' + finding.category : '')"></div>
                                    </div>
                                    <div class="flex items-center gap-2">
                                        <span x-show="finding.triage" class="px-2 py-0.5 rounded text-xs font-medium"
                                            :class="triageClass(finding.triage.status)"
                                            x-text="finding.triage.status"></span>
                                    </div>
                                </div>
                                <div class="text-sm text-gray-300 mb-2" x-text="finding.description || ''"></div>
                                <!-- Triage controls -->
                                <div class="bg-gray-800/50 rounded p-3 space-y-2">
                                    <div class="flex flex-wrap gap-3">
                                        <div class="flex-1 min-w-[12rem]">
                                            <label class="block text-xs text-gray-400 mb-1">Status</label>
                                            <select :id="'triage-status-' + (finding.id || finding.title)"
                                                class="w-full bg-gray-700 border border-gray-600 rounded px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-red-500 focus:border-red-500 h-9"
                                                x-model="finding._triageStatus">
                                                <option value="open">Open</option>
                                                <option value="false_positive">False Positive</option>
                                                <option value="accepted_risk">Accepted Risk</option>
                                            </select>
                                        </div>
                                        <div class="flex-1 min-w-[12rem]">
                                            <label class="block text-xs text-gray-400 mb-1">Assignee</label>
                                            <input type="text" :id="'triage-assignee-' + (finding.id || finding.title)"
                                                class="w-full bg-gray-700 border border-gray-600 rounded px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-red-500 focus:border-red-500 h-9"
                                                x-model="finding._triageAssignee"
                                                placeholder="Username">
                                        </div>
                                    </div>
                                    <div>
                                        <label class="block text-xs text-gray-400 mb-1">Notes</label>
                                        <textarea :id="'triage-notes-' + (finding.id || finding.title)"
                                            class="w-full bg-gray-700 border border-gray-600 rounded px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-red-500 focus:border-red-500"
                                            rows="2"
                                            x-model="finding._triageNotes"
                                            placeholder="Add triage notes..."></textarea>
                                    </div>
                                    <div class="flex justify-end">
                                        <button @click="saveFindingTriage(selectedScan, finding)"
                                            class="bg-red-600 hover:bg-red-700 px-3 py-1.5 rounded text-sm font-medium transition h-9 inline-flex items-center focus:outline-none focus:ring-2 focus:ring-red-500 focus:ring-offset-2 focus:ring-offset-gray-800">Save</button>
                                    </div>
                                </div>
                            </div>
                        </template>
                    </div>
                </div>
                <pre class="bg-gray-900 p-4 rounded overflow-auto max-h-96 text-sm" x-show="results && (!results.findings || results.findings.length === 0)" x-text="JSON.stringify(results, null, 2)"></pre>
            </div>
        </div>
    </div>

    <script>
        function dashboard() {
            return {
                version: '',
                health: 'Checking...',
                wsStatus: 'Connecting...',
                scans: [],
                presets: [],
                newScan: { target: '', preset: 'quick' },
                scanning: false,
                selectedScan: null,
                results: null,
                ws: null,
                selectedForCompare: [],
                compareResults: null,
                showCompare: false,
                comparing: false,
                scanFilter: { search: '', status: '', sort: 'started_at_desc' },
                mitreData: null,
                srAnnouncement: '',
                // Auth state
                authEnabled: false,
                authenticated: false,
                username: '',
                showLogin: true,
                loginForm: { username: '', password: '' },
                loginError: '',
                loggingIn: false,

                async init() {
                    await this.checkHealth();
                    await this.checkAuth();
                    if (!this.authEnabled || this.authenticated) {
                        await this.loadPresets();
                        await this.loadScans();
                        this.connectWebSocket();
                    }
                },

                async checkAuth() {
                    try {
                        const res = await fetch('/api/auth/status');
                        const data = await res.json();
                        this.authEnabled = data.auth_enabled;
                        this.authenticated = data.authenticated;
                        this.username = data.username || '';
                        if (this.authenticated) {
                            this.showLogin = false;
                        }
                    } catch (e) {
                        console.error('Failed to check auth:', e);
                    }
                },

                async login() {
                    this.loggingIn = true;
                    this.loginError = '';
                    try {
                        const res = await fetch('/api/auth/login', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify(this.loginForm)
                        });
                        const data = await res.json();
                        if (res.ok && data.success) {
                            this.authenticated = true;
                            this.username = data.username;
                            this.showLogin = false;
                            this.loginForm = { username: '', password: '' };
                            this.srAnnouncement = 'Login successful. Welcome, ' + this.username;
                            await this.loadPresets();
                            await this.loadScans();
                            this.connectWebSocket();
                        } else {
                            this.loginError = data.detail || 'Login failed';
                            this.srAnnouncement = 'Login failed: ' + this.loginError;
                        }
                    } catch (e) {
                        this.loginError = 'Connection failed';
                        this.srAnnouncement = 'Login failed: connection error';
                    }
                    this.loggingIn = false;
                },

                async logout() {
                    try {
                        await fetch('/api/auth/logout', { method: 'POST' });
                    } catch (e) {
                        console.error('Logout error:', e);
                    }
                    this.authenticated = false;
                    this.srAnnouncement = 'Logged out';
                    this.username = '';
                    this.showLogin = true;
                    this.scans = [];
                    if (this.ws) {
                        this.ws.close();
                        this.ws = null;
                    }
                },

                connectWebSocket() {
                    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
                    this.ws = new WebSocket(`${protocol}//${window.location.host}/ws`);

                    this.ws.onopen = () => {
                        this.wsStatus = 'Connected';
                        console.log('WebSocket connected');
                    };

                    this.ws.onclose = () => {
                        this.wsStatus = 'Disconnected';
                        console.log('WebSocket disconnected, reconnecting in 3s...');
                        setTimeout(() => this.connectWebSocket(), 3000);
                    };

                    this.ws.onerror = (e) => {
                        console.error('WebSocket error:', e);
                        this.wsStatus = 'Error';
                    };

                    this.ws.onmessage = (e) => {
                        try {
                            const event = JSON.parse(e.data);
                            this.handleWSEvent(event);
                        } catch (err) {
                            console.error('Failed to parse WebSocket message:', err);
                        }
                    };
                },

                handleWSEvent(event) {
                    console.log('WS Event:', event.event, event);

                    // Find and update scan in list
                    const scanIndex = this.scans.findIndex(s => s.scan_id === event.scan_id);

                    switch (event.event) {
                        case 'scan_started':
                            // Reload scans to get the new one
                            this.loadScans();
                            this.srAnnouncement = 'Scan ' + event.scan_id + ' started';
                            break;

                        case 'scan_progress':
                            if (scanIndex >= 0) {
                                this.scans[scanIndex].progress = event.data.progress;
                                this.scans[scanIndex].current_module = event.data.current_module;
                            }
                            break;

                        case 'scan_completed':
                            if (scanIndex >= 0) {
                                this.scans[scanIndex].status = 'completed';
                                this.scans[scanIndex].progress = 100;
                                this.scans[scanIndex].current_module = null;
                            }
                            this.srAnnouncement = 'Scan ' + event.scan_id + ' completed';
                            break;

                        case 'scan_failed':
                            if (scanIndex >= 0) {
                                this.scans[scanIndex].status = 'failed';
                                this.scans[scanIndex].error = event.data.error;
                            }
                            this.srAnnouncement = 'Scan ' + event.scan_id + ' failed';
                            break;

                        case 'connection':
                            console.log('WS connection confirmed:', event.data.message);
                            break;
                    }
                },

                async checkHealth() {
                    try {
                        const res = await fetch('/api/health');
                        const data = await res.json();
                        this.version = data.version;
                        this.health = 'Connected';
                    } catch (e) {
                        this.health = 'Disconnected';
                    }
                },

                async loadPresets() {
                    try {
                        const res = await fetch('/api/settings/presets');
                        const data = await res.json();
                        this.presets = data.presets;
                    } catch (e) {
                        console.error('Failed to load presets:', e);
                    }
                },

                async loadScans() {
                    try {
                        const params = new URLSearchParams({ limit: '50' });
                        if (this.scanFilter.status) params.set('status', this.scanFilter.status);
                        if (this.scanFilter.search) params.set('search', this.scanFilter.search);
                        if (this.scanFilter.sort) params.set('sort', this.scanFilter.sort);
                        const res = await fetch(`/api/scans?${params.toString()}`);
                        if (res.status === 401) {
                            this.authenticated = false;
                            this.showLogin = true;
                            return;
                        }
                        this.scans = await res.json();
                    } catch (e) {
                        console.error('Failed to load scans:', e);
                    }
                },

                async startScan() {
                    this.scanning = true;
                    try {
                        const res = await fetch('/api/scans', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify(this.newScan)
                        });
                        if (res.ok) {
                            this.newScan.target = '';
                            // WebSocket will notify us of the new scan
                        }
                    } catch (e) {
                        console.error('Failed to start scan:', e);
                    }
                    this.scanning = false;
                },

                async viewResults(scanId) {
                    try {
                        const res = await fetch(`/api/scans/${scanId}/results`);
                        this.results = await res.json();
                        // Initialize triage draft fields from server state
                        if (this.results.findings) {
                            for (const f of this.results.findings) {
                                const t = f.triage || {};
                                f._triageStatus = t.status || 'open';
                                f._triageNotes = t.notes || '';
                                f._triageAssignee = t.assignee || '';
                            }
                            this.srAnnouncement = 'Loaded ' + this.results.findings.length + ' findings for scan ' + scanId;
                        } else {
                            this.srAnnouncement = 'Loaded results for scan ' + scanId;
                        }
                        this.selectedScan = scanId;
                        this.loadMitre(scanId);
                        // Render charts after Alpine has updated the DOM
                        this.$nextTick(() => {
                            requestAnimationFrame(() => {
                                this.renderSeverityChart();
                                this.renderModuleChart();
                                this.renderRiskGauge();
                                this.renderTimelineChart();
                            });
                        });
                    } catch (e) {
                        console.error('Failed to load results:', e);
                    }
                },

                async loadMitre(scanId) {
                    try {
                        const res = await fetch(`/api/scans/${scanId}/mitre`);
                        if (res.ok) {
                            this.mitreData = await res.json();
                        } else {
                            this.mitreData = null;
                        }
                    } catch (e) {
                        console.error('Failed to load MITRE data:', e);
                        this.mitreData = null;
                    }
                },

                toggleCompareSelection(scanId) {
                    const idx = this.selectedForCompare.indexOf(scanId);
                    if (idx >= 0) {
                        this.selectedForCompare.splice(idx, 1);
                    } else if (this.selectedForCompare.length < 2) {
                        this.selectedForCompare.push(scanId);
                    }
                },

                isSelectedForCompare(scanId) {
                    return this.selectedForCompare.includes(scanId);
                },

                async setBaseline(scanId) {
                    try {
                        const res = await fetch(`/api/scans/${scanId}/baseline`, { method: 'POST' });
                        if (res.ok) {
                            const data = await res.json();
                            this.srAnnouncement = data.message;
                        } else {
                            const err = await res.json();
                            this.srAnnouncement = 'Failed to set baseline: ' + (err.detail || 'Unknown error');
                        }
                    } catch (e) {
                        console.error('Failed to set baseline:', e);
                        this.srAnnouncement = 'Failed to set baseline: network error';
                    }
                },

                async compareSelectedScans() {
                    if (this.selectedForCompare.length !== 2) return;
                    this.comparing = true;
                    try {
                        const res = await fetch('/api/scans/compare', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({
                                baseline_scan_id: this.selectedForCompare[0],
                                current_scan_id: this.selectedForCompare[1]
                            })
                        });
                        if (res.ok) {
                            this.compareResults = await res.json();
                            this.showCompare = true;
                            this.selectedScan = null;
                            const total = (this.compareResults.total_new || 0) + (this.compareResults.total_resolved || 0) + (this.compareResults.total_modified || 0) + (this.compareResults.total_regression || 0);
                            this.srAnnouncement = 'Comparison complete. ' + total + ' differences found';
                        } else {
                            const err = await res.json();
                            alert('Comparison failed: ' + (err.detail || 'Unknown error'));
                            this.srAnnouncement = 'Comparison failed';
                        }
                    } catch (e) {
                        console.error('Failed to compare scans:', e);
                        alert('Comparison failed: network error');
                    }
                    this.comparing = false;
                },

                closeCompare() {
                    this.showCompare = false;
                    this.compareResults = null;
                    this.selectedForCompare = [];
                },

                renderSeverityChart() {
                    const canvas = document.getElementById('severityChart');
                    if (!canvas || !this.results || !this.results.findings) return;

                    const ctx = canvas.getContext('2d');
                    if (window._severityChart) {
                        window._severityChart.destroy();
                    }

                    // Count findings by severity
                    const counts = {};
                    const colors = {
                        critical: '#dc3545',
                        high: '#fd7e14',
                        medium: '#ffc107',
                        low: '#28a745',
                        info: '#17a2b8',
                        unknown: '#6c757d'
                    };
                    const order = ['critical', 'high', 'medium', 'low', 'info'];

                    for (const f of this.results.findings) {
                        const sev = (f.severity || 'unknown').toLowerCase();
                        counts[sev] = (counts[sev] || 0) + 1;
                    }

                    const labels = [];
                    const data = [];
                    const bgColors = [];
                    for (const sev of order) {
                        if (counts[sev]) {
                            labels.push(sev.charAt(0).toUpperCase() + sev.slice(1));
                            data.push(counts[sev]);
                            bgColors.push(colors[sev] || colors.unknown);
                        }
                    }
                    if (counts.unknown) {
                        labels.push('Unknown');
                        data.push(counts.unknown);
                        bgColors.push(colors.unknown);
                    }

                    if (labels.length === 0) return;

                    window._severityChart = new Chart(ctx, {
                        type: 'doughnut',
                        data: {
                            labels: labels,
                            datasets: [{
                                data: data,
                                backgroundColor: bgColors,
                                borderWidth: 1
                            }]
                        },
                        options: {
                            responsive: true,
                            maintainAspectRatio: false,
                            plugins: {
                                legend: { position: 'right', labels: { color: '#d1d5db' } },
                                title: { display: true, text: 'Findings by Severity', color: '#d1d5db' },
                                tooltip: { bodyColor: '#d1d5db', titleColor: '#f3f4f6' }
                            }
                        }
                    });
                },

                renderModuleChart() {
                    const canvas = document.getElementById('moduleChart');
                    if (!canvas || !this.results || !this.results.findings) return;

                    const ctx = canvas.getContext('2d');
                    if (window._moduleChart) {
                        window._moduleChart.destroy();
                    }

                    const counts = {};
                    for (const f of this.results.findings) {
                        const mod = (f.module || 'unknown').split('.').pop();
                        counts[mod] = (counts[mod] || 0) + 1;
                    }

                    const labels = Object.keys(counts);
                    const data = Object.values(counts);

                    if (labels.length === 0) return;

                    window._moduleChart = new Chart(ctx, {
                        type: 'bar',
                        data: {
                            labels: labels,
                            datasets: [{
                                label: 'Findings',
                                data: data,
                                backgroundColor: '#dc3545',
                                borderWidth: 1
                            }]
                        },
                        options: {
                            responsive: true,
                            maintainAspectRatio: false,
                            plugins: {
                                legend: { display: false },
                                title: { display: true, text: 'Findings by Module', color: '#d1d5db' },
                                tooltip: { bodyColor: '#d1d5db', titleColor: '#f3f4f6' }
                            },
                            scales: {
                                y: { beginAtZero: true, ticks: { color: '#9ca3af' }, grid: { color: '#374151' } },
                                x: { ticks: { color: '#9ca3af' }, grid: { color: '#374151' } }
                            }
                        }
                    });
                },

                renderRiskGauge() {
                    const canvas = document.getElementById('riskGauge');
                    if (!canvas || !this.results || !this.results.findings) return;

                    const ctx = canvas.getContext('2d');
                    if (window._riskGauge) {
                        window._riskGauge.destroy();
                    }

                    const weights = { critical: 40, high: 25, medium: 15, low: 5, info: 1 };
                    let score = 0;
                    for (const f of this.results.findings) {
                        score += weights[f.severity?.toLowerCase()] || 1;
                    }
                    score = Math.min(100, score);

                    const colors = ['#17a2b8', '#28a745', '#ffc107', '#fd7e14', '#dc3545'];
                    const zoneLabels = ['Minimal', 'Low', 'Medium', 'High', 'Critical'];

                    window._riskGauge = new Chart(ctx, {
                        type: 'doughnut',
                        data: {
                            labels: zoneLabels,
                            datasets: [{
                                data: [20, 20, 20, 20, 20],
                                backgroundColor: colors,
                                borderWidth: 0,
                                circumference: 180,
                                rotation: 270,
                            }]
                        },
                        options: {
                            responsive: true,
                            maintainAspectRatio: false,
                            cutout: '75%',
                            plugins: {
                                legend: { display: false },
                                tooltip: { enabled: false },
                            }
                        },
                        plugins: [{
                            id: 'gaugeText',
                            beforeDraw: (chart) => {
                                const { ctx, chartArea } = chart;
                                if (!chartArea) return;
                                const { top, bottom, left, right } = chartArea;
                                const cx = (left + right) / 2;
                                const cy = (top + bottom) / 2;
                                ctx.save();
                                ctx.fillStyle = '#f3f4f6';
                                ctx.font = 'bold 24px sans-serif';
                                ctx.textAlign = 'center';
                                ctx.textBaseline = 'middle';
                                ctx.fillText(score.toString(), cx, cy);
                                ctx.restore();
                            }
                        }]
                    });
                },

                renderTimelineChart() {
                    const canvas = document.getElementById('timelineChart');
                    if (!canvas || !this.results || !this.results.findings) return;

                    const ctx = canvas.getContext('2d');
                    if (window._timelineChart) {
                        window._timelineChart.destroy();
                    }

                    const bucketCounts = {};
                    for (const f of this.results.findings) {
                        const ts = f.timestamp || f.created_at || f.discovered_at;
                        if (!ts) continue;
                        const date = new Date(ts).toLocaleDateString();
                        bucketCounts[date] = (bucketCounts[date] || 0) + 1;
                    }

                    const labels = Object.keys(bucketCounts).sort((a, b) => new Date(a) - new Date(b));
                    const data = labels.map(d => bucketCounts[d]);

                    if (labels.length === 0) return;

                    window._timelineChart = new Chart(ctx, {
                        type: 'line',
                        data: {
                            labels: labels,
                            datasets: [{
                                label: 'Findings',
                                data: data,
                                borderColor: '#dc3545',
                                backgroundColor: 'rgba(220, 53, 69, 0.2)',
                                fill: true,
                                tension: 0.3,
                                borderWidth: 2
                            }]
                        },
                        options: {
                            responsive: true,
                            maintainAspectRatio: false,
                            plugins: {
                                legend: { display: false },
                                title: { display: true, text: 'Findings Over Time', color: '#d1d5db' },
                                tooltip: { bodyColor: '#d1d5db', titleColor: '#f3f4f6' }
                            },
                            scales: {
                                y: { beginAtZero: true, ticks: { color: '#9ca3af' }, grid: { color: '#374151' } },
                                x: { ticks: { color: '#9ca3af' }, grid: { color: '#374151' } }
                            }
                        }
                    });
                },

                statusClass(status) {
                    return {
                        'pending': 'bg-yellow-500/20 text-yellow-400',
                        'running': 'bg-blue-500/20 text-blue-400',
                        'completed': 'bg-green-500/20 text-green-400',
                        'failed': 'bg-red-500/20 text-red-400',
                    }[status] || 'bg-gray-500/20 text-gray-400';
                },

                severityClass(severity) {
                    return {
                        'critical': 'bg-red-900 text-red-300',
                        'high': 'bg-orange-900 text-orange-300',
                        'medium': 'bg-yellow-900 text-yellow-300',
                        'low': 'bg-blue-900 text-blue-300',
                        'info': 'bg-gray-700 text-gray-300',
                    }[severity] || 'bg-gray-700 text-gray-300';
                },

                triageClass(status) {
                    return {
                        'open': 'bg-gray-700 text-gray-300',
                        'false_positive': 'bg-yellow-900 text-yellow-300',
                        'accepted_risk': 'bg-blue-900 text-blue-300',
                    }[status] || 'bg-gray-700 text-gray-300';
                },

                triageCount(status) {
                    if (!this.results || !this.results.findings) return 0;
                    return this.results.findings.filter(f => {
                        const s = f.triage ? f.triage.status : 'open';
                        return s === status;
                    }).length;
                },

                async saveFindingTriage(scanId, finding) {
                    const fid = finding.id || finding.title || '';
                    if (!fid) {
                        this.srAnnouncement = 'Cannot triage finding without an id or title';
                        return;
                    }
                    try {
                        const res = await fetch(`/api/scans/${scanId}/findings/${encodeURIComponent(fid)}/triage`, {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({
                                status: finding._triageStatus,
                                notes: finding._triageNotes,
                                assignee: finding._triageAssignee,
                            })
                        });
                        if (res.ok) {
                            const data = await res.json();
                            finding.triage = data.triage;
                            this.srAnnouncement = 'Triage saved for finding ' + fid;
                        } else {
                            const err = await res.json();
                            this.srAnnouncement = 'Failed to save triage: ' + (err.detail || 'Unknown error');
                        }
                    } catch (e) {
                        console.error('Failed to save triage:', e);
                        this.srAnnouncement = 'Failed to save triage: network error';
                    }
                },

                formatDate(iso) {
                    if (!iso) return '';
                    return new Date(iso).toLocaleString();
                }
            };
        }
    </script>
</body>
</html>"""


# CLI entry point
def main():
    """Run the web server."""
    import uvicorn

    host = os.environ.get("REDOPS_HOST", "127.0.0.1")
    port = int(os.environ.get("REDOPS_PORT", "8000"))

    print(f"Starting RedOPS Web UI at http://{host}:{port}")
    print(f"API docs at http://{host}:{port}/api/docs")

    uvicorn.run(
        "redops.web.app:create_app",
        host=host,
        port=port,
        factory=True,
        reload=os.environ.get("REDOPS_DEV", "").lower() == "true",
    )


if __name__ == "__main__":
    main()
