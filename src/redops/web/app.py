"""
RedOPS Web UI - FastAPI application.

Provides a REST API and web dashboard for RedOPS functionality.
"""

import os
from datetime import datetime, timezone

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


class AIRequest(BaseModel):
    """Request model for AI operations."""

    action: str = Field(
        ..., description="AI action (analyze, explain, suggest, summarize)"
    )
    query: str | None = Field(default=None, description="Query for explain action")
    scan_id: str | None = Field(default=None, description="Scan ID for analysis")
    provider: str | None = Field(default=None, description="AI provider override")
    model: str | None = Field(default=None, description="Model override")


class AIResponse(BaseModel):
    """Response model for AI operations."""

    action: str
    result: str
    provider: str
    model: str


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


# In-memory scan storage (for demo; use database in production)
_scans: dict[str, ScanStatus] = {}
_scan_results: dict[str, dict] = {}


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
        _scans[scan_id] = status

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
        limit: int = Query(20, ge=1, le=100, description="Max results"),
        user: AuthenticatedUser = Depends(require_auth),
    ):
        """List all scans."""
        scans = list(_scans.values())
        if status:
            scans = [s for s in scans if s.status == status]
        return sorted(scans, key=lambda s: s.started_at, reverse=True)[:limit]

    @app.get("/api/scans/{scan_id}", response_model=ScanStatus, tags=["Scans"])
    async def get_scan(scan_id: str, user: AuthenticatedUser = Depends(require_auth)):
        """Get scan status by ID."""
        if scan_id not in _scans:
            raise HTTPException(status_code=404, detail="Scan not found")
        return _scans[scan_id]

    @app.get("/api/scans/{scan_id}/results", tags=["Scans"])
    async def get_scan_results(
        scan_id: str, user: AuthenticatedUser = Depends(require_auth)
    ):
        """Get scan results."""
        if scan_id not in _scans:
            raise HTTPException(status_code=404, detail="Scan not found")
        if _scans[scan_id].status != "completed":
            raise HTTPException(status_code=400, detail="Scan not completed")
        if scan_id not in _scan_results:
            raise HTTPException(status_code=404, detail="Results not available")
        return _scan_results[scan_id]

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
                if request.scan_id not in _scan_results:
                    raise HTTPException(
                        status_code=404, detail="Scan results not found"
                    )
                result = assistant.analyze_findings(_scan_results[request.scan_id])
            elif request.action == "suggest":
                if not request.scan_id:
                    raise HTTPException(
                        status_code=400, detail="scan_id required for suggest action"
                    )
                if request.scan_id not in _scan_results:
                    raise HTTPException(
                        status_code=404, detail="Scan results not found"
                    )
                result = assistant.suggest_remediations(_scan_results[request.scan_id])
            elif request.action == "summarize":
                if not request.scan_id:
                    raise HTTPException(
                        status_code=400, detail="scan_id required for summarize action"
                    )
                if request.scan_id not in _scan_results:
                    raise HTTPException(
                        status_code=404, detail="Scan results not found"
                    )
                result = assistant.summarize(_scan_results[request.scan_id])
            else:
                raise HTTPException(
                    status_code=400, detail=f"Unknown action: {request.action}"
                )

            return AIResponse(
                action=request.action,
                result=result,
                provider=assistant.provider,
                model=assistant.model,
            )

        except ImportError as e:
            raise HTTPException(status_code=503, detail=f"AI not available: {e}")
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))

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
        _scans[scan_id].status = "running"
        _scans[scan_id].progress = 0

        # Emit scan started event
        await emit_scan_started(scan_id, request.target, request.preset)

        # Simulate scan progress (replace with actual scan in production)
        from redops.core.context import Context
        from redops.modules import recon

        ctx = Context(target=request.target)

        modules = [
            ("domain_profile", recon.domain_profile),
            ("tech_stack", recon.tech_stack),
        ]

        for i, (name, module_fn) in enumerate(modules):
            _scans[scan_id].current_module = name
            progress = int((i / len(modules)) * 100)
            _scans[scan_id].progress = progress

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
        _scan_results[scan_id] = ctx.data
        _scans[scan_id].status = "completed"
        _scans[scan_id].progress = 100
        _scans[scan_id].completed_at = datetime.now(timezone.utc).isoformat() + "Z"
        _scans[scan_id].current_module = None

        # Emit completion
        await emit_scan_completed(scan_id, len(ctx.data))

    except Exception as e:  # Worker safety net — prevents unhandled exceptions from killing the background task
        _scans[scan_id].status = "failed"
        _scans[scan_id].error = str(e)
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
                            <button @click="logout()" class="text-xs text-gray-400 hover:text-gray-200 px-3 h-11 border border-gray-600 rounded inline-flex items-center">Logout</button>
                        </div>
                    </template>
                </div>
            </div>
        </header>

        <!-- Login Modal -->
        <template x-if="authEnabled && !authenticated && showLogin">
            <div class="fixed inset-0 bg-black/50 flex items-center justify-center z-50" role="dialog" aria-modal="true" aria-label="Login dialog" @keydown.escape.window="showLogin = false">
                <div class="bg-gray-800 rounded-lg p-6 sm:p-8 w-full max-w-sm shadow-xl">
                    <h2 class="text-xl font-bold mb-6 text-center" id="login-title">Login to RedOPS</h2>
                    <form @submit.prevent="login()" aria-labelledby="login-title">
                        <div class="mb-4">
                            <label for="login-username" class="block text-sm text-gray-400 mb-2">Username</label>
                            <input id="login-username" type="text" x-model="loginForm.username" required
                                class="w-full bg-gray-700 border border-gray-600 rounded px-4 py-2 focus:outline-none focus:border-red-500 h-11">
                        </div>
                        <div class="mb-6">
                            <label for="login-password" class="block text-sm text-gray-400 mb-2">Password</label>
                            <input id="login-password" type="password" x-model="loginForm.password" required
                                class="w-full bg-gray-700 border border-gray-600 rounded px-4 py-2 focus:outline-none focus:border-red-500 h-11">
                        </div>
                        <p x-show="loginError" class="text-red-400 text-sm mb-4" x-text="loginError"></p>
                        <button type="submit" :disabled="loggingIn"
                            class="w-full bg-red-600 hover:bg-red-700 disabled:bg-gray-600 py-2 rounded font-medium transition h-11">
                            <span x-show="!loggingIn">Login</span>
                            <span x-show="loggingIn">Logging in...</span>
                        </button>
                    </form>
                </div>
            </div>
        </template>

        <div class="container mx-auto px-6 py-8">
            <!-- New Scan Form -->
            <div class="bg-gray-800 rounded-lg p-6 mb-8" role="region" aria-label="New scan">
                <h2 class="text-lg font-semibold mb-4" id="new-scan-title">New Scan</h2>
                <form @submit.prevent="startScan()" class="flex flex-wrap gap-4" aria-labelledby="new-scan-title">
                    <label for="scan-target" class="sr-only">Target</label>
                    <input id="scan-target" type="text" x-model="newScan.target" placeholder="Target (e.g., example.com)"
                        class="w-full sm:flex-1 sm:min-w-0 min-w-0 bg-gray-700 border border-gray-600 rounded px-4 py-2 focus:outline-none focus:border-red-500 h-11">
                    <label for="scan-preset" class="sr-only">Preset</label>
                    <select id="scan-preset" x-model="newScan.preset" class="w-full sm:w-auto bg-gray-700 border border-gray-600 rounded px-4 py-2 h-11">
                        <template x-for="preset in presets" :key="preset.id">
                            <option :value="preset.id" x-text="preset.name"></option>
                        </template>
                    </select>
                    <button type="submit" :disabled="!newScan.target || scanning"
                        class="bg-red-600 hover:bg-red-700 disabled:bg-gray-600 px-6 py-2 rounded font-medium transition h-11 w-full sm:w-auto"
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
                    <button @click="loadScans()" class="text-sm text-gray-400 hover:text-gray-200 h-11 px-3 inline-flex items-center"
                        aria-label="Refresh scans list">Refresh</button>
                </div>
                <!-- Desktop table -->
                <div class="hidden md:block overflow-x-auto">
                    <table class="w-full" aria-labelledby="scans-title">
                        <thead>
                            <tr class="text-left text-gray-400 text-sm border-b border-gray-700">
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
                                    <td class="py-3 font-mono text-sm" x-text="scan.scan_id"></td>
                                    <td class="py-3" x-text="scan.target"></td>
                                    <td class="py-3 capitalize" x-text="scan.preset"></td>
                                    <td class="py-3">
                                        <span :class="statusClass(scan.status)" class="px-2 py-1 rounded text-xs font-medium"
                                            x-text="scan.status"></span>
                                    </td>
                                    <td class="py-3">
                                        <div class="w-24 bg-gray-700 rounded-full h-2">
                                            <div class="bg-red-500 h-2 rounded-full transition-all" :style="'width: ' + scan.progress + '%'"></div>
                                        </div>
                                    </td>
                                    <td class="py-3 text-sm text-gray-400" x-text="formatDate(scan.started_at)"></td>
                                    <td class="py-3">
                                        <button x-show="scan.status === 'completed'" @click="viewResults(scan.scan_id)"
                                            class="text-red-400 hover:text-red-300 text-sm h-11 px-3 inline-flex items-center"
                                            :aria-label="'View results for scan ' + scan.scan_id">View</button>
                                    </td>
                                </tr>
                            </template>
                            <tr x-show="scans.length === 0">
                                <td colspan="7" class="py-8 text-center text-gray-500">No scans yet. Start one above.</td>
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
                                <span :class="statusClass(scan.status)" class="px-2 py-1 rounded text-xs font-medium" x-text="scan.status"></span>
                            </div>
                            <div class="text-sm" x-text="scan.target"></div>
                            <div class="flex items-center justify-between text-sm text-gray-400">
                                <span class="capitalize" x-text="scan.preset"></span>
                                <span x-text="formatDate(scan.started_at)"></span>
                            </div>
                            <div class="w-full bg-gray-700 rounded-full h-2">
                                <div class="bg-red-500 h-2 rounded-full transition-all" :style="'width: ' + scan.progress + '%'"></div>
                            </div>
                            <div class="flex justify-end">
                                <button x-show="scan.status === 'completed'" @click="viewResults(scan.scan_id)"
                                    class="text-red-400 hover:text-red-300 text-sm h-11 px-3 inline-flex items-center"
                                    :aria-label="'View results for scan ' + scan.scan_id">View Results</button>
                            </div>
                        </div>
                    </template>
                    <div x-show="scans.length === 0" class="py-8 text-center text-gray-500">No scans yet. Start one above.</div>
                </div>
            </div>

            <!-- Results Panel -->
            <div x-show="selectedScan" class="bg-gray-800 rounded-lg p-6" role="region" aria-label="Scan results">
                <div class="flex items-center justify-between mb-4">
                    <h2 class="text-lg font-semibold" id="results-title">Scan Results: <span x-text="selectedScan"></span></h2>
                    <button @click="selectedScan = null" class="text-gray-400 hover:text-gray-200"
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
                <pre class="bg-gray-900 p-4 rounded overflow-auto max-h-96 text-sm" x-text="JSON.stringify(results, null, 2)"></pre>
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
                            await this.loadPresets();
                            await this.loadScans();
                            this.connectWebSocket();
                        } else {
                            this.loginError = data.detail || 'Login failed';
                        }
                    } catch (e) {
                        this.loginError = 'Connection failed';
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
                            break;

                        case 'scan_failed':
                            if (scanIndex >= 0) {
                                this.scans[scanIndex].status = 'failed';
                                this.scans[scanIndex].error = event.data.error;
                            }
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
                        const res = await fetch('/api/scans?limit=10');
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
                        this.selectedScan = scanId;
                        // Allow DOM to update before rendering charts
                        setTimeout(() => {
                            this.renderSeverityChart();
                            this.renderModuleChart();
                            this.renderRiskGauge();
                            this.renderTimelineChart();
                        }, 50);
                    } catch (e) {
                        console.error('Failed to load results:', e);
                    }
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
                                legend: { position: 'right' },
                                title: { display: true, text: 'Findings by Severity' }
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
                                title: { display: true, text: 'Findings by Module' }
                            },
                            scales: {
                                y: { beginAtZero: true, ticks: { color: '#9ca3af' } },
                                x: { ticks: { color: '#9ca3af' } }
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
                                const { ctx, chartArea: { top, bottom, left, right } } = chart;
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
                                title: { display: true, text: 'Findings Over Time' }
                            },
                            scales: {
                                y: { beginAtZero: true, ticks: { color: '#9ca3af' } },
                                x: { ticks: { color: '#9ca3af' } }
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
