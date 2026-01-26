"""
RedOPS Web UI - FastAPI application.

Provides a REST API and web dashboard for RedOPS functionality.
"""

import os
from datetime import datetime, UTC
from typing import Optional

from fastapi import FastAPI, HTTPException, BackgroundTasks, Query, WebSocket, WebSocketDisconnect, Depends, Response, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, RedirectResponse
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

from redops.main import __version__


# Request/Response models
class ScanRequest(BaseModel):
    """Request model for starting a scan."""

    target: str = Field(..., description="Target domain or URL")
    preset: str = Field(default="quick", description="Scan preset (quick, recon, full, ai_enhanced)")
    modules: Optional[list[str]] = Field(default=None, description="Specific modules to run")


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
    completed_at: Optional[str] = None
    progress: int = 0
    current_module: Optional[str] = None
    results_path: Optional[str] = None
    error: Optional[str] = None


class AIRequest(BaseModel):
    """Request model for AI operations."""

    action: str = Field(..., description="AI action (analyze, explain, suggest, summarize)")
    query: Optional[str] = Field(default=None, description="Query for explain action")
    scan_id: Optional[str] = Field(default=None, description="Scan ID for analysis")
    provider: Optional[str] = Field(default=None, description="AI provider override")
    model: Optional[str] = Field(default=None, description="Model override")


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
    username: Optional[str] = None


class AuthStatusResponse(BaseModel):
    """Response model for auth status check."""

    authenticated: bool
    username: Optional[str] = None
    auth_method: Optional[str] = None
    auth_enabled: bool


# In-memory scan storage (for demo; use database in production)
_scans: dict[str, ScanStatus] = {}
_scan_results: dict[str, dict] = {}


def create_app(auth_config: Optional[AuthConfig] = None) -> FastAPI:
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
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],  # Configure for production
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Health check (public)
    @app.get("/api/health", response_model=HealthResponse, tags=["System"])
    async def health_check():
        """Check API health status."""
        auth_manager = get_auth_manager()
        return HealthResponse(
            status="healthy",
            version=__version__,
            timestamp=datetime.now(UTC).isoformat() + "Z",
            auth_enabled=auth_manager.config.enabled,
        )

    # Authentication endpoints
    @app.get("/api/auth/status", response_model=AuthStatusResponse, tags=["Auth"])
    async def auth_status(user: Optional[AuthenticatedUser] = Depends(optional_auth)):
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
            response.set_cookie(
                key="redops_session",
                value=token,
                httponly=True,
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
        now = datetime.now(UTC).isoformat() + "Z"

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
        status: Optional[str] = Query(None, description="Filter by status"),
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
    async def get_scan_results(scan_id: str, user: AuthenticatedUser = Depends(require_auth)):
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
    async def ai_action(request: AIRequest, user: AuthenticatedUser = Depends(require_auth)):
        """Perform AI-assisted analysis."""
        try:
            from redops.modules.ai_assistant import AIAssistant

            assistant = AIAssistant(
                provider=request.provider,
                model=request.model,
            )

            if request.action == "explain":
                if not request.query:
                    raise HTTPException(status_code=400, detail="Query required for explain action")
                result = assistant.explain(request.query)
            elif request.action == "analyze":
                if not request.scan_id:
                    raise HTTPException(status_code=400, detail="scan_id required for analyze action")
                if request.scan_id not in _scan_results:
                    raise HTTPException(status_code=404, detail="Scan results not found")
                result = assistant.analyze_findings(_scan_results[request.scan_id])
            elif request.action == "suggest":
                if not request.scan_id:
                    raise HTTPException(status_code=400, detail="scan_id required for suggest action")
                if request.scan_id not in _scan_results:
                    raise HTTPException(status_code=404, detail="Scan results not found")
                result = assistant.suggest_remediations(_scan_results[request.scan_id])
            elif request.action == "summarize":
                if not request.scan_id:
                    raise HTTPException(status_code=400, detail="scan_id required for summarize action")
                if request.scan_id not in _scan_results:
                    raise HTTPException(status_code=404, detail="Scan results not found")
                result = assistant.summarize(_scan_results[request.scan_id])
            else:
                raise HTTPException(status_code=400, detail=f"Unknown action: {request.action}")

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
            except Exception as e:
                ctx.log(f"Module {name} failed: {e}", level="ERROR")
                success = False

            # Emit module end
            await emit_module_end(scan_id, name, success)

            await asyncio.sleep(0.5)  # Yield to event loop

        # Store results
        _scan_results[scan_id] = ctx.data
        _scans[scan_id].status = "completed"
        _scans[scan_id].progress = 100
        _scans[scan_id].completed_at = datetime.now(UTC).isoformat() + "Z"
        _scans[scan_id].current_module = None

        # Emit completion
        await emit_scan_completed(scan_id, len(ctx.data))

    except Exception as e:
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
</head>
<body class="bg-gray-900 text-gray-100 min-h-screen">
    <div x-data="dashboard()" x-init="init()">
        <!-- Header -->
        <header class="bg-gray-800 border-b border-gray-700 px-6 py-4">
            <div class="flex items-center justify-between">
                <div class="flex items-center space-x-3">
                    <span class="text-2xl">🔴</span>
                    <h1 class="text-xl font-bold text-red-500">RedOPS</h1>
                    <span class="text-gray-500 text-sm" x-text="'v' + version"></span>
                </div>
                <div class="flex items-center space-x-4">
                    <span class="text-sm" :class="wsStatus === 'Connected' ? 'text-green-400' : 'text-yellow-400'" x-text="'WS: ' + wsStatus"></span>
                    <span class="text-sm text-gray-400" x-text="health"></span>
                    <!-- Auth status -->
                    <template x-if="authEnabled && authenticated">
                        <div class="flex items-center space-x-2">
                            <span class="text-sm text-green-400" x-text="'User: ' + username"></span>
                            <button @click="logout()" class="text-xs text-gray-400 hover:text-gray-200 px-2 py-1 border border-gray-600 rounded">Logout</button>
                        </div>
                    </template>
                </div>
            </div>
        </header>

        <!-- Login Modal -->
        <template x-if="authEnabled && !authenticated && showLogin">
            <div class="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
                <div class="bg-gray-800 rounded-lg p-8 w-96 shadow-xl">
                    <h2 class="text-xl font-bold mb-6 text-center">Login to RedOPS</h2>
                    <form @submit.prevent="login()">
                        <div class="mb-4">
                            <label class="block text-sm text-gray-400 mb-2">Username</label>
                            <input type="text" x-model="loginForm.username" required
                                class="w-full bg-gray-700 border border-gray-600 rounded px-4 py-2 focus:outline-none focus:border-red-500">
                        </div>
                        <div class="mb-6">
                            <label class="block text-sm text-gray-400 mb-2">Password</label>
                            <input type="password" x-model="loginForm.password" required
                                class="w-full bg-gray-700 border border-gray-600 rounded px-4 py-2 focus:outline-none focus:border-red-500">
                        </div>
                        <p x-show="loginError" class="text-red-400 text-sm mb-4" x-text="loginError"></p>
                        <button type="submit" :disabled="loggingIn"
                            class="w-full bg-red-600 hover:bg-red-700 disabled:bg-gray-600 py-2 rounded font-medium transition">
                            <span x-show="!loggingIn">Login</span>
                            <span x-show="loggingIn">Logging in...</span>
                        </button>
                    </form>
                </div>
            </div>
        </template>

        <div class="container mx-auto px-6 py-8">
            <!-- New Scan Form -->
            <div class="bg-gray-800 rounded-lg p-6 mb-8">
                <h2 class="text-lg font-semibold mb-4">New Scan</h2>
                <form @submit.prevent="startScan()" class="flex flex-wrap gap-4">
                    <input type="text" x-model="newScan.target" placeholder="Target (e.g., example.com)"
                        class="flex-1 min-w-64 bg-gray-700 border border-gray-600 rounded px-4 py-2 focus:outline-none focus:border-red-500">
                    <select x-model="newScan.preset" class="bg-gray-700 border border-gray-600 rounded px-4 py-2">
                        <template x-for="preset in presets" :key="preset.id">
                            <option :value="preset.id" x-text="preset.name"></option>
                        </template>
                    </select>
                    <button type="submit" :disabled="!newScan.target || scanning"
                        class="bg-red-600 hover:bg-red-700 disabled:bg-gray-600 px-6 py-2 rounded font-medium transition">
                        <span x-show="!scanning">Start Scan</span>
                        <span x-show="scanning">Starting...</span>
                    </button>
                </form>
            </div>

            <!-- Scans List -->
            <div class="bg-gray-800 rounded-lg p-6 mb-8">
                <div class="flex items-center justify-between mb-4">
                    <h2 class="text-lg font-semibold">Recent Scans</h2>
                    <button @click="loadScans()" class="text-sm text-gray-400 hover:text-gray-200">Refresh</button>
                </div>
                <div class="overflow-x-auto">
                    <table class="w-full">
                        <thead>
                            <tr class="text-left text-gray-400 text-sm border-b border-gray-700">
                                <th class="pb-3">ID</th>
                                <th class="pb-3">Target</th>
                                <th class="pb-3">Preset</th>
                                <th class="pb-3">Status</th>
                                <th class="pb-3">Progress</th>
                                <th class="pb-3">Started</th>
                                <th class="pb-3">Actions</th>
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
                                            class="text-red-400 hover:text-red-300 text-sm">View</button>
                                    </td>
                                </tr>
                            </template>
                            <tr x-show="scans.length === 0">
                                <td colspan="7" class="py-8 text-center text-gray-500">No scans yet. Start one above.</td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </div>

            <!-- Results Panel -->
            <div x-show="selectedScan" class="bg-gray-800 rounded-lg p-6">
                <div class="flex items-center justify-between mb-4">
                    <h2 class="text-lg font-semibold">Scan Results: <span x-text="selectedScan"></span></h2>
                    <button @click="selectedScan = null" class="text-gray-400 hover:text-gray-200">&times;</button>
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
                    } catch (e) {
                        console.error('Failed to load results:', e);
                    }
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
