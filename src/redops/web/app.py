"""
RedOPS Web UI - FastAPI application.

Provides a REST API and web dashboard for RedOPS functionality.
"""

import os
from datetime import datetime
from typing import Optional

from fastapi import FastAPI, HTTPException, BackgroundTasks, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

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


# In-memory scan storage (for demo; use database in production)
_scans: dict[str, ScanStatus] = {}
_scan_results: dict[str, dict] = {}


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    app = FastAPI(
        title="RedOPS API",
        description="REST API for RedOPS security assessment framework",
        version=__version__,
        docs_url="/api/docs",
        redoc_url="/api/redoc",
    )

    # CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],  # Configure for production
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Health check
    @app.get("/api/health", response_model=HealthResponse, tags=["System"])
    async def health_check():
        """Check API health status."""
        return HealthResponse(
            status="healthy",
            version=__version__,
            timestamp=datetime.utcnow().isoformat() + "Z",
        )

    # Scan endpoints
    @app.post("/api/scans", response_model=ScanResponse, tags=["Scans"])
    async def start_scan(request: ScanRequest, background_tasks: BackgroundTasks):
        """Start a new security scan."""
        import uuid

        scan_id = str(uuid.uuid4())[:8]
        now = datetime.utcnow().isoformat() + "Z"

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
    ):
        """List all scans."""
        scans = list(_scans.values())
        if status:
            scans = [s for s in scans if s.status == status]
        return sorted(scans, key=lambda s: s.started_at, reverse=True)[:limit]

    @app.get("/api/scans/{scan_id}", response_model=ScanStatus, tags=["Scans"])
    async def get_scan(scan_id: str):
        """Get scan status by ID."""
        if scan_id not in _scans:
            raise HTTPException(status_code=404, detail="Scan not found")
        return _scans[scan_id]

    @app.get("/api/scans/{scan_id}/results", tags=["Scans"])
    async def get_scan_results(scan_id: str):
        """Get scan results."""
        if scan_id not in _scans:
            raise HTTPException(status_code=404, detail="Scan not found")
        if _scans[scan_id].status != "completed":
            raise HTTPException(status_code=400, detail="Scan not completed")
        if scan_id not in _scan_results:
            raise HTTPException(status_code=404, detail="Results not available")
        return _scan_results[scan_id]

    # AI endpoints
    @app.post("/api/ai", response_model=AIResponse, tags=["AI"])
    async def ai_action(request: AIRequest):
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

    return app


async def run_scan_task(scan_id: str, request: ScanRequest):
    """Background task to run a scan."""
    import asyncio

    try:
        _scans[scan_id].status = "running"
        _scans[scan_id].progress = 0

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
            _scans[scan_id].progress = int((i / len(modules)) * 100)

            try:
                ctx = module_fn(ctx)
            except Exception as e:
                ctx.log(f"Module {name} failed: {e}", level="ERROR")

            await asyncio.sleep(0.5)  # Yield to event loop

        # Store results
        _scan_results[scan_id] = ctx.data
        _scans[scan_id].status = "completed"
        _scans[scan_id].progress = 100
        _scans[scan_id].completed_at = datetime.utcnow().isoformat() + "Z"
        _scans[scan_id].current_module = None

    except Exception as e:
        _scans[scan_id].status = "failed"
        _scans[scan_id].error = str(e)


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
                    <span class="text-sm text-gray-400" x-text="health"></span>
                </div>
            </div>
        </header>

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
                scans: [],
                presets: [],
                newScan: { target: '', preset: 'quick' },
                scanning: false,
                selectedScan: null,
                results: null,
                pollInterval: null,

                async init() {
                    await this.checkHealth();
                    await this.loadPresets();
                    await this.loadScans();
                    this.pollInterval = setInterval(() => this.loadScans(), 5000);
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
                            await this.loadScans();
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
