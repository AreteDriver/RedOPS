"""
RF Operator Dashboard — FastAPI router with SSE streaming.

Provides REST endpoints for session management, target discovery,
tool orchestration, AI analysis, and a real-time SSE event stream
backed by the RedOPS event bus.
"""

import asyncio
import json
import logging
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, AsyncGenerator

from fastapi import APIRouter, FastAPI, HTTPException, Request
from pydantic import BaseModel, Field
from sse_starlette.sse import EventSourceResponse

from redops.core.event_bus import (
    AsyncEventBus,
    Event,
    create_async_event_bus,
)
from redops.modules.rf.ai_client import AIClient

logger = logging.getLogger(__name__)

# =====================================================================
# Pydantic models
# =====================================================================


class SessionStatus(str, Enum):
    """RF session lifecycle states."""

    CREATED = "created"
    ACTIVE = "active"
    ENDED = "ended"


class ToolState(str, Enum):
    """Running tool states."""

    RUNNING = "running"
    STOPPED = "stopped"
    ERROR = "error"


# --- Request models ---


class CreateSessionRequest(BaseModel):
    """Body for POST /sessions."""

    name: str = Field(..., min_length=1, max_length=128)
    notes: str = Field(default="", max_length=4096)


class StartToolRequest(BaseModel):
    """Body for POST /tools/start."""

    tool_name: str = Field(..., min_length=1, max_length=64)
    interface: str = Field(..., min_length=1, max_length=32)
    args: dict[str, Any] = Field(default_factory=dict)


class AnalyzeRequest(BaseModel):
    """Body for POST /analyze."""

    objective: str = Field(
        default="identify_priority_targets",
        max_length=256,
    )


# --- Response models ---


class InterfaceStatus(BaseModel):
    """Wireless interface status."""

    name: str
    mode: str = "managed"
    channel: int | None = None
    mac: str | None = None


class StatusResponse(BaseModel):
    """Response for GET /status."""

    interfaces: list[InterfaceStatus] = Field(default_factory=list)
    running_tools: list[str] = Field(default_factory=list)
    active_session_id: str | None = None
    uptime_seconds: float = 0.0


class TargetResponse(BaseModel):
    """Single discovered target."""

    target_id: str
    essid: str | None = None
    bssid: str
    encryption: str = "unknown"
    signal: int = -100
    channel: int = 0
    wps: bool = False
    clients: int = 0
    first_seen: str
    last_seen: str
    captures: list[str] = Field(default_factory=list)
    findings: list[str] = Field(default_factory=list)


class TargetListResponse(BaseModel):
    """Response for GET /targets."""

    count: int
    targets: list[TargetResponse]


class SessionResponse(BaseModel):
    """Single session."""

    session_id: str
    name: str
    notes: str = ""
    status: SessionStatus
    created_at: str
    started_at: str | None = None
    ended_at: str | None = None
    target_count: int = 0
    capture_count: int = 0


class SessionListResponse(BaseModel):
    """Response for GET /sessions."""

    count: int
    sessions: list[SessionResponse]


class RunningToolResponse(BaseModel):
    """A currently running tool."""

    tool_id: str
    tool_name: str
    interface: str
    args: dict[str, Any] = Field(default_factory=dict)
    state: ToolState
    started_at: str
    pid: int | None = None


class RunningToolsResponse(BaseModel):
    """Response for GET /tools/running."""

    count: int
    tools: list[RunningToolResponse]


class CaptureResponse(BaseModel):
    """A capture file entry."""

    capture_id: str
    target_bssid: str
    capture_type: str
    file_path: str | None = None
    packet_count: int = 0
    created_at: str


class CaptureListResponse(BaseModel):
    """Response for GET /captures."""

    count: int
    captures: list[CaptureResponse]


class AnalyzeResponse(BaseModel):
    """Response for POST /analyze."""

    recommendations: list[dict[str, Any]] = Field(
        default_factory=list,
    )
    raw_response: str | None = None
    model: str | None = None


class AuditLogEntry(BaseModel):
    """Single audit log event."""

    event_id: str
    event_type: str
    timestamp: str
    source: str = ""
    data: dict[str, Any] = Field(default_factory=dict)


class AuditLogResponse(BaseModel):
    """Response for GET /audit-log."""

    count: int
    events: list[AuditLogEntry]


class MessageResponse(BaseModel):
    """Generic message response."""

    message: str
    detail: dict[str, Any] = Field(default_factory=dict)


# =====================================================================
# In-memory state (replaced by persistence layer in production)
# =====================================================================


class _RFState:
    """Shared mutable state for the RF module."""

    def __init__(self) -> None:
        self.sessions: dict[str, dict[str, Any]] = {}
        self.active_session_id: str | None = None
        self.targets: dict[str, dict[str, Any]] = {}
        self.running_tools: dict[str, dict[str, Any]] = {}
        self.captures: list[dict[str, Any]] = []
        self.start_time: datetime = datetime.now(tz=timezone.utc)
        self.event_bus: AsyncEventBus = create_async_event_bus()
        self.ai_client: AIClient = AIClient()


_state = _RFState()

# =====================================================================
# Router
# =====================================================================

router = APIRouter(prefix="/api/rf", tags=["rf"])


# ------------------------------------------------------------------
# GET /status
# ------------------------------------------------------------------


@router.get(
    "/status",
    response_model=StatusResponse,
    summary="Current RF operator status",
)
async def get_status() -> StatusResponse:
    """Return interface status, running tools, and active session."""
    uptime = (datetime.now(tz=timezone.utc) - _state.start_time).total_seconds()
    return StatusResponse(
        interfaces=[],
        running_tools=[t["tool_name"] for t in _state.running_tools.values()],
        active_session_id=_state.active_session_id,
        uptime_seconds=round(uptime, 2),
    )


# ------------------------------------------------------------------
# Targets
# ------------------------------------------------------------------


@router.get(
    "/targets",
    response_model=TargetListResponse,
    summary="List discovered targets",
)
async def list_targets() -> TargetListResponse:
    """Return all targets discovered in the active session."""
    targets = [TargetResponse(**t) for t in _state.targets.values()]
    return TargetListResponse(count=len(targets), targets=targets)


@router.get(
    "/targets/{target_id}",
    response_model=TargetResponse,
    summary="Target detail",
)
async def get_target(target_id: str) -> TargetResponse:
    """Return detail for a single target including clients and captures."""
    target = _state.targets.get(target_id)
    if target is None:
        raise HTTPException(status_code=404, detail="Target not found")
    return TargetResponse(**target)


# ------------------------------------------------------------------
# Sessions
# ------------------------------------------------------------------


@router.get(
    "/sessions",
    response_model=SessionListResponse,
    summary="List all sessions",
)
async def list_sessions() -> SessionListResponse:
    """Return all RF sessions."""
    sessions = [SessionResponse(**s) for s in _state.sessions.values()]
    return SessionListResponse(
        count=len(sessions),
        sessions=sessions,
    )


@router.get(
    "/sessions/{session_id}",
    response_model=SessionResponse,
    summary="Session detail",
)
async def get_session(session_id: str) -> SessionResponse:
    """Return detail for a specific session."""
    session = _state.sessions.get(session_id)
    if session is None:
        raise HTTPException(
            status_code=404,
            detail="Session not found",
        )
    return SessionResponse(**session)


@router.post(
    "/sessions",
    response_model=SessionResponse,
    status_code=201,
    summary="Create a new session",
)
async def create_session(
    body: CreateSessionRequest,
) -> SessionResponse:
    """Create a new RF session."""
    session_id = str(uuid.uuid4())
    now = datetime.now(tz=timezone.utc).isoformat()
    session: dict[str, Any] = {
        "session_id": session_id,
        "name": body.name,
        "notes": body.notes,
        "status": SessionStatus.CREATED,
        "created_at": now,
        "started_at": None,
        "ended_at": None,
        "target_count": 0,
        "capture_count": 0,
    }
    _state.sessions[session_id] = session

    await _emit_event("session_created", {"session_id": session_id})
    logger.info("Session created: %s (%s)", session_id, body.name)
    return SessionResponse(**session)


@router.post(
    "/sessions/{session_id}/start",
    response_model=SessionResponse,
    summary="Start a session",
)
async def start_session(session_id: str) -> SessionResponse:
    """Activate a session for scanning."""
    session = _state.sessions.get(session_id)
    if session is None:
        raise HTTPException(
            status_code=404,
            detail="Session not found",
        )
    if session["status"] == SessionStatus.ACTIVE:
        raise HTTPException(
            status_code=409,
            detail="Session already active",
        )

    now = datetime.now(tz=timezone.utc).isoformat()
    session["status"] = SessionStatus.ACTIVE
    session["started_at"] = now
    _state.active_session_id = session_id

    await _emit_event(
        "session_started",
        {"session_id": session_id},
    )
    logger.info("Session started: %s", session_id)
    return SessionResponse(**session)


@router.post(
    "/sessions/{session_id}/end",
    response_model=SessionResponse,
    summary="End a session",
)
async def end_session(session_id: str) -> SessionResponse:
    """End an active session."""
    session = _state.sessions.get(session_id)
    if session is None:
        raise HTTPException(
            status_code=404,
            detail="Session not found",
        )
    if session["status"] == SessionStatus.ENDED:
        raise HTTPException(
            status_code=409,
            detail="Session already ended",
        )

    now = datetime.now(tz=timezone.utc).isoformat()
    session["status"] = SessionStatus.ENDED
    session["ended_at"] = now
    if _state.active_session_id == session_id:
        _state.active_session_id = None

    await _emit_event(
        "session_ended",
        {"session_id": session_id},
    )
    logger.info("Session ended: %s", session_id)
    return SessionResponse(**session)


# ------------------------------------------------------------------
# Tools
# ------------------------------------------------------------------


@router.post(
    "/tools/start",
    response_model=RunningToolResponse,
    status_code=201,
    summary="Start an RF tool",
)
async def start_tool(body: StartToolRequest) -> RunningToolResponse:
    """Launch an RF tool on the specified interface."""
    tool_id = str(uuid.uuid4())
    now = datetime.now(tz=timezone.utc).isoformat()
    tool_entry: dict[str, Any] = {
        "tool_id": tool_id,
        "tool_name": body.tool_name,
        "interface": body.interface,
        "args": body.args,
        "state": ToolState.RUNNING,
        "started_at": now,
        "pid": None,
    }
    _state.running_tools[tool_id] = tool_entry

    await _emit_event(
        "tool_started",
        {
            "tool_id": tool_id,
            "tool_name": body.tool_name,
            "interface": body.interface,
        },
    )
    logger.info(
        "Tool started: %s (%s on %s)",
        tool_id,
        body.tool_name,
        body.interface,
    )
    return RunningToolResponse(**tool_entry)


@router.post(
    "/tools/{tool_id}/stop",
    response_model=RunningToolResponse,
    summary="Stop a running tool",
)
async def stop_tool(tool_id: str) -> RunningToolResponse:
    """Stop a running tool by its ID."""
    tool_entry = _state.running_tools.get(tool_id)
    if tool_entry is None:
        raise HTTPException(
            status_code=404,
            detail="Tool not found",
        )
    if tool_entry["state"] != ToolState.RUNNING:
        raise HTTPException(
            status_code=409,
            detail="Tool is not running",
        )

    tool_entry["state"] = ToolState.STOPPED

    await _emit_event(
        "tool_stopped",
        {
            "tool_id": tool_id,
            "tool_name": tool_entry["tool_name"],
        },
    )
    logger.info("Tool stopped: %s", tool_id)
    return RunningToolResponse(**tool_entry)


@router.get(
    "/tools/running",
    response_model=RunningToolsResponse,
    summary="List running tools",
)
async def list_running_tools() -> RunningToolsResponse:
    """Return all currently running tools."""
    running = [
        RunningToolResponse(**t)
        for t in _state.running_tools.values()
        if t["state"] == ToolState.RUNNING
    ]
    return RunningToolsResponse(count=len(running), tools=running)


# ------------------------------------------------------------------
# SSE stream
# ------------------------------------------------------------------


@router.get(
    "/stream",
    summary="SSE event stream",
)
async def event_stream(request: Request) -> EventSourceResponse:
    """Server-Sent Events endpoint for real-time RF updates.

    Streams events from the internal event bus: ap_discovered,
    handshake_captured, pmkid_captured, tool_started, tool_stopped,
    alert, and more.
    """
    return EventSourceResponse(
        _sse_generator(request),
        media_type="text/event-stream",
    )


async def _sse_generator(
    request: Request,
) -> AsyncGenerator[dict[str, str], None]:
    """Yield SSE-formatted dicts from the event bus.

    Args:
        request: The incoming HTTP request (used to detect
                 client disconnect).

    Yields:
        Dicts with ``event`` and ``data`` keys consumed by
        ``EventSourceResponse``.
    """
    queue: asyncio.Queue[Event] = asyncio.Queue()

    async def _handler(event: Event) -> None:
        await queue.put(event)

    sub = await _state.event_bus.subscribe(handler=_handler)

    try:
        while not await request.is_disconnected():
            try:
                event = await asyncio.wait_for(
                    queue.get(),
                    timeout=15.0,
                )
                yield {
                    "event": event.event_type,
                    "data": json.dumps(event.to_dict()),
                }
            except asyncio.TimeoutError:
                # Send keepalive comment
                yield {"event": "keepalive", "data": ""}
    finally:
        await _state.event_bus.unsubscribe(sub)


# ------------------------------------------------------------------
# AI analysis
# ------------------------------------------------------------------


@router.post(
    "/analyze",
    response_model=AnalyzeResponse,
    summary="Trigger AI analysis on current scan data",
)
async def analyze(body: AnalyzeRequest) -> AnalyzeResponse:
    """Send current targets to the AI client for analysis."""
    targets = list(_state.targets.values())
    if not targets:
        raise HTTPException(
            status_code=422,
            detail="No targets available for analysis",
        )

    try:
        result = await _state.ai_client.analyze_scan(
            targets=targets,
            objective=body.objective,
        )
    except (OSError, RuntimeError, TypeError, ValueError, ConnectionError) as exc:
        logger.error("AI analysis failed: %s", exc)
        raise HTTPException(
            status_code=502,
            detail=f"AI analysis failed: {exc}",
        ) from exc

    await _emit_event(
        "ai_analysis_complete",
        {"objective": body.objective, "target_count": len(targets)},
    )

    return AnalyzeResponse(
        recommendations=result.get("recommendations", []),
        raw_response=result.get("raw_response"),
        model=_state.ai_client.model,
    )


# ------------------------------------------------------------------
# Captures
# ------------------------------------------------------------------


@router.get(
    "/captures",
    response_model=CaptureListResponse,
    summary="List captures for active session",
)
async def list_captures() -> CaptureListResponse:
    """Return capture files associated with the active session."""
    captures = [CaptureResponse(**c) for c in _state.captures]
    return CaptureListResponse(
        count=len(captures),
        captures=captures,
    )


# ------------------------------------------------------------------
# Audit log
# ------------------------------------------------------------------


@router.get(
    "/audit-log",
    response_model=AuditLogResponse,
    summary="Recent events from event bus",
)
async def get_audit_log(
    limit: int = 100,
) -> AuditLogResponse:
    """Return recent events from the event bus ring buffer."""
    store = _state.event_bus._event_store
    events: list[Event] = []
    if store is not None:
        events = store.get_events(limit=limit)

    entries = [
        AuditLogEntry(
            event_id=e.id,
            event_type=e.event_type,
            timestamp=e.timestamp.isoformat(),
            source=e.source,
            data=e._get_data(),
        )
        for e in events
    ]
    return AuditLogResponse(count=len(entries), events=entries)


# =====================================================================
# Helpers
# =====================================================================


async def _emit_event(
    event_type: str,
    data: dict[str, Any],
) -> None:
    """Publish a typed event to the internal event bus.

    Args:
        event_type: Short snake_case event name.
        data: Arbitrary payload dict.
    """
    event = Event(
        source="rf_dashboard",
        metadata={"rf_event_type": event_type, **data},
    )
    await _state.event_bus.publish(event)


# =====================================================================
# Registration helper
# =====================================================================


def register_rf_routes(app: FastAPI) -> None:
    """Mount the RF operator router onto a FastAPI application.

    Args:
        app: The FastAPI application instance.
    """
    app.include_router(router)
    logger.info("RF dashboard routes registered at /api/rf")
