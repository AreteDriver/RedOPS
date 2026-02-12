"""
WebSocket manager for real-time scan updates.

Provides broadcast functionality for scan progress and completion events.
"""

import json
from typing import Any
from dataclasses import dataclass, asdict
from enum import Enum


class EventType(Enum):
    """WebSocket event types."""

    SCAN_STARTED = "scan_started"
    SCAN_PROGRESS = "scan_progress"
    SCAN_MODULE_START = "scan_module_start"
    SCAN_MODULE_END = "scan_module_end"
    SCAN_COMPLETED = "scan_completed"
    SCAN_FAILED = "scan_failed"
    FINDING_ADDED = "finding_added"
    CONNECTION = "connection"


@dataclass
class WSEvent:
    """WebSocket event message."""

    event: str
    data: dict[str, Any]
    scan_id: str | None = None
    timestamp: str | None = None

    def to_json(self) -> str:
        """Serialize to JSON."""
        return json.dumps(asdict(self))


class ConnectionManager:
    """
    Manages WebSocket connections and broadcasts.

    Supports:
    - Multiple clients per connection
    - Scan-specific subscriptions
    - Broadcast to all or filtered clients
    """

    def __init__(self):
        """Initialize connection manager."""
        self.active_connections: set = set()
        self.scan_subscriptions: dict[str, set] = {}  # scan_id -> websockets

    async def connect(self, websocket) -> None:
        """
        Accept and register a new WebSocket connection.

        Args:
            websocket: FastAPI WebSocket instance
        """
        await websocket.accept()
        self.active_connections.add(websocket)

        # Send connection confirmation
        await self.send_personal(
            websocket,
            WSEvent(
                event=EventType.CONNECTION.value,
                data={
                    "status": "connected",
                    "message": "WebSocket connected successfully",
                },
            ),
        )

    def disconnect(self, websocket) -> None:
        """
        Remove a WebSocket connection.

        Args:
            websocket: FastAPI WebSocket instance
        """
        self.active_connections.discard(websocket)

        # Remove from all scan subscriptions
        for scan_id in list(self.scan_subscriptions.keys()):
            self.scan_subscriptions[scan_id].discard(websocket)
            if not self.scan_subscriptions[scan_id]:
                del self.scan_subscriptions[scan_id]

    def subscribe_to_scan(self, websocket, scan_id: str) -> None:
        """
        Subscribe a websocket to scan updates.

        Args:
            websocket: FastAPI WebSocket instance
            scan_id: Scan ID to subscribe to
        """
        if scan_id not in self.scan_subscriptions:
            self.scan_subscriptions[scan_id] = set()
        self.scan_subscriptions[scan_id].add(websocket)

    def unsubscribe_from_scan(self, websocket, scan_id: str) -> None:
        """
        Unsubscribe a websocket from scan updates.

        Args:
            websocket: FastAPI WebSocket instance
            scan_id: Scan ID to unsubscribe from
        """
        if scan_id in self.scan_subscriptions:
            self.scan_subscriptions[scan_id].discard(websocket)

    async def send_personal(self, websocket, event: WSEvent) -> None:
        """
        Send event to a specific websocket.

        Args:
            websocket: Target WebSocket
            event: Event to send
        """
        try:
            await websocket.send_text(event.to_json())
        except Exception:
            self.disconnect(websocket)

    async def broadcast(self, event: WSEvent) -> None:
        """
        Broadcast event to all connected clients.

        Args:
            event: Event to broadcast
        """
        disconnected = set()
        for websocket in self.active_connections:
            try:
                await websocket.send_text(event.to_json())
            except Exception:
                disconnected.add(websocket)

        # Clean up disconnected clients
        for ws in disconnected:
            self.disconnect(ws)

    async def broadcast_to_scan(self, scan_id: str, event: WSEvent) -> None:
        """
        Broadcast event to clients subscribed to a specific scan.

        Args:
            scan_id: Scan ID
            event: Event to broadcast
        """
        if scan_id not in self.scan_subscriptions:
            return

        disconnected = set()
        for websocket in self.scan_subscriptions[scan_id]:
            try:
                await websocket.send_text(event.to_json())
            except Exception:
                disconnected.add(websocket)

        # Clean up disconnected clients
        for ws in disconnected:
            self.disconnect(ws)

    def get_stats(self) -> dict[str, Any]:
        """Get connection statistics."""
        return {
            "total_connections": len(self.active_connections),
            "scan_subscriptions": {
                scan_id: len(clients)
                for scan_id, clients in self.scan_subscriptions.items()
            },
        }


# Global connection manager instance
manager = ConnectionManager()


async def emit_scan_started(scan_id: str, target: str, preset: str) -> None:
    """Emit scan started event."""
    from datetime import datetime, timezone

    await manager.broadcast(
        WSEvent(
            event=EventType.SCAN_STARTED.value,
            scan_id=scan_id,
            data={"target": target, "preset": preset},
            timestamp=datetime.now(timezone.utc).isoformat() + "Z",
        )
    )


async def emit_scan_progress(
    scan_id: str,
    progress: int,
    current_module: str | None = None,
) -> None:
    """Emit scan progress event."""
    from datetime import datetime, timezone

    event = WSEvent(
        event=EventType.SCAN_PROGRESS.value,
        scan_id=scan_id,
        data={"progress": progress, "current_module": current_module},
        timestamp=datetime.now(timezone.utc).isoformat() + "Z",
    )

    # Broadcast to all and to scan subscribers
    await manager.broadcast(event)


async def emit_module_start(scan_id: str, module_name: str) -> None:
    """Emit module start event."""
    from datetime import datetime, timezone

    await manager.broadcast_to_scan(
        scan_id,
        WSEvent(
            event=EventType.SCAN_MODULE_START.value,
            scan_id=scan_id,
            data={"module": module_name},
            timestamp=datetime.now(timezone.utc).isoformat() + "Z",
        ),
    )


async def emit_module_end(scan_id: str, module_name: str, success: bool = True) -> None:
    """Emit module end event."""
    from datetime import datetime, timezone

    await manager.broadcast_to_scan(
        scan_id,
        WSEvent(
            event=EventType.SCAN_MODULE_END.value,
            scan_id=scan_id,
            data={"module": module_name, "success": success},
            timestamp=datetime.now(timezone.utc).isoformat() + "Z",
        ),
    )


async def emit_scan_completed(scan_id: str, findings_count: int = 0) -> None:
    """Emit scan completed event."""
    from datetime import datetime, timezone

    await manager.broadcast(
        WSEvent(
            event=EventType.SCAN_COMPLETED.value,
            scan_id=scan_id,
            data={"findings_count": findings_count},
            timestamp=datetime.now(timezone.utc).isoformat() + "Z",
        )
    )


async def emit_scan_failed(scan_id: str, error: str) -> None:
    """Emit scan failed event."""
    from datetime import datetime, timezone

    await manager.broadcast(
        WSEvent(
            event=EventType.SCAN_FAILED.value,
            scan_id=scan_id,
            data={"error": error},
            timestamp=datetime.now(timezone.utc).isoformat() + "Z",
        )
    )


async def emit_finding(
    scan_id: str,
    severity: str,
    title: str,
    module: str,
) -> None:
    """Emit finding added event."""
    from datetime import datetime, timezone

    await manager.broadcast_to_scan(
        scan_id,
        WSEvent(
            event=EventType.FINDING_ADDED.value,
            scan_id=scan_id,
            data={"severity": severity, "title": title, "module": module},
            timestamp=datetime.now(timezone.utc).isoformat() + "Z",
        ),
    )
