"""Tests for WebSocket manager."""

import pytest
from unittest.mock import AsyncMock, MagicMock

# Skip tests if fastapi is not installed (optional dependency)
pytest.importorskip("fastapi")

from redops.web.websocket import (
    ConnectionManager,
    WSEvent,
    EventType,
    emit_scan_started,
    emit_scan_progress,
    emit_scan_completed,
    emit_scan_failed,
)


class TestWSEvent:
    """Tests for WSEvent dataclass."""

    def test_to_json(self):
        """Test event serialization."""
        event = WSEvent(
            event="test_event",
            data={"key": "value"},
            scan_id="abc123",
        )
        json_str = event.to_json()

        assert '"event": "test_event"' in json_str
        assert '"scan_id": "abc123"' in json_str
        assert '"key": "value"' in json_str


class TestConnectionManager:
    """Tests for ConnectionManager."""

    @pytest.fixture
    def manager(self):
        """Create a connection manager."""
        return ConnectionManager()

    @pytest.fixture
    def mock_websocket(self):
        """Create a mock websocket."""
        ws = AsyncMock()
        ws.accept = AsyncMock()
        ws.send_text = AsyncMock()
        return ws

    async def test_connect(self, manager, mock_websocket):
        """Test connecting a websocket."""
        await manager.connect(mock_websocket)

        assert mock_websocket in manager.active_connections
        mock_websocket.accept.assert_called_once()
        mock_websocket.send_text.assert_called_once()

    def test_disconnect(self, manager, mock_websocket):
        """Test disconnecting a websocket."""
        manager.active_connections.add(mock_websocket)
        manager.scan_subscriptions["scan1"] = {mock_websocket}

        manager.disconnect(mock_websocket)

        assert mock_websocket not in manager.active_connections
        assert "scan1" not in manager.scan_subscriptions

    def test_subscribe_to_scan(self, manager, mock_websocket):
        """Test subscribing to a scan."""
        manager.subscribe_to_scan(mock_websocket, "scan123")

        assert mock_websocket in manager.scan_subscriptions["scan123"]

    def test_unsubscribe_from_scan(self, manager, mock_websocket):
        """Test unsubscribing from a scan."""
        manager.scan_subscriptions["scan123"] = {mock_websocket}

        manager.unsubscribe_from_scan(mock_websocket, "scan123")

        assert mock_websocket not in manager.scan_subscriptions.get("scan123", set())

    async def test_send_personal(self, manager, mock_websocket):
        """Test sending to a specific websocket."""
        event = WSEvent(event="test", data={})

        await manager.send_personal(mock_websocket, event)

        mock_websocket.send_text.assert_called_once()
        call_arg = mock_websocket.send_text.call_args[0][0]
        assert '"event": "test"' in call_arg

    async def test_broadcast(self, manager):
        """Test broadcasting to all connections."""
        ws1 = AsyncMock()
        ws2 = AsyncMock()
        manager.active_connections = {ws1, ws2}

        event = WSEvent(event="broadcast", data={"msg": "hello"})
        await manager.broadcast(event)

        ws1.send_text.assert_called_once()
        ws2.send_text.assert_called_once()

    async def test_broadcast_to_scan(self, manager):
        """Test broadcasting to scan subscribers."""
        ws1 = AsyncMock()
        ws2 = AsyncMock()
        ws_other = AsyncMock()

        manager.active_connections = {ws1, ws2, ws_other}
        manager.scan_subscriptions["scan1"] = {ws1, ws2}

        event = WSEvent(event="scan_update", scan_id="scan1", data={})
        await manager.broadcast_to_scan("scan1", event)

        ws1.send_text.assert_called_once()
        ws2.send_text.assert_called_once()
        ws_other.send_text.assert_not_called()

    async def test_broadcast_handles_disconnected(self, manager):
        """Test that broadcast removes disconnected clients."""
        ws_good = AsyncMock()
        ws_bad = AsyncMock()
        ws_bad.send_text.side_effect = OSError("Connection closed")

        manager.active_connections = {ws_good, ws_bad}

        event = WSEvent(event="test", data={})
        await manager.broadcast(event)

        assert ws_good in manager.active_connections
        assert ws_bad not in manager.active_connections

    def test_get_stats(self, manager, mock_websocket):
        """Test getting connection stats."""
        manager.active_connections = {mock_websocket}
        manager.scan_subscriptions = {"scan1": {mock_websocket}}

        stats = manager.get_stats()

        assert stats["total_connections"] == 1
        assert stats["scan_subscriptions"]["scan1"] == 1


class TestEmitFunctions:
    """Tests for emit helper functions."""

    @pytest.fixture
    def mock_manager(self, monkeypatch):
        """Mock the global manager."""
        mock = MagicMock()
        mock.broadcast = AsyncMock()
        mock.broadcast_to_scan = AsyncMock()
        monkeypatch.setattr("redops.web.websocket.manager", mock)
        return mock

    async def test_emit_scan_started(self, mock_manager):
        """Test emit_scan_started."""
        await emit_scan_started("scan123", "example.com", "quick")

        mock_manager.broadcast.assert_called_once()
        event = mock_manager.broadcast.call_args[0][0]
        assert event.event == EventType.SCAN_STARTED.value
        assert event.scan_id == "scan123"
        assert event.data["target"] == "example.com"

    async def test_emit_scan_progress(self, mock_manager):
        """Test emit_scan_progress."""
        await emit_scan_progress("scan123", 50, "domain_profile")

        mock_manager.broadcast.assert_called_once()
        event = mock_manager.broadcast.call_args[0][0]
        assert event.event == EventType.SCAN_PROGRESS.value
        assert event.data["progress"] == 50
        assert event.data["current_module"] == "domain_profile"

    async def test_emit_scan_completed(self, mock_manager):
        """Test emit_scan_completed."""
        await emit_scan_completed("scan123", 5)

        mock_manager.broadcast.assert_called_once()
        event = mock_manager.broadcast.call_args[0][0]
        assert event.event == EventType.SCAN_COMPLETED.value
        assert event.data["findings_count"] == 5

    async def test_emit_scan_failed(self, mock_manager):
        """Test emit_scan_failed."""
        await emit_scan_failed("scan123", "Connection timeout")

        mock_manager.broadcast.assert_called_once()
        event = mock_manager.broadcast.call_args[0][0]
        assert event.event == EventType.SCAN_FAILED.value
        assert event.data["error"] == "Connection timeout"


class TestEventType:
    """Tests for EventType enum."""

    def test_event_types(self):
        """Test event type values."""
        assert EventType.SCAN_STARTED.value == "scan_started"
        assert EventType.SCAN_PROGRESS.value == "scan_progress"
        assert EventType.SCAN_COMPLETED.value == "scan_completed"
        assert EventType.SCAN_FAILED.value == "scan_failed"
        assert EventType.FINDING_ADDED.value == "finding_added"
