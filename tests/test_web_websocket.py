"""Tests for WebSocket module."""

import json
import pytest
from unittest.mock import MagicMock, AsyncMock, patch

from redops.web.websocket import (
    EventType,
    WSEvent,
    ConnectionManager,
    manager,
    emit_scan_started,
    emit_scan_progress,
    emit_module_start,
    emit_module_end,
    emit_scan_completed,
    emit_scan_failed,
    emit_finding,
)


class TestEventType:
    """Tests for EventType enum."""

    def test_scan_started(self):
        """Test scan started event type."""
        assert EventType.SCAN_STARTED.value == "scan_started"

    def test_scan_progress(self):
        """Test scan progress event type."""
        assert EventType.SCAN_PROGRESS.value == "scan_progress"

    def test_scan_module_start(self):
        """Test module start event type."""
        assert EventType.SCAN_MODULE_START.value == "scan_module_start"

    def test_scan_module_end(self):
        """Test module end event type."""
        assert EventType.SCAN_MODULE_END.value == "scan_module_end"

    def test_scan_completed(self):
        """Test scan completed event type."""
        assert EventType.SCAN_COMPLETED.value == "scan_completed"

    def test_scan_failed(self):
        """Test scan failed event type."""
        assert EventType.SCAN_FAILED.value == "scan_failed"

    def test_finding_added(self):
        """Test finding added event type."""
        assert EventType.FINDING_ADDED.value == "finding_added"

    def test_connection(self):
        """Test connection event type."""
        assert EventType.CONNECTION.value == "connection"


class TestWSEvent:
    """Tests for WSEvent dataclass."""

    def test_basic_creation(self):
        """Test basic event creation."""
        event = WSEvent(event="test", data={"key": "value"})
        assert event.event == "test"
        assert event.data == {"key": "value"}

    def test_with_scan_id(self):
        """Test event with scan ID."""
        event = WSEvent(event="test", data={}, scan_id="scan-123")
        assert event.scan_id == "scan-123"

    def test_with_timestamp(self):
        """Test event with timestamp."""
        event = WSEvent(event="test", data={}, timestamp="2024-01-15T10:00:00Z")
        assert event.timestamp == "2024-01-15T10:00:00Z"

    def test_to_json(self):
        """Test JSON serialization."""
        event = WSEvent(event="test", data={"key": "value"}, scan_id="scan-123")
        j = event.to_json()
        parsed = json.loads(j)
        assert parsed["event"] == "test"
        assert parsed["data"] == {"key": "value"}
        assert parsed["scan_id"] == "scan-123"

    def test_to_json_with_none(self):
        """Test JSON serialization with None fields."""
        event = WSEvent(event="test", data={})
        j = event.to_json()
        parsed = json.loads(j)
        assert parsed["scan_id"] is None
        assert parsed["timestamp"] is None


class TestConnectionManager:
    """Tests for ConnectionManager class."""

    def test_init(self):
        """Test initialization."""
        cm = ConnectionManager()
        assert len(cm.active_connections) == 0
        assert len(cm.scan_subscriptions) == 0

    @pytest.mark.asyncio
    async def test_connect(self):
        """Test connecting a websocket."""
        cm = ConnectionManager()
        ws = AsyncMock()

        await cm.connect(ws)

        assert ws in cm.active_connections
        ws.accept.assert_called_once()
        ws.send_text.assert_called_once()

    def test_disconnect(self):
        """Test disconnecting a websocket."""
        cm = ConnectionManager()
        ws = MagicMock()
        cm.active_connections.add(ws)

        cm.disconnect(ws)

        assert ws not in cm.active_connections

    def test_disconnect_removes_from_subscriptions(self):
        """Test disconnect removes from all subscriptions."""
        cm = ConnectionManager()
        ws = MagicMock()
        cm.active_connections.add(ws)
        cm.scan_subscriptions["scan-1"] = {ws}
        cm.scan_subscriptions["scan-2"] = {ws}

        cm.disconnect(ws)

        assert "scan-1" not in cm.scan_subscriptions
        assert "scan-2" not in cm.scan_subscriptions

    def test_subscribe_to_scan(self):
        """Test subscribing to a scan."""
        cm = ConnectionManager()
        ws = MagicMock()

        cm.subscribe_to_scan(ws, "scan-123")

        assert ws in cm.scan_subscriptions["scan-123"]

    def test_subscribe_to_scan_multiple(self):
        """Test multiple subscriptions to same scan."""
        cm = ConnectionManager()
        ws1 = MagicMock()
        ws2 = MagicMock()

        cm.subscribe_to_scan(ws1, "scan-123")
        cm.subscribe_to_scan(ws2, "scan-123")

        assert ws1 in cm.scan_subscriptions["scan-123"]
        assert ws2 in cm.scan_subscriptions["scan-123"]

    def test_unsubscribe_from_scan(self):
        """Test unsubscribing from a scan."""
        cm = ConnectionManager()
        ws = MagicMock()
        cm.scan_subscriptions["scan-123"] = {ws}

        cm.unsubscribe_from_scan(ws, "scan-123")

        assert ws not in cm.scan_subscriptions.get("scan-123", set())

    def test_unsubscribe_nonexistent_scan(self):
        """Test unsubscribing from nonexistent scan."""
        cm = ConnectionManager()
        ws = MagicMock()

        # Should not raise
        cm.unsubscribe_from_scan(ws, "nonexistent")

    @pytest.mark.asyncio
    async def test_send_personal(self):
        """Test sending personal message."""
        cm = ConnectionManager()
        ws = AsyncMock()
        event = WSEvent(event="test", data={})

        await cm.send_personal(ws, event)

        ws.send_text.assert_called_once()

    @pytest.mark.asyncio
    async def test_send_personal_handles_error(self):
        """Test send personal handles errors."""
        cm = ConnectionManager()
        ws = AsyncMock()
        ws.send_text.side_effect = Exception("Connection closed")
        cm.active_connections.add(ws)
        event = WSEvent(event="test", data={})

        await cm.send_personal(ws, event)

        # Should disconnect on error
        assert ws not in cm.active_connections

    @pytest.mark.asyncio
    async def test_broadcast(self):
        """Test broadcasting to all connections."""
        cm = ConnectionManager()
        ws1 = AsyncMock()
        ws2 = AsyncMock()
        cm.active_connections.add(ws1)
        cm.active_connections.add(ws2)
        event = WSEvent(event="test", data={})

        await cm.broadcast(event)

        ws1.send_text.assert_called_once()
        ws2.send_text.assert_called_once()

    @pytest.mark.asyncio
    async def test_broadcast_handles_disconnects(self):
        """Test broadcast handles disconnected clients."""
        cm = ConnectionManager()
        ws1 = AsyncMock()
        ws2 = AsyncMock()
        ws2.send_text.side_effect = Exception("Disconnected")
        cm.active_connections.add(ws1)
        cm.active_connections.add(ws2)
        event = WSEvent(event="test", data={})

        await cm.broadcast(event)

        # ws2 should be disconnected
        assert ws2 not in cm.active_connections
        assert ws1 in cm.active_connections

    @pytest.mark.asyncio
    async def test_broadcast_to_scan(self):
        """Test broadcasting to scan subscribers."""
        cm = ConnectionManager()
        ws1 = AsyncMock()
        ws2 = AsyncMock()
        ws3 = AsyncMock()
        cm.active_connections.add(ws1)
        cm.active_connections.add(ws2)
        cm.active_connections.add(ws3)
        cm.subscribe_to_scan(ws1, "scan-123")
        cm.subscribe_to_scan(ws2, "scan-123")
        event = WSEvent(event="test", data={})

        await cm.broadcast_to_scan("scan-123", event)

        ws1.send_text.assert_called_once()
        ws2.send_text.assert_called_once()
        ws3.send_text.assert_not_called()

    @pytest.mark.asyncio
    async def test_broadcast_to_nonexistent_scan(self):
        """Test broadcasting to nonexistent scan."""
        cm = ConnectionManager()
        event = WSEvent(event="test", data={})

        # Should not raise
        await cm.broadcast_to_scan("nonexistent", event)

    def test_get_stats(self):
        """Test getting connection stats."""
        cm = ConnectionManager()
        ws1 = MagicMock()
        ws2 = MagicMock()
        cm.active_connections.add(ws1)
        cm.active_connections.add(ws2)
        cm.subscribe_to_scan(ws1, "scan-1")
        cm.subscribe_to_scan(ws2, "scan-1")
        cm.subscribe_to_scan(ws2, "scan-2")

        stats = cm.get_stats()

        assert stats["total_connections"] == 2
        assert stats["scan_subscriptions"]["scan-1"] == 2
        assert stats["scan_subscriptions"]["scan-2"] == 1


class TestEmitFunctions:
    """Tests for emit helper functions."""

    @pytest.mark.asyncio
    async def test_emit_scan_started(self):
        """Test emit scan started."""
        with patch.object(
            manager, "broadcast", new_callable=AsyncMock
        ) as mock_broadcast:
            await emit_scan_started("scan-123", "example.com", "quick")

            mock_broadcast.assert_called_once()
            event = mock_broadcast.call_args[0][0]
            assert event.event == "scan_started"
            assert event.scan_id == "scan-123"
            assert event.data["target"] == "example.com"

    @pytest.mark.asyncio
    async def test_emit_scan_progress(self):
        """Test emit scan progress."""
        with patch.object(
            manager, "broadcast", new_callable=AsyncMock
        ) as mock_broadcast:
            await emit_scan_progress("scan-123", 50, "domain_scan")

            mock_broadcast.assert_called_once()
            event = mock_broadcast.call_args[0][0]
            assert event.event == "scan_progress"
            assert event.data["progress"] == 50
            assert event.data["current_module"] == "domain_scan"

    @pytest.mark.asyncio
    async def test_emit_module_start(self):
        """Test emit module start."""
        with patch.object(
            manager, "broadcast_to_scan", new_callable=AsyncMock
        ) as mock_broadcast:
            await emit_module_start("scan-123", "domain_scan")

            mock_broadcast.assert_called_once()
            call_args = mock_broadcast.call_args
            assert call_args[0][0] == "scan-123"
            event = call_args[0][1]
            assert event.event == "scan_module_start"
            assert event.data["module"] == "domain_scan"

    @pytest.mark.asyncio
    async def test_emit_module_end(self):
        """Test emit module end."""
        with patch.object(
            manager, "broadcast_to_scan", new_callable=AsyncMock
        ) as mock_broadcast:
            await emit_module_end("scan-123", "domain_scan", success=True)

            mock_broadcast.assert_called_once()
            event = mock_broadcast.call_args[0][1]
            assert event.event == "scan_module_end"
            assert event.data["module"] == "domain_scan"
            assert event.data["success"] is True

    @pytest.mark.asyncio
    async def test_emit_scan_completed(self):
        """Test emit scan completed."""
        with patch.object(
            manager, "broadcast", new_callable=AsyncMock
        ) as mock_broadcast:
            await emit_scan_completed("scan-123", findings_count=10)

            mock_broadcast.assert_called_once()
            event = mock_broadcast.call_args[0][0]
            assert event.event == "scan_completed"
            assert event.data["findings_count"] == 10

    @pytest.mark.asyncio
    async def test_emit_scan_failed(self):
        """Test emit scan failed."""
        with patch.object(
            manager, "broadcast", new_callable=AsyncMock
        ) as mock_broadcast:
            await emit_scan_failed("scan-123", "Connection timeout")

            mock_broadcast.assert_called_once()
            event = mock_broadcast.call_args[0][0]
            assert event.event == "scan_failed"
            assert event.data["error"] == "Connection timeout"

    @pytest.mark.asyncio
    async def test_emit_finding(self):
        """Test emit finding."""
        with patch.object(
            manager, "broadcast_to_scan", new_callable=AsyncMock
        ) as mock_broadcast:
            await emit_finding("scan-123", "critical", "SQL Injection", "vuln_scan")

            mock_broadcast.assert_called_once()
            event = mock_broadcast.call_args[0][1]
            assert event.event == "finding_added"
            assert event.data["severity"] == "critical"
            assert event.data["title"] == "SQL Injection"
            assert event.data["module"] == "vuln_scan"


class TestGlobalManager:
    """Tests for global manager instance."""

    def test_global_manager_exists(self):
        """Test global manager is initialized."""
        assert manager is not None
        assert isinstance(manager, ConnectionManager)
