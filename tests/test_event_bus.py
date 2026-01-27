"""Tests for event bus module."""

import asyncio
import os
import tempfile
import threading
import time
from datetime import datetime, timedelta
from unittest.mock import MagicMock

import pytest

from redops.core.event_bus import (
    # Enums
    EventPriority,
    EventStatus,
    # Base classes
    Event,
    DomainEvent,
    Subscription,
    # Event types
    ScanStartedEvent,
    ScanCompletedEvent,
    ScanFailedEvent,
    FindingDiscoveredEvent,
    ModuleExecutedEvent,
    ErrorOccurredEvent,
    # Event stores
    MemoryEventStore,
    FileEventStore,
    # Dead letter queue
    DeadLetterQueue,
    # Event buses
    EventBus,
    AsyncEventBus,
    BackgroundEventBus,
    # Utilities
    EventAggregator,
    EventReplay,
    EventEmitter,
    # Convenience functions
    create_event_bus,
    create_async_event_bus,
    get_event_bus,
    set_event_bus,
    publish,
    subscribe,
)


# =============================================================================
# EventPriority Tests
# =============================================================================


class TestEventPriority:
    """Tests for EventPriority enum."""

    def test_priority_values(self):
        """Test priority ordering."""
        assert EventPriority.LOW.value < EventPriority.NORMAL.value
        assert EventPriority.NORMAL.value < EventPriority.HIGH.value
        assert EventPriority.HIGH.value < EventPriority.CRITICAL.value


class TestEventStatus:
    """Tests for EventStatus enum."""

    def test_all_statuses(self):
        """Test all status values exist."""
        assert EventStatus.PENDING.value == "pending"
        assert EventStatus.PROCESSING.value == "processing"
        assert EventStatus.COMPLETED.value == "completed"
        assert EventStatus.FAILED.value == "failed"
        assert EventStatus.RETRYING.value == "retrying"


# =============================================================================
# Event Tests
# =============================================================================


class TestEvent:
    """Tests for base Event class."""

    def test_create_basic(self):
        """Test basic event creation."""
        event = Event()
        assert event.id is not None
        assert event.timestamp is not None
        assert event.priority == EventPriority.NORMAL

    def test_create_with_fields(self):
        """Test event with all fields."""
        event = Event(
            source="test-source",
            correlation_id="corr-123",
            causation_id="cause-456",
            priority=EventPriority.HIGH,
            metadata={"key": "value"},
        )
        assert event.source == "test-source"
        assert event.correlation_id == "corr-123"
        assert event.causation_id == "cause-456"
        assert event.priority == EventPriority.HIGH
        assert event.metadata == {"key": "value"}

    def test_event_type(self):
        """Test event_type property."""
        event = Event()
        assert event.event_type == "Event"

        scan_event = ScanStartedEvent()
        assert scan_event.event_type == "ScanStartedEvent"

    def test_to_dict(self):
        """Test conversion to dictionary."""
        event = Event(source="test", correlation_id="corr-1")
        data = event.to_dict()

        assert data["id"] == event.id
        assert data["type"] == "Event"
        assert data["source"] == "test"
        assert data["correlation_id"] == "corr-1"
        assert "timestamp" in data

    def test_from_dict(self):
        """Test creation from dictionary."""
        data = {
            "id": "test-id",
            "source": "test-source",
            "correlation_id": "corr-1",
            "priority": 2,
            "timestamp": "2024-01-01T12:00:00",
        }
        event = Event.from_dict(data)

        assert event.id == "test-id"
        assert event.source == "test-source"
        assert event.correlation_id == "corr-1"
        assert event.priority == EventPriority.HIGH

    def test_with_correlation(self):
        """Test with_correlation method."""
        event = Event()
        result = event.with_correlation("corr-123")

        assert result is event  # Same object
        assert event.correlation_id == "corr-123"

    def test_caused_by(self):
        """Test caused_by method."""
        cause = Event(correlation_id="shared-corr")
        effect = Event()

        result = effect.caused_by(cause)

        assert result is effect
        assert effect.causation_id == cause.id
        assert effect.correlation_id == "shared-corr"

    def test_unique_ids(self):
        """Test events have unique IDs."""
        events = [Event() for _ in range(100)]
        ids = [e.id for e in events]
        assert len(set(ids)) == 100


class TestDomainEvent:
    """Tests for DomainEvent class."""

    def test_create(self):
        """Test domain event creation."""
        event = DomainEvent(
            aggregate_type="Order",
            aggregate_id="order-123",
            version=1,
        )
        assert event.aggregate_type == "Order"
        assert event.aggregate_id == "order-123"
        assert event.version == 1


# =============================================================================
# Specific Event Types Tests
# =============================================================================


class TestSpecificEventTypes:
    """Tests for specific event types."""

    def test_scan_started_event(self):
        """Test ScanStartedEvent."""
        event = ScanStartedEvent(
            target="example.com",
            scan_type="recon",
            options={"depth": 3},
        )
        assert event.target == "example.com"
        assert event.scan_type == "recon"
        assert event.options == {"depth": 3}

    def test_scan_completed_event(self):
        """Test ScanCompletedEvent."""
        event = ScanCompletedEvent(
            target="example.com",
            scan_type="recon",
            duration_seconds=45.5,
            findings_count=10,
        )
        assert event.duration_seconds == 45.5
        assert event.findings_count == 10

    def test_scan_failed_event(self):
        """Test ScanFailedEvent."""
        event = ScanFailedEvent(
            target="example.com",
            error="Connection timeout",
            error_type="TimeoutError",
        )
        assert event.error == "Connection timeout"
        assert event.error_type == "TimeoutError"

    def test_finding_discovered_event(self):
        """Test FindingDiscoveredEvent."""
        event = FindingDiscoveredEvent(
            finding_id="finding-1",
            severity="high",
            category="vulnerability",
            title="SQL Injection",
            target="example.com",
        )
        assert event.severity == "high"
        assert event.title == "SQL Injection"

    def test_module_executed_event(self):
        """Test ModuleExecutedEvent."""
        event = ModuleExecutedEvent(
            module_name="dns_resolver",
            duration_seconds=2.5,
            success=True,
        )
        assert event.module_name == "dns_resolver"
        assert event.success is True

    def test_error_occurred_event(self):
        """Test ErrorOccurredEvent."""
        event = ErrorOccurredEvent(
            error_type="ValueError",
            error_message="Invalid input",
            stack_trace="...",
            context={"input": "bad"},
        )
        assert event.error_type == "ValueError"
        assert event.context == {"input": "bad"}


# =============================================================================
# Subscription Tests
# =============================================================================


class TestSubscription:
    """Tests for Subscription class."""

    def test_create_basic(self):
        """Test basic subscription creation."""
        handler = MagicMock()
        sub = Subscription(handler=handler)

        assert sub.id is not None
        assert sub.handler is handler
        assert sub.event_type is None
        assert sub.is_active

    def test_create_with_type(self):
        """Test subscription with event type."""
        handler = MagicMock()
        sub = Subscription(handler=handler, event_type=ScanStartedEvent)

        assert sub.event_type == ScanStartedEvent

    def test_matches_any_event(self):
        """Test subscription matches any event."""
        sub = Subscription(handler=MagicMock())

        assert sub.matches(Event())
        assert sub.matches(ScanStartedEvent())

    def test_matches_specific_type(self):
        """Test subscription matches specific type."""
        sub = Subscription(handler=MagicMock(), event_type=ScanStartedEvent)

        assert sub.matches(ScanStartedEvent())
        assert not sub.matches(Event())
        assert not sub.matches(ScanCompletedEvent())

    def test_matches_with_filter(self):
        """Test subscription with filter function."""
        sub = Subscription(
            handler=MagicMock(),
            filter_fn=lambda e: e.priority == EventPriority.HIGH,
        )

        high_event = Event(priority=EventPriority.HIGH)
        low_event = Event(priority=EventPriority.LOW)

        assert sub.matches(high_event)
        assert not sub.matches(low_event)

    def test_cancel(self):
        """Test subscription cancellation."""
        sub = Subscription(handler=MagicMock())
        assert sub.is_active

        sub.cancel()
        assert not sub.is_active
        assert not sub.matches(Event())


# =============================================================================
# MemoryEventStore Tests
# =============================================================================


class TestMemoryEventStore:
    """Tests for MemoryEventStore."""

    @pytest.fixture
    def store(self):
        """Create memory store."""
        return MemoryEventStore()

    def test_append_and_get(self, store):
        """Test appending and getting events."""
        event = Event(source="test")
        store.append(event)

        retrieved = store.get_by_id(event.id)
        assert retrieved is event

    def test_get_events_all(self, store):
        """Test getting all events."""
        for i in range(5):
            store.append(Event(source=f"source-{i}"))

        events = store.get_events()
        assert len(events) == 5

    def test_get_events_by_type(self, store):
        """Test filtering by event type."""
        store.append(Event())
        store.append(ScanStartedEvent())
        store.append(ScanCompletedEvent())

        events = store.get_events(event_type="ScanStartedEvent")
        assert len(events) == 1
        assert events[0].event_type == "ScanStartedEvent"

    def test_get_events_by_time(self, store):
        """Test filtering by time range."""
        old_event = Event()
        old_event.timestamp = datetime.now() - timedelta(hours=2)
        store.append(old_event)

        new_event = Event()
        store.append(new_event)

        since = datetime.now() - timedelta(hours=1)
        events = store.get_events(since=since)
        assert len(events) == 1

    def test_get_events_by_correlation(self, store):
        """Test filtering by correlation ID."""
        store.append(Event(correlation_id="corr-1"))
        store.append(Event(correlation_id="corr-2"))
        store.append(Event(correlation_id="corr-1"))

        events = store.get_events(correlation_id="corr-1")
        assert len(events) == 2

    def test_get_events_limit(self, store):
        """Test limit on returned events."""
        for i in range(10):
            store.append(Event())

        events = store.get_events(limit=3)
        assert len(events) == 3

    def test_count(self, store):
        """Test counting events."""
        store.append(Event())
        store.append(ScanStartedEvent())
        store.append(ScanStartedEvent())

        assert store.count() == 3
        assert store.count(event_type="ScanStartedEvent") == 2

    def test_max_events_trim(self):
        """Test trimming when over max."""
        store = MemoryEventStore(max_events=5)

        for i in range(10):
            store.append(Event(source=f"event-{i}"))

        assert store.count() == 5
        # Oldest should be removed
        events = store.get_events()
        sources = [e.source for e in events]
        assert "event-0" not in sources

    def test_clear(self, store):
        """Test clearing store."""
        for i in range(5):
            store.append(Event())

        store.clear()
        assert store.count() == 0


# =============================================================================
# FileEventStore Tests
# =============================================================================


class TestFileEventStore:
    """Tests for FileEventStore."""

    @pytest.fixture
    def temp_file(self):
        """Create temporary file."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".jsonl") as f:
            yield f.name
        if os.path.exists(f.name):
            os.unlink(f.name)

    def test_append_and_persist(self, temp_file):
        """Test appending and persistence."""
        store = FileEventStore(temp_file)
        event = Event(source="test")
        store.append(event)

        # Create new store to verify persistence
        store2 = FileEventStore(temp_file)
        events = store2.get_events()
        assert len(events) == 1
        assert events[0].source == "test"

    def test_get_by_id(self, temp_file):
        """Test getting by ID."""
        store = FileEventStore(temp_file)
        event = Event(source="test")
        store.append(event)

        retrieved = store.get_by_id(event.id)
        assert retrieved is not None
        assert retrieved.id == event.id

    def test_count(self, temp_file):
        """Test counting events."""
        store = FileEventStore(temp_file)
        store.append(Event())
        store.append(ScanStartedEvent())

        assert store.count() == 2
        assert store.count(event_type="Event") == 1


# =============================================================================
# DeadLetterQueue Tests
# =============================================================================


class TestDeadLetterQueue:
    """Tests for DeadLetterQueue."""

    @pytest.fixture
    def dlq(self):
        """Create dead letter queue."""
        return DeadLetterQueue()

    def test_add_and_get(self, dlq):
        """Test adding and getting entries."""
        event = Event()
        handler = MagicMock()
        error = ValueError("test error")

        dlq.add(event, handler, error)

        entries = dlq.get_all()
        assert len(entries) == 1
        assert entries[0]["error"] == "test error"
        assert entries[0]["error_type"] == "ValueError"

    def test_count(self, dlq):
        """Test counting entries."""
        dlq.add(Event(), MagicMock(), ValueError("e1"))
        dlq.add(Event(), MagicMock(), ValueError("e2"))

        assert dlq.count() == 2

    def test_clear(self, dlq):
        """Test clearing queue."""
        dlq.add(Event(), MagicMock(), ValueError("e"))
        dlq.clear()

        assert dlq.count() == 0

    def test_max_size(self):
        """Test max size enforcement."""
        dlq = DeadLetterQueue(max_size=5)

        for i in range(10):
            dlq.add(Event(), MagicMock(), ValueError(f"e{i}"))

        assert dlq.count() == 5


# =============================================================================
# EventBus Tests
# =============================================================================


class TestEventBus:
    """Tests for EventBus."""

    @pytest.fixture
    def bus(self):
        """Create event bus."""
        return EventBus()

    def test_subscribe_and_publish(self, bus):
        """Test basic subscribe and publish."""
        received = []
        bus.subscribe(lambda e: received.append(e))

        event = Event()
        handlers_called = bus.publish(event)

        assert handlers_called == 1
        assert received == [event]

    def test_subscribe_by_type(self, bus):
        """Test subscribing to specific type."""
        received = []
        bus.subscribe(
            lambda e: received.append(e),
            event_type=ScanStartedEvent,
        )

        bus.publish(Event())  # Should not match
        bus.publish(ScanStartedEvent())  # Should match

        assert len(received) == 1
        assert isinstance(received[0], ScanStartedEvent)

    def test_subscribe_with_filter(self, bus):
        """Test subscribing with filter."""
        received = []
        bus.subscribe(
            lambda e: received.append(e),
            filter_fn=lambda e: e.priority == EventPriority.HIGH,
        )

        bus.publish(Event(priority=EventPriority.LOW))
        bus.publish(Event(priority=EventPriority.HIGH))

        assert len(received) == 1

    def test_handler_priority(self, bus):
        """Test handlers called in priority order."""
        order = []

        bus.subscribe(lambda e: order.append(1), priority=1)
        bus.subscribe(lambda e: order.append(3), priority=3)
        bus.subscribe(lambda e: order.append(2), priority=2)

        bus.publish(Event())

        assert order == [3, 2, 1]

    def test_once_subscription(self, bus):
        """Test one-time subscription."""
        received = []
        bus.subscribe(lambda e: received.append(e), once=True)

        bus.publish(Event())
        bus.publish(Event())

        assert len(received) == 1

    def test_unsubscribe(self, bus):
        """Test unsubscribing."""
        received = []
        sub = bus.subscribe(lambda e: received.append(e))

        bus.publish(Event())
        bus.unsubscribe(sub)
        bus.publish(Event())

        assert len(received) == 1

    def test_on_decorator(self, bus):
        """Test @on decorator."""
        received = []

        @bus.on(ScanStartedEvent)
        def handle_scan(event):
            received.append(event)

        bus.publish(ScanStartedEvent())
        assert len(received) == 1

    def test_once_decorator(self, bus):
        """Test @once decorator."""
        received = []

        @bus.once(Event)
        def handle_once(event):
            received.append(event)

        bus.publish(Event())
        bus.publish(Event())
        assert len(received) == 1

    def test_handler_error_caught(self, bus):
        """Test handler errors are caught."""

        def bad_handler(event):
            raise ValueError("test error")

        bus.subscribe(bad_handler)

        # Should not raise
        handlers = bus.publish(Event())
        assert handlers == 0  # Handler failed

        # Should be in dead letter queue
        assert bus.dead_letter_queue.count() == 1

    def test_clear(self, bus):
        """Test clearing subscriptions."""
        bus.subscribe(lambda e: None)
        bus.subscribe(lambda e: None)

        bus.clear()
        assert bus.subscription_count == 0

    def test_stats(self, bus):
        """Test statistics tracking."""
        bus.subscribe(lambda e: None)

        bus.publish(Event())
        bus.publish(Event())

        stats = bus.stats
        assert stats["events_published"] == 2
        assert stats["events_handled"] == 2

    def test_publish_all(self, bus):
        """Test publishing multiple events."""
        received = []
        bus.subscribe(lambda e: received.append(e))

        events = [Event(), Event(), Event()]
        total = bus.publish_all(events)

        assert total == 3
        assert len(received) == 3

    def test_with_event_store(self):
        """Test bus with event store."""
        store = MemoryEventStore()
        bus = EventBus(event_store=store)

        bus.publish(Event())
        bus.publish(Event())

        assert store.count() == 2


# =============================================================================
# AsyncEventBus Tests
# =============================================================================


class TestAsyncEventBus:
    """Tests for AsyncEventBus."""

    def test_subscribe_and_publish(self):
        """Test basic async subscribe and publish."""

        async def run_test():
            bus = AsyncEventBus()
            received = []

            async def handler(event):
                received.append(event)

            await bus.subscribe(handler)
            await bus.publish(Event())

            assert len(received) == 1

        asyncio.run(run_test())

    def test_sync_handler(self):
        """Test sync handler in async bus."""

        async def run_test():
            bus = AsyncEventBus()
            received = []

            def sync_handler(event):
                received.append(event)

            await bus.subscribe(sync_handler)
            await bus.publish(Event())

            assert len(received) == 1

        asyncio.run(run_test())

    def test_concurrent_publish(self):
        """Test concurrent handler execution."""

        async def run_test():
            bus = AsyncEventBus()
            call_times = []

            async def slow_handler(event):
                await asyncio.sleep(0.05)
                call_times.append(time.time())

            await bus.subscribe(slow_handler)
            await bus.subscribe(slow_handler)

            start = time.time()
            await bus.publish_concurrent(Event())
            duration = time.time() - start

            # Should complete in ~0.05s not ~0.1s (concurrent)
            assert duration < 0.08

        asyncio.run(run_test())

    def test_on_decorator(self):
        """Test @on decorator."""

        async def run_test():
            bus = AsyncEventBus()
            received = []

            @bus.on(ScanStartedEvent)
            async def handle_scan(event):
                received.append(event)

            await bus.publish(ScanStartedEvent())
            assert len(received) == 1

        asyncio.run(run_test())

    def test_clear(self):
        """Test clearing subscriptions."""

        async def run_test():
            bus = AsyncEventBus()
            await bus.subscribe(lambda e: None)
            await bus.clear()

            stats = bus.stats
            assert stats["events_published"] == 0

        asyncio.run(run_test())


# =============================================================================
# BackgroundEventBus Tests
# =============================================================================


class TestBackgroundEventBus:
    """Tests for BackgroundEventBus."""

    def test_start_stop(self):
        """Test starting and stopping."""
        bus = BackgroundEventBus()
        bus.start()
        assert bus._running

        bus.stop()
        assert not bus._running

    def test_context_manager(self):
        """Test context manager usage."""
        with BackgroundEventBus() as bus:
            assert bus._running
        assert not bus._running

    def test_publish_and_process(self):
        """Test publishing and background processing."""
        received = []

        with BackgroundEventBus() as bus:
            bus.subscribe(lambda e: received.append(e))
            bus.publish(Event())

            # Wait for processing
            time.sleep(0.2)

        assert len(received) == 1

    def test_queue_size(self):
        """Test queue size tracking."""
        bus = BackgroundEventBus()
        bus.start()

        # Don't subscribe - events won't be consumed immediately
        for i in range(5):
            bus.publish(Event(), block=False)

        # Give worker time to process
        time.sleep(0.2)

        bus.stop()

    def test_on_decorator(self):
        """Test @on decorator."""
        received = []

        with BackgroundEventBus() as bus:

            @bus.on(Event)
            def handler(event):
                received.append(event)

            bus.publish(Event())
            time.sleep(0.2)

        assert len(received) == 1

    def test_stats(self):
        """Test statistics."""
        with BackgroundEventBus() as bus:
            bus.subscribe(lambda e: None)
            bus.publish(Event())
            time.sleep(0.2)

            stats = bus.stats
            assert stats["events_queued"] == 1


# =============================================================================
# EventAggregator Tests
# =============================================================================


class TestEventAggregator:
    """Tests for EventAggregator."""

    def test_add_and_flush(self):
        """Test adding and manual flush."""
        aggregator = EventAggregator(window_seconds=10)

        aggregator.add(Event())
        aggregator.add(Event())

        events = aggregator.flush()
        assert len(events) == 2
        assert aggregator.pending_count == 0

    def test_auto_flush_on_max(self):
        """Test automatic flush on max events."""
        flushed = []

        aggregator = EventAggregator(
            max_events=3,
            on_flush=lambda events: flushed.extend(events),
        )

        aggregator.add(Event())
        aggregator.add(Event())
        assert len(flushed) == 0

        aggregator.add(Event())  # Should trigger flush
        assert len(flushed) == 3

    def test_auto_flush_on_timeout(self):
        """Test automatic flush on timeout."""
        flushed = []

        aggregator = EventAggregator(
            window_seconds=0.1,
            on_flush=lambda events: flushed.extend(events),
        )

        aggregator.add(Event())
        time.sleep(0.2)

        assert len(flushed) == 1

    def test_pending_count(self):
        """Test pending count tracking."""
        aggregator = EventAggregator()

        assert aggregator.pending_count == 0
        aggregator.add(Event())
        assert aggregator.pending_count == 1


# =============================================================================
# EventReplay Tests
# =============================================================================


class TestEventReplay:
    """Tests for EventReplay."""

    def test_replay(self):
        """Test replaying events."""
        store = MemoryEventStore()
        store.append(Event(source="e1"))
        store.append(Event(source="e2"))
        store.append(Event(source="e3"))

        replayed = []
        replay = EventReplay(store)
        count = replay.replay(lambda e: replayed.append(e))

        assert count == 3
        assert len(replayed) == 3

    def test_replay_with_filter(self):
        """Test replaying with filters."""
        store = MemoryEventStore()
        store.append(Event())
        store.append(ScanStartedEvent())

        replayed = []
        replay = EventReplay(store)
        count = replay.replay(
            lambda e: replayed.append(e),
            event_type="ScanStartedEvent",
        )

        assert count == 1

    def test_replay_to_bus(self):
        """Test replaying to an event bus."""
        store = MemoryEventStore()
        store.append(Event())
        store.append(Event())

        received = []
        bus = EventBus()
        bus.subscribe(lambda e: received.append(e))

        replay = EventReplay(store)
        replay.replay_to_bus(bus)

        assert len(received) == 2


# =============================================================================
# EventEmitter Tests
# =============================================================================


class TestEventEmitter:
    """Tests for EventEmitter mixin."""

    def test_emit_without_bus(self):
        """Test emitting without a bus."""
        emitter = EventEmitter()
        result = emitter.emit(Event())
        assert result == 0

    def test_emit_with_bus(self):
        """Test emitting with a bus."""
        received = []
        bus = EventBus()
        bus.subscribe(lambda e: received.append(e))

        emitter = EventEmitter(bus=bus)
        result = emitter.emit(Event())

        assert result == 1
        assert len(received) == 1

    def test_source_set(self):
        """Test source is set from emitter class name."""
        received = []
        bus = EventBus()
        bus.subscribe(lambda e: received.append(e))

        emitter = EventEmitter(bus=bus)
        emitter.emit(Event())

        assert received[0].source == "EventEmitter"

    def test_set_event_bus(self):
        """Test setting bus after creation."""
        received = []
        bus = EventBus()
        bus.subscribe(lambda e: received.append(e))

        emitter = EventEmitter()
        emitter.set_event_bus(bus)
        emitter.emit(Event())

        assert len(received) == 1

    def test_emit_many(self):
        """Test emitting multiple events."""
        received = []
        bus = EventBus()
        bus.subscribe(lambda e: received.append(e))

        emitter = EventEmitter(bus=bus)
        result = emitter.emit_many([Event(), Event(), Event()])

        assert result == 3
        assert len(received) == 3


# =============================================================================
# Convenience Function Tests
# =============================================================================


class TestConvenienceFunctions:
    """Tests for convenience functions."""

    def test_create_event_bus_memory(self):
        """Test creating memory-backed bus."""
        bus = create_event_bus(store_type="memory")
        bus.publish(Event())
        assert bus.stats["events_published"] == 1

    def test_create_event_bus_file(self):
        """Test creating file-backed bus."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            path = f.name

        try:
            bus = create_event_bus(store_type="file", store_path=path)
            bus.publish(Event())
        finally:
            os.unlink(path)

    def test_create_event_bus_file_requires_path(self):
        """Test file bus requires path."""
        with pytest.raises(ValueError):
            create_event_bus(store_type="file")

    def test_create_async_event_bus(self):
        """Test creating async bus."""
        bus = create_async_event_bus()
        assert isinstance(bus, AsyncEventBus)

    def test_global_event_bus(self):
        """Test global event bus."""
        # Reset global bus
        set_event_bus(EventBus())

        received = []
        subscribe(lambda e: received.append(e))
        publish(Event())

        assert len(received) == 1

    def test_get_creates_bus(self):
        """Test get_event_bus creates if needed."""
        # Reset global
        import redops.core.event_bus as eb

        eb._global_bus = None

        bus = get_event_bus()
        assert bus is not None

        # Should return same instance
        assert get_event_bus() is bus


# =============================================================================
# Integration Tests
# =============================================================================


class TestEventBusIntegration:
    """Integration tests for event bus."""

    def test_full_workflow(self):
        """Test complete event workflow."""
        store = MemoryEventStore()
        bus = EventBus(event_store=store)

        # Track events
        scan_starts = []
        scan_completes = []
        all_events = []

        bus.subscribe(lambda e: scan_starts.append(e), event_type=ScanStartedEvent)
        bus.subscribe(lambda e: scan_completes.append(e), event_type=ScanCompletedEvent)
        bus.subscribe(lambda e: all_events.append(e))

        # Simulate scan
        correlation = "scan-123"
        start_event = ScanStartedEvent(
            target="example.com",
            scan_type="recon",
        ).with_correlation(correlation)
        bus.publish(start_event)

        complete_event = ScanCompletedEvent(
            target="example.com",
            scan_type="recon",
            duration_seconds=10.5,
            findings_count=5,
        ).caused_by(start_event)
        bus.publish(complete_event)

        # Verify
        assert len(scan_starts) == 1
        assert len(scan_completes) == 1
        assert len(all_events) == 2

        # Verify causation chain
        assert complete_event.causation_id == start_event.id
        assert complete_event.correlation_id == correlation

        # Verify persistence
        stored = store.get_events(correlation_id=correlation)
        assert len(stored) == 2

    def test_error_handling_workflow(self):
        """Test error handling with dead letter queue."""
        bus = EventBus()
        errors = []

        def failing_handler(event):
            raise ValueError("Handler failed")

        def error_tracker(event):
            errors.append(event)

        bus.subscribe(failing_handler)
        bus.subscribe(error_tracker)  # Should still be called

        bus.publish(Event())

        assert len(errors) == 1  # Error tracker received event
        assert bus.dead_letter_queue.count() == 1  # Failed handler recorded

    def test_multi_threaded_publishing(self):
        """Test thread-safe publishing."""
        bus = EventBus()
        received = []
        lock = threading.Lock()

        def handler(event):
            with lock:
                received.append(event)

        bus.subscribe(handler)

        def publisher():
            for _ in range(100):
                bus.publish(Event())

        threads = [threading.Thread(target=publisher) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(received) == 500

    def test_replay_after_restart(self):
        """Test replaying events after restart."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".jsonl") as f:
            path = f.name

        try:
            # First session - publish events
            store1 = FileEventStore(path)
            bus1 = EventBus(event_store=store1)
            bus1.publish(ScanStartedEvent(target="example.com"))
            bus1.publish(ScanCompletedEvent(target="example.com"))

            # Second session - replay events
            store2 = FileEventStore(path)
            replayed = []

            replay = EventReplay(store2)
            replay.replay(lambda e: replayed.append(e))

            assert len(replayed) == 2
        finally:
            os.unlink(path)
