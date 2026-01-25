"""
Event Bus - Pub/sub messaging and event sourcing system.

Provides decoupled communication between components through events.
"""

import asyncio
import json
import logging
import queue
import threading
import time
import uuid
from abc import ABC, abstractmethod
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import (
    Any,
    Callable,
    Coroutine,
    Dict,
    Generic,
    List,
    Optional,
    Set,
    Type,
    TypeVar,
    Union,
)
from weakref import WeakSet

logger = logging.getLogger(__name__)


# Type variables
T = TypeVar("T", bound="Event")
HandlerType = Union[Callable[["Event"], None], Callable[["Event"], Coroutine[Any, Any, None]]]


class EventPriority(Enum):
    """Event priority levels."""

    LOW = 0
    NORMAL = 1
    HIGH = 2
    CRITICAL = 3


class EventStatus(Enum):
    """Event processing status."""

    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"
    RETRYING = "retrying"


@dataclass
class Event:
    """Base event class."""

    # Auto-generated fields
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=datetime.now)

    # Event metadata
    source: str = ""
    correlation_id: Optional[str] = None
    causation_id: Optional[str] = None
    priority: EventPriority = EventPriority.NORMAL
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def event_type(self) -> str:
        """Get the event type name."""
        return self.__class__.__name__

    def to_dict(self) -> Dict[str, Any]:
        """Convert event to dictionary."""
        return {
            "id": self.id,
            "type": self.event_type,
            "timestamp": self.timestamp.isoformat(),
            "source": self.source,
            "correlation_id": self.correlation_id,
            "causation_id": self.causation_id,
            "priority": self.priority.value,
            "metadata": self.metadata,
            "data": self._get_data(),
        }

    def _get_data(self) -> Dict[str, Any]:
        """Get event-specific data (override in subclasses)."""
        # Get all fields that aren't base Event fields
        base_fields = {"id", "timestamp", "source", "correlation_id",
                       "causation_id", "priority", "metadata"}
        return {
            k: v for k, v in self.__dict__.items()
            if k not in base_fields
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Event":
        """Create event from dictionary."""
        event = cls(
            id=data.get("id", str(uuid.uuid4())),
            source=data.get("source", ""),
            correlation_id=data.get("correlation_id"),
            causation_id=data.get("causation_id"),
            priority=EventPriority(data.get("priority", 1)),
            metadata=data.get("metadata", {}),
        )
        if "timestamp" in data:
            event.timestamp = datetime.fromisoformat(data["timestamp"])
        return event

    def with_correlation(self, correlation_id: str) -> "Event":
        """Return copy with correlation ID set."""
        self.correlation_id = correlation_id
        return self

    def caused_by(self, cause: "Event") -> "Event":
        """Set causation from another event."""
        self.causation_id = cause.id
        if cause.correlation_id:
            self.correlation_id = cause.correlation_id
        return self


@dataclass
class DomainEvent(Event):
    """Domain event with aggregate information."""

    aggregate_type: str = ""
    aggregate_id: str = ""
    version: int = 0


# Common event types

@dataclass
class ScanStartedEvent(Event):
    """Emitted when a scan starts."""
    target: str = ""
    scan_type: str = ""
    options: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ScanCompletedEvent(Event):
    """Emitted when a scan completes."""
    target: str = ""
    scan_type: str = ""
    duration_seconds: float = 0.0
    findings_count: int = 0


@dataclass
class ScanFailedEvent(Event):
    """Emitted when a scan fails."""
    target: str = ""
    scan_type: str = ""
    error: str = ""
    error_type: str = ""


@dataclass
class FindingDiscoveredEvent(Event):
    """Emitted when a finding is discovered."""
    finding_id: str = ""
    severity: str = ""
    category: str = ""
    title: str = ""
    target: str = ""


@dataclass
class ModuleExecutedEvent(Event):
    """Emitted when a pipeline module executes."""
    module_name: str = ""
    duration_seconds: float = 0.0
    success: bool = True
    error: Optional[str] = None


@dataclass
class ErrorOccurredEvent(Event):
    """Emitted when an error occurs."""
    error_type: str = ""
    error_message: str = ""
    stack_trace: Optional[str] = None
    context: Dict[str, Any] = field(default_factory=dict)


class Subscription:
    """Represents a subscription to events."""

    def __init__(
        self,
        handler: HandlerType,
        event_type: Optional[Type[Event]] = None,
        filter_fn: Optional[Callable[[Event], bool]] = None,
        priority: int = 0,
        once: bool = False,
    ):
        """
        Create a subscription.

        Args:
            handler: Function to call when event matches
            event_type: Optional specific event type to match
            filter_fn: Optional filter function
            priority: Handler priority (higher = called first)
            once: If True, unsubscribe after first match
        """
        self.id = str(uuid.uuid4())
        self.handler = handler
        self.event_type = event_type
        self.filter_fn = filter_fn
        self.priority = priority
        self.once = once
        self.call_count = 0
        self.created_at = datetime.now()
        self.last_called: Optional[datetime] = None
        self._active = True

    def matches(self, event: Event) -> bool:
        """Check if this subscription matches the event."""
        if not self._active:
            return False

        # Check event type
        if self.event_type is not None:
            if not isinstance(event, self.event_type):
                return False

        # Check filter
        if self.filter_fn is not None:
            try:
                if not self.filter_fn(event):
                    return False
            except Exception as e:
                logger.warning(f"Filter function failed: {e}")
                return False

        return True

    def cancel(self) -> None:
        """Cancel this subscription."""
        self._active = False

    @property
    def is_active(self) -> bool:
        """Check if subscription is active."""
        return self._active


class EventStore(ABC):
    """Abstract base class for event stores."""

    @abstractmethod
    def append(self, event: Event) -> None:
        """Append an event to the store."""
        pass

    @abstractmethod
    def get_events(
        self,
        event_type: Optional[str] = None,
        since: Optional[datetime] = None,
        until: Optional[datetime] = None,
        correlation_id: Optional[str] = None,
        limit: int = 100,
    ) -> List[Event]:
        """Query events from the store."""
        pass

    @abstractmethod
    def get_by_id(self, event_id: str) -> Optional[Event]:
        """Get a specific event by ID."""
        pass

    @abstractmethod
    def count(self, event_type: Optional[str] = None) -> int:
        """Count events in the store."""
        pass


class MemoryEventStore(EventStore):
    """In-memory event store."""

    def __init__(self, max_events: int = 10000):
        """Initialize memory store."""
        self._events: List[Event] = []
        self._by_id: Dict[str, Event] = {}
        self._max_events = max_events
        self._lock = threading.RLock()

    def append(self, event: Event) -> None:
        """Append an event."""
        with self._lock:
            self._events.append(event)
            self._by_id[event.id] = event

            # Trim if over limit
            if len(self._events) > self._max_events:
                removed = self._events[:-self._max_events]
                self._events = self._events[-self._max_events:]
                for e in removed:
                    self._by_id.pop(e.id, None)

    def get_events(
        self,
        event_type: Optional[str] = None,
        since: Optional[datetime] = None,
        until: Optional[datetime] = None,
        correlation_id: Optional[str] = None,
        limit: int = 100,
    ) -> List[Event]:
        """Query events."""
        with self._lock:
            result = self._events.copy()

        # Apply filters
        if event_type:
            result = [e for e in result if e.event_type == event_type]
        if since:
            result = [e for e in result if e.timestamp >= since]
        if until:
            result = [e for e in result if e.timestamp <= until]
        if correlation_id:
            result = [e for e in result if e.correlation_id == correlation_id]

        # Return most recent first, limited
        return sorted(result, key=lambda e: e.timestamp, reverse=True)[:limit]

    def get_by_id(self, event_id: str) -> Optional[Event]:
        """Get event by ID."""
        with self._lock:
            return self._by_id.get(event_id)

    def count(self, event_type: Optional[str] = None) -> int:
        """Count events."""
        with self._lock:
            if event_type:
                return sum(1 for e in self._events if e.event_type == event_type)
            return len(self._events)

    def clear(self) -> None:
        """Clear all events."""
        with self._lock:
            self._events.clear()
            self._by_id.clear()


class FileEventStore(EventStore):
    """File-based event store with append-only log."""

    def __init__(self, path: Union[str, Path]):
        """Initialize file store."""
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._cache: List[Event] = []
        self._loaded = False

    def _load(self) -> None:
        """Load events from file."""
        if self._loaded:
            return

        if self._path.exists():
            with self._lock:
                with self._path.open() as f:
                    for line in f:
                        try:
                            data = json.loads(line.strip())
                            event = Event.from_dict(data)
                            self._cache.append(event)
                        except (json.JSONDecodeError, KeyError):
                            continue
        self._loaded = True

    def append(self, event: Event) -> None:
        """Append event to file."""
        self._load()
        with self._lock:
            with self._path.open("a") as f:
                f.write(json.dumps(event.to_dict()) + "\n")
            self._cache.append(event)

    def get_events(
        self,
        event_type: Optional[str] = None,
        since: Optional[datetime] = None,
        until: Optional[datetime] = None,
        correlation_id: Optional[str] = None,
        limit: int = 100,
    ) -> List[Event]:
        """Query events."""
        self._load()
        with self._lock:
            result = self._cache.copy()

        if event_type:
            result = [e for e in result if e.event_type == event_type]
        if since:
            result = [e for e in result if e.timestamp >= since]
        if until:
            result = [e for e in result if e.timestamp <= until]
        if correlation_id:
            result = [e for e in result if e.correlation_id == correlation_id]

        return sorted(result, key=lambda e: e.timestamp, reverse=True)[:limit]

    def get_by_id(self, event_id: str) -> Optional[Event]:
        """Get event by ID."""
        self._load()
        with self._lock:
            for event in self._cache:
                if event.id == event_id:
                    return event
        return None

    def count(self, event_type: Optional[str] = None) -> int:
        """Count events."""
        self._load()
        with self._lock:
            if event_type:
                return sum(1 for e in self._cache if e.event_type == event_type)
            return len(self._cache)


class DeadLetterQueue:
    """Queue for failed event processing."""

    def __init__(self, max_size: int = 1000):
        """Initialize dead letter queue."""
        self._queue: List[Dict[str, Any]] = []
        self._max_size = max_size
        self._lock = threading.RLock()

    def add(
        self,
        event: Event,
        handler: HandlerType,
        error: Exception,
        attempt: int = 1,
    ) -> None:
        """Add a failed event to the queue."""
        with self._lock:
            self._queue.append({
                "event": event,
                "handler": str(handler),
                "error": str(error),
                "error_type": type(error).__name__,
                "attempt": attempt,
                "failed_at": datetime.now().isoformat(),
            })

            if len(self._queue) > self._max_size:
                self._queue = self._queue[-self._max_size:]

    def get_all(self) -> List[Dict[str, Any]]:
        """Get all dead letter entries."""
        with self._lock:
            return self._queue.copy()

    def count(self) -> int:
        """Count entries in queue."""
        with self._lock:
            return len(self._queue)

    def clear(self) -> None:
        """Clear the queue."""
        with self._lock:
            self._queue.clear()


class EventBus:
    """
    Synchronous event bus for pub/sub messaging.

    Features:
    - Type-based event routing
    - Handler priorities
    - Event filtering
    - One-time subscriptions
    - Dead letter queue for failures
    - Optional event store
    """

    def __init__(
        self,
        event_store: Optional[EventStore] = None,
        dead_letter_queue: Optional[DeadLetterQueue] = None,
    ):
        """
        Initialize event bus.

        Args:
            event_store: Optional store for event persistence
            dead_letter_queue: Optional queue for failed events
        """
        self._subscriptions: List[Subscription] = []
        self._event_store = event_store
        self._dlq = dead_letter_queue or DeadLetterQueue()
        self._lock = threading.RLock()
        self._stats = {
            "events_published": 0,
            "events_handled": 0,
            "events_failed": 0,
        }

    def subscribe(
        self,
        handler: HandlerType,
        event_type: Optional[Type[Event]] = None,
        filter_fn: Optional[Callable[[Event], bool]] = None,
        priority: int = 0,
        once: bool = False,
    ) -> Subscription:
        """
        Subscribe to events.

        Args:
            handler: Function to call when event matches
            event_type: Optional specific event type
            filter_fn: Optional filter function
            priority: Handler priority (higher = called first)
            once: If True, unsubscribe after first call

        Returns:
            Subscription object for management
        """
        sub = Subscription(
            handler=handler,
            event_type=event_type,
            filter_fn=filter_fn,
            priority=priority,
            once=once,
        )

        with self._lock:
            self._subscriptions.append(sub)
            # Sort by priority (descending)
            self._subscriptions.sort(key=lambda s: s.priority, reverse=True)

        return sub

    def unsubscribe(self, subscription: Subscription) -> bool:
        """
        Unsubscribe from events.

        Args:
            subscription: Subscription to remove

        Returns:
            True if removed, False if not found
        """
        subscription.cancel()
        with self._lock:
            if subscription in self._subscriptions:
                self._subscriptions.remove(subscription)
                return True
        return False

    def publish(self, event: Event) -> int:
        """
        Publish an event to all matching subscribers.

        Args:
            event: Event to publish

        Returns:
            Number of handlers called
        """
        # Store event if store configured
        if self._event_store:
            self._event_store.append(event)

        self._stats["events_published"] += 1

        # Get matching subscriptions
        with self._lock:
            matching = [s for s in self._subscriptions if s.matches(event)]

        # Call handlers
        handlers_called = 0
        to_remove = []

        for sub in matching:
            try:
                sub.handler(event)
                sub.call_count += 1
                sub.last_called = datetime.now()
                handlers_called += 1
                self._stats["events_handled"] += 1

                if sub.once:
                    to_remove.append(sub)

            except Exception as e:
                logger.error(f"Handler {sub.handler} failed: {e}")
                self._stats["events_failed"] += 1
                self._dlq.add(event, sub.handler, e)

        # Remove one-time subscriptions
        for sub in to_remove:
            self.unsubscribe(sub)

        return handlers_called

    def publish_all(self, events: List[Event]) -> int:
        """Publish multiple events."""
        total = 0
        for event in events:
            total += self.publish(event)
        return total

    def on(
        self,
        event_type: Type[T],
        priority: int = 0,
    ) -> Callable[[Callable[[T], None]], Callable[[T], None]]:
        """
        Decorator for subscribing to a specific event type.

        Usage:
            @bus.on(ScanStartedEvent)
            def handle_scan_started(event: ScanStartedEvent):
                print(f"Scan started: {event.target}")
        """
        def decorator(handler: Callable[[T], None]) -> Callable[[T], None]:
            self.subscribe(handler, event_type=event_type, priority=priority)
            return handler
        return decorator

    def once(
        self,
        event_type: Type[T],
    ) -> Callable[[Callable[[T], None]], Callable[[T], None]]:
        """Decorator for one-time subscription."""
        def decorator(handler: Callable[[T], None]) -> Callable[[T], None]:
            self.subscribe(handler, event_type=event_type, once=True)
            return handler
        return decorator

    def clear(self) -> None:
        """Clear all subscriptions."""
        with self._lock:
            for sub in self._subscriptions:
                sub.cancel()
            self._subscriptions.clear()

    @property
    def subscription_count(self) -> int:
        """Get number of active subscriptions."""
        with self._lock:
            return len([s for s in self._subscriptions if s.is_active])

    @property
    def stats(self) -> Dict[str, int]:
        """Get event bus statistics."""
        return self._stats.copy()

    @property
    def dead_letter_queue(self) -> DeadLetterQueue:
        """Get the dead letter queue."""
        return self._dlq


class AsyncEventBus:
    """
    Asynchronous event bus for async handlers.

    Supports both sync and async handlers.
    """

    def __init__(
        self,
        event_store: Optional[EventStore] = None,
        dead_letter_queue: Optional[DeadLetterQueue] = None,
    ):
        """Initialize async event bus."""
        self._subscriptions: List[Subscription] = []
        self._event_store = event_store
        self._dlq = dead_letter_queue or DeadLetterQueue()
        self._lock = asyncio.Lock()
        self._stats = {
            "events_published": 0,
            "events_handled": 0,
            "events_failed": 0,
        }

    async def subscribe(
        self,
        handler: HandlerType,
        event_type: Optional[Type[Event]] = None,
        filter_fn: Optional[Callable[[Event], bool]] = None,
        priority: int = 0,
        once: bool = False,
    ) -> Subscription:
        """Subscribe to events."""
        sub = Subscription(
            handler=handler,
            event_type=event_type,
            filter_fn=filter_fn,
            priority=priority,
            once=once,
        )

        async with self._lock:
            self._subscriptions.append(sub)
            self._subscriptions.sort(key=lambda s: s.priority, reverse=True)

        return sub

    async def unsubscribe(self, subscription: Subscription) -> bool:
        """Unsubscribe from events."""
        subscription.cancel()
        async with self._lock:
            if subscription in self._subscriptions:
                self._subscriptions.remove(subscription)
                return True
        return False

    async def publish(self, event: Event) -> int:
        """Publish an event asynchronously."""
        if self._event_store:
            self._event_store.append(event)

        self._stats["events_published"] += 1

        async with self._lock:
            matching = [s for s in self._subscriptions if s.matches(event)]

        handlers_called = 0
        to_remove = []

        for sub in matching:
            try:
                # Handle both sync and async handlers
                if asyncio.iscoroutinefunction(sub.handler):
                    await sub.handler(event)
                else:
                    sub.handler(event)

                sub.call_count += 1
                sub.last_called = datetime.now()
                handlers_called += 1
                self._stats["events_handled"] += 1

                if sub.once:
                    to_remove.append(sub)

            except Exception as e:
                logger.error(f"Async handler {sub.handler} failed: {e}")
                self._stats["events_failed"] += 1
                self._dlq.add(event, sub.handler, e)

        for sub in to_remove:
            await self.unsubscribe(sub)

        return handlers_called

    async def publish_concurrent(self, event: Event) -> int:
        """Publish event with concurrent handler execution."""
        if self._event_store:
            self._event_store.append(event)

        self._stats["events_published"] += 1

        async with self._lock:
            matching = [s for s in self._subscriptions if s.matches(event)]

        async def call_handler(sub: Subscription) -> bool:
            try:
                if asyncio.iscoroutinefunction(sub.handler):
                    await sub.handler(event)
                else:
                    sub.handler(event)
                sub.call_count += 1
                sub.last_called = datetime.now()
                return True
            except Exception as e:
                logger.error(f"Handler failed: {e}")
                self._dlq.add(event, sub.handler, e)
                return False

        results = await asyncio.gather(
            *[call_handler(sub) for sub in matching],
            return_exceptions=True,
        )

        handlers_called = sum(1 for r in results if r is True)
        self._stats["events_handled"] += handlers_called
        self._stats["events_failed"] += len(results) - handlers_called

        return handlers_called

    def on(
        self,
        event_type: Type[T],
        priority: int = 0,
    ) -> Callable:
        """Decorator for subscribing to events."""
        def decorator(handler: Callable) -> Callable:
            # Create subscription synchronously (will be added on first use)
            sub = Subscription(
                handler=handler,
                event_type=event_type,
                priority=priority,
            )
            self._subscriptions.append(sub)
            self._subscriptions.sort(key=lambda s: s.priority, reverse=True)
            return handler
        return decorator

    async def clear(self) -> None:
        """Clear all subscriptions."""
        async with self._lock:
            for sub in self._subscriptions:
                sub.cancel()
            self._subscriptions.clear()

    @property
    def stats(self) -> Dict[str, int]:
        """Get statistics."""
        return self._stats.copy()


class BackgroundEventBus:
    """
    Event bus that processes events in a background thread.

    Events are queued and processed asynchronously.
    """

    def __init__(
        self,
        event_store: Optional[EventStore] = None,
        max_queue_size: int = 10000,
        num_workers: int = 1,
    ):
        """
        Initialize background event bus.

        Args:
            event_store: Optional event store
            max_queue_size: Maximum queue size
            num_workers: Number of worker threads
        """
        self._inner_bus = EventBus(event_store=event_store)
        self._queue: queue.Queue = queue.Queue(maxsize=max_queue_size)
        self._workers: List[threading.Thread] = []
        self._num_workers = num_workers
        self._running = False
        self._stats = {
            "events_queued": 0,
            "events_dropped": 0,
        }

    def start(self) -> None:
        """Start background processing."""
        if self._running:
            return

        self._running = True
        for i in range(self._num_workers):
            worker = threading.Thread(
                target=self._worker_loop,
                name=f"EventBusWorker-{i}",
                daemon=True,
            )
            worker.start()
            self._workers.append(worker)

    def stop(self, timeout: float = 5.0) -> None:
        """Stop background processing."""
        self._running = False

        # Signal workers to stop
        for _ in self._workers:
            try:
                self._queue.put(None, timeout=0.1)
            except queue.Full:
                pass

        # Wait for workers
        for worker in self._workers:
            worker.join(timeout=timeout)

        self._workers.clear()

    def _worker_loop(self) -> None:
        """Worker thread main loop."""
        while self._running:
            try:
                event = self._queue.get(timeout=0.5)
                if event is None:
                    break
                self._inner_bus.publish(event)
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Worker error: {e}")

    def subscribe(self, *args, **kwargs) -> Subscription:
        """Subscribe to events (delegates to inner bus)."""
        return self._inner_bus.subscribe(*args, **kwargs)

    def unsubscribe(self, subscription: Subscription) -> bool:
        """Unsubscribe from events."""
        return self._inner_bus.unsubscribe(subscription)

    def publish(self, event: Event, block: bool = True, timeout: float = 1.0) -> bool:
        """
        Queue an event for processing.

        Args:
            event: Event to publish
            block: Whether to block if queue is full
            timeout: Timeout for blocking

        Returns:
            True if queued, False if dropped
        """
        try:
            self._queue.put(event, block=block, timeout=timeout)
            self._stats["events_queued"] += 1
            return True
        except queue.Full:
            self._stats["events_dropped"] += 1
            return False

    def on(self, event_type: Type[T], priority: int = 0):
        """Decorator for subscribing."""
        return self._inner_bus.on(event_type, priority)

    @property
    def queue_size(self) -> int:
        """Get current queue size."""
        return self._queue.qsize()

    @property
    def stats(self) -> Dict[str, int]:
        """Get combined statistics."""
        stats = self._inner_bus.stats.copy()
        stats.update(self._stats)
        return stats

    def __enter__(self) -> "BackgroundEventBus":
        """Context manager entry."""
        self.start()
        return self

    def __exit__(self, *args) -> None:
        """Context manager exit."""
        self.stop()


class EventAggregator:
    """
    Aggregates events over time windows.

    Useful for batching, debouncing, or collecting related events.
    """

    def __init__(
        self,
        window_seconds: float = 1.0,
        max_events: int = 100,
        on_flush: Optional[Callable[[List[Event]], None]] = None,
    ):
        """
        Initialize aggregator.

        Args:
            window_seconds: Time window for aggregation
            max_events: Maximum events before auto-flush
            on_flush: Callback when events are flushed
        """
        self._window = window_seconds
        self._max_events = max_events
        self._on_flush = on_flush
        self._events: List[Event] = []
        self._lock = threading.RLock()
        self._window_start: Optional[float] = None
        self._timer: Optional[threading.Timer] = None

    def add(self, event: Event) -> None:
        """Add an event to the aggregator."""
        with self._lock:
            if self._window_start is None:
                self._window_start = time.time()
                self._schedule_flush()

            self._events.append(event)

            if len(self._events) >= self._max_events:
                self._do_flush()

    def flush(self) -> List[Event]:
        """Manually flush events."""
        with self._lock:
            return self._do_flush()

    def _do_flush(self) -> List[Event]:
        """Internal flush implementation."""
        events = self._events.copy()
        self._events.clear()
        self._window_start = None

        if self._timer:
            self._timer.cancel()
            self._timer = None

        if self._on_flush and events:
            try:
                self._on_flush(events)
            except Exception as e:
                logger.error(f"Flush callback failed: {e}")

        return events

    def _schedule_flush(self) -> None:
        """Schedule automatic flush."""
        if self._timer:
            self._timer.cancel()

        self._timer = threading.Timer(self._window, self._timer_flush)
        self._timer.daemon = True
        self._timer.start()

    def _timer_flush(self) -> None:
        """Timer callback."""
        with self._lock:
            if self._events:
                self._do_flush()

    @property
    def pending_count(self) -> int:
        """Get number of pending events."""
        with self._lock:
            return len(self._events)


class EventReplay:
    """Replays events from an event store."""

    def __init__(self, event_store: EventStore):
        """Initialize replayer."""
        self._store = event_store

    def replay(
        self,
        handler: Callable[[Event], None],
        event_type: Optional[str] = None,
        since: Optional[datetime] = None,
        until: Optional[datetime] = None,
        limit: int = 1000,
    ) -> int:
        """
        Replay events to a handler.

        Args:
            handler: Function to call for each event
            event_type: Optional filter by event type
            since: Optional start time
            until: Optional end time
            limit: Maximum events to replay

        Returns:
            Number of events replayed
        """
        events = self._store.get_events(
            event_type=event_type,
            since=since,
            until=until,
            limit=limit,
        )

        # Replay in chronological order
        events = sorted(events, key=lambda e: e.timestamp)

        for event in events:
            try:
                handler(event)
            except Exception as e:
                logger.error(f"Replay handler failed on {event.id}: {e}")

        return len(events)

    def replay_to_bus(
        self,
        bus: EventBus,
        **kwargs,
    ) -> int:
        """Replay events by publishing to a bus."""
        return self.replay(bus.publish, **kwargs)


class EventEmitter:
    """
    Mixin class for objects that emit events.

    Provides a simple interface for emitting events to a bus.
    """

    def __init__(self, bus: Optional[EventBus] = None):
        """Initialize emitter."""
        self._event_bus = bus
        self._source = self.__class__.__name__

    def set_event_bus(self, bus: EventBus) -> None:
        """Set the event bus."""
        self._event_bus = bus

    def emit(self, event: Event) -> int:
        """
        Emit an event.

        Args:
            event: Event to emit

        Returns:
            Number of handlers called, or 0 if no bus
        """
        if self._event_bus is None:
            return 0

        event.source = self._source
        return self._event_bus.publish(event)

    def emit_many(self, events: List[Event]) -> int:
        """Emit multiple events."""
        total = 0
        for event in events:
            total += self.emit(event)
        return total


# Convenience functions

def create_event_bus(
    store_type: str = "memory",
    store_path: Optional[str] = None,
    max_events: int = 10000,
) -> EventBus:
    """
    Create an event bus with common configuration.

    Args:
        store_type: "memory" or "file"
        store_path: Path for file store
        max_events: Maximum events in store
    """
    if store_type == "memory":
        store = MemoryEventStore(max_events=max_events)
    elif store_type == "file":
        if not store_path:
            raise ValueError("store_path required for file store")
        store = FileEventStore(store_path)
    else:
        store = None

    return EventBus(event_store=store)


def create_async_event_bus(
    store_type: str = "memory",
    store_path: Optional[str] = None,
    max_events: int = 10000,
) -> AsyncEventBus:
    """Create an async event bus."""
    if store_type == "memory":
        store = MemoryEventStore(max_events=max_events)
    elif store_type == "file":
        if not store_path:
            raise ValueError("store_path required for file store")
        store = FileEventStore(store_path)
    else:
        store = None

    return AsyncEventBus(event_store=store)


# Global event bus instance (optional singleton pattern)
_global_bus: Optional[EventBus] = None


def get_event_bus() -> EventBus:
    """Get or create the global event bus."""
    global _global_bus
    if _global_bus is None:
        _global_bus = EventBus()
    return _global_bus


def set_event_bus(bus: EventBus) -> None:
    """Set the global event bus."""
    global _global_bus
    _global_bus = bus


def publish(event: Event) -> int:
    """Publish to the global event bus."""
    return get_event_bus().publish(event)


def subscribe(
    handler: HandlerType,
    event_type: Optional[Type[Event]] = None,
    **kwargs,
) -> Subscription:
    """Subscribe to the global event bus."""
    return get_event_bus().subscribe(handler, event_type, **kwargs)
