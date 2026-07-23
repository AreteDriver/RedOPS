"""
Asyncio-based in-process pub/sub event bus for RF operations.

Supports both sync and async callbacks, keeps a ring buffer
of recent events for dashboard catch-up, and is thread-safe.
"""

import asyncio
import inspect
import logging
import threading
import time
import uuid
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Callable, Coroutine

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Event types
# ---------------------------------------------------------------------------

EVENT_AP_DISCOVERED = "ap_discovered"
EVENT_CLIENT_FOUND = "client_found"
EVENT_HANDSHAKE_CAPTURED = "handshake_captured"
EVENT_PMKID_CAPTURED = "pmkid_captured"
EVENT_TOOL_STARTED = "tool_started"
EVENT_TOOL_STOPPED = "tool_stopped"
EVENT_SCAN_COMPLETE = "scan_complete"
EVENT_INTERFACE_CHANGED = "interface_changed"
EVENT_ALERT = "alert"

ALL_EVENT_TYPES: tuple[str, ...] = (
    EVENT_AP_DISCOVERED,
    EVENT_CLIENT_FOUND,
    EVENT_HANDSHAKE_CAPTURED,
    EVENT_PMKID_CAPTURED,
    EVENT_TOOL_STARTED,
    EVENT_TOOL_STOPPED,
    EVENT_SCAN_COMPLETE,
    EVENT_INTERFACE_CHANGED,
    EVENT_ALERT,
)

# Type alias for subscriber callbacks.
SyncCallback = Callable[["Event"], Any]
AsyncCallback = Callable[["Event"], Coroutine[Any, Any, Any]]
Callback = SyncCallback | AsyncCallback

# ---------------------------------------------------------------------------
# Event dataclass
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Event:
    """An immutable event emitted on the bus.

    Attributes:
        event_type: One of the ``EVENT_*`` constants.
        data: Arbitrary payload dictionary.
        event_id: Unique id (auto-generated).
        timestamp: Unix epoch seconds (auto-generated).
    """

    event_type: str
    data: dict[str, Any] = field(default_factory=dict)
    event_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    timestamp: float = field(default_factory=time.time)


# ---------------------------------------------------------------------------
# Subscription handle
# ---------------------------------------------------------------------------


@dataclass
class _Subscription:
    """Internal record of a single subscriber."""

    sub_id: str
    event_type: str
    callback: Callback
    is_async: bool


# ---------------------------------------------------------------------------
# EventBus
# ---------------------------------------------------------------------------


class EventBus:
    """Thread-safe asyncio event bus with ring-buffer history.

    Usage::

        bus = EventBus()

        async def on_ap(event: Event) -> None:
            print(event.data)

        bus.subscribe("ap_discovered", on_ap)
        await bus.emit("ap_discovered", {"bssid": "AA:BB:CC:DD:EE:FF"})

    Sync callbacks are run in the default executor so they
    never block the event loop.  The bus keeps the last 1 000
    events in a ring buffer accessible via ``recent_events``.
    """

    def __init__(
        self,
        history_size: int = 1000,
    ) -> None:
        """Initialize the event bus.

        Args:
            history_size: Maximum number of events kept in the
                ring buffer for late-joining consumers.
        """
        self._lock = threading.Lock()
        self._subs: dict[str, list[_Subscription]] = {}
        self._history: deque[Event] = deque(maxlen=history_size)
        self._queues: dict[str, asyncio.Queue[Event]] = {}
        self._queue_filters: dict[str, str | None] = {}
        logger.debug(
            "EventBus initialized (history_size=%d)",
            history_size,
        )

    # ------------------------------------------------------------------
    # Subscribe / unsubscribe
    # ------------------------------------------------------------------

    def subscribe(
        self,
        event_type: str,
        callback: Callback,
    ) -> str:
        """Register a callback for an event type.

        Args:
            event_type: The event type to listen for.
            callback: A sync or async callable that accepts
                an ``Event`` argument.

        Returns:
            A subscription id that can be passed to
            ``unsubscribe``.
        """
        sub_id = uuid.uuid4().hex[:12]
        is_async = inspect.iscoroutinefunction(callback)
        sub = _Subscription(
            sub_id=sub_id,
            event_type=event_type,
            callback=callback,
            is_async=is_async,
        )
        with self._lock:
            self._subs.setdefault(event_type, []).append(sub)
        logger.debug(
            "Subscribed %s to %s (async=%s)",
            sub_id,
            event_type,
            is_async,
        )
        return sub_id

    def unsubscribe(self, sub_id: str) -> bool:
        """Remove a subscription by its id.

        Args:
            sub_id: The id returned by ``subscribe``.

        Returns:
            ``True`` if the subscription was found and
            removed, ``False`` otherwise.
        """
        with self._lock:
            for event_type, subs in self._subs.items():
                for i, sub in enumerate(subs):
                    if sub.sub_id == sub_id:
                        subs.pop(i)
                        logger.debug(
                            "Unsubscribed %s from %s",
                            sub_id,
                            event_type,
                        )
                        return True
        return False

    # ------------------------------------------------------------------
    # Async queue consumers
    # ------------------------------------------------------------------

    def create_queue(
        self,
        event_type: str | None = None,
        maxsize: int = 0,
    ) -> str:
        """Create an async queue that receives events.

        Args:
            event_type: If set, only events of this type are
                pushed.  ``None`` means all events.
            maxsize: Maximum queue depth (0 = unbounded).

        Returns:
            A queue id to pass to ``get_queue`` or
            ``remove_queue``.
        """
        queue_id = uuid.uuid4().hex[:12]
        with self._lock:
            self._queues[queue_id] = asyncio.Queue(maxsize=maxsize)
            self._queue_filters[queue_id] = event_type
        logger.debug(
            "Queue %s created (filter=%s)",
            queue_id,
            event_type,
        )
        return queue_id

    def get_queue(self, queue_id: str) -> asyncio.Queue[Event] | None:
        """Return the ``asyncio.Queue`` for a given id.

        Args:
            queue_id: The id returned by ``create_queue``.

        Returns:
            The queue, or ``None`` if not found.
        """
        return self._queues.get(queue_id)

    def remove_queue(self, queue_id: str) -> bool:
        """Remove an async queue.

        Args:
            queue_id: The id returned by ``create_queue``.

        Returns:
            ``True`` if the queue was found and removed.
        """
        with self._lock:
            removed = self._queues.pop(queue_id, None)
            self._queue_filters.pop(queue_id, None)
        return removed is not None

    # ------------------------------------------------------------------
    # Emit
    # ------------------------------------------------------------------

    async def emit(
        self,
        event_type: str,
        data: dict[str, Any] | None = None,
    ) -> Event:
        """Emit an event to all subscribers and queues.

        Args:
            event_type: The event type constant.
            data: Optional payload dict.

        Returns:
            The ``Event`` instance that was broadcast.
        """
        event = Event(
            event_type=event_type,
            data=data or {},
        )

        # Append to ring buffer (thread-safe via lock).
        with self._lock:
            self._history.append(event)
            subs = list(self._subs.get(event_type, []))
            queues_to_notify: list[asyncio.Queue[Event]] = []
            for qid, q in self._queues.items():
                filt = self._queue_filters.get(qid)
                if filt is None or filt == event_type:
                    queues_to_notify.append(q)

        logger.debug(
            "Emitting %s (%d subs, %d queues)",
            event_type,
            len(subs),
            len(queues_to_notify),
        )

        # Dispatch to callback subscribers.
        loop = asyncio.get_running_loop()
        for sub in subs:
            try:
                if sub.is_async:
                    await sub.callback(event)  # type: ignore[misc]
                else:
                    await loop.run_in_executor(None, sub.callback, event)
            except (OSError, RuntimeError, TypeError, ValueError):
                logger.exception(
                    "Error in subscriber %s for %s",
                    sub.sub_id,
                    event_type,
                )

        # Push to async queues (non-blocking put).
        for q in queues_to_notify:
            try:
                q.put_nowait(event)
            except asyncio.QueueFull:
                logger.warning(
                    "Queue full — dropping %s event",
                    event_type,
                )

        return event

    def emit_sync(
        self,
        event_type: str,
        data: dict[str, Any] | None = None,
    ) -> Event:
        """Emit from a non-async context (thread-safe).

        This pushes the event into history and queues but
        only invokes *sync* callbacks immediately.  Async
        callbacks are skipped with a warning.

        Args:
            event_type: The event type constant.
            data: Optional payload dict.

        Returns:
            The ``Event`` instance that was broadcast.
        """
        event = Event(
            event_type=event_type,
            data=data or {},
        )

        with self._lock:
            self._history.append(event)
            subs = list(self._subs.get(event_type, []))
            queues_to_notify: list[asyncio.Queue[Event]] = []
            for qid, q in self._queues.items():
                filt = self._queue_filters.get(qid)
                if filt is None or filt == event_type:
                    queues_to_notify.append(q)

        for sub in subs:
            if sub.is_async:
                logger.warning(
                    "Skipping async subscriber %s in emit_sync for %s",
                    sub.sub_id,
                    event_type,
                )
                continue
            try:
                sub.callback(event)
            except (OSError, RuntimeError, TypeError, ValueError):
                logger.exception(
                    "Error in subscriber %s for %s",
                    sub.sub_id,
                    event_type,
                )

        for q in queues_to_notify:
            try:
                q.put_nowait(event)
            except asyncio.QueueFull:
                logger.warning(
                    "Queue full — dropping %s event",
                    event_type,
                )

        return event

    # ------------------------------------------------------------------
    # History / introspection
    # ------------------------------------------------------------------

    @property
    def recent_events(self) -> list[Event]:
        """Return a snapshot of the ring buffer.

        Returns:
            List of recent events, oldest first.
        """
        with self._lock:
            return list(self._history)

    def recent_events_by_type(self, event_type: str) -> list[Event]:
        """Return recent events filtered by type.

        Args:
            event_type: The event type to filter on.

        Returns:
            Filtered list of events, oldest first.
        """
        with self._lock:
            return [e for e in self._history if e.event_type == event_type]

    @property
    def subscriber_count(self) -> int:
        """Total number of active subscriptions."""
        with self._lock:
            return sum(len(s) for s in self._subs.values())

    def clear_history(self) -> None:
        """Clear the ring buffer."""
        with self._lock:
            self._history.clear()
        logger.debug("Event history cleared")
