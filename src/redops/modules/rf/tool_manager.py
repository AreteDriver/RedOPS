"""
RF tool process manager with interface locking.

Manages concurrent RF tool subprocesses (airodump-ng, hcxdumptool,
tshark, etc.), enforcing one-tool-per-interface constraints and
providing lifecycle management with event bus integration.

Requires: asyncio event loop, redops event bus.
"""

import asyncio
import logging
import signal
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from pathlib import Path
from typing import Any

from redops.core.event_bus import Event, EventBus

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Resource classification
# ---------------------------------------------------------------------------


class ResourceClass(Enum):
    """Resource classification for RF tools.

    Controls scheduling constraints and interface exclusivity.
    """

    RF_SCAN = auto()
    RF_INJECT = auto()
    CPU_HEAVY = auto()
    PASSIVE = auto()


class IngestionStrategy(Enum):
    """How a tool's output should be consumed.

    Determines whether the manager reads stdout in real-time,
    watches an output file, or collects results after completion.
    """

    STREAM = "stream"
    FILEWATCH = "filewatch"
    COLLECT = "collect"


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ToolSpec:
    """Specification for a registered RF tool.

    Attributes:
        name: Human-readable tool identifier.
        binary_path: Absolute path or bare command name for the tool binary.
        requires_monitor: Whether the tool needs a monitor-mode interface.
        requires_root: Whether the tool must run as root / via sudo.
        ingestion_strategy: How to consume the tool's output.
        parser_class: Dotted path to the parser class for this tool's output.
        resource_class: Scheduling resource classification.
        default_args: Default arguments appended to every invocation.
    """

    name: str
    binary_path: str
    requires_monitor: bool = False
    requires_root: bool = False
    ingestion_strategy: IngestionStrategy = IngestionStrategy.STREAM
    parser_class: str = ""
    resource_class: ResourceClass = ResourceClass.RF_SCAN
    default_args: list[str] = field(default_factory=list)


@dataclass
class ToolProcess:
    """A running tool instance managed by ToolManager.

    Attributes:
        id: Unique identifier for this process instance.
        spec: The tool specification that was launched.
        process: The asyncio subprocess handle.
        session_id: Identifier for the current engagement session.
        target_id: Identifier for the target being operated on.
        interface: Wireless interface assigned to this process.
        started_at: Timestamp when the process was started.
        log_path: Path to the combined stdout/stderr log file.
        args: Arguments the process was started with.
    """

    id: str
    spec: ToolSpec
    process: asyncio.subprocess.Process
    session_id: str
    target_id: str
    interface: str
    started_at: datetime
    log_path: Path
    args: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serialize process metadata to a plain dict.

        Returns:
            Dict with process info suitable for API responses / logging.
        """
        return {
            "id": self.id,
            "tool": self.spec.name,
            "interface": self.interface,
            "session_id": self.session_id,
            "target_id": self.target_id,
            "started_at": self.started_at.isoformat(),
            "log_path": str(self.log_path),
            "pid": self.process.pid,
            "args": self.args,
            "resource_class": self.spec.resource_class.name,
        }


# ---------------------------------------------------------------------------
# Event types
# ---------------------------------------------------------------------------


@dataclass
class ToolStartedEvent(Event):
    """Emitted when an RF tool process starts."""

    tool_name: str = ""
    tool_id: str = ""
    interface: str = ""
    session_id: str = ""
    target_id: str = ""
    pid: int = 0


@dataclass
class ToolStoppedEvent(Event):
    """Emitted when an RF tool process stops."""

    tool_name: str = ""
    tool_id: str = ""
    interface: str = ""
    session_id: str = ""
    exit_code: int | None = None
    runtime_seconds: float = 0.0


@dataclass
class ToolOutputEvent(Event):
    """Emitted when a stream-parsed tool produces a line of output."""

    tool_name: str = ""
    tool_id: str = ""
    line: str = ""


@dataclass
class ToolErrorEvent(Event):
    """Emitted when a tool encounters an error."""

    tool_name: str = ""
    tool_id: str = ""
    error: str = ""


# ---------------------------------------------------------------------------
# ToolManager
# ---------------------------------------------------------------------------


class ToolManager:
    """Manages concurrent RF tool subprocesses with interface locking.

    Enforces one-tool-per-interface constraints, provides graceful
    shutdown semantics, and integrates with the RedOPS event bus
    for lifecycle notifications.

    Attributes:
        interface_lock: Maps interface name to the tool_id that holds it.
    """

    def __init__(
        self,
        event_bus: EventBus,
        session_path: Path,
    ) -> None:
        """Initialize the tool manager.

        Args:
            event_bus: RedOPS event bus for publishing lifecycle events.
            session_path: Base directory for session log files.
        """
        self._event_bus: EventBus = event_bus
        self._session_path: Path = Path(session_path)
        self._registry: dict[str, ToolSpec] = {}
        self._running: dict[str, ToolProcess] = {}
        self._reader_tasks: dict[str, asyncio.Task[None]] = {}
        self.interface_lock: dict[str, str] = {}

        logger.info(
            "ToolManager initialized, session_path=%s",
            self._session_path,
        )

    # ------------------------------------------------------------------
    # Registry
    # ------------------------------------------------------------------

    def register_tool(self, spec: ToolSpec) -> None:
        """Register a tool specification in the manager's registry.

        Args:
            spec: Tool specification to register. If a tool with the same
                  name already exists it will be overwritten.
        """
        self._registry[spec.name] = spec
        logger.info(
            "Registered tool '%s' (binary=%s, monitor=%s, root=%s, "
            "ingestion=%s, resource=%s)",
            spec.name,
            spec.binary_path,
            spec.requires_monitor,
            spec.requires_root,
            spec.ingestion_strategy.value,
            spec.resource_class.name,
        )

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start_tool(
        self,
        name: str,
        interface: str,
        args: list[str] | None = None,
        *,
        session_id: str = "",
        target_id: str = "",
    ) -> ToolProcess:
        """Start a registered tool as an async subprocess.

        Acquires the interface lock, builds the command line, starts the
        process with stdout/stderr redirected to a session log file, and
        optionally launches a reader task for stream-parsed tools.

        Args:
            name: Registered tool name.
            interface: Wireless interface to operate on.
            args: Additional command-line arguments.
            session_id: Current session identifier.
            target_id: Target identifier for correlation.

        Returns:
            ToolProcess handle for the started process.

        Raises:
            KeyError: If the tool name is not registered.
            RuntimeError: If the interface is already locked by another tool,
                          or if the subprocess fails to start.
        """
        if name not in self._registry:
            raise KeyError(f"Tool '{name}' is not registered")

        spec = self._registry[name]
        args = args or []
        tool_id = str(uuid.uuid4())

        # --- Interface locking ---
        self._acquire_interface(interface, tool_id, spec)

        # --- Prepare log directory ---
        log_dir = self._session_path / session_id / "rf_logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_path = log_dir / f"{name}_{timestamp}_{tool_id[:8]}.log"

        # --- Build command ---
        cmd = self._build_command(spec, interface, args)

        # --- Start subprocess ---
        try:
            log_fh = log_path.open("w")
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=log_fh,
                stderr=asyncio.subprocess.STDOUT,
            )
        except FileNotFoundError as exc:
            self._release_interface(interface, tool_id)
            raise RuntimeError(
                f"Binary not found for tool '{name}': {spec.binary_path}"
            ) from exc
        except OSError as exc:
            self._release_interface(interface, tool_id)
            raise RuntimeError(
                f"Failed to start tool '{name}': {exc}"
            ) from exc

        tool_proc = ToolProcess(
            id=tool_id,
            spec=spec,
            process=process,
            session_id=session_id,
            target_id=target_id,
            interface=interface,
            started_at=datetime.now(),
            log_path=log_path,
            args=args,
        )
        self._running[tool_id] = tool_proc

        # --- Stream reader task ---
        if spec.ingestion_strategy == IngestionStrategy.STREAM:
            task = asyncio.create_task(
                self._stream_reader(tool_id, log_path, spec.name),
                name=f"reader-{tool_id[:8]}",
            )
            self._reader_tasks[tool_id] = task

        # --- Emit event ---
        self._event_bus.publish(
            ToolStartedEvent(
                source="ToolManager",
                tool_name=spec.name,
                tool_id=tool_id,
                interface=interface,
                session_id=session_id,
                target_id=target_id,
                pid=process.pid or 0,
            )
        )

        logger.info(
            "Started tool '%s' (id=%s, pid=%s, interface=%s)",
            name,
            tool_id[:8],
            process.pid,
            interface,
        )
        return tool_proc

    async def stop_tool(self, tool_id: str) -> bool:
        """Stop a running tool process gracefully.

        Sends SIGTERM, waits up to 5 seconds, then escalates to SIGKILL
        if the process has not exited. Releases the interface lock and
        emits a ``ToolStoppedEvent``.

        Args:
            tool_id: Unique identifier of the running tool process.

        Returns:
            True if the process was stopped, False if tool_id was not found.
        """
        if tool_id not in self._running:
            logger.warning("stop_tool called for unknown id: %s", tool_id[:8])
            return False

        tool_proc = self._running[tool_id]
        process = tool_proc.process

        logger.info(
            "Stopping tool '%s' (id=%s, pid=%s)",
            tool_proc.spec.name,
            tool_id[:8],
            process.pid,
        )

        # Cancel reader task first
        reader_task = self._reader_tasks.pop(tool_id, None)
        if reader_task is not None and not reader_task.done():
            reader_task.cancel()
            try:
                await reader_task
            except asyncio.CancelledError:
                pass

        # Graceful termination
        exit_code: int | None = None
        try:
            if process.returncode is None:
                process.send_signal(signal.SIGTERM)
                try:
                    exit_code = await asyncio.wait_for(
                        process.wait(),
                        timeout=5.0,
                    )
                except asyncio.TimeoutError:
                    logger.warning(
                        "Tool '%s' (pid=%s) did not exit after SIGTERM, sending SIGKILL",
                        tool_proc.spec.name,
                        process.pid,
                    )
                    process.kill()
                    exit_code = await process.wait()
            else:
                exit_code = process.returncode
        except ProcessLookupError:
            logger.debug("Process already exited (pid=%s)", process.pid)
            exit_code = process.returncode

        # Release lock and clean up
        self._release_interface(tool_proc.interface, tool_id)
        del self._running[tool_id]

        runtime = (datetime.now() - tool_proc.started_at).total_seconds()

        # Emit event
        self._event_bus.publish(
            ToolStoppedEvent(
                source="ToolManager",
                tool_name=tool_proc.spec.name,
                tool_id=tool_id,
                interface=tool_proc.interface,
                session_id=tool_proc.session_id,
                exit_code=exit_code,
                runtime_seconds=runtime,
            )
        )

        logger.info(
            "Stopped tool '%s' (id=%s, exit_code=%s, runtime=%.1fs)",
            tool_proc.spec.name,
            tool_id[:8],
            exit_code,
            runtime,
        )
        return True

    async def stop_all(self) -> None:
        """Stop all running tool processes.

        Iterates over a snapshot of running tool IDs and calls
        ``stop_tool`` for each. Errors during individual stops are
        logged but do not prevent other tools from being stopped.
        """
        tool_ids = list(self._running.keys())
        if not tool_ids:
            logger.info("No running tools to stop")
            return

        logger.info("Stopping all %d running tool(s)", len(tool_ids))
        for tool_id in tool_ids:
            try:
                await self.stop_tool(tool_id)
            except Exception:
                logger.exception(
                    "Error stopping tool %s",
                    tool_id[:8],
                )

    def get_running(self) -> list[dict[str, Any]]:
        """Get metadata for all currently running tool processes.

        Returns:
            List of dicts with process info (see ToolProcess.to_dict).
        """
        return [tp.to_dict() for tp in self._running.values()]

    # ------------------------------------------------------------------
    # Interface locking
    # ------------------------------------------------------------------

    def _acquire_interface(
        self,
        interface: str,
        tool_id: str,
        spec: ToolSpec,
    ) -> None:
        """Acquire an exclusive lock on a wireless interface.

        Args:
            interface: Interface name to lock.
            tool_id: ID of the tool requesting the lock.
            spec: Tool spec (used for resource class checks).

        Raises:
            RuntimeError: If the interface is already held by another tool.
        """
        holder = self.interface_lock.get(interface)
        if holder is not None:
            holder_proc = self._running.get(holder)
            holder_name = holder_proc.spec.name if holder_proc else "unknown"
            raise RuntimeError(
                f"Interface '{interface}' is locked by tool '{holder_name}' "
                f"(id={holder[:8]}). Only one tool per interface is allowed."
            )

        # Inject tools require exclusive access — verify no other tool
        # is using *any* interface in inject mode on overlapping hardware.
        if spec.resource_class == ResourceClass.RF_INJECT:
            for locked_iface, locked_id in self.interface_lock.items():
                locked_proc = self._running.get(locked_id)
                if locked_proc and locked_proc.spec.resource_class == ResourceClass.RF_INJECT:
                    raise RuntimeError(
                        f"Cannot start inject tool '{spec.name}' on '{interface}': "
                        f"another inject tool '{locked_proc.spec.name}' is active "
                        f"on '{locked_iface}'."
                    )

        self.interface_lock[interface] = tool_id
        logger.debug(
            "Interface '%s' locked by tool_id=%s",
            interface,
            tool_id[:8],
        )

    def _release_interface(self, interface: str, tool_id: str) -> None:
        """Release the lock on a wireless interface.

        Args:
            interface: Interface name to unlock.
            tool_id: ID of the tool releasing the lock.
        """
        current_holder = self.interface_lock.get(interface)
        if current_holder == tool_id:
            del self.interface_lock[interface]
            logger.debug("Interface '%s' released by tool_id=%s", interface, tool_id[:8])
        elif current_holder is not None:
            logger.warning(
                "Interface '%s' held by %s, not by %s — not releasing",
                interface,
                current_holder[:8],
                tool_id[:8],
            )

    # ------------------------------------------------------------------
    # Command building
    # ------------------------------------------------------------------

    def _build_command(
        self,
        spec: ToolSpec,
        interface: str,
        extra_args: list[str],
    ) -> list[str]:
        """Build the full command list for subprocess execution.

        Args:
            spec: Tool specification.
            interface: Interface name to pass to the tool.
            extra_args: Additional arguments from the caller.

        Returns:
            Complete command list ready for create_subprocess_exec.
        """
        cmd: list[str] = []

        if spec.requires_root:
            cmd.append("sudo")

        cmd.append(spec.binary_path)
        cmd.extend(spec.default_args)
        cmd.extend(extra_args)

        # Most RF tools accept the interface as the last positional arg
        # Caller can override by including -i/--interface in extra_args
        if not any(a in ("-i", "--interface") for a in extra_args):
            cmd.append(interface)

        return cmd

    # ------------------------------------------------------------------
    # Stream reader
    # ------------------------------------------------------------------

    async def _stream_reader(
        self,
        tool_id: str,
        log_path: Path,
        tool_name: str,
    ) -> None:
        """Tail the log file and emit output events for stream-parsed tools.

        Opens the log file and follows new lines, emitting a
        ``ToolOutputEvent`` for each non-empty line. Runs until the
        tool process exits or the task is cancelled.

        Args:
            tool_id: ID of the running tool process.
            log_path: Path to the log file being tailed.
            tool_name: Name of the tool (for event metadata).
        """
        try:
            # Wait briefly for the file to be created
            await asyncio.sleep(0.5)

            if not log_path.exists():
                logger.warning(
                    "Log file %s does not exist for reader task",
                    log_path,
                )
                return

            with log_path.open("r") as fh:
                while tool_id in self._running:
                    line = fh.readline()
                    if line:
                        stripped = line.rstrip("\n\r")
                        if stripped:
                            self._event_bus.publish(
                                ToolOutputEvent(
                                    source="ToolManager",
                                    tool_name=tool_name,
                                    tool_id=tool_id,
                                    line=stripped,
                                )
                            )
                    else:
                        # No new data, yield control
                        await asyncio.sleep(0.1)
        except asyncio.CancelledError:
            logger.debug("Stream reader cancelled for %s", tool_id[:8])
        except Exception:
            logger.exception("Stream reader error for tool %s", tool_id[:8])


# ---------------------------------------------------------------------------
# Pre-registered tool specs
# ---------------------------------------------------------------------------

# Canonical specs for common RF tools. Call register_defaults() to load
# them into a ToolManager instance.

_DEFAULT_TOOL_SPECS: list[ToolSpec] = [
    ToolSpec(
        name="airodump-ng",
        binary_path="airodump-ng",
        requires_monitor=True,
        requires_root=True,
        ingestion_strategy=IngestionStrategy.STREAM,
        parser_class="redops.modules.rf.parsers.AirodumpParser",
        resource_class=ResourceClass.RF_SCAN,
    ),
    ToolSpec(
        name="hcxdumptool",
        binary_path="hcxdumptool",
        requires_monitor=True,
        requires_root=True,
        ingestion_strategy=IngestionStrategy.FILEWATCH,
        parser_class="redops.modules.rf.parsers.HcxdumptoolParser",
        resource_class=ResourceClass.RF_SCAN,
    ),
    ToolSpec(
        name="horst",
        binary_path="horst",
        requires_monitor=True,
        requires_root=True,
        ingestion_strategy=IngestionStrategy.STREAM,
        parser_class="redops.modules.rf.parsers.HorstParser",
        resource_class=ResourceClass.RF_SCAN,
    ),
    ToolSpec(
        name="tshark",
        binary_path="tshark",
        requires_monitor=False,
        requires_root=True,
        ingestion_strategy=IngestionStrategy.STREAM,
        parser_class="redops.modules.rf.parsers.TsharkParser",
        resource_class=ResourceClass.RF_SCAN,
        default_args=["-l"],  # line-buffered output
    ),
    ToolSpec(
        name="reaver",
        binary_path="reaver",
        requires_monitor=True,
        requires_root=True,
        ingestion_strategy=IngestionStrategy.COLLECT,
        parser_class="redops.modules.rf.parsers.ReaverParser",
        resource_class=ResourceClass.RF_INJECT,
    ),
    ToolSpec(
        name="mdk4",
        binary_path="mdk4",
        requires_monitor=True,
        requires_root=True,
        ingestion_strategy=IngestionStrategy.STREAM,
        parser_class="redops.modules.rf.parsers.Mdk4Parser",
        resource_class=ResourceClass.RF_INJECT,
    ),
    ToolSpec(
        name="wavemon",
        binary_path="wavemon",
        requires_monitor=False,
        requires_root=False,
        ingestion_strategy=IngestionStrategy.STREAM,
        parser_class="redops.modules.rf.parsers.WavemonParser",
        resource_class=ResourceClass.PASSIVE,
    ),
    ToolSpec(
        name="wifite",
        binary_path="wifite",
        requires_monitor=True,
        requires_root=True,
        ingestion_strategy=IngestionStrategy.COLLECT,
        parser_class="redops.modules.rf.parsers.WifiteParser",
        resource_class=ResourceClass.RF_SCAN,
    ),
]


def register_defaults(manager: ToolManager) -> None:
    """Register all default RF tool specs into a ToolManager.

    Args:
        manager: ToolManager instance to populate.
    """
    for spec in _DEFAULT_TOOL_SPECS:
        manager.register_tool(spec)
    logger.info("Registered %d default RF tool specs", len(_DEFAULT_TOOL_SPECS))
