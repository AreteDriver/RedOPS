"""
Context - Central data store for pipeline execution.

The Context object is passed through each step of the pipeline,
preserving all intermediate outputs for reporting and simulation steps.
"""

from typing import Any, TYPE_CHECKING
from datetime import datetime, timezone
import json

if TYPE_CHECKING:
    from redops.core.config import RedOpsConfig


class Context:
    """
    Central data store for pipeline execution.

    Supports .add(), .get(), .log() operations and preserves
    all intermediate outputs.
    """

    def __init__(
        self,
        target: str | None = None,
        config: "RedOpsConfig | None" = None,
        *,
        authorization: Any | None = None,
    ):
        """
        Initialize a new Context.

        Args:
            target: The target of the pipeline execution (e.g., domain, directory)
            config: RedOps configuration (scope, output settings, etc.)
            authorization: ActiveAuthorization instance for active/offensive modules.
        """
        self.target = target
        self.config = config
        self.authorization = authorization
        self.data: dict[str, Any] = {}
        self.logs: list[dict[str, Any]] = []
        self.metadata: dict[str, Any] = {
            "created_at": datetime.now(timezone.utc).isoformat(),
            "target": target,
        }
        self._checkpoints: list[dict[str, Any]] = []

    def save(self) -> None:
        """
        Save a checkpoint of the current context state.

        Checkpoints are stored in a stack; call rollback() to restore
        the most recent checkpoint.
        """
        import copy

        checkpoint = {
            "data": copy.deepcopy(self.data),
            "logs": copy.deepcopy(self.logs),
            "metadata": copy.deepcopy(self.metadata),
        }
        self._checkpoints.append(checkpoint)
        self.log("Context checkpoint saved", level="DEBUG")

    def rollback(self) -> None:
        """
        Restore the context data and metadata to the last checkpoint.

        Logs are intentionally preserved (append-only audit trail).

        Raises:
            RuntimeError: If no checkpoints exist.
        """
        if not self._checkpoints:
            raise RuntimeError("No checkpoints available to rollback")

        checkpoint = self._checkpoints.pop()
        self.data = checkpoint["data"]
        self.metadata = checkpoint["metadata"]
        # Logs are NOT rolled back — they form an immutable audit trail
        self.log("Context rolled back to previous checkpoint", level="WARNING")

    def clear_checkpoints(self) -> None:
        """Remove all stored checkpoints."""
        self._checkpoints.clear()
        self.log("All checkpoints cleared", level="DEBUG")

    def add(self, key: str, value: Any) -> None:
        """
        Add or update a value in the context.

        Args:
            key: The key to store the value under
            value: The value to store
        """
        self.data[key] = value
        self.log(f"Added data to context: {key}", level="DEBUG")

    def get(self, key: str, default: Any = None) -> Any:
        """
        Retrieve a value from the context.

        Args:
            key: The key to retrieve
            default: Default value if key doesn't exist

        Returns:
            The value associated with the key, or default if not found
        """
        return self.data.get(key, default)

    def log(self, message: str, level: str = "INFO", **kwargs) -> None:
        """
        Add a log entry to the context.

        Args:
            message: The log message
            level: Log level (DEBUG, INFO, WARNING, ERROR)
            **kwargs: Additional metadata to include in the log entry
        """
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": level,
            "message": message,
            **kwargs,
        }
        self.logs.append(log_entry)

    def get_logs(self, level: str | None = None) -> list[dict[str, Any]]:
        """
        Retrieve logs, optionally filtered by level.

        Args:
            level: Optional log level to filter by

        Returns:
            List of log entries
        """
        if level is None:
            return self.logs
        return [log for log in self.logs if log.get("level") == level]

    def to_dict(self) -> dict[str, Any]:
        """
        Convert context to dictionary for serialization.

        Returns:
            Dictionary representation of the context
        """
        return {
            "target": self.target,
            "metadata": self.metadata,
            "data": self.data,
            "logs": self.logs,
        }

    def to_json(self, indent: int = 2) -> str:
        """
        Convert context to JSON string.

        Args:
            indent: Number of spaces for indentation

        Returns:
            JSON string representation of the context
        """
        return json.dumps(self.to_dict(), indent=indent, default=str)

    def __repr__(self) -> str:
        return f"Context(target={self.target}, data_keys={list(self.data.keys())})"
