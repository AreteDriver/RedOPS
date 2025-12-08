"""
Context - Central data store for pipeline execution.

The Context object is passed through each step of the pipeline,
preserving all intermediate outputs for reporting and simulation steps.
"""

from typing import Any, Dict, List, Optional
from datetime import datetime
import json


class Context:
    """
    Central data store for pipeline execution.
    
    Supports .add(), .get(), .log() operations and preserves
    all intermediate outputs.
    """
    
    def __init__(self, target: Optional[str] = None):
        """
        Initialize a new Context.
        
        Args:
            target: The target of the pipeline execution (e.g., domain, directory)
        """
        self.target = target
        self.data: Dict[str, Any] = {}
        self.logs: List[Dict[str, Any]] = []
        self.metadata: Dict[str, Any] = {
            "created_at": datetime.utcnow().isoformat(),
            "target": target
        }
        
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
            "timestamp": datetime.utcnow().isoformat(),
            "level": level,
            "message": message,
            **kwargs
        }
        self.logs.append(log_entry)
        
    def get_logs(self, level: Optional[str] = None) -> List[Dict[str, Any]]:
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
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert context to dictionary for serialization.
        
        Returns:
            Dictionary representation of the context
        """
        return {
            "target": self.target,
            "metadata": self.metadata,
            "data": self.data,
            "logs": self.logs
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
