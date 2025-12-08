"""
Configuration management for RedOps.

Handles loading configuration from files and environment variables.
"""

from typing import List, Optional, Dict, Any
from pathlib import Path
import json
import os
from pydantic import BaseModel, Field


class ScopeConfig(BaseModel):
    """Configuration for scope validation."""
    allowed_domains: List[str] = Field(default_factory=list)
    allowed_ips: List[str] = Field(default_factory=list)
    allowed_directories: List[str] = Field(default_factory=list)
    strict_mode: bool = True


class OutputConfig(BaseModel):
    """Configuration for output settings."""
    output_dir: str = "./output"
    format: str = "markdown"  # markdown, html, json
    include_logs: bool = True
    verbose: bool = False


class ModuleConfig(BaseModel):
    """Configuration for module settings."""
    timeout: int = 300  # seconds
    max_retries: int = 3
    user_agent: str = "RedOps/1.0 (OSINT Framework)"


class RedOpsConfig(BaseModel):
    """Main configuration for RedOps."""
    scope: ScopeConfig = Field(default_factory=ScopeConfig)
    output: OutputConfig = Field(default_factory=OutputConfig)
    modules: ModuleConfig = Field(default_factory=ModuleConfig)
    custom: Dict[str, Any] = Field(default_factory=dict)
    
    @classmethod
    def from_file(cls, path: Path) -> "RedOpsConfig":
        """
        Load configuration from a JSON file.
        
        Args:
            path: Path to the configuration file
            
        Returns:
            RedOpsConfig instance
        """
        with open(path, 'r') as f:
            data = json.load(f)
        return cls(**data)
    
    @classmethod
    def from_env(cls) -> "RedOpsConfig":
        """
        Load configuration from environment variables.
        
        Returns:
            RedOpsConfig instance
        """
        config = cls()
        
        # Override with environment variables if present
        if os.getenv("REDOPS_OUTPUT_DIR"):
            config.output.output_dir = os.getenv("REDOPS_OUTPUT_DIR")
        
        if os.getenv("REDOPS_VERBOSE"):
            config.output.verbose = os.getenv("REDOPS_VERBOSE").lower() == "true"
        
        if os.getenv("REDOPS_STRICT_SCOPE"):
            config.scope.strict_mode = os.getenv("REDOPS_STRICT_SCOPE").lower() == "true"
        
        return config
    
    def to_file(self, path: Path) -> None:
        """
        Save configuration to a JSON file.
        
        Args:
            path: Path to save the configuration file
        """
        with open(path, 'w') as f:
            json.dump(self.model_dump(), f, indent=2)


# Default configuration instance
default_config = RedOpsConfig()
