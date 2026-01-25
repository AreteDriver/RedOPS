"""
Configuration Management for RedOPS.

Supports YAML/TOML config files, profiles, environment variable overrides,
and hierarchical configuration merging.
"""

import os
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

# Optional imports for config file formats
try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False

try:
    import tomllib
    TOML_AVAILABLE = True
except ImportError:
    try:
        import tomli as tomllib
        TOML_AVAILABLE = True
    except ImportError:
        TOML_AVAILABLE = False


class ConfigFormat(Enum):
    """Supported configuration file formats."""
    YAML = "yaml"
    TOML = "toml"
    JSON = "json"
    ENV = "env"


class ConfigProfile(Enum):
    """Pre-defined configuration profiles."""
    DEFAULT = "default"
    DEVELOPMENT = "development"
    PRODUCTION = "production"
    TESTING = "testing"
    MINIMAL = "minimal"
    COMPREHENSIVE = "comprehensive"


@dataclass
class ModuleConfig:
    """Configuration for a specific module."""
    enabled: bool = True
    timeout: int = 30
    retries: int = 3
    options: dict = field(default_factory=dict)


@dataclass
class OutputConfig:
    """Output configuration settings."""
    directory: str = "./output"
    format: str = "json"
    include_raw: bool = False
    compress: bool = False
    max_file_size_mb: int = 100


@dataclass
class NetworkConfig:
    """Network-related configuration."""
    timeout: int = 30
    max_connections: int = 10
    rate_limit: float = 1.0  # requests per second
    proxy: str | None = None
    verify_ssl: bool = True
    user_agent: str = "RedOPS/1.0"


@dataclass
class LoggingConfig:
    """Logging configuration."""
    level: str = "INFO"
    file: str | None = None
    format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    max_size_mb: int = 10
    backup_count: int = 5


@dataclass
class CacheConfig:
    """Cache configuration."""
    enabled: bool = True
    directory: str = "./.cache"
    ttl_seconds: int = 3600
    max_size_mb: int = 500


@dataclass
class RedOPSConfiguration:
    """Complete RedOPS configuration."""
    profile: str = "default"
    modules: dict[str, ModuleConfig] = field(default_factory=dict)
    output: OutputConfig = field(default_factory=OutputConfig)
    network: NetworkConfig = field(default_factory=NetworkConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    cache: CacheConfig = field(default_factory=CacheConfig)
    custom: dict[str, Any] = field(default_factory=dict)


class ConfigValidationError(Exception):
    """Raised when configuration validation fails."""

    def __init__(self, errors: list[str]):
        self.errors = errors
        super().__init__(f"Configuration validation failed: {', '.join(errors)}")


class ConfigManager:
    """
    Manages RedOPS configuration with support for multiple sources.

    Configuration priority (highest to lowest):
    1. CLI arguments
    2. Environment variables
    3. User config file (~/.redops/config.yaml)
    4. Project config file (./redops.yaml)
    5. Profile defaults
    6. Built-in defaults
    """

    ENV_PREFIX = "REDOPS_"
    DEFAULT_CONFIG_NAMES = ["redops.yaml", "redops.yml", "redops.toml", ".redops.yaml"]
    USER_CONFIG_DIR = Path.home() / ".redops"

    # Profile definitions
    PROFILES: dict[str, dict] = {
        ConfigProfile.DEFAULT.value: {},
        ConfigProfile.DEVELOPMENT.value: {
            "logging": {"level": "DEBUG"},
            "cache": {"enabled": True, "ttl_seconds": 300},
            "network": {"verify_ssl": False},
        },
        ConfigProfile.PRODUCTION.value: {
            "logging": {"level": "WARNING"},
            "cache": {"enabled": True, "ttl_seconds": 7200},
            "network": {"verify_ssl": True, "rate_limit": 0.5},
        },
        ConfigProfile.TESTING.value: {
            "logging": {"level": "DEBUG"},
            "cache": {"enabled": False},
            "network": {"timeout": 5, "retries": 1},
        },
        ConfigProfile.MINIMAL.value: {
            "modules": {
                "domain_profile": {"enabled": True},
                "tech_stack": {"enabled": True},
            },
            "cache": {"enabled": False},
        },
        ConfigProfile.COMPREHENSIVE.value: {
            "modules": {
                "domain_profile": {"enabled": True},
                "tech_stack": {"enabled": True},
                "social_osint": {"enabled": True},
                "exposure_scan": {"enabled": True},
                "infrastructure": {"enabled": True},
                "threat_intel": {"enabled": True},
                "compliance": {"enabled": True},
                "correlation": {"enabled": True},
                "executive_report": {"enabled": True},
            },
            "output": {"include_raw": True},
        },
    }

    def __init__(self):
        self._config: RedOPSConfiguration = RedOPSConfiguration()
        self._sources: list[str] = []
        self._raw_config: dict = {}

    @property
    def config(self) -> RedOPSConfiguration:
        """Get the current configuration."""
        return self._config

    @property
    def sources(self) -> list[str]:
        """Get list of configuration sources that were loaded."""
        return self._sources.copy()

    def load(
        self,
        config_file: str | Path | None = None,
        profile: str | None = None,
        cli_overrides: dict | None = None,
        auto_discover: bool = True,
    ) -> RedOPSConfiguration:
        """
        Load configuration from all sources.

        Args:
            config_file: Explicit config file path
            profile: Configuration profile to use
            cli_overrides: CLI argument overrides
            auto_discover: Whether to auto-discover config files

        Returns:
            Merged configuration
        """
        self._sources = []
        self._raw_config = {}

        # Start with defaults
        merged = self._get_defaults()
        self._sources.append("defaults")

        # Apply profile if specified
        if profile:
            profile_config = self._get_profile_config(profile)
            merged = self._deep_merge(merged, profile_config)
            self._sources.append(f"profile:{profile}")

        # Auto-discover project config
        if auto_discover:
            project_config = self._discover_project_config()
            if project_config:
                merged = self._deep_merge(merged, project_config)

        # Load user config
        user_config = self._load_user_config()
        if user_config:
            merged = self._deep_merge(merged, user_config)

        # Load explicit config file
        if config_file:
            file_config = self._load_file(config_file)
            merged = self._deep_merge(merged, file_config)
            self._sources.append(f"file:{config_file}")

        # Apply environment variables
        env_config = self._load_env_vars()
        if env_config:
            merged = self._deep_merge(merged, env_config)
            self._sources.append("environment")

        # Apply CLI overrides
        if cli_overrides:
            merged = self._deep_merge(merged, cli_overrides)
            self._sources.append("cli")

        self._raw_config = merged
        self._config = self._dict_to_config(merged)

        return self._config

    def validate(self) -> list[str]:
        """
        Validate the current configuration.

        Returns:
            List of validation errors (empty if valid)
        """
        errors = []

        # Validate output directory is writable
        output_dir = Path(self._config.output.directory)
        if output_dir.exists() and not os.access(output_dir, os.W_OK):
            errors.append(f"Output directory not writable: {output_dir}")

        # Validate network settings
        if self._config.network.timeout <= 0:
            errors.append("Network timeout must be positive")

        if self._config.network.max_connections <= 0:
            errors.append("Max connections must be positive")

        if self._config.network.rate_limit <= 0:
            errors.append("Rate limit must be positive")

        # Validate logging level
        valid_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        if self._config.logging.level.upper() not in valid_levels:
            errors.append(f"Invalid logging level: {self._config.logging.level}")

        # Validate cache settings
        if self._config.cache.enabled:
            if self._config.cache.ttl_seconds <= 0:
                errors.append("Cache TTL must be positive")
            if self._config.cache.max_size_mb <= 0:
                errors.append("Cache max size must be positive")

        # Validate module configs
        for name, mod_config in self._config.modules.items():
            if mod_config.timeout <= 0:
                errors.append(f"Module '{name}' timeout must be positive")
            if mod_config.retries < 0:
                errors.append(f"Module '{name}' retries cannot be negative")

        return errors

    def validate_or_raise(self) -> None:
        """Validate configuration and raise if invalid."""
        errors = self.validate()
        if errors:
            raise ConfigValidationError(errors)

    def get_module_config(self, module_name: str) -> ModuleConfig:
        """Get configuration for a specific module."""
        if module_name in self._config.modules:
            return self._config.modules[module_name]
        return ModuleConfig()  # Default config

    def is_module_enabled(self, module_name: str) -> bool:
        """Check if a module is enabled."""
        mod_config = self.get_module_config(module_name)
        return mod_config.enabled

    def get(self, key: str, default: Any = None) -> Any:
        """
        Get a configuration value by dot-notation key.

        Args:
            key: Dot-notation key (e.g., "network.timeout")
            default: Default value if key not found

        Returns:
            Configuration value
        """
        parts = key.split(".")
        value = self._raw_config

        for part in parts:
            if isinstance(value, dict) and part in value:
                value = value[part]
            else:
                return default

        return value

    def set(self, key: str, value: Any) -> None:
        """
        Set a configuration value by dot-notation key.

        Args:
            key: Dot-notation key (e.g., "network.timeout")
            value: Value to set
        """
        parts = key.split(".")
        target = self._raw_config

        for part in parts[:-1]:
            if part not in target:
                target[part] = {}
            target = target[part]

        target[parts[-1]] = value
        self._config = self._dict_to_config(self._raw_config)

    def to_dict(self) -> dict:
        """Export configuration as dictionary."""
        return self._raw_config.copy()

    def to_yaml(self) -> str:
        """Export configuration as YAML string."""
        if not YAML_AVAILABLE:
            raise ImportError("PyYAML is required for YAML export")
        return yaml.dump(self._raw_config, default_flow_style=False, sort_keys=False)

    def to_toml(self) -> str:
        """Export configuration as TOML string."""
        # Simple TOML serialization
        return self._dict_to_toml(self._raw_config)

    def save(self, path: str | Path, format: ConfigFormat = ConfigFormat.YAML) -> None:
        """
        Save configuration to file.

        Args:
            path: Output file path
            format: Output format
        """
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)

        if format == ConfigFormat.YAML:
            content = self.to_yaml()
        elif format == ConfigFormat.TOML:
            content = self.to_toml()
        elif format == ConfigFormat.JSON:
            import json
            content = json.dumps(self._raw_config, indent=2)
        else:
            raise ValueError(f"Unsupported format for saving: {format}")

        path.write_text(content)

    def generate_default_config(self, format: ConfigFormat = ConfigFormat.YAML) -> str:
        """
        Generate a default configuration file content.

        Args:
            format: Output format

        Returns:
            Configuration file content
        """
        defaults = self._get_defaults()
        defaults["profile"] = "default"

        # Add helpful comments for YAML
        if format == ConfigFormat.YAML:
            if not YAML_AVAILABLE:
                raise ImportError("PyYAML is required for YAML generation")

            header = """# RedOPS Configuration File
# See documentation for all available options

"""
            return header + yaml.dump(defaults, default_flow_style=False, sort_keys=False)

        elif format == ConfigFormat.TOML:
            header = """# RedOPS Configuration File
# See documentation for all available options

"""
            return header + self._dict_to_toml(defaults)

        elif format == ConfigFormat.JSON:
            import json
            return json.dumps(defaults, indent=2)

        raise ValueError(f"Unsupported format: {format}")

    def _get_defaults(self) -> dict:
        """Get default configuration as dictionary."""
        return {
            "profile": "default",
            "modules": {},
            "output": {
                "directory": "./output",
                "format": "json",
                "include_raw": False,
                "compress": False,
                "max_file_size_mb": 100,
            },
            "network": {
                "timeout": 30,
                "max_connections": 10,
                "rate_limit": 1.0,
                "proxy": None,
                "verify_ssl": True,
                "user_agent": "RedOPS/1.0",
            },
            "logging": {
                "level": "INFO",
                "file": None,
                "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
                "max_size_mb": 10,
                "backup_count": 5,
            },
            "cache": {
                "enabled": True,
                "directory": "./.cache",
                "ttl_seconds": 3600,
                "max_size_mb": 500,
            },
            "custom": {},
        }

    def _get_profile_config(self, profile: str) -> dict:
        """Get configuration overrides for a profile."""
        if profile in self.PROFILES:
            return self.PROFILES[profile]

        # Check for custom profile file
        profile_file = self.USER_CONFIG_DIR / "profiles" / f"{profile}.yaml"
        if profile_file.exists():
            return self._load_file(profile_file)

        return {}

    def _discover_project_config(self) -> dict | None:
        """Discover and load project configuration file."""
        cwd = Path.cwd()

        for name in self.DEFAULT_CONFIG_NAMES:
            config_path = cwd / name
            if config_path.exists():
                self._sources.append(f"project:{config_path}")
                return self._load_file(config_path)

        return None

    def _load_user_config(self) -> dict | None:
        """Load user configuration from ~/.redops/config.yaml."""
        for ext in ["yaml", "yml", "toml"]:
            config_path = self.USER_CONFIG_DIR / f"config.{ext}"
            if config_path.exists():
                self._sources.append(f"user:{config_path}")
                return self._load_file(config_path)

        return None

    def _load_file(self, path: str | Path) -> dict:
        """Load configuration from a file."""
        path = Path(path)

        if not path.exists():
            raise FileNotFoundError(f"Config file not found: {path}")

        content = path.read_text()
        suffix = path.suffix.lower()

        if suffix in (".yaml", ".yml"):
            if not YAML_AVAILABLE:
                raise ImportError("PyYAML is required to load YAML config files")
            return yaml.safe_load(content) or {}

        elif suffix == ".toml":
            if not TOML_AVAILABLE:
                raise ImportError("tomllib/tomli is required to load TOML config files")
            return tomllib.loads(content)

        elif suffix == ".json":
            import json
            return json.loads(content)

        else:
            # Try YAML by default
            if YAML_AVAILABLE:
                return yaml.safe_load(content) or {}
            raise ValueError(f"Unsupported config file format: {suffix}")

    def _load_env_vars(self) -> dict:
        """Load configuration from environment variables."""
        config = {}

        for key, value in os.environ.items():
            if not key.startswith(self.ENV_PREFIX):
                continue

            # Convert REDOPS_NETWORK_TIMEOUT to network.timeout
            config_key = key[len(self.ENV_PREFIX):].lower().replace("__", ".")

            # Parse value
            parsed_value = self._parse_env_value(value)

            # Set nested value
            parts = config_key.split(".")
            target = config
            for part in parts[:-1]:
                if part not in target:
                    target[part] = {}
                target = target[part]
            target[parts[-1]] = parsed_value

        return config

    def _parse_env_value(self, value: str) -> Any:
        """Parse environment variable value to appropriate type."""
        # Boolean
        if value.lower() in ("true", "yes", "1", "on"):
            return True
        if value.lower() in ("false", "no", "0", "off"):
            return False

        # None
        if value.lower() in ("none", "null", ""):
            return None

        # Integer
        if re.match(r"^-?\d+$", value):
            return int(value)

        # Float
        if re.match(r"^-?\d+\.\d+$", value):
            return float(value)

        # String
        return value

    def _deep_merge(self, base: dict, override: dict) -> dict:
        """Deep merge two dictionaries."""
        result = base.copy()

        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._deep_merge(result[key], value)
            else:
                result[key] = value

        return result

    def _dict_to_config(self, data: dict) -> RedOPSConfiguration:
        """Convert dictionary to RedOPSConfiguration."""
        # Parse modules
        modules = {}
        for name, mod_data in data.get("modules", {}).items():
            if isinstance(mod_data, dict):
                modules[name] = ModuleConfig(
                    enabled=mod_data.get("enabled", True),
                    timeout=mod_data.get("timeout", 30),
                    retries=mod_data.get("retries", 3),
                    options=mod_data.get("options", {}),
                )
            else:
                modules[name] = ModuleConfig(enabled=bool(mod_data))

        # Parse output
        output_data = data.get("output", {})
        output = OutputConfig(
            directory=output_data.get("directory", "./output"),
            format=output_data.get("format", "json"),
            include_raw=output_data.get("include_raw", False),
            compress=output_data.get("compress", False),
            max_file_size_mb=output_data.get("max_file_size_mb", 100),
        )

        # Parse network
        network_data = data.get("network", {})
        network = NetworkConfig(
            timeout=network_data.get("timeout", 30),
            max_connections=network_data.get("max_connections", 10),
            rate_limit=network_data.get("rate_limit", 1.0),
            proxy=network_data.get("proxy"),
            verify_ssl=network_data.get("verify_ssl", True),
            user_agent=network_data.get("user_agent", "RedOPS/1.0"),
        )

        # Parse logging
        logging_data = data.get("logging", {})
        logging_config = LoggingConfig(
            level=logging_data.get("level", "INFO"),
            file=logging_data.get("file"),
            format=logging_data.get("format", "%(asctime)s - %(name)s - %(levelname)s - %(message)s"),
            max_size_mb=logging_data.get("max_size_mb", 10),
            backup_count=logging_data.get("backup_count", 5),
        )

        # Parse cache
        cache_data = data.get("cache", {})
        cache = CacheConfig(
            enabled=cache_data.get("enabled", True),
            directory=cache_data.get("directory", "./.cache"),
            ttl_seconds=cache_data.get("ttl_seconds", 3600),
            max_size_mb=cache_data.get("max_size_mb", 500),
        )

        return RedOPSConfiguration(
            profile=data.get("profile", "default"),
            modules=modules,
            output=output,
            network=network,
            logging=logging_config,
            cache=cache,
            custom=data.get("custom", {}),
        )

    def _dict_to_toml(self, data: dict, prefix: str = "") -> str:
        """Convert dictionary to TOML string."""
        lines = []
        tables = []

        for key, value in data.items():
            full_key = f"{prefix}.{key}" if prefix else key

            if isinstance(value, dict):
                tables.append((full_key, value))
            elif value is None:
                # Skip None values in TOML
                pass
            elif isinstance(value, bool):
                lines.append(f"{key} = {str(value).lower()}")
            elif isinstance(value, str):
                lines.append(f'{key} = "{value}"')
            elif isinstance(value, (int, float)):
                lines.append(f"{key} = {value}")
            elif isinstance(value, list):
                items = ", ".join(
                    f'"{v}"' if isinstance(v, str) else str(v)
                    for v in value
                )
                lines.append(f"{key} = [{items}]")

        result = "\n".join(lines)

        for table_key, table_data in tables:
            table_content = self._dict_to_toml(table_data, table_key)
            if table_content.strip():
                result += f"\n\n[{table_key}]\n{table_content}"

        return result


# Convenience functions
_global_config_manager: ConfigManager | None = None


def get_config_manager() -> ConfigManager:
    """Get the global configuration manager instance."""
    global _global_config_manager
    if _global_config_manager is None:
        _global_config_manager = ConfigManager()
    return _global_config_manager


def load_config(
    config_file: str | Path | None = None,
    profile: str | None = None,
    cli_overrides: dict | None = None,
    auto_discover: bool = True,
) -> RedOPSConfiguration:
    """
    Load configuration using the global manager.

    Args:
        config_file: Explicit config file path
        profile: Configuration profile to use
        cli_overrides: CLI argument overrides
        auto_discover: Whether to auto-discover config files

    Returns:
        Loaded configuration
    """
    manager = get_config_manager()
    return manager.load(config_file, profile, cli_overrides, auto_discover)


def get_config() -> RedOPSConfiguration:
    """Get the current global configuration."""
    return get_config_manager().config
