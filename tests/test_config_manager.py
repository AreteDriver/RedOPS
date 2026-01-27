"""
Tests for RedOPS Configuration Management.
"""

import json
import os
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from redops.core.config_manager import (
    CacheConfig,
    ConfigFormat,
    ConfigManager,
    ConfigProfile,
    ConfigValidationError,
    LoggingConfig,
    ModuleConfig,
    NetworkConfig,
    OutputConfig,
    RedOPSConfiguration,
    get_config,
    get_config_manager,
    load_config,
    YAML_AVAILABLE,
)


class TestModuleConfig:
    """Tests for ModuleConfig dataclass."""

    def test_default_values(self):
        """Test default ModuleConfig values."""
        config = ModuleConfig()
        assert config.enabled is True
        assert config.timeout == 30
        assert config.retries == 3
        assert config.options == {}

    def test_custom_values(self):
        """Test ModuleConfig with custom values."""
        config = ModuleConfig(
            enabled=False,
            timeout=60,
            retries=5,
            options={"key": "value"},
        )
        assert config.enabled is False
        assert config.timeout == 60
        assert config.retries == 5
        assert config.options == {"key": "value"}


class TestOutputConfig:
    """Tests for OutputConfig dataclass."""

    def test_default_values(self):
        """Test default OutputConfig values."""
        config = OutputConfig()
        assert config.directory == "./output"
        assert config.format == "json"
        assert config.include_raw is False
        assert config.compress is False
        assert config.max_file_size_mb == 100

    def test_custom_values(self):
        """Test OutputConfig with custom values."""
        config = OutputConfig(
            directory="/custom/output",
            format="html",
            include_raw=True,
            compress=True,
            max_file_size_mb=50,
        )
        assert config.directory == "/custom/output"
        assert config.format == "html"
        assert config.include_raw is True
        assert config.compress is True
        assert config.max_file_size_mb == 50


class TestNetworkConfig:
    """Tests for NetworkConfig dataclass."""

    def test_default_values(self):
        """Test default NetworkConfig values."""
        config = NetworkConfig()
        assert config.timeout == 30
        assert config.max_connections == 10
        assert config.rate_limit == 1.0
        assert config.proxy is None
        assert config.verify_ssl is True
        assert config.user_agent == "RedOPS/1.0"

    def test_custom_values(self):
        """Test NetworkConfig with custom values."""
        config = NetworkConfig(
            timeout=60,
            max_connections=20,
            rate_limit=0.5,
            proxy="http://proxy:8080",
            verify_ssl=False,
            user_agent="CustomAgent/2.0",
        )
        assert config.timeout == 60
        assert config.max_connections == 20
        assert config.rate_limit == 0.5
        assert config.proxy == "http://proxy:8080"
        assert config.verify_ssl is False
        assert config.user_agent == "CustomAgent/2.0"


class TestLoggingConfig:
    """Tests for LoggingConfig dataclass."""

    def test_default_values(self):
        """Test default LoggingConfig values."""
        config = LoggingConfig()
        assert config.level == "INFO"
        assert config.file is None
        assert "%(asctime)s" in config.format
        assert config.max_size_mb == 10
        assert config.backup_count == 5

    def test_custom_values(self):
        """Test LoggingConfig with custom values."""
        config = LoggingConfig(
            level="DEBUG",
            file="/var/log/redops.log",
            format="%(message)s",
            max_size_mb=50,
            backup_count=10,
        )
        assert config.level == "DEBUG"
        assert config.file == "/var/log/redops.log"
        assert config.format == "%(message)s"
        assert config.max_size_mb == 50
        assert config.backup_count == 10


class TestCacheConfig:
    """Tests for CacheConfig dataclass."""

    def test_default_values(self):
        """Test default CacheConfig values."""
        config = CacheConfig()
        assert config.enabled is True
        assert config.directory == "./.cache"
        assert config.ttl_seconds == 3600
        assert config.max_size_mb == 500

    def test_custom_values(self):
        """Test CacheConfig with custom values."""
        config = CacheConfig(
            enabled=False,
            directory="/tmp/cache",
            ttl_seconds=7200,
            max_size_mb=1000,
        )
        assert config.enabled is False
        assert config.directory == "/tmp/cache"
        assert config.ttl_seconds == 7200
        assert config.max_size_mb == 1000


class TestRedOPSConfiguration:
    """Tests for RedOPSConfiguration dataclass."""

    def test_default_values(self):
        """Test default RedOPSConfiguration values."""
        config = RedOPSConfiguration()
        assert config.profile == "default"
        assert config.modules == {}
        assert isinstance(config.output, OutputConfig)
        assert isinstance(config.network, NetworkConfig)
        assert isinstance(config.logging, LoggingConfig)
        assert isinstance(config.cache, CacheConfig)
        assert config.custom == {}

    def test_with_modules(self):
        """Test RedOPSConfiguration with modules."""
        config = RedOPSConfiguration(
            modules={
                "domain_profile": ModuleConfig(enabled=True),
                "tech_stack": ModuleConfig(enabled=False),
            }
        )
        assert len(config.modules) == 2
        assert config.modules["domain_profile"].enabled is True
        assert config.modules["tech_stack"].enabled is False


class TestConfigManager:
    """Tests for ConfigManager class."""

    def test_initialization(self):
        """Test ConfigManager initialization."""
        manager = ConfigManager()
        assert isinstance(manager.config, RedOPSConfiguration)
        assert manager.sources == []

    def test_load_defaults(self):
        """Test loading default configuration."""
        manager = ConfigManager()
        config = manager.load(auto_discover=False)

        assert config.profile == "default"
        assert config.network.timeout == 30
        assert config.cache.enabled is True
        assert "defaults" in manager.sources

    def test_load_with_profile_development(self):
        """Test loading with development profile."""
        manager = ConfigManager()
        config = manager.load(profile="development", auto_discover=False)

        assert config.logging.level == "DEBUG"
        assert config.network.verify_ssl is False
        assert "profile:development" in manager.sources

    def test_load_with_profile_production(self):
        """Test loading with production profile."""
        manager = ConfigManager()
        config = manager.load(profile="production", auto_discover=False)

        assert config.logging.level == "WARNING"
        assert config.network.verify_ssl is True
        assert config.network.rate_limit == 0.5

    def test_load_with_profile_testing(self):
        """Test loading with testing profile."""
        manager = ConfigManager()
        config = manager.load(profile="testing", auto_discover=False)

        assert config.logging.level == "DEBUG"
        assert config.cache.enabled is False
        assert config.network.timeout == 5

    def test_load_with_profile_minimal(self):
        """Test loading with minimal profile."""
        manager = ConfigManager()
        config = manager.load(profile="minimal", auto_discover=False)

        assert config.cache.enabled is False
        assert "domain_profile" in config.modules
        assert "tech_stack" in config.modules

    def test_load_with_profile_comprehensive(self):
        """Test loading with comprehensive profile."""
        manager = ConfigManager()
        config = manager.load(profile="comprehensive", auto_discover=False)

        assert config.output.include_raw is True
        assert len(config.modules) >= 9

    def test_load_with_cli_overrides(self):
        """Test loading with CLI overrides."""
        manager = ConfigManager()
        config = manager.load(
            cli_overrides={"network": {"timeout": 120}},
            auto_discover=False,
        )

        assert config.network.timeout == 120
        assert "cli" in manager.sources

    def test_load_json_config_file(self):
        """Test loading JSON config file."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"network": {"timeout": 45}}, f)
            f.flush()

            try:
                manager = ConfigManager()
                config = manager.load(config_file=f.name, auto_discover=False)

                assert config.network.timeout == 45
                assert f"file:{f.name}" in manager.sources
            finally:
                os.unlink(f.name)

    def test_load_nonexistent_file_raises(self):
        """Test that loading nonexistent file raises FileNotFoundError."""
        manager = ConfigManager()
        with pytest.raises(FileNotFoundError):
            manager.load(config_file="/nonexistent/config.json", auto_discover=False)

    def test_get_module_config_existing(self):
        """Test getting existing module config."""
        manager = ConfigManager()
        manager.load(
            cli_overrides={
                "modules": {"test_module": {"enabled": True, "timeout": 60}}
            },
            auto_discover=False,
        )

        mod_config = manager.get_module_config("test_module")
        assert mod_config.enabled is True
        assert mod_config.timeout == 60

    def test_get_module_config_nonexistent(self):
        """Test getting nonexistent module config returns defaults."""
        manager = ConfigManager()
        manager.load(auto_discover=False)

        mod_config = manager.get_module_config("nonexistent")
        assert mod_config.enabled is True  # Default
        assert mod_config.timeout == 30  # Default

    def test_is_module_enabled_true(self):
        """Test checking if module is enabled."""
        manager = ConfigManager()
        manager.load(
            cli_overrides={"modules": {"enabled_module": {"enabled": True}}},
            auto_discover=False,
        )

        assert manager.is_module_enabled("enabled_module") is True

    def test_is_module_enabled_false(self):
        """Test checking if module is disabled."""
        manager = ConfigManager()
        manager.load(
            cli_overrides={"modules": {"disabled_module": {"enabled": False}}},
            auto_discover=False,
        )

        assert manager.is_module_enabled("disabled_module") is False

    def test_get_dot_notation(self):
        """Test getting value by dot notation."""
        manager = ConfigManager()
        manager.load(auto_discover=False)

        assert manager.get("network.timeout") == 30
        assert manager.get("cache.enabled") is True
        assert manager.get("output.directory") == "./output"

    def test_get_dot_notation_default(self):
        """Test getting nonexistent key returns default."""
        manager = ConfigManager()
        manager.load(auto_discover=False)

        assert manager.get("nonexistent.key") is None
        assert manager.get("nonexistent.key", "default") == "default"

    def test_set_dot_notation(self):
        """Test setting value by dot notation."""
        manager = ConfigManager()
        manager.load(auto_discover=False)

        manager.set("network.timeout", 120)
        assert manager.get("network.timeout") == 120
        assert manager.config.network.timeout == 120

    def test_set_creates_nested_structure(self):
        """Test set creates nested structure if needed."""
        manager = ConfigManager()
        manager.load(auto_discover=False)

        manager.set("custom.nested.key", "value")
        assert manager.get("custom.nested.key") == "value"

    def test_to_dict(self):
        """Test exporting configuration as dictionary."""
        manager = ConfigManager()
        manager.load(auto_discover=False)

        config_dict = manager.to_dict()
        assert isinstance(config_dict, dict)
        assert "network" in config_dict
        assert "cache" in config_dict

    def test_validate_valid_config(self):
        """Test validation of valid configuration."""
        manager = ConfigManager()
        manager.load(auto_discover=False)

        errors = manager.validate()
        assert errors == []

    def test_validate_invalid_timeout(self):
        """Test validation catches invalid timeout."""
        manager = ConfigManager()
        manager.load(
            cli_overrides={"network": {"timeout": -1}},
            auto_discover=False,
        )

        errors = manager.validate()
        assert any("timeout" in e.lower() for e in errors)

    def test_validate_invalid_max_connections(self):
        """Test validation catches invalid max_connections."""
        manager = ConfigManager()
        manager.load(
            cli_overrides={"network": {"max_connections": 0}},
            auto_discover=False,
        )

        errors = manager.validate()
        assert any("connections" in e.lower() for e in errors)

    def test_validate_invalid_rate_limit(self):
        """Test validation catches invalid rate_limit."""
        manager = ConfigManager()
        manager.load(
            cli_overrides={"network": {"rate_limit": -0.5}},
            auto_discover=False,
        )

        errors = manager.validate()
        assert any("rate limit" in e.lower() for e in errors)

    def test_validate_invalid_logging_level(self):
        """Test validation catches invalid logging level."""
        manager = ConfigManager()
        manager.load(
            cli_overrides={"logging": {"level": "INVALID"}},
            auto_discover=False,
        )

        errors = manager.validate()
        assert any("logging level" in e.lower() for e in errors)

    def test_validate_invalid_cache_ttl(self):
        """Test validation catches invalid cache TTL."""
        manager = ConfigManager()
        manager.load(
            cli_overrides={"cache": {"enabled": True, "ttl_seconds": 0}},
            auto_discover=False,
        )

        errors = manager.validate()
        assert any("ttl" in e.lower() for e in errors)

    def test_validate_invalid_module_timeout(self):
        """Test validation catches invalid module timeout."""
        manager = ConfigManager()
        manager.load(
            cli_overrides={"modules": {"test": {"timeout": -5}}},
            auto_discover=False,
        )

        errors = manager.validate()
        assert any("timeout" in e.lower() for e in errors)

    def test_validate_invalid_module_retries(self):
        """Test validation catches invalid module retries."""
        manager = ConfigManager()
        manager.load(
            cli_overrides={"modules": {"test": {"retries": -1}}},
            auto_discover=False,
        )

        errors = manager.validate()
        assert any("retries" in e.lower() for e in errors)

    def test_validate_or_raise_valid(self):
        """Test validate_or_raise with valid config."""
        manager = ConfigManager()
        manager.load(auto_discover=False)

        # Should not raise
        manager.validate_or_raise()

    def test_validate_or_raise_invalid(self):
        """Test validate_or_raise with invalid config."""
        manager = ConfigManager()
        manager.load(
            cli_overrides={"network": {"timeout": -1}},
            auto_discover=False,
        )

        with pytest.raises(ConfigValidationError) as exc_info:
            manager.validate_or_raise()

        assert len(exc_info.value.errors) > 0

    def test_generate_default_config_json(self):
        """Test generating default config as JSON."""
        manager = ConfigManager()
        manager.load(auto_discover=False)

        content = manager.generate_default_config(format=ConfigFormat.JSON)

        parsed = json.loads(content)
        assert "profile" in parsed
        assert "network" in parsed

    def test_generate_default_config_toml(self):
        """Test generating default config as TOML."""
        manager = ConfigManager()
        manager.load(auto_discover=False)

        content = manager.generate_default_config(format=ConfigFormat.TOML)

        assert "profile" in content
        assert "[network]" in content

    def test_save_json(self):
        """Test saving configuration as JSON."""
        manager = ConfigManager()
        manager.load(auto_discover=False)

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            try:
                manager.save(f.name, format=ConfigFormat.JSON)

                content = Path(f.name).read_text()
                parsed = json.loads(content)
                assert "network" in parsed
            finally:
                os.unlink(f.name)

    def test_save_toml(self):
        """Test saving configuration as TOML."""
        manager = ConfigManager()
        manager.load(auto_discover=False)

        with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
            try:
                manager.save(f.name, format=ConfigFormat.TOML)

                content = Path(f.name).read_text()
                assert "[network]" in content
            finally:
                os.unlink(f.name)

    def test_to_toml(self):
        """Test exporting configuration as TOML."""
        manager = ConfigManager()
        manager.load(auto_discover=False)

        toml_content = manager.to_toml()

        assert isinstance(toml_content, str)
        assert "[network]" in toml_content
        assert "timeout = 30" in toml_content


class TestConfigManagerEnvironmentVariables:
    """Tests for environment variable loading."""

    def test_load_env_string(self):
        """Test loading string from environment."""
        with patch.dict(os.environ, {"REDOPS_OUTPUT__DIRECTORY": "/custom/output"}):
            manager = ConfigManager()
            config = manager.load(auto_discover=False)

            assert config.output.directory == "/custom/output"

    def test_load_env_integer(self):
        """Test loading integer from environment."""
        with patch.dict(os.environ, {"REDOPS_NETWORK__TIMEOUT": "120"}):
            manager = ConfigManager()
            config = manager.load(auto_discover=False)

            assert config.network.timeout == 120

    def test_load_env_float(self):
        """Test loading float from environment."""
        with patch.dict(os.environ, {"REDOPS_NETWORK__RATE_LIMIT": "2.5"}):
            manager = ConfigManager()
            config = manager.load(auto_discover=False)

            assert config.network.rate_limit == 2.5

    def test_load_env_boolean_true(self):
        """Test loading boolean true from environment."""
        for value in ["true", "True", "TRUE", "yes", "1", "on"]:
            with patch.dict(os.environ, {"REDOPS_CACHE__ENABLED": value}):
                manager = ConfigManager()
                config = manager.load(auto_discover=False)

                assert config.cache.enabled is True

    def test_load_env_boolean_false(self):
        """Test loading boolean false from environment."""
        for value in ["false", "False", "FALSE", "no", "0", "off"]:
            with patch.dict(os.environ, {"REDOPS_CACHE__ENABLED": value}):
                manager = ConfigManager()
                config = manager.load(auto_discover=False)

                assert config.cache.enabled is False

    def test_load_env_none(self):
        """Test loading None from environment."""
        for value in ["none", "null", ""]:
            with patch.dict(os.environ, {"REDOPS_NETWORK__PROXY": value}):
                manager = ConfigManager()
                config = manager.load(auto_discover=False)

                assert config.network.proxy is None

    def test_env_overrides_file(self):
        """Test that environment overrides file config."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({"network": {"timeout": 45}}, f)
            f.flush()

            try:
                with patch.dict(os.environ, {"REDOPS_NETWORK__TIMEOUT": "90"}):
                    manager = ConfigManager()
                    config = manager.load(config_file=f.name, auto_discover=False)

                    # Environment should override file
                    assert config.network.timeout == 90
            finally:
                os.unlink(f.name)


class TestConfigManagerDeepMerge:
    """Tests for deep merge functionality."""

    def test_deep_merge_simple(self):
        """Test simple deep merge."""
        manager = ConfigManager()

        base = {"a": 1, "b": 2}
        override = {"b": 3, "c": 4}

        result = manager._deep_merge(base, override)

        assert result == {"a": 1, "b": 3, "c": 4}

    def test_deep_merge_nested(self):
        """Test nested deep merge."""
        manager = ConfigManager()

        base = {"a": {"x": 1, "y": 2}, "b": 3}
        override = {"a": {"y": 20, "z": 30}}

        result = manager._deep_merge(base, override)

        assert result == {"a": {"x": 1, "y": 20, "z": 30}, "b": 3}

    def test_deep_merge_preserves_base(self):
        """Test that deep merge doesn't modify original."""
        manager = ConfigManager()

        base = {"a": 1}
        override = {"b": 2}

        manager._deep_merge(base, override)

        assert base == {"a": 1}  # Unchanged
        assert override == {"b": 2}  # Unchanged


class TestConfigManagerParseEnvValue:
    """Tests for environment value parsing."""

    def test_parse_true_values(self):
        """Test parsing true boolean values."""
        manager = ConfigManager()

        for value in ["true", "True", "TRUE", "yes", "YES", "1", "on", "ON"]:
            assert manager._parse_env_value(value) is True

    def test_parse_false_values(self):
        """Test parsing false boolean values."""
        manager = ConfigManager()

        for value in ["false", "False", "FALSE", "no", "NO", "0", "off", "OFF"]:
            assert manager._parse_env_value(value) is False

    def test_parse_none_values(self):
        """Test parsing None values."""
        manager = ConfigManager()

        for value in ["none", "None", "NONE", "null", "NULL", ""]:
            assert manager._parse_env_value(value) is None

    def test_parse_integer(self):
        """Test parsing integer values."""
        manager = ConfigManager()

        assert manager._parse_env_value("42") == 42
        assert manager._parse_env_value("-10") == -10
        assert manager._parse_env_value("0") is False  # "0" is boolean false

    def test_parse_float(self):
        """Test parsing float values."""
        manager = ConfigManager()

        assert manager._parse_env_value("3.14") == 3.14
        assert manager._parse_env_value("-2.5") == -2.5

    def test_parse_string(self):
        """Test parsing string values."""
        manager = ConfigManager()

        assert manager._parse_env_value("hello") == "hello"
        assert manager._parse_env_value("/path/to/file") == "/path/to/file"


class TestConfigProfile:
    """Tests for ConfigProfile enum."""

    def test_profile_values(self):
        """Test ConfigProfile enum values."""
        assert ConfigProfile.DEFAULT.value == "default"
        assert ConfigProfile.DEVELOPMENT.value == "development"
        assert ConfigProfile.PRODUCTION.value == "production"
        assert ConfigProfile.TESTING.value == "testing"
        assert ConfigProfile.MINIMAL.value == "minimal"
        assert ConfigProfile.COMPREHENSIVE.value == "comprehensive"


class TestConfigFormat:
    """Tests for ConfigFormat enum."""

    def test_format_values(self):
        """Test ConfigFormat enum values."""
        assert ConfigFormat.YAML.value == "yaml"
        assert ConfigFormat.TOML.value == "toml"
        assert ConfigFormat.JSON.value == "json"
        assert ConfigFormat.ENV.value == "env"


class TestConfigValidationError:
    """Tests for ConfigValidationError exception."""

    def test_single_error(self):
        """Test ConfigValidationError with single error."""
        error = ConfigValidationError(["Invalid timeout"])

        assert len(error.errors) == 1
        assert "Invalid timeout" in str(error)

    def test_multiple_errors(self):
        """Test ConfigValidationError with multiple errors."""
        errors = ["Invalid timeout", "Invalid rate limit"]
        error = ConfigValidationError(errors)

        assert len(error.errors) == 2
        assert "Invalid timeout" in str(error)
        assert "Invalid rate limit" in str(error)


class TestGlobalFunctions:
    """Tests for global convenience functions."""

    def test_get_config_manager(self):
        """Test getting global config manager."""
        manager = get_config_manager()
        assert isinstance(manager, ConfigManager)

    def test_get_config_manager_singleton(self):
        """Test that get_config_manager returns same instance."""
        manager1 = get_config_manager()
        manager2 = get_config_manager()
        assert manager1 is manager2

    def test_load_config(self):
        """Test load_config convenience function."""
        config = load_config(auto_discover=False)
        assert isinstance(config, RedOPSConfiguration)

    def test_load_config_with_profile(self):
        """Test load_config with profile."""
        config = load_config(profile="testing", auto_discover=False)
        assert config.cache.enabled is False

    def test_get_config(self):
        """Test get_config convenience function."""
        load_config(auto_discover=False)
        config = get_config()
        assert isinstance(config, RedOPSConfiguration)


class TestProjectConfigDiscovery:
    """Tests for project config file discovery."""

    @pytest.mark.skipif(not YAML_AVAILABLE, reason="PyYAML not installed")
    def test_discovers_redops_yaml(self):
        """Test discovering redops.yaml in current directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_file = Path(tmpdir) / "redops.yaml"
            config_file.write_text("network:\n  timeout: 99\n")

            original_cwd = os.getcwd()
            try:
                os.chdir(tmpdir)
                manager = ConfigManager()
                config = manager.load(auto_discover=True)

                assert config.network.timeout == 99
                assert any("project:" in s for s in manager.sources)
            finally:
                os.chdir(original_cwd)

    @pytest.mark.skipif(not YAML_AVAILABLE, reason="PyYAML not installed")
    def test_discovers_redops_yml(self):
        """Test discovering redops.yml in current directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_file = Path(tmpdir) / "redops.yml"
            config_file.write_text("cache:\n  enabled: false\n")

            original_cwd = os.getcwd()
            try:
                os.chdir(tmpdir)
                manager = ConfigManager()
                config = manager.load(auto_discover=True)

                assert config.cache.enabled is False
            finally:
                os.chdir(original_cwd)

    def test_discovers_redops_toml(self):
        """Test discovering redops.toml in current directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_file = Path(tmpdir) / "redops.toml"
            config_file.write_text("[network]\ntimeout = 88\n")

            original_cwd = os.getcwd()
            try:
                os.chdir(tmpdir)
                manager = ConfigManager()
                config = manager.load(auto_discover=True)

                assert config.network.timeout == 88
            finally:
                os.chdir(original_cwd)


class TestModuleConfigFromBool:
    """Tests for module config specified as boolean."""

    def test_module_as_true(self):
        """Test module config specified as true."""
        manager = ConfigManager()
        manager.load(
            cli_overrides={"modules": {"simple_module": True}},
            auto_discover=False,
        )

        mod_config = manager.get_module_config("simple_module")
        assert mod_config.enabled is True

    def test_module_as_false(self):
        """Test module config specified as false."""
        manager = ConfigManager()
        manager.load(
            cli_overrides={"modules": {"disabled_module": False}},
            auto_discover=False,
        )

        mod_config = manager.get_module_config("disabled_module")
        assert mod_config.enabled is False


class TestConfigPriority:
    """Tests for configuration source priority."""

    def test_cli_overrides_env(self):
        """Test that CLI overrides environment."""
        with patch.dict(os.environ, {"REDOPS_NETWORK__TIMEOUT": "60"}):
            manager = ConfigManager()
            config = manager.load(
                cli_overrides={"network": {"timeout": 120}},
                auto_discover=False,
            )

            assert config.network.timeout == 120

    def test_env_overrides_profile(self):
        """Test that environment overrides profile."""
        with patch.dict(os.environ, {"REDOPS_NETWORK__TIMEOUT": "99"}):
            manager = ConfigManager()
            config = manager.load(profile="testing", auto_discover=False)

            # Testing profile sets timeout=5, env should override
            assert config.network.timeout == 99

    def test_profile_overrides_defaults(self):
        """Test that profile overrides defaults."""
        manager = ConfigManager()
        config = manager.load(profile="testing", auto_discover=False)

        # Testing profile sets timeout=5, default is 30
        assert config.network.timeout == 5
