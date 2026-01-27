"""Tests for the configuration management module."""

import json
import os
from unittest.mock import patch
from redops.core.config import (
    ScopeConfig,
    OutputConfig,
    ModuleConfig,
    AIConfig,
    APIKeysConfig,
    RedOpsConfig,
)


class TestScopeConfig:
    """Tests for ScopeConfig model."""

    def test_default_values(self):
        """Test default values for ScopeConfig."""
        config = ScopeConfig()

        assert config.allowed_domains == []
        assert config.allowed_ips == []
        assert config.allowed_directories == []
        assert config.strict_mode is True

    def test_custom_values(self):
        """Test custom values for ScopeConfig."""
        config = ScopeConfig(
            allowed_domains=["example.com", "test.com"],
            allowed_ips=["192.168.1.0/24"],
            allowed_directories=["/tmp", "/var"],
            strict_mode=False,
        )

        assert config.allowed_domains == ["example.com", "test.com"]
        assert config.allowed_ips == ["192.168.1.0/24"]
        assert config.allowed_directories == ["/tmp", "/var"]
        assert config.strict_mode is False


class TestOutputConfig:
    """Tests for OutputConfig model."""

    def test_default_values(self):
        """Test default values for OutputConfig."""
        config = OutputConfig()

        assert config.output_dir == "./output"
        assert config.format == "markdown"
        assert config.include_logs is True
        assert config.verbose is False

    def test_custom_values(self):
        """Test custom values for OutputConfig."""
        config = OutputConfig(
            output_dir="/custom/output",
            format="html",
            include_logs=False,
            verbose=True,
        )

        assert config.output_dir == "/custom/output"
        assert config.format == "html"
        assert config.include_logs is False
        assert config.verbose is True


class TestModuleConfig:
    """Tests for ModuleConfig model."""

    def test_default_values(self):
        """Test default values for ModuleConfig."""
        config = ModuleConfig()

        assert config.timeout == 300
        assert config.max_retries == 3
        assert config.user_agent == "RedOps/1.0 (OSINT Framework)"

    def test_custom_values(self):
        """Test custom values for ModuleConfig."""
        config = ModuleConfig(
            timeout=600,
            max_retries=5,
            user_agent="CustomAgent/2.0",
        )

        assert config.timeout == 600
        assert config.max_retries == 5
        assert config.user_agent == "CustomAgent/2.0"


class TestAIConfig:
    """Tests for AIConfig model."""

    def test_default_values(self):
        """Test default values for AIConfig."""
        config = AIConfig()

        assert config.provider == "openai"
        assert config.model == "gpt-4o-mini"
        assert config.max_tokens == 2048
        assert config.temperature == 0.7
        assert config.enabled is True

    def test_custom_values(self):
        """Test custom values for AIConfig."""
        config = AIConfig(
            provider="anthropic",
            model="claude-3-opus",
            max_tokens=4096,
            temperature=0.5,
            enabled=False,
        )

        assert config.provider == "anthropic"
        assert config.model == "claude-3-opus"
        assert config.max_tokens == 4096
        assert config.temperature == 0.5
        assert config.enabled is False


class TestAPIKeysConfig:
    """Tests for APIKeysConfig model."""

    def test_default_values(self):
        """Test default values for APIKeysConfig."""
        config = APIKeysConfig()

        assert config.openai is None
        assert config.anthropic is None
        assert config.shodan is None
        assert config.virustotal is None
        assert config.securitytrails is None
        assert config.censys is None
        assert config.hunter is None

    def test_custom_values(self):
        """Test custom values for APIKeysConfig."""
        config = APIKeysConfig(
            openai="sk-test123",
            anthropic="anthropic-key",
            shodan="shodan-key",
        )

        assert config.openai == "sk-test123"
        assert config.anthropic == "anthropic-key"
        assert config.shodan == "shodan-key"

    def test_get_key_from_config(self):
        """Test get_key returns stored config value."""
        config = APIKeysConfig(openai="sk-stored-key")

        result = config.get_key("openai")

        assert result == "sk-stored-key"

    def test_get_key_from_environment(self):
        """Test get_key returns environment variable first."""
        config = APIKeysConfig(openai="sk-stored-key")

        with patch.dict(os.environ, {"OPENAI_API_KEY": "sk-env-key"}):
            result = config.get_key("openai")

        assert result == "sk-env-key"

    def test_get_key_env_takes_precedence(self):
        """Test environment variable takes precedence over stored value."""
        config = APIKeysConfig(shodan="stored-shodan-key")

        with patch.dict(os.environ, {"SHODAN_API_KEY": "env-shodan-key"}):
            result = config.get_key("shodan")

        assert result == "env-shodan-key"

    def test_get_key_nonexistent_provider(self):
        """Test get_key returns None for nonexistent provider."""
        config = APIKeysConfig()

        result = config.get_key("nonexistent")

        assert result is None

    def test_get_key_no_env_no_config(self):
        """Test get_key returns None when neither env nor config set."""
        config = APIKeysConfig()

        result = config.get_key("openai")

        assert result is None

    def test_set_key_valid_provider(self):
        """Test set_key sets value for valid provider."""
        config = APIKeysConfig()

        config.set_key("openai", "new-key")

        assert config.openai == "new-key"

    def test_set_key_invalid_provider(self):
        """Test set_key does nothing for invalid provider."""
        config = APIKeysConfig()

        config.set_key("invalid_provider", "some-key")

        # Should not raise, just do nothing
        assert (
            not hasattr(config, "invalid_provider")
            or getattr(config, "invalid_provider", None) is None
        )

    def test_mask_key_none(self):
        """Test mask_key with None value."""
        config = APIKeysConfig()

        result = config.mask_key(None)

        assert result == "(not set)"

    def test_mask_key_empty_string(self):
        """Test mask_key with empty string."""
        config = APIKeysConfig()

        result = config.mask_key("")

        assert result == "(not set)"

    def test_mask_key_short(self):
        """Test mask_key with short key (8 chars or less)."""
        config = APIKeysConfig()

        result = config.mask_key("12345678")

        assert result == "********"

    def test_mask_key_very_short(self):
        """Test mask_key with very short key."""
        config = APIKeysConfig()

        result = config.mask_key("abc")

        assert result == "***"

    def test_mask_key_normal(self):
        """Test mask_key with normal length key."""
        config = APIKeysConfig()

        result = config.mask_key("sk-1234567890abcdef")

        assert result.startswith("sk-1")
        assert result.endswith("cdef")
        assert "*" in result

    def test_mask_key_preserves_first_and_last_four(self):
        """Test mask_key preserves first 4 and last 4 characters."""
        config = APIKeysConfig()
        key = "TEST-fake-key-HERE"

        result = config.mask_key(key)

        assert result[:4] == "TEST"
        assert result[-4:] == "HERE"
        assert len(result) == len(key)


class TestRedOpsConfig:
    """Tests for RedOpsConfig model."""

    def test_default_values(self):
        """Test default values for RedOpsConfig."""
        config = RedOpsConfig()

        assert isinstance(config.scope, ScopeConfig)
        assert isinstance(config.output, OutputConfig)
        assert isinstance(config.modules, ModuleConfig)
        assert isinstance(config.api_keys, APIKeysConfig)
        assert isinstance(config.ai, AIConfig)
        assert config.custom == {}

    def test_custom_values(self):
        """Test custom values for RedOpsConfig."""
        config = RedOpsConfig(
            scope=ScopeConfig(allowed_domains=["test.com"]),
            output=OutputConfig(verbose=True),
            custom={"key": "value"},
        )

        assert config.scope.allowed_domains == ["test.com"]
        assert config.output.verbose is True
        assert config.custom == {"key": "value"}

    def test_from_file(self, tmp_path):
        """Test loading config from JSON file."""
        config_data = {
            "scope": {"allowed_domains": ["example.com"], "strict_mode": False},
            "output": {"output_dir": "/custom/dir", "verbose": True},
            "ai": {"provider": "anthropic", "model": "claude-3"},
        }
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config_data))

        config = RedOpsConfig.from_file(config_file)

        assert config.scope.allowed_domains == ["example.com"]
        assert config.scope.strict_mode is False
        assert config.output.output_dir == "/custom/dir"
        assert config.output.verbose is True
        assert config.ai.provider == "anthropic"
        assert config.ai.model == "claude-3"

    def test_from_file_minimal(self, tmp_path):
        """Test loading minimal config from file."""
        config_data = {}
        config_file = tmp_path / "minimal.json"
        config_file.write_text(json.dumps(config_data))

        config = RedOpsConfig.from_file(config_file)

        # Should use defaults
        assert config.scope.strict_mode is True
        assert config.output.format == "markdown"

    def test_from_env_default(self):
        """Test from_env with no environment variables."""
        with patch.dict(os.environ, {}, clear=True):
            # Clear relevant env vars
            for key in list(os.environ.keys()):
                if key.startswith("REDOPS_"):
                    del os.environ[key]

            config = RedOpsConfig.from_env()

        assert isinstance(config, RedOpsConfig)

    def test_from_env_output_dir(self):
        """Test from_env with REDOPS_OUTPUT_DIR."""
        with patch.dict(os.environ, {"REDOPS_OUTPUT_DIR": "/env/output"}):
            config = RedOpsConfig.from_env()

        assert config.output.output_dir == "/env/output"

    def test_from_env_verbose_true(self):
        """Test from_env with REDOPS_VERBOSE=true."""
        with patch.dict(os.environ, {"REDOPS_VERBOSE": "true"}):
            config = RedOpsConfig.from_env()

        assert config.output.verbose is True

    def test_from_env_verbose_false(self):
        """Test from_env with REDOPS_VERBOSE=false."""
        with patch.dict(os.environ, {"REDOPS_VERBOSE": "false"}):
            config = RedOpsConfig.from_env()

        assert config.output.verbose is False

    def test_from_env_strict_scope_true(self):
        """Test from_env with REDOPS_STRICT_SCOPE=true."""
        with patch.dict(os.environ, {"REDOPS_STRICT_SCOPE": "true"}):
            config = RedOpsConfig.from_env()

        assert config.scope.strict_mode is True

    def test_from_env_strict_scope_false(self):
        """Test from_env with REDOPS_STRICT_SCOPE=false."""
        with patch.dict(os.environ, {"REDOPS_STRICT_SCOPE": "false"}):
            config = RedOpsConfig.from_env()

        assert config.scope.strict_mode is False

    def test_from_env_ai_provider(self):
        """Test from_env with REDOPS_AI_PROVIDER."""
        with patch.dict(os.environ, {"REDOPS_AI_PROVIDER": "anthropic"}):
            config = RedOpsConfig.from_env()

        assert config.ai.provider == "anthropic"

    def test_from_env_ai_model(self):
        """Test from_env with REDOPS_AI_MODEL."""
        with patch.dict(os.environ, {"REDOPS_AI_MODEL": "gpt-4"}):
            config = RedOpsConfig.from_env()

        assert config.ai.model == "gpt-4"

    def test_from_env_multiple_vars(self):
        """Test from_env with multiple environment variables."""
        env_vars = {
            "REDOPS_OUTPUT_DIR": "/multi/output",
            "REDOPS_VERBOSE": "true",
            "REDOPS_STRICT_SCOPE": "false",
            "REDOPS_AI_PROVIDER": "local",
            "REDOPS_AI_MODEL": "llama-3",
        }
        with patch.dict(os.environ, env_vars):
            config = RedOpsConfig.from_env()

        assert config.output.output_dir == "/multi/output"
        assert config.output.verbose is True
        assert config.scope.strict_mode is False
        assert config.ai.provider == "local"
        assert config.ai.model == "llama-3"

    def test_to_file(self, tmp_path):
        """Test saving config to JSON file."""
        config = RedOpsConfig(
            scope=ScopeConfig(allowed_domains=["save-test.com"]),
            output=OutputConfig(verbose=True),
        )
        config_file = tmp_path / "saved_config.json"

        config.to_file(config_file)

        assert config_file.exists()
        saved_data = json.loads(config_file.read_text())
        assert saved_data["scope"]["allowed_domains"] == ["save-test.com"]
        assert saved_data["output"]["verbose"] is True

    def test_to_file_roundtrip(self, tmp_path):
        """Test saving and loading config produces same result."""
        original = RedOpsConfig(
            scope=ScopeConfig(allowed_domains=["roundtrip.com"], strict_mode=False),
            output=OutputConfig(output_dir="/roundtrip", format="json"),
            ai=AIConfig(provider="anthropic", model="claude-3"),
            custom={"custom_key": "custom_value"},
        )
        config_file = tmp_path / "roundtrip.json"

        original.to_file(config_file)
        loaded = RedOpsConfig.from_file(config_file)

        assert loaded.scope.allowed_domains == original.scope.allowed_domains
        assert loaded.scope.strict_mode == original.scope.strict_mode
        assert loaded.output.output_dir == original.output.output_dir
        assert loaded.output.format == original.output.format
        assert loaded.ai.provider == original.ai.provider
        assert loaded.ai.model == original.ai.model
        assert loaded.custom == original.custom

    def test_get_api_key(self):
        """Test get_api_key wrapper method."""
        config = RedOpsConfig(api_keys=APIKeysConfig(openai="wrapper-test-key"))

        result = config.get_api_key("openai")

        assert result == "wrapper-test-key"

    def test_get_api_key_from_env(self):
        """Test get_api_key wrapper returns env var."""
        config = RedOpsConfig()

        with patch.dict(os.environ, {"SHODAN_API_KEY": "env-shodan"}):
            result = config.get_api_key("shodan")

        assert result == "env-shodan"

    def test_set_api_key(self):
        """Test set_api_key wrapper method."""
        config = RedOpsConfig()

        config.set_api_key("virustotal", "vt-key-123")

        assert config.api_keys.virustotal == "vt-key-123"

    def test_set_api_key_updates_existing(self):
        """Test set_api_key updates existing key."""
        config = RedOpsConfig(api_keys=APIKeysConfig(censys="old-key"))

        config.set_api_key("censys", "new-key")

        assert config.api_keys.censys == "new-key"


class TestDefaultConfig:
    """Tests for the default_config instance."""

    def test_default_config_exists(self):
        """Test that default_config is created."""
        from redops.core.config import default_config

        assert isinstance(default_config, RedOpsConfig)

    def test_default_config_is_from_env(self):
        """Test that default_config is loaded from environment."""
        # This just verifies it doesn't crash on import
        from redops.core.config import default_config

        assert default_config is not None
