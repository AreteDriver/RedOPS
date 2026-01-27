"""Tests for the CLI settings module."""

import json
import os
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock, call
from io import StringIO

from redops.cli.settings import (
    API_PROVIDERS,
    AI_PROVIDERS,
    clear_screen,
    print_header,
    print_menu,
    get_input,
    get_secret_input,
    confirm,
    mask_key,
    get_config_path,
    load_config,
    save_config,
    get_default_config,
    SettingsMenu,
    run_settings_menu,
    set_api_key_direct,
    get_api_key_direct,
    list_api_keys,
)


class TestAPIProviders:
    """Tests for API_PROVIDERS constant."""

    def test_api_providers_structure(self):
        """Test API_PROVIDERS has expected structure."""
        assert "openai" in API_PROVIDERS
        assert "anthropic" in API_PROVIDERS
        assert "shodan" in API_PROVIDERS

        for provider, info in API_PROVIDERS.items():
            assert "name" in info
            assert "description" in info
            assert "env_var" in info
            assert "url" in info

    def test_ai_providers_structure(self):
        """Test AI_PROVIDERS has expected structure."""
        assert "openai" in AI_PROVIDERS
        assert "anthropic" in AI_PROVIDERS
        assert "gemini" in AI_PROVIDERS
        assert "ollama" in AI_PROVIDERS
        assert "groq" in AI_PROVIDERS

        for provider, info in AI_PROVIDERS.items():
            assert "name" in info
            assert "models" in info
            assert "default_model" in info
            assert len(info["models"]) > 0


class TestClearScreen:
    """Tests for clear_screen function."""

    def test_clear_screen_unix(self):
        """Test clear_screen outputs ANSI escape codes."""
        with patch("builtins.print") as mock_print:
            clear_screen()
            mock_print.assert_called_once_with("\033[2J\033[H", end="", flush=True)

    def test_clear_screen_windows(self):
        """Test clear_screen outputs ANSI escape codes (platform independent)."""
        with patch("builtins.print") as mock_print:
            clear_screen()
            mock_print.assert_called_once_with("\033[2J\033[H", end="", flush=True)


class TestPrintHeader:
    """Tests for print_header function."""

    def test_print_header(self, capsys):
        """Test print_header output."""
        print_header("Test Title")
        captured = capsys.readouterr()

        assert "Test Title" in captured.out
        assert "=" in captured.out

    def test_print_header_formatting(self, capsys):
        """Test print_header has proper formatting."""
        print_header("Header")
        captured = capsys.readouterr()

        lines = captured.out.strip().split("\n")
        assert len(lines) >= 3  # separator, title, separator


class TestPrintMenu:
    """Tests for print_menu function."""

    def test_print_menu_basic(self, capsys):
        """Test print_menu with basic options."""
        options = ["Option 1", "Option 2", "Option 3"]
        print_menu(options)
        captured = capsys.readouterr()

        assert "[1] Option 1" in captured.out
        assert "[2] Option 2" in captured.out
        assert "[3] Option 3" in captured.out

    def test_print_menu_with_title(self, capsys):
        """Test print_menu with custom title."""
        options = ["A", "B"]
        print_menu(options, title="Custom Title:")
        captured = capsys.readouterr()

        assert "Custom Title:" in captured.out
        assert "[1] A" in captured.out

    def test_print_menu_empty(self, capsys):
        """Test print_menu with empty options."""
        print_menu([])
        captured = capsys.readouterr()

        assert "Select an option:" in captured.out


class TestGetInput:
    """Tests for get_input function."""

    def test_get_input_no_default(self):
        """Test get_input without default."""
        with patch("builtins.input", return_value="user input"):
            result = get_input("Enter value")

        assert result == "user input"

    def test_get_input_with_default_user_enters(self):
        """Test get_input with default, user enters value."""
        with patch("builtins.input", return_value="custom"):
            result = get_input("Enter value", default="default")

        assert result == "custom"

    def test_get_input_with_default_user_empty(self):
        """Test get_input with default, user enters nothing."""
        with patch("builtins.input", return_value=""):
            result = get_input("Enter value", default="default")

        assert result == "default"

    def test_get_input_strips_whitespace(self):
        """Test get_input strips whitespace."""
        with patch("builtins.input", return_value="  value  "):
            result = get_input("Enter value")

        assert result == "value"


class TestGetSecretInput:
    """Tests for get_secret_input function."""

    def test_get_secret_input(self):
        """Test get_secret_input uses getpass."""
        with patch("getpass.getpass", return_value="secret"):
            result = get_secret_input("Enter secret")

        assert result == "secret"


class TestConfirm:
    """Tests for confirm function."""

    def test_confirm_yes(self):
        """Test confirm with 'y' response."""
        with patch("builtins.input", return_value="y"):
            result = confirm("Continue?")

        assert result is True

    def test_confirm_yes_full(self):
        """Test confirm with 'yes' response."""
        with patch("builtins.input", return_value="yes"):
            result = confirm("Continue?")

        assert result is True

    def test_confirm_no(self):
        """Test confirm with 'n' response."""
        with patch("builtins.input", return_value="n"):
            result = confirm("Continue?")

        assert result is False

    def test_confirm_empty_default_false(self):
        """Test confirm with empty input, default False."""
        with patch("builtins.input", return_value=""):
            result = confirm("Continue?", default=False)

        assert result is False

    def test_confirm_empty_default_true(self):
        """Test confirm with empty input, default True."""
        with patch("builtins.input", return_value=""):
            result = confirm("Continue?", default=True)

        assert result is True

    def test_confirm_case_insensitive(self):
        """Test confirm is case insensitive."""
        with patch("builtins.input", return_value="Y"):
            result = confirm("Continue?")

        assert result is True


class TestMaskKey:
    """Tests for mask_key function."""

    def test_mask_key_none(self):
        """Test mask_key with None."""
        assert mask_key(None) == "(not set)"

    def test_mask_key_empty(self):
        """Test mask_key with empty string."""
        assert mask_key("") == "(not set)"

    def test_mask_key_short(self):
        """Test mask_key with short key."""
        assert mask_key("12345678") == "********"
        assert mask_key("abc") == "***"

    def test_mask_key_normal(self):
        """Test mask_key with normal key."""
        result = mask_key("sk-test-key-value")
        assert result.startswith("sk-t")
        assert result.endswith("alue")
        assert "*" in result


class TestGetConfigPath:
    """Tests for get_config_path function."""

    def test_get_config_path_default(self):
        """Test get_config_path returns default path."""
        with patch.dict(os.environ, {}, clear=False):
            # Remove REDOPS_CONFIG if present
            os.environ.pop("REDOPS_CONFIG", None)
            path = get_config_path()

        assert path == Path.home() / ".config" / "redops" / "config.json"

    def test_get_config_path_from_env(self):
        """Test get_config_path from environment variable."""
        with patch.dict(os.environ, {"REDOPS_CONFIG": "/custom/config.json"}):
            path = get_config_path()

        assert path == Path("/custom/config.json")


class TestLoadConfig:
    """Tests for load_config function."""

    def test_load_config_file_exists(self, tmp_path):
        """Test load_config when file exists."""
        config_data = {"api_keys": {"openai": "test-key"}, "verbosity": "debug"}
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config_data))

        with patch("redops.cli.settings.get_config_path", return_value=config_file):
            config = load_config()

        assert config["api_keys"]["openai"] == "test-key"
        assert config["verbosity"] == "debug"

    def test_load_config_file_not_exists(self, tmp_path):
        """Test load_config when file doesn't exist."""
        config_file = tmp_path / "nonexistent.json"

        with patch("redops.cli.settings.get_config_path", return_value=config_file):
            config = load_config()

        # Should return default config
        assert "output_dir" in config
        assert "api_keys" in config


class TestSaveConfig:
    """Tests for save_config function."""

    def test_save_config(self, tmp_path):
        """Test save_config writes file."""
        config_file = tmp_path / "config.json"
        config = {"api_keys": {"openai": "saved-key"}}

        with patch("redops.cli.settings.get_config_path", return_value=config_file):
            save_config(config)

        assert config_file.exists()
        saved = json.loads(config_file.read_text())
        assert saved["api_keys"]["openai"] == "saved-key"

    def test_save_config_creates_directory(self, tmp_path):
        """Test save_config creates parent directories."""
        config_file = tmp_path / "nested" / "dir" / "config.json"
        config = {"test": "value"}

        with patch("redops.cli.settings.get_config_path", return_value=config_file):
            save_config(config)

        assert config_file.exists()


class TestGetDefaultConfig:
    """Tests for get_default_config function."""

    def test_get_default_config_structure(self):
        """Test get_default_config has expected structure."""
        config = get_default_config()

        assert "output_dir" in config
        assert "verbosity" in config
        assert "output_format" in config
        assert "api_keys" in config
        assert "ollama" in config
        assert "ai" in config

    def test_get_default_config_ai_settings(self):
        """Test get_default_config has AI settings."""
        config = get_default_config()

        assert config["ai"]["provider"] == "openai"
        assert config["ai"]["model"] == "gpt-4o-mini"
        assert config["ai"]["enabled"] is True


class TestSettingsMenu:
    """Tests for SettingsMenu class."""

    def test_init(self, tmp_path):
        """Test SettingsMenu initialization."""
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(get_default_config()))

        with patch("redops.cli.settings.get_config_path", return_value=config_file):
            menu = SettingsMenu(quiet=True)

        assert menu.quiet is True
        assert menu.changes_made is False
        assert "api_keys" in menu.config

    def test_run_exit_without_saving(self, tmp_path):
        """Test run with exit without saving."""
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(get_default_config()))

        with patch("redops.cli.settings.get_config_path", return_value=config_file):
            menu = SettingsMenu(quiet=True)

        with patch("builtins.input", return_value="6"):
            result = menu.run()

        assert result == 0

    def test_run_save_and_exit(self, tmp_path):
        """Test run with save and exit."""
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(get_default_config()))

        with patch("redops.cli.settings.get_config_path", return_value=config_file):
            menu = SettingsMenu(quiet=True)

        with patch("builtins.input", return_value="5"):
            result = menu.run()

        assert result == 0

    def test_run_invalid_choice(self, tmp_path):
        """Test run with invalid choice then exit."""
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(get_default_config()))

        with patch("redops.cli.settings.get_config_path", return_value=config_file):
            menu = SettingsMenu(quiet=True)

        with patch("builtins.input", side_effect=["invalid", "", "6"]):
            result = menu.run()

        assert result == 0

    def test_get_api_key_from_config(self, tmp_path):
        """Test _get_api_key returns config value."""
        config = get_default_config()
        config["api_keys"]["openai"] = "config-key"
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config))

        with patch("redops.cli.settings.get_config_path", return_value=config_file):
            menu = SettingsMenu(quiet=True)

        result = menu._get_api_key("openai")
        assert result == "config-key"

    def test_get_api_key_from_env(self, tmp_path):
        """Test _get_api_key returns env var first."""
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(get_default_config()))

        with patch("redops.cli.settings.get_config_path", return_value=config_file):
            menu = SettingsMenu(quiet=True)

        with patch.dict(os.environ, {"OPENAI_API_KEY": "env-key"}):
            result = menu._get_api_key("openai")

        assert result == "env-key"

    def test_api_keys_menu_back(self, tmp_path):
        """Test api_keys_menu with back option."""
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(get_default_config()))

        with patch("redops.cli.settings.get_config_path", return_value=config_file):
            menu = SettingsMenu(quiet=True)

        with patch("builtins.input", return_value="B"):
            menu.api_keys_menu()

    def test_api_keys_menu_add(self, tmp_path):
        """Test api_keys_menu add option."""
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(get_default_config()))

        with patch("redops.cli.settings.get_config_path", return_value=config_file):
            menu = SettingsMenu(quiet=True)

        with patch("builtins.input", side_effect=["A", "cancel", "B"]):
            menu.api_keys_menu()

    def test_api_keys_menu_select_provider(self, tmp_path):
        """Test api_keys_menu selecting provider by number."""
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(get_default_config()))

        with patch("redops.cli.settings.get_config_path", return_value=config_file):
            menu = SettingsMenu(quiet=True)

        # Input sequence: "1" selects provider, "" for Press Enter, "B" to go back
        with patch("builtins.input", side_effect=["1", "", "B"]):
            with patch("getpass.getpass", return_value=""):
                menu.api_keys_menu()

    def test_edit_api_key_set(self, tmp_path):
        """Test edit_api_key sets key."""
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(get_default_config()))

        with patch("redops.cli.settings.get_config_path", return_value=config_file):
            menu = SettingsMenu(quiet=True)

        with patch("getpass.getpass", return_value="new-api-key"):
            with patch("builtins.input", return_value=""):
                menu.edit_api_key("openai")

        assert menu.config["api_keys"]["openai"] == "new-api-key"
        assert menu.changes_made is True

    def test_edit_api_key_empty(self, tmp_path):
        """Test edit_api_key with empty input."""
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(get_default_config()))

        with patch("redops.cli.settings.get_config_path", return_value=config_file):
            menu = SettingsMenu(quiet=True)

        with patch("getpass.getpass", return_value=""):
            with patch("builtins.input", return_value=""):
                menu.edit_api_key("openai")

        assert menu.changes_made is False

    def test_remove_api_key(self, tmp_path):
        """Test remove_api_key removes key."""
        config = get_default_config()
        config["api_keys"]["openai"] = "to-remove"
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config))

        with patch("redops.cli.settings.get_config_path", return_value=config_file):
            menu = SettingsMenu(quiet=True)

        with patch("builtins.input", side_effect=["1", "y", ""]):
            menu.remove_api_key()

        assert menu.config["api_keys"]["openai"] is None
        assert menu.changes_made is True

    def test_remove_api_key_cancel(self, tmp_path):
        """Test remove_api_key with cancel."""
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(get_default_config()))

        with patch("redops.cli.settings.get_config_path", return_value=config_file):
            menu = SettingsMenu(quiet=True)

        with patch("builtins.input", return_value="cancel"):
            menu.remove_api_key()

    def test_test_api_key_not_set(self, tmp_path, capsys):
        """Test test_api_key when no key configured."""
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(get_default_config()))

        with patch("redops.cli.settings.get_config_path", return_value=config_file):
            menu = SettingsMenu(quiet=True)

        with patch("builtins.input", side_effect=["1", ""]):
            menu.test_api_key()

        captured = capsys.readouterr()
        assert "No API key configured" in captured.out

    def test_test_api_key_cancel(self, tmp_path):
        """Test test_api_key with cancel."""
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(get_default_config()))

        with patch("redops.cli.settings.get_config_path", return_value=config_file):
            menu = SettingsMenu(quiet=True)

        with patch("builtins.input", return_value="cancel"):
            menu.test_api_key()

    def test_test_provider_openai_success(self, tmp_path):
        """Test _test_provider with OpenAI success."""
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(get_default_config()))

        with patch("redops.cli.settings.get_config_path", return_value=config_file):
            menu = SettingsMenu(quiet=True)

        mock_openai = MagicMock()
        mock_client = MagicMock()
        mock_openai.OpenAI.return_value = mock_client

        with patch.dict("sys.modules", {"openai": mock_openai}):
            result = menu._test_provider("openai", "test-key")

        assert result is True

    def test_test_provider_import_error(self, tmp_path, capsys):
        """Test _test_provider with ImportError."""
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(get_default_config()))

        with patch("redops.cli.settings.get_config_path", return_value=config_file):
            menu = SettingsMenu(quiet=True)

        with patch("builtins.__import__", side_effect=ImportError("No module")):
            result = menu._test_provider("openai", "test-key")

        assert result is False

    def test_test_provider_exception(self, tmp_path, capsys):
        """Test _test_provider with exception."""
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(get_default_config()))

        with patch("redops.cli.settings.get_config_path", return_value=config_file):
            menu = SettingsMenu(quiet=True)

        mock_openai = MagicMock()
        mock_openai.OpenAI.side_effect = Exception("API Error")

        with patch.dict("sys.modules", {"openai": mock_openai}):
            result = menu._test_provider("openai", "test-key")

        assert result is False

    def test_test_provider_unknown(self, tmp_path):
        """Test _test_provider with unknown provider."""
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(get_default_config()))

        with patch("redops.cli.settings.get_config_path", return_value=config_file):
            menu = SettingsMenu(quiet=True)

        result = menu._test_provider("unknown", "test-key")
        assert result is False

    def test_ai_settings_menu_back(self, tmp_path):
        """Test ai_settings_menu back option."""
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(get_default_config()))

        with patch("redops.cli.settings.get_config_path", return_value=config_file):
            menu = SettingsMenu(quiet=True)

        with patch("builtins.input", return_value="6"):
            menu.ai_settings_menu()

    def test_change_ai_provider(self, tmp_path):
        """Test change_ai_provider."""
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(get_default_config()))

        with patch("redops.cli.settings.get_config_path", return_value=config_file):
            menu = SettingsMenu(quiet=True)

        with patch("builtins.input", side_effect=["2", ""]):
            menu.change_ai_provider()

        assert menu.config["ai"]["provider"] == "anthropic"
        assert menu.changes_made is True

    def test_change_ai_model(self, tmp_path):
        """Test change_ai_model."""
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(get_default_config()))

        with patch("redops.cli.settings.get_config_path", return_value=config_file):
            menu = SettingsMenu(quiet=True)

        with patch("builtins.input", side_effect=["1", ""]):
            menu.change_ai_model()

        assert menu.changes_made is True

    def test_change_max_tokens(self, tmp_path):
        """Test change_max_tokens."""
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(get_default_config()))

        with patch("redops.cli.settings.get_config_path", return_value=config_file):
            menu = SettingsMenu(quiet=True)

        with patch("builtins.input", side_effect=["4096", ""]):
            menu.change_max_tokens()

        assert menu.config["ai"]["max_tokens"] == 4096
        assert menu.changes_made is True

    def test_change_max_tokens_invalid(self, tmp_path, capsys):
        """Test change_max_tokens with invalid input."""
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(get_default_config()))

        with patch("redops.cli.settings.get_config_path", return_value=config_file):
            menu = SettingsMenu(quiet=True)

        with patch("builtins.input", side_effect=["invalid", ""]):
            menu.change_max_tokens()

        captured = capsys.readouterr()
        assert "Invalid value" in captured.out

    def test_change_temperature(self, tmp_path):
        """Test change_temperature."""
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(get_default_config()))

        with patch("redops.cli.settings.get_config_path", return_value=config_file):
            menu = SettingsMenu(quiet=True)

        with patch("builtins.input", side_effect=["0.5", ""]):
            menu.change_temperature()

        assert menu.config["ai"]["temperature"] == 0.5
        assert menu.changes_made is True

    def test_change_temperature_out_of_range(self, tmp_path, capsys):
        """Test change_temperature with out of range value."""
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(get_default_config()))

        with patch("redops.cli.settings.get_config_path", return_value=config_file):
            menu = SettingsMenu(quiet=True)

        with patch("builtins.input", side_effect=["2.0", ""]):
            menu.change_temperature()

        captured = capsys.readouterr()
        assert "between 0.0 and 1.0" in captured.out

    def test_change_temperature_invalid(self, tmp_path, capsys):
        """Test change_temperature with invalid input."""
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(get_default_config()))

        with patch("redops.cli.settings.get_config_path", return_value=config_file):
            menu = SettingsMenu(quiet=True)

        with patch("builtins.input", side_effect=["invalid", ""]):
            menu.change_temperature()

        captured = capsys.readouterr()
        assert "Invalid value" in captured.out

    def test_toggle_ai(self, tmp_path):
        """Test toggle_ai."""
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(get_default_config()))

        with patch("redops.cli.settings.get_config_path", return_value=config_file):
            menu = SettingsMenu(quiet=True)

        original = menu.config["ai"]["enabled"]

        with patch("builtins.input", return_value=""):
            menu.toggle_ai()

        assert menu.config["ai"]["enabled"] != original
        assert menu.changes_made is True

    def test_view_config(self, tmp_path, capsys):
        """Test view_config."""
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(get_default_config()))

        with patch("redops.cli.settings.get_config_path", return_value=config_file):
            menu = SettingsMenu(quiet=True)

        with patch("builtins.input", return_value=""):
            menu.view_config()

        captured = capsys.readouterr()
        assert "output_dir" in captured.out

    def test_reset_defaults_confirm(self, tmp_path):
        """Test reset_defaults with confirmation."""
        config = get_default_config()
        config["verbosity"] = "debug"
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config))

        with patch("redops.cli.settings.get_config_path", return_value=config_file):
            menu = SettingsMenu(quiet=True)

        with patch("builtins.input", side_effect=["y", ""]):
            menu.reset_defaults()

        assert menu.config["verbosity"] == "normal"
        assert menu.changes_made is True

    def test_reset_defaults_cancel(self, tmp_path):
        """Test reset_defaults with cancel."""
        config = get_default_config()
        config["verbosity"] = "debug"
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config))

        with patch("redops.cli.settings.get_config_path", return_value=config_file):
            menu = SettingsMenu(quiet=True)

        with patch("builtins.input", side_effect=["n", ""]):
            menu.reset_defaults()

        assert menu.config["verbosity"] == "debug"

    def test_save_and_exit_with_changes(self, tmp_path):
        """Test save_and_exit with changes."""
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(get_default_config()))

        with patch("redops.cli.settings.get_config_path", return_value=config_file):
            menu = SettingsMenu(quiet=True)
            menu.changes_made = True

        result = menu.save_and_exit()

        assert result == 0
        # Verify file was saved
        assert config_file.exists()

    def test_save_and_exit_no_changes(self, tmp_path, capsys):
        """Test save_and_exit without changes."""
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(get_default_config()))

        with patch("redops.cli.settings.get_config_path", return_value=config_file):
            menu = SettingsMenu(quiet=True)

        result = menu.save_and_exit()

        assert result == 0
        captured = capsys.readouterr()
        assert "No changes to save" in captured.out

    def test_exit_without_saving_no_changes(self, tmp_path):
        """Test exit_without_saving without changes."""
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(get_default_config()))

        with patch("redops.cli.settings.get_config_path", return_value=config_file):
            menu = SettingsMenu(quiet=True)

        result = menu.exit_without_saving()

        assert result == 0

    def test_exit_without_saving_with_changes_discard(self, tmp_path):
        """Test exit_without_saving with changes, choose discard."""
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(get_default_config()))

        with patch("redops.cli.settings.get_config_path", return_value=config_file):
            menu = SettingsMenu(quiet=True)
            menu.changes_made = True

        with patch("builtins.input", return_value="y"):
            result = menu.exit_without_saving()

        assert result == 0

    def test_exit_without_saving_with_changes_save(self, tmp_path):
        """Test exit_without_saving with changes, choose save."""
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(get_default_config()))

        with patch("redops.cli.settings.get_config_path", return_value=config_file):
            menu = SettingsMenu(quiet=True)
            menu.changes_made = True

        with patch("builtins.input", return_value="n"):
            result = menu.exit_without_saving()

        assert result == 0


class TestRunSettingsMenu:
    """Tests for run_settings_menu function."""

    def test_run_settings_menu(self, tmp_path):
        """Test run_settings_menu."""
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(get_default_config()))

        with patch("redops.cli.settings.get_config_path", return_value=config_file):
            with patch("builtins.input", return_value="6"):
                result = run_settings_menu(quiet=True)

        assert result == 0


class TestSetApiKeyDirect:
    """Tests for set_api_key_direct function."""

    def test_set_api_key_direct_success(self, tmp_path, capsys):
        """Test set_api_key_direct with valid provider."""
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(get_default_config()))

        with patch("redops.cli.settings.get_config_path", return_value=config_file):
            result = set_api_key_direct("openai", "direct-key")

        assert result is True
        captured = capsys.readouterr()
        assert "has been saved" in captured.out

    def test_set_api_key_direct_unknown_provider(self, capsys):
        """Test set_api_key_direct with unknown provider."""
        result = set_api_key_direct("unknown", "key")

        assert result is False
        captured = capsys.readouterr()
        assert "Unknown provider" in captured.out


class TestGetApiKeyDirect:
    """Tests for get_api_key_direct function."""

    def test_get_api_key_direct_from_config(self, tmp_path):
        """Test get_api_key_direct from config."""
        config = get_default_config()
        config["api_keys"]["shodan"] = "shodan-key"
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config))

        with patch("redops.cli.settings.get_config_path", return_value=config_file):
            result = get_api_key_direct("shodan")

        assert result == "shodan-key"

    def test_get_api_key_direct_from_env(self, tmp_path):
        """Test get_api_key_direct from environment."""
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(get_default_config()))

        with patch("redops.cli.settings.get_config_path", return_value=config_file):
            with patch.dict(os.environ, {"SHODAN_API_KEY": "env-shodan"}):
                result = get_api_key_direct("shodan")

        assert result == "env-shodan"

    def test_get_api_key_direct_not_set(self, tmp_path):
        """Test get_api_key_direct when not set."""
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(get_default_config()))

        with patch("redops.cli.settings.get_config_path", return_value=config_file):
            result = get_api_key_direct("shodan")

        assert result is None


class TestListApiKeys:
    """Tests for list_api_keys function."""

    def test_list_api_keys_empty(self, tmp_path, capsys):
        """Test list_api_keys with no keys set."""
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(get_default_config()))

        with patch("redops.cli.settings.get_config_path", return_value=config_file):
            list_api_keys()

        captured = capsys.readouterr()
        assert "Configured API Keys" in captured.out
        assert "(not set)" in captured.out

    def test_list_api_keys_with_config(self, tmp_path, capsys):
        """Test list_api_keys with configured keys."""
        config = get_default_config()
        config["api_keys"]["openai"] = "configured-key"
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config))

        with patch("redops.cli.settings.get_config_path", return_value=config_file):
            list_api_keys()

        captured = capsys.readouterr()
        assert "conf" in captured.out  # masked key starts with conf

    def test_list_api_keys_with_env(self, tmp_path, capsys):
        """Test list_api_keys with env var."""
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(get_default_config()))

        with patch("redops.cli.settings.get_config_path", return_value=config_file):
            with patch.dict(os.environ, {"OPENAI_API_KEY": "env-key-value"}):
                list_api_keys()

        captured = capsys.readouterr()
        assert "from env" in captured.out
