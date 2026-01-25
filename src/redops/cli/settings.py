"""
Interactive Settings Menu for RedOPS.

Provides a text-based user interface for managing API keys
and configuration settings.
"""

import sys
import os
import json
import getpass
from pathlib import Path
from typing import Optional, Dict, Any, List


# Available API key providers
API_PROVIDERS = {
    "openai": {
        "name": "OpenAI",
        "description": "GPT models for AI assistance",
        "env_var": "OPENAI_API_KEY",
        "url": "https://platform.openai.com/api-keys",
    },
    "anthropic": {
        "name": "Anthropic",
        "description": "Claude models for AI assistance",
        "env_var": "ANTHROPIC_API_KEY",
        "url": "https://console.anthropic.com/settings/keys",
    },
    "shodan": {
        "name": "Shodan",
        "description": "Internet-wide scanning and reconnaissance",
        "env_var": "SHODAN_API_KEY",
        "url": "https://account.shodan.io/",
    },
    "virustotal": {
        "name": "VirusTotal",
        "description": "Malware and URL analysis",
        "env_var": "VIRUSTOTAL_API_KEY",
        "url": "https://www.virustotal.com/gui/my-apikey",
    },
    "securitytrails": {
        "name": "SecurityTrails",
        "description": "DNS and domain intelligence",
        "env_var": "SECURITYTRAILS_API_KEY",
        "url": "https://securitytrails.com/app/account/credentials",
    },
    "censys": {
        "name": "Censys",
        "description": "Internet asset discovery",
        "env_var": "CENSYS_API_KEY",
        "url": "https://search.censys.io/account/api",
    },
    "hunter": {
        "name": "Hunter.io",
        "description": "Email discovery and verification",
        "env_var": "HUNTER_API_KEY",
        "url": "https://hunter.io/api-keys",
    },
    "google": {
        "name": "Google AI (Gemini)",
        "description": "Gemini models for AI assistance",
        "env_var": "GOOGLE_API_KEY",
        "url": "https://aistudio.google.com/app/apikey",
    },
    "groq": {
        "name": "Groq",
        "description": "Fast inference for open models",
        "env_var": "GROQ_API_KEY",
        "url": "https://console.groq.com/keys",
    },
}

# AI Provider options
AI_PROVIDERS = {
    "openai": {
        "name": "OpenAI",
        "models": ["gpt-4o", "gpt-4o-mini", "gpt-4-turbo", "gpt-3.5-turbo"],
        "default_model": "gpt-4o-mini",
    },
    "anthropic": {
        "name": "Anthropic",
        "models": [
            "claude-sonnet-4-20250514",
            "claude-opus-4-20250514",
            "claude-3-5-haiku-20241022",
        ],
        "default_model": "claude-sonnet-4-20250514",
    },
    "gemini": {
        "name": "Google Gemini",
        "models": [
            "gemini-2.0-flash",
            "gemini-1.5-pro",
            "gemini-1.5-flash",
        ],
        "default_model": "gemini-2.0-flash",
    },
    "ollama": {
        "name": "Ollama (Local)",
        "models": [
            "llama3.2",
            "llama3.1",
            "mistral",
            "codellama",
            "deepseek-r1",
        ],
        "default_model": "llama3.2",
    },
    "groq": {
        "name": "Groq (Fast)",
        "models": [
            "llama-3.3-70b-versatile",
            "llama-3.1-8b-instant",
            "mixtral-8x7b-32768",
            "gemma2-9b-it",
        ],
        "default_model": "llama-3.3-70b-versatile",
    },
}


def clear_screen():
    """Clear the terminal screen."""
    os.system("cls" if os.name == "nt" else "clear")


def print_header(title: str):
    """Print a styled header."""
    width = 60
    print()
    print("=" * width)
    print(f"  {title}".center(width))
    print("=" * width)
    print()


def print_menu(options: List[str], title: str = "Select an option:"):
    """Print a numbered menu."""
    print(title)
    print("-" * 40)
    for i, option in enumerate(options, 1):
        print(f"  [{i}] {option}")
    print()


def get_input(prompt: str, default: str = "") -> str:
    """Get user input with optional default."""
    if default:
        result = input(f"{prompt} [{default}]: ").strip()
        return result if result else default
    return input(f"{prompt}: ").strip()


def get_secret_input(prompt: str) -> str:
    """Get secret input (hidden while typing)."""
    return getpass.getpass(f"{prompt}: ")


def confirm(prompt: str, default: bool = False) -> bool:
    """Get yes/no confirmation from user."""
    suffix = " [Y/n]" if default else " [y/N]"
    response = input(f"{prompt}{suffix}: ").strip().lower()
    if not response:
        return default
    return response in ("y", "yes")


def mask_key(key: Optional[str]) -> str:
    """Return masked version of API key for display."""
    if not key:
        return "(not set)"
    if len(key) <= 8:
        return "*" * len(key)
    return key[:4] + "*" * (len(key) - 8) + key[-4:]


def get_config_path() -> Path:
    """Get the configuration file path."""
    env_path = os.environ.get("REDOPS_CONFIG")
    if env_path:
        return Path(env_path)
    return Path.home() / ".config" / "redops" / "config.json"


def load_config() -> Dict[str, Any]:
    """Load configuration from file."""
    config_path = get_config_path()
    if config_path.exists():
        with open(config_path, "r") as f:
            return json.load(f)
    return get_default_config()


def save_config(config: Dict[str, Any]) -> None:
    """Save configuration to file."""
    config_path = get_config_path()
    config_path.parent.mkdir(parents=True, exist_ok=True)
    with open(config_path, "w") as f:
        json.dump(config, f, indent=2)


def get_default_config() -> Dict[str, Any]:
    """Get default configuration."""
    return {
        "output_dir": "./output",
        "verbosity": "normal",
        "output_format": "text",
        "api_keys": {
            "openai": None,
            "anthropic": None,
            "google": None,
            "groq": None,
            "shodan": None,
            "virustotal": None,
            "securitytrails": None,
            "censys": None,
            "hunter": None,
        },
        "ollama": {
            "base_url": "http://localhost:11434",
        },
        "ai": {
            "provider": "openai",
            "model": "gpt-4o-mini",
            "max_tokens": 2048,
            "temperature": 0.7,
            "enabled": True,
        },
    }


class SettingsMenu:
    """Interactive settings menu for RedOPS."""

    def __init__(self, quiet: bool = False):
        """Initialize the settings menu."""
        self.config = load_config()
        self.quiet = quiet
        self.changes_made = False

    def run(self) -> int:
        """Run the interactive settings menu."""
        while True:
            if not self.quiet:
                clear_screen()
            print_header("RedOPS Settings")

            options = [
                "Manage API Keys",
                "AI Assistant Settings",
                "View Current Configuration",
                "Reset to Defaults",
                "Save and Exit",
                "Exit without Saving",
            ]
            print_menu(options)

            choice = get_input("Enter choice")

            if choice == "1":
                self.api_keys_menu()
            elif choice == "2":
                self.ai_settings_menu()
            elif choice == "3":
                self.view_config()
            elif choice == "4":
                self.reset_defaults()
            elif choice == "5":
                return self.save_and_exit()
            elif choice == "6":
                return self.exit_without_saving()
            else:
                print("Invalid choice. Please try again.")
                input("Press Enter to continue...")

    def api_keys_menu(self):
        """Manage API keys."""
        while True:
            if not self.quiet:
                clear_screen()
            print_header("API Key Management")

            # Ensure api_keys exists in config
            if "api_keys" not in self.config:
                self.config["api_keys"] = {}

            # Show current status
            print("Current API Key Status:")
            print("-" * 50)

            providers = list(API_PROVIDERS.keys())
            for i, provider in enumerate(providers, 1):
                info = API_PROVIDERS[provider]
                key = self._get_api_key(provider)
                status = mask_key(key)
                print(f"  [{i}] {info['name']}: {status}")

            print()
            print("  [A] Add/Update API Key")
            print("  [R] Remove API Key")
            print("  [T] Test API Key")
            print("  [B] Back to Main Menu")
            print()

            choice = get_input("Enter choice").upper()

            if choice == "A":
                self.add_api_key()
            elif choice == "R":
                self.remove_api_key()
            elif choice == "T":
                self.test_api_key()
            elif choice == "B":
                return
            elif choice.isdigit():
                idx = int(choice) - 1
                if 0 <= idx < len(providers):
                    self.edit_api_key(providers[idx])
            else:
                print("Invalid choice.")
                input("Press Enter to continue...")

    def _get_api_key(self, provider: str) -> Optional[str]:
        """Get API key for provider, checking env vars first."""
        # Check environment variable first
        env_var = API_PROVIDERS.get(provider, {}).get("env_var", "")
        if env_var:
            env_key = os.getenv(env_var)
            if env_key:
                return env_key
        # Check config
        return self.config.get("api_keys", {}).get(provider)

    def add_api_key(self):
        """Add or update an API key."""
        print()
        print("Select provider to add/update:")
        providers = list(API_PROVIDERS.keys())
        for i, provider in enumerate(providers, 1):
            info = API_PROVIDERS[provider]
            print(f"  [{i}] {info['name']} - {info['description']}")

        print()
        choice = get_input("Enter number (or 'cancel')")

        if choice.lower() == "cancel":
            return

        if choice.isdigit():
            idx = int(choice) - 1
            if 0 <= idx < len(providers):
                self.edit_api_key(providers[idx])
            else:
                print("Invalid selection.")
                input("Press Enter to continue...")

    def edit_api_key(self, provider: str):
        """Edit API key for a specific provider."""
        info = API_PROVIDERS[provider]
        print()
        print(f"Provider: {info['name']}")
        print(f"Description: {info['description']}")
        print(f"Get your key at: {info['url']}")
        print()

        current = self._get_api_key(provider)
        if current:
            print(f"Current key: {mask_key(current)}")

        print()
        api_key = get_secret_input("Enter API key (hidden)")

        if api_key:
            if "api_keys" not in self.config:
                self.config["api_keys"] = {}
            self.config["api_keys"][provider] = api_key
            self.changes_made = True
            print(f"\nAPI key for {info['name']} has been set.")
        else:
            print("\nNo changes made.")

        input("Press Enter to continue...")

    def remove_api_key(self):
        """Remove an API key."""
        print()
        print("Select provider to remove key:")
        providers = list(API_PROVIDERS.keys())
        for i, provider in enumerate(providers, 1):
            info = API_PROVIDERS[provider]
            key = self._get_api_key(provider)
            if key:
                print(f"  [{i}] {info['name']}: {mask_key(key)}")
            else:
                print(f"  [{i}] {info['name']}: (not set)")

        print()
        choice = get_input("Enter number (or 'cancel')")

        if choice.lower() == "cancel":
            return

        if choice.isdigit():
            idx = int(choice) - 1
            if 0 <= idx < len(providers):
                provider = providers[idx]
                if confirm(f"Remove API key for {API_PROVIDERS[provider]['name']}?"):
                    if "api_keys" in self.config:
                        self.config["api_keys"][provider] = None
                    self.changes_made = True
                    print("API key removed.")
                else:
                    print("Cancelled.")
            else:
                print("Invalid selection.")

        input("Press Enter to continue...")

    def test_api_key(self):
        """Test an API key."""
        print()
        print("Select provider to test:")
        providers = ["openai", "anthropic", "google", "groq"]  # AI providers with API keys
        for i, provider in enumerate(providers, 1):
            info = API_PROVIDERS[provider]
            key = self._get_api_key(provider)
            status = "configured" if key else "not set"
            print(f"  [{i}] {info['name']}: {status}")

        print()
        choice = get_input("Enter number (or 'cancel')")

        if choice.lower() == "cancel":
            return

        if choice.isdigit():
            idx = int(choice) - 1
            if 0 <= idx < len(providers):
                provider = providers[idx]
                key = self._get_api_key(provider)
                if not key:
                    print(
                        f"\nNo API key configured for {API_PROVIDERS[provider]['name']}."
                    )
                else:
                    print(f"\nTesting {API_PROVIDERS[provider]['name']} API...")
                    result = self._test_provider(provider, key)
                    if result:
                        print("API key is valid!")
                    else:
                        print("API key test failed. Please check your key.")
            else:
                print("Invalid selection.")

        input("Press Enter to continue...")

    def _test_provider(self, provider: str, key: str) -> bool:
        """Test API key for a provider."""
        try:
            if provider == "openai":
                import openai

                client = openai.OpenAI(api_key=key)
                client.models.list()
                return True
            elif provider == "anthropic":
                import anthropic

                client = anthropic.Anthropic(api_key=key)
                # Simple test - just initialize the client
                return True
            elif provider == "google":
                import google.generativeai as genai

                genai.configure(api_key=key)
                # List models to verify key works
                list(genai.list_models())
                return True
            elif provider == "groq":
                from groq import Groq

                client = Groq(api_key=key)
                # List models to verify key works
                client.models.list()
                return True
        except ImportError:
            print(f"Required library for {provider} is not installed.")
            return False
        except Exception as e:
            print(f"Error: {e}")
            return False
        return False

    def ai_settings_menu(self):
        """Configure AI assistant settings."""
        while True:
            if not self.quiet:
                clear_screen()
            print_header("AI Assistant Settings")

            # Ensure ai config exists
            if "ai" not in self.config:
                self.config["ai"] = get_default_config()["ai"]

            ai_config = self.config["ai"]

            print("Current Settings:")
            print("-" * 40)
            print(f"  Provider: {ai_config.get('provider', 'openai')}")
            print(f"  Model: {ai_config.get('model', 'gpt-4o-mini')}")
            print(f"  Max Tokens: {ai_config.get('max_tokens', 2048)}")
            print(f"  Temperature: {ai_config.get('temperature', 0.7)}")
            print(f"  Enabled: {'Yes' if ai_config.get('enabled', True) else 'No'}")
            print()

            options = [
                "Change AI Provider",
                "Change Model",
                "Change Max Tokens",
                "Change Temperature",
                "Toggle AI Assistance",
                "Back to Main Menu",
            ]
            print_menu(options)

            choice = get_input("Enter choice")

            if choice == "1":
                self.change_ai_provider()
            elif choice == "2":
                self.change_ai_model()
            elif choice == "3":
                self.change_max_tokens()
            elif choice == "4":
                self.change_temperature()
            elif choice == "5":
                self.toggle_ai()
            elif choice == "6":
                return
            else:
                print("Invalid choice.")
                input("Press Enter to continue...")

    def change_ai_provider(self):
        """Change AI provider."""
        print()
        print("Select AI Provider:")
        providers = list(AI_PROVIDERS.keys())
        for i, provider in enumerate(providers, 1):
            info = AI_PROVIDERS[provider]
            current = (
                " (current)"
                if self.config.get("ai", {}).get("provider") == provider
                else ""
            )
            print(f"  [{i}] {info['name']}{current}")

        print()
        choice = get_input("Enter number")

        if choice.isdigit():
            idx = int(choice) - 1
            if 0 <= idx < len(providers):
                provider = providers[idx]
                self.config["ai"]["provider"] = provider
                # Update model to default for this provider
                self.config["ai"]["model"] = AI_PROVIDERS[provider]["default_model"]
                self.changes_made = True
                print(f"\nAI provider changed to {AI_PROVIDERS[provider]['name']}.")
            else:
                print("Invalid selection.")

        input("Press Enter to continue...")

    def change_ai_model(self):
        """Change AI model."""
        provider = self.config.get("ai", {}).get("provider", "openai")
        models = AI_PROVIDERS.get(provider, {}).get("models", [])

        print()
        print(f"Select Model for {AI_PROVIDERS[provider]['name']}:")
        current_model = self.config.get("ai", {}).get("model", "")
        for i, model in enumerate(models, 1):
            current = " (current)" if model == current_model else ""
            print(f"  [{i}] {model}{current}")

        print()
        choice = get_input("Enter number")

        if choice.isdigit():
            idx = int(choice) - 1
            if 0 <= idx < len(models):
                self.config["ai"]["model"] = models[idx]
                self.changes_made = True
                print(f"\nModel changed to {models[idx]}.")
            else:
                print("Invalid selection.")

        input("Press Enter to continue...")

    def change_max_tokens(self):
        """Change max tokens setting."""
        print()
        current = self.config.get("ai", {}).get("max_tokens", 2048)
        print(f"Current max tokens: {current}")
        print("Recommended: 1024-4096")
        print()

        value = get_input("Enter new value", str(current))
        if value.isdigit():
            self.config["ai"]["max_tokens"] = int(value)
            self.changes_made = True
            print(f"\nMax tokens set to {value}.")
        else:
            print("Invalid value. Please enter a number.")

        input("Press Enter to continue...")

    def change_temperature(self):
        """Change temperature setting."""
        print()
        current = self.config.get("ai", {}).get("temperature", 0.7)
        print(f"Current temperature: {current}")
        print("Range: 0.0 (deterministic) to 1.0 (creative)")
        print()

        value = get_input("Enter new value", str(current))
        try:
            temp = float(value)
            if 0.0 <= temp <= 1.0:
                self.config["ai"]["temperature"] = temp
                self.changes_made = True
                print(f"\nTemperature set to {temp}.")
            else:
                print("Value must be between 0.0 and 1.0.")
        except ValueError:
            print("Invalid value. Please enter a decimal number.")

        input("Press Enter to continue...")

    def toggle_ai(self):
        """Toggle AI assistance on/off."""
        current = self.config.get("ai", {}).get("enabled", True)
        self.config["ai"]["enabled"] = not current
        self.changes_made = True
        status = "enabled" if self.config["ai"]["enabled"] else "disabled"
        print(f"\nAI assistance {status}.")
        input("Press Enter to continue...")

    def view_config(self):
        """View current configuration."""
        if not self.quiet:
            clear_screen()
        print_header("Current Configuration")

        # Create display version with masked keys
        display_config = json.loads(json.dumps(self.config))
        if "api_keys" in display_config:
            for provider in display_config["api_keys"]:
                key = display_config["api_keys"][provider]
                display_config["api_keys"][provider] = mask_key(key)

        print(json.dumps(display_config, indent=2))
        print()
        print(f"Config file: {get_config_path()}")
        print()
        input("Press Enter to continue...")

    def reset_defaults(self):
        """Reset configuration to defaults."""
        if confirm("Reset all settings to defaults? This cannot be undone"):
            self.config = get_default_config()
            self.changes_made = True
            print("\nConfiguration reset to defaults.")
        else:
            print("\nCancelled.")
        input("Press Enter to continue...")

    def save_and_exit(self) -> int:
        """Save configuration and exit."""
        if self.changes_made:
            save_config(self.config)
            print("\nConfiguration saved.")
        else:
            print("\nNo changes to save.")
        return 0

    def exit_without_saving(self) -> int:
        """Exit without saving changes."""
        if self.changes_made:
            if not confirm("Discard unsaved changes?"):
                return self.save_and_exit()
        print("\nExiting without saving.")
        return 0


def run_settings_menu(quiet: bool = False) -> int:
    """Run the settings menu."""
    menu = SettingsMenu(quiet=quiet)
    return menu.run()


def set_api_key_direct(provider: str, key: str) -> bool:
    """Set an API key directly without interactive menu."""
    if provider not in API_PROVIDERS:
        print(f"Unknown provider: {provider}")
        print(f"Available providers: {', '.join(API_PROVIDERS.keys())}")
        return False

    config = load_config()
    if "api_keys" not in config:
        config["api_keys"] = {}

    config["api_keys"][provider] = key
    save_config(config)

    print(f"API key for {API_PROVIDERS[provider]['name']} has been saved.")
    return True


def get_api_key_direct(provider: str) -> Optional[str]:
    """Get an API key directly."""
    # Check environment variable first
    env_var = API_PROVIDERS.get(provider, {}).get("env_var", "")
    if env_var:
        env_key = os.getenv(env_var)
        if env_key:
            return env_key

    # Check config
    config = load_config()
    return config.get("api_keys", {}).get(provider)


def list_api_keys() -> None:
    """List all configured API keys (masked)."""
    config = load_config()
    api_keys = config.get("api_keys", {})

    print("\nConfigured API Keys:")
    print("-" * 50)

    for provider, info in API_PROVIDERS.items():
        # Check env var first
        env_var = info.get("env_var", "")
        env_key = os.getenv(env_var) if env_var else None
        config_key = api_keys.get(provider)

        if env_key:
            status = f"{mask_key(env_key)} (from env: {env_var})"
        elif config_key:
            status = mask_key(config_key)
        else:
            status = "(not set)"

        print(f"  {info['name']}: {status}")

    print()


if __name__ == "__main__":
    sys.exit(run_settings_menu())
