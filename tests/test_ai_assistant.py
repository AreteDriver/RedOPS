"""Tests for AI Assistant module."""

import json
import os
import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch, mock_open


class TestLoadConfig:
    """Tests for load_config function."""

    def test_load_config_default_path(self, tmp_path):
        """Test loading config from default path."""
        from redops.modules.ai_assistant import load_config

        config_dir = tmp_path / ".config" / "redops"
        config_dir.mkdir(parents=True)
        config_file = config_dir / "config.json"
        config_file.write_text('{"ai": {"provider": "openai"}}')

        with patch.object(Path, "home", return_value=tmp_path):
            with patch.dict(os.environ, {}, clear=True):
                # Remove REDOPS_CONFIG if present
                os.environ.pop("REDOPS_CONFIG", None)
                result = load_config()

        assert result == {"ai": {"provider": "openai"}}

    def test_load_config_env_path(self, tmp_path):
        """Test loading config from environment variable path."""
        from redops.modules.ai_assistant import load_config

        config_file = tmp_path / "custom_config.json"
        config_file.write_text('{"ai": {"provider": "anthropic"}}')

        with patch.dict(os.environ, {"REDOPS_CONFIG": str(config_file)}):
            result = load_config()

        assert result == {"ai": {"provider": "anthropic"}}

    def test_load_config_file_not_exists(self, tmp_path):
        """Test loading config when file doesn't exist."""
        from redops.modules.ai_assistant import load_config

        with patch.object(Path, "home", return_value=tmp_path):
            with patch.dict(os.environ, {}, clear=True):
                os.environ.pop("REDOPS_CONFIG", None)
                result = load_config()

        assert result == {}


class TestGetApiKey:
    """Tests for get_api_key function."""

    def test_get_api_key_from_env(self):
        """Test getting API key from environment variable."""
        from redops.modules.ai_assistant import get_api_key

        with patch.dict(os.environ, {"OPENAI_API_KEY": "test-key-123"}):
            result = get_api_key("openai")

        assert result == "test-key-123"

    def test_get_api_key_from_config(self, tmp_path):
        """Test getting API key from config file."""
        from redops.modules.ai_assistant import get_api_key

        config_dir = tmp_path / ".config" / "redops"
        config_dir.mkdir(parents=True)
        config_file = config_dir / "config.json"
        config_file.write_text('{"api_keys": {"anthropic": "config-key-456"}}')

        with patch.object(Path, "home", return_value=tmp_path):
            with patch.dict(os.environ, {}, clear=True):
                os.environ.pop("REDOPS_CONFIG", None)
                os.environ.pop("ANTHROPIC_API_KEY", None)
                result = get_api_key("anthropic")

        assert result == "config-key-456"

    def test_get_api_key_not_found(self, tmp_path):
        """Test getting API key when not found."""
        from redops.modules.ai_assistant import get_api_key

        with patch.object(Path, "home", return_value=tmp_path):
            with patch.dict(os.environ, {}, clear=True):
                os.environ.pop("REDOPS_CONFIG", None)
                os.environ.pop("GROQ_API_KEY", None)
                result = get_api_key("groq")

        assert result is None


class TestAIAssistantInit:
    """Tests for AIAssistant initialization."""

    def test_init_openai_provider(self):
        """Test initializing with OpenAI provider."""
        mock_openai = MagicMock()
        mock_client = MagicMock()
        mock_openai.OpenAI.return_value = mock_client

        with patch.dict("sys.modules", {"openai": mock_openai}):
            with patch.dict(os.environ, {"OPENAI_API_KEY": "test-key"}):
                from redops.modules.ai_assistant import AIAssistant

                assistant = AIAssistant(provider="openai", model="gpt-4")

        assert assistant.provider == "openai"
        assert assistant.model == "gpt-4"
        assert assistant.api_key == "test-key"
        mock_openai.OpenAI.assert_called_once_with(api_key="test-key")

    def test_init_anthropic_provider(self):
        """Test initializing with Anthropic provider."""
        mock_anthropic = MagicMock()
        mock_client = MagicMock()
        mock_anthropic.Anthropic.return_value = mock_client

        with patch.dict("sys.modules", {"anthropic": mock_anthropic}):
            with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "test-key"}):
                from redops.modules.ai_assistant import AIAssistant

                assistant = AIAssistant(provider="anthropic", model="claude-3")

        assert assistant.provider == "anthropic"
        assert assistant.model == "claude-3"
        mock_anthropic.Anthropic.assert_called_once_with(api_key="test-key")

    def test_init_gemini_provider(self):
        """Test initializing with Gemini provider."""
        mock_genai = MagicMock()
        mock_model = MagicMock()
        mock_genai.GenerativeModel.return_value = mock_model

        with patch.dict("sys.modules", {"google.generativeai": mock_genai, "google": MagicMock()}):
            with patch.dict(os.environ, {"GEMINI_API_KEY": "test-key"}):
                from redops.modules.ai_assistant import AIAssistant

                assistant = AIAssistant(provider="gemini", model="gemini-pro")

        assert assistant.provider == "gemini"
        assert assistant.model == "gemini-pro"

    def test_init_ollama_provider(self):
        """Test initializing with Ollama provider (no API key required)."""
        mock_ollama = MagicMock()
        mock_client = MagicMock()
        mock_ollama.Client.return_value = mock_client

        with patch.dict("sys.modules", {"ollama": mock_ollama}):
            with patch.dict(os.environ, {}, clear=True):
                # Ollama doesn't need API key
                os.environ.pop("OLLAMA_API_KEY", None)
                from redops.modules.ai_assistant import AIAssistant

                # Need to mock load_config to avoid file access
                with patch("redops.modules.ai_assistant.load_config", return_value={}):
                    assistant = AIAssistant(provider="ollama", model="llama2")

        assert assistant.provider == "ollama"
        assert assistant.model == "llama2"

    def test_init_groq_provider(self):
        """Test initializing with Groq provider."""
        mock_groq_module = MagicMock()
        mock_groq_class = MagicMock()
        mock_groq_module.Groq = mock_groq_class

        with patch.dict("sys.modules", {"groq": mock_groq_module}):
            with patch.dict(os.environ, {"GROQ_API_KEY": "test-key"}):
                from redops.modules.ai_assistant import AIAssistant

                assistant = AIAssistant(provider="groq", model="mixtral")

        assert assistant.provider == "groq"
        assert assistant.model == "mixtral"

    def test_init_no_api_key_error(self):
        """Test initialization fails without API key for non-ollama providers."""
        with patch("redops.modules.ai_assistant.load_config", return_value={}):
            with patch.dict(os.environ, {}, clear=True):
                os.environ.pop("OPENAI_API_KEY", None)
                from redops.modules.ai_assistant import AIAssistant

                with pytest.raises(ValueError, match="No API key found"):
                    AIAssistant(provider="openai")

    def test_init_unsupported_provider(self):
        """Test initialization fails with unsupported provider."""
        with patch("redops.modules.ai_assistant.load_config", return_value={}):
            with patch.dict(os.environ, {"UNSUPPORTED_API_KEY": "key"}):
                from redops.modules.ai_assistant import AIAssistant

                with pytest.raises(ValueError, match="Unsupported provider"):
                    AIAssistant(provider="unsupported")

    def test_init_openai_import_error(self):
        """Test initialization fails when OpenAI not installed."""
        with patch.dict(os.environ, {"OPENAI_API_KEY": "test-key"}):
            with patch("redops.modules.ai_assistant.load_config", return_value={}):
                from redops.modules.ai_assistant import AIAssistant

                # Remove openai from modules to simulate not installed
                import sys
                original = sys.modules.get("openai")
                sys.modules["openai"] = None

                try:
                    with pytest.raises(ImportError, match="OpenAI library not installed"):
                        AIAssistant(provider="openai")
                finally:
                    if original:
                        sys.modules["openai"] = original

    def test_init_anthropic_import_error(self):
        """Test initialization fails when Anthropic not installed."""
        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "test-key"}):
            with patch("redops.modules.ai_assistant.load_config", return_value={}):
                from redops.modules.ai_assistant import AIAssistant

                import sys
                original = sys.modules.get("anthropic")
                sys.modules["anthropic"] = None

                try:
                    with pytest.raises(ImportError, match="Anthropic library not installed"):
                        AIAssistant(provider="anthropic")
                finally:
                    if original:
                        sys.modules["anthropic"] = original

    def test_init_with_config_defaults(self, tmp_path):
        """Test initialization uses config defaults."""
        config = {
            "ai": {
                "provider": "openai",
                "model": "gpt-4o",
                "max_tokens": 4096,
                "temperature": 0.5,
            }
        }

        mock_openai = MagicMock()
        with patch.dict("sys.modules", {"openai": mock_openai}):
            with patch("redops.modules.ai_assistant.load_config", return_value=config):
                with patch.dict(os.environ, {"OPENAI_API_KEY": "test-key"}):
                    from redops.modules.ai_assistant import AIAssistant

                    assistant = AIAssistant()

        assert assistant.provider == "openai"
        assert assistant.model == "gpt-4o"
        assert assistant.max_tokens == 4096
        assert assistant.temperature == 0.5


class TestAIAssistantAPICalls:
    """Tests for AIAssistant API call methods."""

    @pytest.fixture
    def mock_openai_assistant(self):
        """Create a mocked OpenAI assistant."""
        mock_openai = MagicMock()
        mock_client = MagicMock()
        mock_openai.OpenAI.return_value = mock_client

        with patch.dict("sys.modules", {"openai": mock_openai}):
            with patch.dict(os.environ, {"OPENAI_API_KEY": "test-key"}):
                from redops.modules.ai_assistant import AIAssistant

                assistant = AIAssistant(provider="openai", model="gpt-4")
                assistant.client = mock_client
                return assistant, mock_client

    @pytest.fixture
    def mock_anthropic_assistant(self):
        """Create a mocked Anthropic assistant."""
        mock_anthropic = MagicMock()
        mock_client = MagicMock()
        mock_anthropic.Anthropic.return_value = mock_client

        with patch.dict("sys.modules", {"anthropic": mock_anthropic}):
            with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "test-key"}):
                from redops.modules.ai_assistant import AIAssistant

                assistant = AIAssistant(provider="anthropic", model="claude-3")
                assistant.client = mock_client
                return assistant, mock_client

    def test_call_openai(self, mock_openai_assistant):
        """Test calling OpenAI API."""
        assistant, mock_client = mock_openai_assistant

        mock_response = MagicMock()
        mock_response.choices = [MagicMock(message=MagicMock(content="AI response"))]
        mock_client.chat.completions.create.return_value = mock_response

        result = assistant._call_openai("Test prompt", "System prompt")

        assert result == "AI response"
        mock_client.chat.completions.create.assert_called_once()
        call_args = mock_client.chat.completions.create.call_args
        assert call_args.kwargs["model"] == "gpt-4"
        assert len(call_args.kwargs["messages"]) == 2
        assert call_args.kwargs["messages"][0]["role"] == "system"
        assert call_args.kwargs["messages"][1]["role"] == "user"

    def test_call_openai_no_system_prompt(self, mock_openai_assistant):
        """Test calling OpenAI API without system prompt."""
        assistant, mock_client = mock_openai_assistant

        mock_response = MagicMock()
        mock_response.choices = [MagicMock(message=MagicMock(content="AI response"))]
        mock_client.chat.completions.create.return_value = mock_response

        result = assistant._call_openai("Test prompt")

        call_args = mock_client.chat.completions.create.call_args
        assert len(call_args.kwargs["messages"]) == 1
        assert call_args.kwargs["messages"][0]["role"] == "user"

    def test_call_anthropic(self, mock_anthropic_assistant):
        """Test calling Anthropic API."""
        assistant, mock_client = mock_anthropic_assistant

        mock_response = MagicMock()
        mock_response.content = [MagicMock(text="Claude response")]
        mock_client.messages.create.return_value = mock_response

        result = assistant._call_anthropic("Test prompt", "System prompt")

        assert result == "Claude response"
        mock_client.messages.create.assert_called_once()
        call_args = mock_client.messages.create.call_args
        assert call_args.kwargs["system"] == "System prompt"

    def test_call_anthropic_default_system(self, mock_anthropic_assistant):
        """Test calling Anthropic API with default system prompt."""
        assistant, mock_client = mock_anthropic_assistant

        mock_response = MagicMock()
        mock_response.content = [MagicMock(text="Claude response")]
        mock_client.messages.create.return_value = mock_response

        result = assistant._call_anthropic("Test prompt")

        call_args = mock_client.messages.create.call_args
        assert "security analysis assistant" in call_args.kwargs["system"]

    def test_call_gemini(self):
        """Test calling Gemini API."""
        mock_genai = MagicMock()
        mock_model = MagicMock()
        mock_response = MagicMock()
        mock_response.text = "Gemini response"
        mock_model.generate_content.return_value = mock_response
        mock_genai.GenerativeModel.return_value = mock_model

        with patch.dict("sys.modules", {"google.generativeai": mock_genai, "google": MagicMock()}):
            with patch.dict(os.environ, {"GEMINI_API_KEY": "test-key"}):
                from redops.modules.ai_assistant import AIAssistant

                assistant = AIAssistant(provider="gemini", model="gemini-pro")
                assistant.client = mock_model

                result = assistant._call_gemini("Test prompt", "System prompt")

        assert result == "Gemini response"

    def test_call_gemini_no_system(self):
        """Test calling Gemini API without system prompt."""
        mock_genai = MagicMock()
        mock_model = MagicMock()
        mock_response = MagicMock()
        mock_response.text = "Gemini response"
        mock_model.generate_content.return_value = mock_response
        mock_genai.GenerativeModel.return_value = mock_model

        with patch.dict("sys.modules", {"google.generativeai": mock_genai, "google": MagicMock()}):
            with patch.dict(os.environ, {"GEMINI_API_KEY": "test-key"}):
                from redops.modules.ai_assistant import AIAssistant

                assistant = AIAssistant(provider="gemini", model="gemini-pro")
                assistant.client = mock_model

                result = assistant._call_gemini("Test prompt")

        assert result == "Gemini response"

    def test_call_ollama(self):
        """Test calling Ollama API."""
        mock_ollama = MagicMock()
        mock_client = MagicMock()
        mock_client.chat.return_value = {"message": {"content": "Ollama response"}}
        mock_ollama.Client.return_value = mock_client

        with patch.dict("sys.modules", {"ollama": mock_ollama}):
            with patch("redops.modules.ai_assistant.load_config", return_value={}):
                from redops.modules.ai_assistant import AIAssistant

                assistant = AIAssistant(provider="ollama", model="llama2")
                assistant.client = mock_client

                result = assistant._call_ollama("Test prompt", "System prompt")

        assert result == "Ollama response"
        mock_client.chat.assert_called_once()

    def test_call_groq(self):
        """Test calling Groq API."""
        mock_groq_module = MagicMock()
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.choices = [MagicMock(message=MagicMock(content="Groq response"))]
        mock_client.chat.completions.create.return_value = mock_response
        mock_groq_module.Groq.return_value = mock_client

        with patch.dict("sys.modules", {"groq": mock_groq_module}):
            with patch.dict(os.environ, {"GROQ_API_KEY": "test-key"}):
                from redops.modules.ai_assistant import AIAssistant

                assistant = AIAssistant(provider="groq", model="mixtral")
                assistant.client = mock_client

                result = assistant._call_groq("Test prompt", "System prompt")

        assert result == "Groq response"

    def test_call_api_routing_openai(self, mock_openai_assistant):
        """Test _call_api routes to OpenAI correctly."""
        assistant, mock_client = mock_openai_assistant

        mock_response = MagicMock()
        mock_response.choices = [MagicMock(message=MagicMock(content="Response"))]
        mock_client.chat.completions.create.return_value = mock_response

        result = assistant._call_api("Test prompt", "System prompt")

        assert result == "Response"

    def test_call_api_routing_unsupported(self, mock_openai_assistant):
        """Test _call_api raises for unsupported provider."""
        assistant, _ = mock_openai_assistant
        assistant.provider = "unsupported"

        with pytest.raises(ValueError, match="Unsupported provider"):
            assistant._call_api("Test prompt")

    def test_call_api_routing_anthropic(self, mock_anthropic_assistant):
        """Test _call_api routes to Anthropic correctly."""
        assistant, mock_client = mock_anthropic_assistant

        mock_response = MagicMock()
        mock_response.content = [MagicMock(text="Response")]
        mock_client.messages.create.return_value = mock_response

        result = assistant._call_api("Test prompt", "System prompt")

        assert result == "Response"

    def test_call_api_routing_gemini(self):
        """Test _call_api routes to Gemini correctly."""
        mock_genai = MagicMock()
        mock_model = MagicMock()
        mock_response = MagicMock()
        mock_response.text = "Gemini response"
        mock_model.generate_content.return_value = mock_response
        mock_genai.GenerativeModel.return_value = mock_model

        with patch.dict("sys.modules", {"google.generativeai": mock_genai, "google": MagicMock()}):
            with patch.dict(os.environ, {"GEMINI_API_KEY": "test-key"}):
                from redops.modules.ai_assistant import AIAssistant

                assistant = AIAssistant(provider="gemini", model="gemini-pro")
                assistant.client = mock_model

                result = assistant._call_api("Test prompt")

        assert result == "Gemini response"

    def test_call_api_routing_ollama(self):
        """Test _call_api routes to Ollama correctly."""
        mock_ollama = MagicMock()
        mock_client = MagicMock()
        mock_client.chat.return_value = {"message": {"content": "Ollama response"}}
        mock_ollama.Client.return_value = mock_client

        with patch.dict("sys.modules", {"ollama": mock_ollama}):
            with patch("redops.modules.ai_assistant.load_config", return_value={}):
                from redops.modules.ai_assistant import AIAssistant

                assistant = AIAssistant(provider="ollama", model="llama2")
                assistant.client = mock_client

                result = assistant._call_api("Test prompt")

        assert result == "Ollama response"

    def test_call_api_routing_groq(self):
        """Test _call_api routes to Groq correctly."""
        mock_groq_module = MagicMock()
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.choices = [MagicMock(message=MagicMock(content="Groq response"))]
        mock_client.chat.completions.create.return_value = mock_response
        mock_groq_module.Groq.return_value = mock_client

        with patch.dict("sys.modules", {"groq": mock_groq_module}):
            with patch.dict(os.environ, {"GROQ_API_KEY": "test-key"}):
                from redops.modules.ai_assistant import AIAssistant

                assistant = AIAssistant(provider="groq", model="mixtral")
                assistant.client = mock_client

                result = assistant._call_api("Test prompt")

        assert result == "Groq response"


class TestAIAssistantMethods:
    """Tests for AIAssistant high-level methods."""

    @pytest.fixture
    def assistant_with_mock_api(self):
        """Create assistant with mocked API call."""
        mock_openai = MagicMock()
        mock_client = MagicMock()
        mock_openai.OpenAI.return_value = mock_client

        with patch.dict("sys.modules", {"openai": mock_openai}):
            with patch.dict(os.environ, {"OPENAI_API_KEY": "test-key"}):
                from redops.modules.ai_assistant import AIAssistant

                assistant = AIAssistant(provider="openai", model="gpt-4")

                # Mock _call_api to return predictable results
                assistant._call_api = MagicMock(return_value="AI analysis result")
                return assistant

    def test_analyze_findings(self, assistant_with_mock_api):
        """Test analyze_findings method."""
        scan_data = {
            "target": "example.com",
            "timestamp": "2024-01-01T00:00:00Z",
            "exposure_scan": {"exposures": [{"type": "open_port", "port": 22}]},
        }

        result = assistant_with_mock_api.analyze_findings(scan_data)

        assert result == "AI analysis result"
        assistant_with_mock_api._call_api.assert_called_once()
        call_args = assistant_with_mock_api._call_api.call_args
        assert "security scan findings" in call_args.args[0].lower()

    def test_explain(self, assistant_with_mock_api):
        """Test explain method."""
        result = assistant_with_mock_api.explain("What is SQL injection?")

        assert result == "AI analysis result"
        assistant_with_mock_api._call_api.assert_called_once()

    def test_explain_with_context(self, assistant_with_mock_api):
        """Test explain method with context."""
        context = {"vulnerability": "CVE-2021-44228"}
        result = assistant_with_mock_api.explain("Explain this CVE", context=context)

        assert result == "AI analysis result"
        call_args = assistant_with_mock_api._call_api.call_args
        assert "CVE-2021-44228" in call_args.args[0]

    def test_suggest_remediations(self, assistant_with_mock_api):
        """Test suggest_remediations method."""
        scan_data = {
            "target": "example.com",
            "exposure_scan": {"exposures": [{"type": "weak_cipher"}]},
        }

        result = assistant_with_mock_api.suggest_remediations(scan_data)

        assert result == "AI analysis result"
        call_args = assistant_with_mock_api._call_api.call_args
        assert "remediation" in call_args.args[0].lower()

    def test_summarize(self, assistant_with_mock_api):
        """Test summarize method."""
        scan_data = {"target": "example.com", "timestamp": "2024-01-01"}

        result = assistant_with_mock_api.summarize(scan_data)

        assert result == "AI analysis result"
        call_args = assistant_with_mock_api._call_api.call_args
        assert "executive summary" in call_args.args[0].lower()

    def test_chat(self, assistant_with_mock_api):
        """Test chat method."""
        result = assistant_with_mock_api.chat("How do I secure my server?")

        assert result == "AI analysis result"
        assistant_with_mock_api._call_api.assert_called_once()

    def test_chat_with_context(self, assistant_with_mock_api):
        """Test chat method with scan context."""
        context = {
            "target": "example.com",
            "exposure_scan": {"exposures": []},
        }

        result = assistant_with_mock_api.chat("What risks were found?", context=context)

        assert result == "AI analysis result"
        call_args = assistant_with_mock_api._call_api.call_args
        assert "example.com" in call_args.args[0]

    def test_correlate_threats(self, assistant_with_mock_api):
        """Test correlate_threats method."""
        scan_data = {
            "target": "example.com",
            "threat_intel": {"iocs": [{"type": "ip", "value": "1.2.3.4"}]},
        }

        result = assistant_with_mock_api.correlate_threats(scan_data)

        assert result == "AI analysis result"
        call_args = assistant_with_mock_api._call_api.call_args
        assert "threat" in call_args.args[0].lower()

    def test_generate_report_section_executive(self, assistant_with_mock_api):
        """Test generating executive report section."""
        scan_data = {"target": "example.com"}

        result = assistant_with_mock_api.generate_report_section(
            scan_data, section_type="executive"
        )

        assert result == "AI analysis result"
        call_args = assistant_with_mock_api._call_api.call_args
        assert "executive" in call_args.args[0].lower()

    def test_generate_report_section_technical(self, assistant_with_mock_api):
        """Test generating technical report section."""
        scan_data = {"target": "example.com"}

        result = assistant_with_mock_api.generate_report_section(
            scan_data, section_type="technical"
        )

        assert result == "AI analysis result"
        call_args = assistant_with_mock_api._call_api.call_args
        assert "technical" in call_args.args[0].lower()

    def test_generate_report_section_recommendations(self, assistant_with_mock_api):
        """Test generating recommendations report section."""
        scan_data = {"target": "example.com"}

        result = assistant_with_mock_api.generate_report_section(
            scan_data, section_type="recommendations"
        )

        assert result == "AI analysis result"

    def test_generate_report_section_risk(self, assistant_with_mock_api):
        """Test generating risk report section."""
        scan_data = {"target": "example.com"}

        result = assistant_with_mock_api.generate_report_section(
            scan_data, section_type="risk"
        )

        assert result == "AI analysis result"

    def test_generate_report_section_compliance(self, assistant_with_mock_api):
        """Test generating compliance report section."""
        scan_data = {"target": "example.com"}

        result = assistant_with_mock_api.generate_report_section(
            scan_data, section_type="compliance"
        )

        assert result == "AI analysis result"

    def test_generate_report_section_unknown_type(self, assistant_with_mock_api):
        """Test generating report section with unknown type defaults to executive."""
        scan_data = {"target": "example.com"}

        result = assistant_with_mock_api.generate_report_section(
            scan_data, section_type="unknown"
        )

        assert result == "AI analysis result"


class TestExtractFindingsSummary:
    """Tests for _extract_findings_summary method."""

    @pytest.fixture
    def assistant(self):
        """Create assistant for testing."""
        mock_openai = MagicMock()
        with patch.dict("sys.modules", {"openai": mock_openai}):
            with patch.dict(os.environ, {"OPENAI_API_KEY": "test-key"}):
                from redops.modules.ai_assistant import AIAssistant

                return AIAssistant(provider="openai")

    def test_extract_basic_fields(self, assistant):
        """Test extracting basic fields."""
        scan_data = {
            "target": "example.com",
            "timestamp": "2024-01-01T00:00:00Z",
        }

        result = assistant._extract_findings_summary(scan_data)

        assert result["target"] == "example.com"
        assert result["scan_time"] == "2024-01-01T00:00:00Z"

    def test_extract_exposures(self, assistant):
        """Test extracting exposure data."""
        scan_data = {
            "target": "example.com",
            "exposure_scan": {
                "exposures": [
                    {"type": "open_port", "port": 22},
                    {"type": "open_port", "port": 80},
                ]
            },
        }

        result = assistant._extract_findings_summary(scan_data)

        assert "exposures" in result
        assert len(result["exposures"]) == 2

    def test_extract_threat_intel(self, assistant):
        """Test extracting threat intelligence data."""
        scan_data = {
            "target": "example.com",
            "threat_intel": {
                "iocs": [
                    {"type": "ip", "value": "1.2.3.4"},
                    {"type": "domain", "value": "malicious.com"},
                ]
            },
        }

        result = assistant._extract_findings_summary(scan_data)

        assert "threat_indicators" in result
        assert len(result["threat_indicators"]) == 2

    def test_extract_compliance(self, assistant):
        """Test extracting compliance data."""
        scan_data = {
            "target": "example.com",
            "compliance": {
                "gaps": [
                    {"standard": "PCI-DSS", "requirement": "1.1"},
                    {"standard": "SOC2", "requirement": "CC6.1"},
                ]
            },
        }

        result = assistant._extract_findings_summary(scan_data)

        assert "compliance_gaps" in result
        assert len(result["compliance_gaps"]) == 2

    def test_extract_correlations(self, assistant):
        """Test extracting correlation data."""
        scan_data = {
            "target": "example.com",
            "correlations": {
                "findings": [{"correlation": "A relates to B"}],
                "insights": [{"insight": "Pattern detected"}],
            },
        }

        result = assistant._extract_findings_summary(scan_data)

        assert "correlations" in result
        assert "insights" in result

    def test_extract_executive_report(self, assistant):
        """Test extracting executive report data."""
        scan_data = {
            "target": "example.com",
            "executive_report": {
                "executive_summary": {"risk_level": "high"},
                "recommendations": [{"action": "Update firewall"}],
            },
        }

        result = assistant._extract_findings_summary(scan_data)

        assert "executive_summary" in result
        assert "recommendations" in result

    def test_extract_domain_profile(self, assistant):
        """Test extracting domain profile data."""
        scan_data = {
            "target": "example.com",
            "domain_profile": {
                "dns": {"A": ["1.2.3.4"]},
                "registrar": "GoDaddy",
            },
        }

        result = assistant._extract_findings_summary(scan_data)

        assert "domain_info" in result
        assert result["domain_info"]["registrar"] == "GoDaddy"

    def test_extract_tech_stack(self, assistant):
        """Test extracting tech stack data."""
        scan_data = {
            "target": "example.com",
            "tech_stack": {
                "technologies": [
                    {"name": "nginx"},
                    {"name": "PHP"},
                ]
            },
        }

        result = assistant._extract_findings_summary(scan_data)

        assert "technologies" in result
        assert len(result["technologies"]) == 2

    def test_extract_limits_results(self, assistant):
        """Test that extraction limits results to prevent large payloads."""
        # Create more than 10 exposures
        exposures = [{"type": f"exposure_{i}"} for i in range(20)]
        scan_data = {
            "target": "example.com",
            "exposure_scan": {"exposures": exposures},
        }

        result = assistant._extract_findings_summary(scan_data)

        # Should be limited to 10
        assert len(result["exposures"]) == 10

    def test_extract_missing_fields(self, assistant):
        """Test extraction with missing optional fields."""
        scan_data = {"target": "example.com"}

        result = assistant._extract_findings_summary(scan_data)

        assert result["target"] == "example.com"
        assert result["scan_time"] == "Unknown"
        assert "exposures" not in result
        assert "threat_indicators" not in result


class TestModuleWrappers:
    """Tests for module wrapper functions."""

    def test_ai_analyze_success(self):
        """Test ai_analyze function success path."""
        from redops.modules.ai_assistant import ai_analyze

        # Create a mock assistant that we can inject
        mock_assistant = MagicMock()
        mock_assistant.analyze_findings.return_value = "Analysis result"
        mock_assistant.provider = "openai"
        mock_assistant.model = "gpt-4"

        mock_ctx = MagicMock()
        mock_ctx.data = {"target": "example.com"}

        with patch("redops.modules.ai_assistant.AIAssistant", return_value=mock_assistant):
            result = ai_analyze(mock_ctx)

        mock_ctx.add.assert_called_once()
        call_args = mock_ctx.add.call_args
        assert call_args.args[0] == "ai_analysis"
        assert "analysis" in call_args.args[1]
        assert result == mock_ctx

    def test_ai_analyze_failure(self):
        """Test ai_analyze function handles errors."""
        from redops.modules.ai_assistant import ai_analyze

        mock_ctx = MagicMock()
        mock_ctx.data = {"target": "example.com"}

        with patch("redops.modules.ai_assistant.AIAssistant", side_effect=ValueError("No API key")):
            result = ai_analyze(mock_ctx)

        mock_ctx.log.assert_called_once()
        log_call = mock_ctx.log.call_args
        assert "failed" in log_call.args[0].lower()
        assert log_call.kwargs["level"] == "ERROR"
        assert result == mock_ctx

    def test_ai_summarize_success(self):
        """Test ai_summarize function success path."""
        from redops.modules.ai_assistant import ai_summarize

        mock_assistant = MagicMock()
        mock_assistant.summarize.return_value = "Summary result"
        mock_assistant.provider = "openai"
        mock_assistant.model = "gpt-4"

        mock_ctx = MagicMock()
        mock_ctx.data = {"target": "example.com"}

        with patch("redops.modules.ai_assistant.AIAssistant", return_value=mock_assistant):
            result = ai_summarize(mock_ctx)

        mock_ctx.add.assert_called_once()
        call_args = mock_ctx.add.call_args
        assert call_args.args[0] == "ai_summary"
        assert result == mock_ctx

    def test_ai_summarize_failure(self):
        """Test ai_summarize function handles errors."""
        from redops.modules.ai_assistant import ai_summarize

        mock_ctx = MagicMock()
        mock_ctx.data = {"target": "example.com"}

        with patch("redops.modules.ai_assistant.AIAssistant", side_effect=ValueError("No API key")):
            result = ai_summarize(mock_ctx)

        mock_ctx.log.assert_called_once()
        assert result == mock_ctx

    def test_ai_recommend_success(self):
        """Test ai_recommend function success path."""
        from redops.modules.ai_assistant import ai_recommend

        mock_assistant = MagicMock()
        mock_assistant.suggest_remediations.return_value = "Recommendations"
        mock_assistant.provider = "openai"
        mock_assistant.model = "gpt-4"

        mock_ctx = MagicMock()
        mock_ctx.data = {"target": "example.com"}

        with patch("redops.modules.ai_assistant.AIAssistant", return_value=mock_assistant):
            result = ai_recommend(mock_ctx)

        mock_ctx.add.assert_called_once()
        call_args = mock_ctx.add.call_args
        assert call_args.args[0] == "ai_recommendations"
        assert result == mock_ctx

    def test_ai_recommend_failure(self):
        """Test ai_recommend function handles errors."""
        from redops.modules.ai_assistant import ai_recommend

        mock_ctx = MagicMock()
        mock_ctx.data = {"target": "example.com"}

        with patch("redops.modules.ai_assistant.AIAssistant", side_effect=ValueError("No API key")):
            result = ai_recommend(mock_ctx)

        mock_ctx.log.assert_called_once()
        assert result == mock_ctx


class TestOllamaWithConfig:
    """Tests for Ollama with custom configuration."""

    def test_ollama_custom_base_url(self):
        """Test Ollama uses custom base URL from config."""
        mock_ollama = MagicMock()
        mock_client = MagicMock()
        mock_ollama.Client.return_value = mock_client

        config = {"ollama": {"base_url": "http://custom-server:11434"}}

        with patch.dict("sys.modules", {"ollama": mock_ollama}):
            with patch("redops.modules.ai_assistant.load_config", return_value=config):
                from redops.modules.ai_assistant import AIAssistant

                assistant = AIAssistant(provider="ollama", model="llama2")

        mock_ollama.Client.assert_called_with(host="http://custom-server:11434")


class TestGeminiImportError:
    """Tests for Gemini import error handling."""

    def test_gemini_import_error(self):
        """Test initialization fails when google-generativeai not installed."""
        with patch.dict(os.environ, {"GEMINI_API_KEY": "test-key"}):
            with patch("redops.modules.ai_assistant.load_config", return_value={}):
                import sys
                # Remove google modules to simulate not installed
                original_google = sys.modules.get("google")
                original_genai = sys.modules.get("google.generativeai")
                sys.modules["google.generativeai"] = None
                sys.modules["google"] = None

                try:
                    from redops.modules.ai_assistant import AIAssistant

                    with pytest.raises(ImportError, match="Google AI library not installed"):
                        AIAssistant(provider="gemini")
                finally:
                    if original_google:
                        sys.modules["google"] = original_google
                    if original_genai:
                        sys.modules["google.generativeai"] = original_genai


class TestOllamaImportError:
    """Tests for Ollama import error handling."""

    def test_ollama_import_error(self):
        """Test initialization fails when ollama not installed."""
        with patch("redops.modules.ai_assistant.load_config", return_value={}):
            import sys
            original = sys.modules.get("ollama")
            sys.modules["ollama"] = None

            try:
                from redops.modules.ai_assistant import AIAssistant

                with pytest.raises(ImportError, match="Ollama library not installed"):
                    AIAssistant(provider="ollama")
            finally:
                if original:
                    sys.modules["ollama"] = original


class TestGroqImportError:
    """Tests for Groq import error handling."""

    def test_groq_import_error(self):
        """Test initialization fails when groq not installed."""
        with patch.dict(os.environ, {"GROQ_API_KEY": "test-key"}):
            with patch("redops.modules.ai_assistant.load_config", return_value={}):
                import sys
                original = sys.modules.get("groq")
                sys.modules["groq"] = None

                try:
                    from redops.modules.ai_assistant import AIAssistant

                    with pytest.raises(ImportError, match="Groq library not installed"):
                        AIAssistant(provider="groq")
                finally:
                    if original:
                        sys.modules["groq"] = original
