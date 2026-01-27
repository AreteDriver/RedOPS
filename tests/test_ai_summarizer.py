"""Tests for AI Summarizer module."""

import json
from unittest.mock import MagicMock, patch


class TestSummarize:
    """Tests for summarize function."""

    def test_summarize_with_ai_string_data(self):
        """Test summarize with AI assistant and string data."""
        from redops.modules.ai_summarizer import summarize

        mock_assistant = MagicMock()
        mock_assistant.summarize.return_value = "AI generated summary"

        with patch(
            "redops.modules.ai_assistant.AIAssistant", return_value=mock_assistant
        ):
            result = summarize("some security data")

        assert result == "AI generated summary"
        mock_assistant.summarize.assert_called_once()
        # Should be called with raw_data since it's not valid JSON
        call_args = mock_assistant.summarize.call_args[0][0]
        assert call_args == {"raw_data": "some security data"}

    def test_summarize_with_ai_json_string(self):
        """Test summarize with AI assistant and JSON string data."""
        from redops.modules.ai_summarizer import summarize

        mock_assistant = MagicMock()
        mock_assistant.summarize.return_value = "AI generated summary"

        json_data = '{"target": "example.com", "findings": []}'

        with patch(
            "redops.modules.ai_assistant.AIAssistant", return_value=mock_assistant
        ):
            result = summarize(json_data)

        assert result == "AI generated summary"
        call_args = mock_assistant.summarize.call_args[0][0]
        assert call_args == {"target": "example.com", "findings": []}

    def test_summarize_with_ai_dict_data(self):
        """Test summarize with AI assistant and dict data."""
        from redops.modules.ai_summarizer import summarize

        mock_assistant = MagicMock()
        mock_assistant.summarize.return_value = "AI generated summary"

        data_dict = {"target": "example.com", "severity": "high"}

        with patch(
            "redops.modules.ai_assistant.AIAssistant", return_value=mock_assistant
        ):
            result = summarize(data_dict)

        assert result == "AI generated summary"
        call_args = mock_assistant.summarize.call_args[0][0]
        assert call_args == data_dict

    def test_summarize_fallback_truncation_long_data(self):
        """Test summarize falls back to truncation when AI not available."""
        from redops.modules.ai_summarizer import summarize

        long_data = "x" * 500

        with patch(
            "redops.modules.ai_assistant.AIAssistant",
            side_effect=ValueError("No API key"),
        ):
            result = summarize(long_data)

        assert len(result) == 403  # 400 + "..."
        assert result.endswith("...")

    def test_summarize_fallback_short_data(self):
        """Test summarize returns short data as-is when AI not available."""
        from redops.modules.ai_summarizer import summarize

        short_data = "short data"

        with patch(
            "redops.modules.ai_assistant.AIAssistant",
            side_effect=ValueError("No API key"),
        ):
            result = summarize(short_data)

        assert result == "short data"

    def test_summarize_fallback_on_import_error(self):
        """Test summarize falls back when AIAssistant import fails."""
        from redops.modules.ai_summarizer import summarize

        with patch(
            "redops.modules.ai_assistant.AIAssistant",
            side_effect=ImportError("No module"),
        ):
            result = summarize("test data")

        assert result == "test data"

    def test_summarize_with_custom_prompt(self):
        """Test summarize with custom prompt (prompt is accepted but not used directly)."""
        from redops.modules.ai_summarizer import summarize

        mock_assistant = MagicMock()
        mock_assistant.summarize.return_value = "Custom summary"

        with patch(
            "redops.modules.ai_assistant.AIAssistant", return_value=mock_assistant
        ):
            result = summarize("data", prompt="Custom prompt:")

        assert result == "Custom summary"

    def test_summarize_invalid_json_string(self):
        """Test summarize with invalid JSON string falls back to raw_data."""
        from redops.modules.ai_summarizer import summarize

        mock_assistant = MagicMock()
        mock_assistant.summarize.return_value = "Summary"

        invalid_json = "{not valid json"

        with patch(
            "redops.modules.ai_assistant.AIAssistant", return_value=mock_assistant
        ):
            summarize(invalid_json)

        call_args = mock_assistant.summarize.call_args[0][0]
        assert call_args == {"raw_data": invalid_json}


class TestAnalyze:
    """Tests for analyze function."""

    def test_analyze_with_ai_string_data(self):
        """Test analyze with AI assistant and string data."""
        from redops.modules.ai_summarizer import analyze

        mock_assistant = MagicMock()
        mock_assistant.analyze_findings.return_value = "AI analysis result"

        with patch(
            "redops.modules.ai_assistant.AIAssistant", return_value=mock_assistant
        ):
            result = analyze("some security data")

        assert result == "AI analysis result"
        mock_assistant.analyze_findings.assert_called_once()
        call_args = mock_assistant.analyze_findings.call_args[0][0]
        assert call_args == {"raw_data": "some security data"}

    def test_analyze_with_ai_json_string(self):
        """Test analyze with AI assistant and JSON string data."""
        from redops.modules.ai_summarizer import analyze

        mock_assistant = MagicMock()
        mock_assistant.analyze_findings.return_value = "AI analysis"

        json_data = '{"vulnerabilities": [{"severity": "critical"}]}'

        with patch(
            "redops.modules.ai_assistant.AIAssistant", return_value=mock_assistant
        ):
            result = analyze(json_data)

        assert result == "AI analysis"
        call_args = mock_assistant.analyze_findings.call_args[0][0]
        assert call_args == {"vulnerabilities": [{"severity": "critical"}]}

    def test_analyze_with_ai_dict_data(self):
        """Test analyze with AI assistant and dict data."""
        from redops.modules.ai_summarizer import analyze

        mock_assistant = MagicMock()
        mock_assistant.analyze_findings.return_value = "Dict analysis"

        data_dict = {"scan_results": {"open_ports": [22, 80, 443]}}

        with patch(
            "redops.modules.ai_assistant.AIAssistant", return_value=mock_assistant
        ):
            result = analyze(data_dict)

        assert result == "Dict analysis"
        call_args = mock_assistant.analyze_findings.call_args[0][0]
        assert call_args == data_dict

    def test_analyze_fallback_to_summarize(self):
        """Test analyze falls back to summarize when AI not available."""
        from redops.modules.ai_summarizer import analyze

        with patch(
            "redops.modules.ai_assistant.AIAssistant",
            side_effect=ValueError("No API key"),
        ):
            result = analyze("short data")

        # Falls back to summarize which returns data as-is if short
        assert result == "short data"

    def test_analyze_fallback_truncates_long_data(self):
        """Test analyze fallback truncates long data."""
        from redops.modules.ai_summarizer import analyze

        long_data = "y" * 500

        with patch(
            "redops.modules.ai_assistant.AIAssistant",
            side_effect=ValueError("No API key"),
        ):
            result = analyze(long_data)

        assert len(result) == 403
        assert result.endswith("...")

    def test_analyze_fallback_on_import_error(self):
        """Test analyze falls back when AIAssistant import fails."""
        from redops.modules.ai_summarizer import analyze

        with patch(
            "redops.modules.ai_assistant.AIAssistant",
            side_effect=ImportError("No module"),
        ):
            result = analyze("test data")

        assert result == "test data"

    def test_analyze_with_custom_prompt(self):
        """Test analyze with custom prompt."""
        from redops.modules.ai_summarizer import analyze

        mock_assistant = MagicMock()
        mock_assistant.analyze_findings.return_value = "Analysis"

        with patch(
            "redops.modules.ai_assistant.AIAssistant", return_value=mock_assistant
        ):
            result = analyze("data", prompt="Analyze this:")

        assert result == "Analysis"

    def test_analyze_invalid_json_string(self):
        """Test analyze with invalid JSON string."""
        from redops.modules.ai_summarizer import analyze

        mock_assistant = MagicMock()
        mock_assistant.analyze_findings.return_value = "Analysis"

        invalid_json = "not json at all"

        with patch(
            "redops.modules.ai_assistant.AIAssistant", return_value=mock_assistant
        ):
            analyze(invalid_json)

        call_args = mock_assistant.analyze_findings.call_args[0][0]
        assert call_args == {"raw_data": invalid_json}


class TestExplain:
    """Tests for explain function."""

    def test_explain_simple_query(self):
        """Test explain with simple query and no context."""
        from redops.modules.ai_summarizer import explain

        mock_assistant = MagicMock()
        mock_assistant.explain.return_value = (
            "SQL injection is a code injection technique..."
        )

        with patch(
            "redops.modules.ai_assistant.AIAssistant", return_value=mock_assistant
        ):
            result = explain("What is SQL injection?")

        assert result == "SQL injection is a code injection technique..."
        mock_assistant.explain.assert_called_once_with(
            "What is SQL injection?", context=None
        )

    def test_explain_with_json_context(self):
        """Test explain with JSON context string."""
        from redops.modules.ai_summarizer import explain

        mock_assistant = MagicMock()
        mock_assistant.explain.return_value = "Explanation with context"

        context_json = '{"cve": "CVE-2021-44228", "severity": "critical"}'

        with patch(
            "redops.modules.ai_assistant.AIAssistant", return_value=mock_assistant
        ):
            result = explain("Explain this vulnerability", context=context_json)

        assert result == "Explanation with context"
        call_args = mock_assistant.explain.call_args
        assert call_args[0][0] == "Explain this vulnerability"
        assert call_args[1]["context"] == {
            "cve": "CVE-2021-44228",
            "severity": "critical",
        }

    def test_explain_with_plain_text_context(self):
        """Test explain with plain text context (not JSON)."""
        from redops.modules.ai_summarizer import explain

        mock_assistant = MagicMock()
        mock_assistant.explain.return_value = "Explanation"

        plain_context = "Found in production server logs"

        with patch(
            "redops.modules.ai_assistant.AIAssistant", return_value=mock_assistant
        ):
            result = explain("What does this mean?", context=plain_context)

        assert result == "Explanation"
        call_args = mock_assistant.explain.call_args
        assert call_args[1]["context"] == {"context": plain_context}

    def test_explain_fallback_on_value_error(self):
        """Test explain returns error message when AI not available."""
        from redops.modules.ai_summarizer import explain

        with patch(
            "redops.modules.ai_assistant.AIAssistant",
            side_effect=ValueError("No API key"),
        ):
            result = explain("What is XSS?")

        assert "AI explanation not available" in result
        assert "No API key" in result

    def test_explain_fallback_on_import_error(self):
        """Test explain returns error message when import fails."""
        from redops.modules.ai_summarizer import explain

        with patch(
            "redops.modules.ai_assistant.AIAssistant",
            side_effect=ImportError("Module not found"),
        ):
            result = explain("Explain CSRF")

        assert "AI explanation not available" in result

    def test_explain_with_none_context(self):
        """Test explain with explicitly None context."""
        from redops.modules.ai_summarizer import explain

        mock_assistant = MagicMock()
        mock_assistant.explain.return_value = "Explanation"

        with patch(
            "redops.modules.ai_assistant.AIAssistant", return_value=mock_assistant
        ):
            result = explain("What is SSRF?", context=None)

        assert result == "Explanation"
        call_args = mock_assistant.explain.call_args
        assert call_args[1]["context"] is None

    def test_explain_with_empty_context(self):
        """Test explain with empty string context."""
        from redops.modules.ai_summarizer import explain

        mock_assistant = MagicMock()
        mock_assistant.explain.return_value = "Explanation"

        with patch(
            "redops.modules.ai_assistant.AIAssistant", return_value=mock_assistant
        ):
            # Empty string is falsy, so context_dict stays None
            result = explain("What is RCE?", context="")

        assert result == "Explanation"
        call_args = mock_assistant.explain.call_args
        assert call_args[1]["context"] is None


class TestEdgeCases:
    """Tests for edge cases and boundary conditions."""

    def test_summarize_exactly_400_chars(self):
        """Test summarize with exactly 400 characters (boundary)."""
        from redops.modules.ai_summarizer import summarize

        data_400 = "a" * 400

        with patch(
            "redops.modules.ai_assistant.AIAssistant", side_effect=ValueError("No key")
        ):
            result = summarize(data_400)

        # Exactly 400, no truncation
        assert result == data_400
        assert len(result) == 400

    def test_summarize_401_chars_truncates(self):
        """Test summarize with 401 characters truncates."""
        from redops.modules.ai_summarizer import summarize

        data_401 = "b" * 401

        with patch(
            "redops.modules.ai_assistant.AIAssistant", side_effect=ValueError("No key")
        ):
            result = summarize(data_401)

        assert len(result) == 403  # 400 + "..."
        assert result.endswith("...")

    def test_summarize_empty_string(self):
        """Test summarize with empty string."""
        from redops.modules.ai_summarizer import summarize

        with patch(
            "redops.modules.ai_assistant.AIAssistant", side_effect=ValueError("No key")
        ):
            result = summarize("")

        assert result == ""

    def test_analyze_empty_dict(self):
        """Test analyze with empty dict."""
        from redops.modules.ai_summarizer import analyze

        mock_assistant = MagicMock()
        mock_assistant.analyze_findings.return_value = "No findings"

        with patch(
            "redops.modules.ai_assistant.AIAssistant", return_value=mock_assistant
        ):
            result = analyze({})

        assert result == "No findings"
        call_args = mock_assistant.analyze_findings.call_args[0][0]
        assert call_args == {}

    def test_summarize_list_data(self):
        """Test summarize with list data (non-string, non-dict)."""
        from redops.modules.ai_summarizer import summarize

        mock_assistant = MagicMock()
        mock_assistant.summarize.return_value = "List summary"

        list_data = [{"finding": 1}, {"finding": 2}]

        with patch(
            "redops.modules.ai_assistant.AIAssistant", return_value=mock_assistant
        ):
            result = summarize(list_data)

        assert result == "List summary"
        call_args = mock_assistant.summarize.call_args[0][0]
        assert call_args == list_data

    def test_analyze_list_data(self):
        """Test analyze with list data."""
        from redops.modules.ai_summarizer import analyze

        mock_assistant = MagicMock()
        mock_assistant.analyze_findings.return_value = "List analysis"

        list_data = [{"vuln": "xss"}, {"vuln": "sqli"}]

        with patch(
            "redops.modules.ai_assistant.AIAssistant", return_value=mock_assistant
        ):
            result = analyze(list_data)

        assert result == "List analysis"
        call_args = mock_assistant.analyze_findings.call_args[0][0]
        assert call_args == list_data

    def test_explain_complex_json_context(self):
        """Test explain with complex nested JSON context."""
        from redops.modules.ai_summarizer import explain

        mock_assistant = MagicMock()
        mock_assistant.explain.return_value = "Complex explanation"

        complex_context = json.dumps(
            {
                "scan": {
                    "target": "example.com",
                    "findings": [
                        {"type": "xss", "severity": "high"},
                        {"type": "sqli", "severity": "critical"},
                    ],
                }
            }
        )

        with patch(
            "redops.modules.ai_assistant.AIAssistant", return_value=mock_assistant
        ):
            result = explain("Summarize these findings", context=complex_context)

        assert result == "Complex explanation"
        call_args = mock_assistant.explain.call_args[1]["context"]
        assert "scan" in call_args
        assert len(call_args["scan"]["findings"]) == 2
