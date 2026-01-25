from unittest.mock import patch, MagicMock

from redops.modules.ai_summarizer import summarize


def test_summarize_short():
    """Test summarize with short data returns meaningful content."""
    data = "Alert: Critical vulnerability found in server X."
    # Mock AI to test fallback
    with patch("redops.modules.ai_assistant.AIAssistant", side_effect=ValueError("No API key")):
        summary = summarize(data)
        assert "vulnerability" in summary.lower() or "alert" in summary.lower()


def test_summarize_long():
    """Test summarize with long data truncates in fallback mode."""
    data = "Alert " + ("A" * 500)
    # Mock AI to test fallback truncation
    with patch("redops.modules.ai_assistant.AIAssistant", side_effect=ValueError("No API key")):
        summary = summarize(data)
        assert summary.endswith("...")
        assert len(summary) == 403  # 400 chars + "..."


def test_summarize_with_ai():
    """Test summarize uses AI when available."""
    data = "Alert: Test vulnerability"
    mock_instance = MagicMock()
    mock_instance.summarize.return_value = "AI generated summary"
    with patch("redops.modules.ai_assistant.AIAssistant", return_value=mock_instance):
        summary = summarize(data)
        assert summary == "AI generated summary"
        mock_instance.summarize.assert_called_once()
