def summarize(data: str, prompt: str = "Summarize the following security data:") -> str:
    """
    Uses a cloud LLM or local model to summarize output.
    Integrates with OpenAI or Anthropic via the AI Assistant module.
    Falls back to truncation if no API key is configured.
    """
    try:
        from redops.modules.ai_assistant import AIAssistant

        assistant = AIAssistant()

        # If data is a string, try to parse as JSON
        if isinstance(data, str):
            try:
                import json
                data_dict = json.loads(data)
            except (json.JSONDecodeError, TypeError):
                # Use as-is if not valid JSON
                data_dict = {"raw_data": data}
        else:
            data_dict = data

        # Use AI to summarize
        return assistant.summarize(data_dict)

    except (ImportError, ValueError) as e:
        # Fallback: No AI configured, use simple truncation
        if len(data) > 400:
            return data[:400] + "..."
        return data


def analyze(data: str, prompt: str = "Analyze the following security data:") -> str:
    """
    Uses AI to analyze security data and provide insights.
    Falls back to basic summary if no API key is configured.
    """
    try:
        from redops.modules.ai_assistant import AIAssistant

        assistant = AIAssistant()

        if isinstance(data, str):
            try:
                import json
                data_dict = json.loads(data)
            except (json.JSONDecodeError, TypeError):
                data_dict = {"raw_data": data}
        else:
            data_dict = data

        return assistant.analyze_findings(data_dict)

    except (ImportError, ValueError):
        return summarize(data, prompt)


def explain(query: str, context: str = None) -> str:
    """
    Uses AI to explain a security concept or finding.
    """
    try:
        from redops.modules.ai_assistant import AIAssistant

        assistant = AIAssistant()

        context_dict = None
        if context:
            try:
                import json
                context_dict = json.loads(context)
            except (json.JSONDecodeError, TypeError):
                context_dict = {"context": context}

        return assistant.explain(query, context=context_dict)

    except (ImportError, ValueError) as e:
        return f"AI explanation not available: {e}"
