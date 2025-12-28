
def summarize(data: str, prompt: str = "Summarize the following security data:") -> str:
    """
    Uses a cloud LLM or local model to summarize output.
    Modify this stub to integrate with your preferred AI provider (OpenAI, HuggingFace, etc.)
    """
    # Example: AI integration stub
    # import openai
    # openai.api_key = os.getenv("OPENAI_API_KEY")
    #
    # response = openai.Completion.create(
    #     model="gpt-3.5-turbo",
    #     prompt=f"{prompt}\n\n{data}",
    #     max_tokens=128
    # )
    # summary = response["choices"][0]["text"].strip()
    # return summary

    # For development, just truncate data and return
    if len(data) > 400:
        return data[:400] + "..."
    return data
