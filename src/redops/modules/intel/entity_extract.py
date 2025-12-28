"""
Entity extraction module.

Extracts entities (organizations, people, locations, etc.) from text and data.
"""

from typing import Optional, Dict, Any, List
from redops.core.context import Context


def extract_entities(ctx: Context, params: Optional[Dict[str, Any]] = None) -> Context:
    """
    Extract entities from context data.

    Args:
        ctx: Pipeline context
        params: Optional parameters

    Returns:
        Updated context
    """
    params = params or {}

    ctx.log("Extracting entities from context data", level="INFO")

    entities = {
        "organizations": [],
        "people": [],
        "locations": [],
        "technologies": [],
        "emails": [],
        "urls": [],
    }

    # Placeholder: Real implementation would use NLP libraries like:
    # - spaCy for named entity recognition
    # - NLTK for text processing
    # - Regular expressions for structured data

    ctx.add("entities", entities)
    ctx.log("Entity extraction completed (placeholder)", level="INFO")

    return ctx


def extract_from_text(text: str) -> Dict[str, List[str]]:
    """
    Extract entities from a text string.

    Args:
        text: Text to analyze

    Returns:
        Dictionary of extracted entities
    """
    import re

    entities = {
        "organizations": [],
        "people": [],
        "locations": [],
        "technologies": [],
        "emails": [],
        "urls": [],
    }

    # Email extraction
    email_pattern = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
    entities["emails"] = re.findall(email_pattern, text)

    # URL extraction
    url_pattern = r"http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+"
    entities["urls"] = re.findall(url_pattern, text)

    return entities
