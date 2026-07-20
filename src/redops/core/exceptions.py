"""RedOPS domain-specific exceptions.

Provides a unified exception hierarchy so callers can distinguish between
configuration errors, network failures, auth problems, and validation issues
instead of catching bare ``Exception``.
"""


class RedOpsError(Exception):
    """Base exception for all RedOPS errors."""

    pass


# ---------------------------------------------------------------------------
# Configuration / environment
# ---------------------------------------------------------------------------


class ConfigurationError(RedOpsError):
    """Missing or invalid configuration."""

    pass


class SecretNotFoundError(ConfigurationError):
    """Required secret or environment variable is missing."""

    pass


# ---------------------------------------------------------------------------
# Network / I/O
# ---------------------------------------------------------------------------


class NetworkError(RedOpsError):
    """Transient or permanent network failure."""

    pass


class APIClientError(NetworkError):
    """Error while communicating with an external API."""

    pass


class RateLimitError(NetworkError):
    """Request blocked by rate limiting."""

    pass


class CircuitOpenError(NetworkError):
    """Circuit breaker is open; requests are not being sent."""

    pass


# ---------------------------------------------------------------------------
# Authentication / authorization
# ---------------------------------------------------------------------------


class AuthError(RedOpsError):
    """Base for authentication and authorization failures."""

    pass


class AuthenticationError(AuthError):
    """Invalid credentials or missing authentication."""

    pass


class AuthorizationError(AuthError):
    """Authenticated user lacks permission."""

    pass


class TokenExpiredError(AuthenticationError):
    """Token has expired."""

    pass


class TokenInvalidError(AuthenticationError):
    """Token is malformed or signature verification failed."""

    pass


class SessionNotFoundError(AuthenticationError):
    """Session does not exist or has been invalidated."""

    pass


# ---------------------------------------------------------------------------
# Validation / data quality
# ---------------------------------------------------------------------------


class ValidationError(RedOpsError):
    """Input data failed validation."""

    pass


class SchemaError(ValidationError):
    """Data does not conform to expected schema."""

    pass


# ---------------------------------------------------------------------------
# Pipeline / module execution
# ---------------------------------------------------------------------------


class PipelineError(RedOpsError):
    """Error during pipeline execution."""

    pass


class ModuleError(PipelineError):
    """Error in a specific pipeline module."""

    pass


class ModuleNotFoundError(ModuleError):
    """Requested module could not be resolved."""

    pass


# ---------------------------------------------------------------------------
# Storage / caching
# ---------------------------------------------------------------------------


class StorageError(RedOpsError):
    """Database, file-system, or cache operation failed."""

    pass


class CacheError(StorageError):
    """Cache read/write failed."""

    pass


# ---------------------------------------------------------------------------
# AI / LLM
# ---------------------------------------------------------------------------


class AIError(RedOpsError):
    """Error during AI model interaction."""

    pass


class AIBudgetExceededError(AIError):
    """Cost or token budget has been exceeded."""

    pass


class AIPromptError(AIError):
    """Prompt generation or validation failed."""

    pass
