"""Tests for the unified exception hierarchy."""

import pytest

from redops.core.exceptions import (
    RedOpsError,
    ConfigurationError,
    SecretNotFoundError,
    NetworkError,
    APIClientError,
    RateLimitError,
    CircuitOpenError,
    AuthError,
    AuthenticationError,
    AuthorizationError,
    TokenExpiredError,
    TokenInvalidError,
    SessionNotFoundError,
    ValidationError,
    SchemaError,
    PipelineError,
    ModuleError,
    ModuleNotFoundError,
    StorageError,
    CacheError,
    AIError,
    AIBudgetExceededError,
    AIPromptError,
)


class TestExceptionHierarchy:
    """Verify the exception inheritance tree."""

    @pytest.mark.parametrize(
        "exc_class,expected_parent",
        [
            (ConfigurationError, RedOpsError),
            (SecretNotFoundError, ConfigurationError),
            (NetworkError, RedOpsError),
            (APIClientError, NetworkError),
            (RateLimitError, NetworkError),
            (CircuitOpenError, NetworkError),
            (AuthError, RedOpsError),
            (AuthenticationError, AuthError),
            (AuthorizationError, AuthError),
            (TokenExpiredError, AuthenticationError),
            (TokenInvalidError, AuthenticationError),
            (SessionNotFoundError, AuthenticationError),
            (ValidationError, RedOpsError),
            (SchemaError, ValidationError),
            (PipelineError, RedOpsError),
            (ModuleError, PipelineError),
            (ModuleNotFoundError, ModuleError),
            (StorageError, RedOpsError),
            (CacheError, StorageError),
            (AIError, RedOpsError),
            (AIBudgetExceededError, AIError),
            (AIPromptError, AIError),
        ],
    )
    def test_inheritance(self, exc_class, expected_parent):
        assert issubclass(exc_class, expected_parent)

    def test_all_are_redops_errors(self):
        classes = [
            ConfigurationError,
            NetworkError,
            AuthError,
            ValidationError,
            PipelineError,
            StorageError,
            AIError,
        ]
        for cls in classes:
            assert issubclass(cls, RedOpsError)

    def test_redops_error_is_builtin_exception(self):
        assert issubclass(RedOpsError, Exception)

    def test_can_catch_subclass_with_parent(self):
        with pytest.raises(AuthError):
            raise AuthenticationError("bad creds")

        with pytest.raises(NetworkError):
            raise RateLimitError("slow down")

    def test_message_preserved(self):
        msg = "something went wrong"
        try:
            raise PipelineError(msg)
        except RedOpsError as e:
            assert str(e) == msg

    def test_exception_attributes(self):
        e = APIClientError("timeout")
        assert e.args[0] == "timeout"
