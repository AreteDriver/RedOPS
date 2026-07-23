"""Exceptions for the active/offensive module gate."""


class ActiveAuthorizationError(Exception):
    """Raised when an active/offensive module runs without recorded operator consent."""

    pass


class EgressBlockedError(Exception):
    """Raised when an active module attempts external egress to a non-local URL."""

    pass
