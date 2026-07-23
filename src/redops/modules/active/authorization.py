"""Authorization gate for active/offensive modules.

Requires recorded operator consent + authorized-target assertion before
any module under ``modules/active/`` can execute.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

from pydantic import BaseModel, Field

from redops.modules.active.exceptions import ActiveAuthorizationError

if TYPE_CHECKING:
    from redops.core.context import Context


class ActiveAuthorization(BaseModel):
    """Recorded operator consent for active/offensive operations.

    Attributes:
        authorization_id: Unique identifier for this authorization.
        operator: Identity of the operator giving consent.
        target_assertion: The specific target(s) this authorization covers.
        consent_text: The exact text the operator agreed to.
        consent_timestamp: When consent was recorded.
        expires_at: When this authorization expires.
    """

    authorization_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    operator: str
    target_assertion: str
    consent_text: str
    consent_timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    expires_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc) + timedelta(hours=24)
    )

    def is_expired(self) -> bool:
        """Return True if this authorization has expired."""
        return datetime.now(timezone.utc) > self.expires_at

    def is_valid(self) -> bool:
        """Return True if authorization is present and not expired."""
        return not self.is_expired()


DEFAULT_CONSENT_TEXT = (
    "I am authorized to perform active security testing on the stated target. "
    "This is my own network, a designated lab environment, or a system for which "
    "I have explicit written permission. I understand that active modules can "
    "disrupt network services and may violate laws if used without authorization."
)


def record_authorization(
    ctx: Context,
    operator: str,
    target_assertion: str,
    consent_text: str = DEFAULT_CONSENT_TEXT,
    duration_hours: float = 24,
) -> ActiveAuthorization:
    """Record operator consent in the pipeline context.

    Args:
        ctx: Pipeline context to store authorization in.
        operator: Identity of the operator (e.g. name, employee ID).
        target_assertion: Specific target this authorization covers
            (e.g. "192.168.99.0/24", "my-home-lab").
        consent_text: The consent text the operator acknowledged.
        duration_hours: How long the authorization remains valid.

    Returns:
        The created ActiveAuthorization instance.
    """
    auth = ActiveAuthorization(
        operator=operator,
        target_assertion=target_assertion,
        consent_text=consent_text,
        expires_at=datetime.now(timezone.utc) + timedelta(hours=duration_hours),
    )
    ctx.authorization = auth
    ctx.log(
        f"Active authorization recorded: {auth.authorization_id} "
        f"for operator={operator} target={target_assertion}",
        level="AUDIT",
    )
    return auth


def is_active_authorized(ctx: Context) -> bool:
    """Check whether the context carries a valid active authorization.

    Args:
        ctx: Pipeline context.

    Returns:
        True if a non-expired authorization is present, False otherwise.
    """
    auth = getattr(ctx, "authorization", None)
    if auth is None:
        return False
    if isinstance(auth, ActiveAuthorization):
        return auth.is_valid()
    return False


def record_authorization_from_params(
    ctx: Context,
    params: dict | None = None,
) -> Context:
    """Pipeline-step wrapper for ``record_authorization``.

    Accepts parameters via the ``params`` dict so it can be invoked from a
    pipeline JSON definition.

    Params:
        operator: Identity of the operator.
        target_assertion: Specific target being authorized.
        consent_text: Optional custom consent text.
        duration_hours: How long the authorization remains valid.

    Returns:
        The updated context with ``ctx.authorization`` set.
    """
    params = params or {}
    record_authorization(
        ctx,
        operator=params.get("operator", "unknown-operator"),
        target_assertion=params.get("target_assertion", ctx.target or "unknown"),
        consent_text=params.get("consent_text", DEFAULT_CONSENT_TEXT),
        duration_hours=params.get("duration_hours", 24),
    )
    return ctx


def assert_active_authorized(ctx: Context) -> None:
    """Raise ActiveAuthorizationError if the context lacks valid authorization.

    Every function under ``modules/active/`` must call this at entry.

    Args:
        ctx: Pipeline context.

    Raises:
        ActiveAuthorizationError: If no valid authorization is present.
    """
    auth = getattr(ctx, "authorization", None)
    if auth is None:
        raise ActiveAuthorizationError(
            "Active module refused: no operator authorization recorded. "
            "Call record_authorization() before executing active modules."
        )
    if isinstance(auth, ActiveAuthorization) and auth.is_expired():
        raise ActiveAuthorizationError(
            f"Active module refused: authorization {auth.authorization_id} "
            f"expired at {auth.expires_at.isoformat()}."
        )
    if not isinstance(auth, ActiveAuthorization):
        raise ActiveAuthorizationError(
            "Active module refused: authorization object is malformed."
        )
