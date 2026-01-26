"""
RedOPS API Module.

Provides RESTful API access to RedOPS functionality.
"""

# Legacy basic API server
from redops.api.server import (
    APIError,
    APIRequest,
    APIResponse,
    APIServer,
    HTTPMethod,
    HTTPStatus,
    Route,
    Router,
    create_api_server,
    run_api_server,
)

# FastAPI application
from redops.api.app import create_app, app
from redops.api.deps import get_db, get_current_user

__all__ = [
    # Legacy server
    "APIError",
    "APIRequest",
    "APIResponse",
    "APIServer",
    "HTTPMethod",
    "HTTPStatus",
    "Route",
    "Router",
    "create_api_server",
    "run_api_server",
    # FastAPI
    "create_app",
    "app",
    "get_db",
    "get_current_user",
]
