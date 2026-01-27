"""RedOPS Web UI - FastAPI-based dashboard and API."""

try:
    from redops.web.app import create_app

    __all__ = ["create_app"]
except ImportError:
    # FastAPI not installed
    create_app = None
    __all__ = []
