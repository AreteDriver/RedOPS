import os

# Set test environment before any redops imports
os.environ.setdefault("REDOPS_TESTING", "true")
os.environ.setdefault("REDOPS_JWT_SECRET", "test-secret-for-pytest-only")

import pytest
from redops.core.context import Context


@pytest.fixture
def basic_context():
    return Context(target="example.com")
