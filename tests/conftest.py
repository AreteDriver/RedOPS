import pytest
from redops.core.context import Context

@pytest.fixture
def basic_context():
    return Context(target="example.com")
