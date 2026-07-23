"""Tests for the Context module."""

import pytest
from redops.core.context import Context


def test_context_initialization():
    """Test Context initialization with target."""
    ctx = Context(target="example.com")
    assert ctx.target == "example.com"
    assert isinstance(ctx.data, dict)
    assert isinstance(ctx.logs, list)
    assert "created_at" in ctx.metadata
    assert ctx.metadata["target"] == "example.com"


def test_context_initialization_no_target():
    """Test Context initialization without target."""
    ctx = Context()
    assert ctx.target is None
    assert len(ctx.data) == 0
    assert len(ctx.logs) == 0


def test_context_add_data():
    """Test adding data to context."""
    ctx = Context(target="test.com")
    ctx.add("key1", "value1")
    ctx.add("key2", {"nested": "data"})

    assert ctx.data["key1"] == "value1"
    assert ctx.data["key2"]["nested"] == "data"
    assert len(ctx.data) == 2


def test_context_get_data():
    """Test retrieving data from context."""
    ctx = Context()
    ctx.add("test_key", "test_value")

    assert ctx.get("test_key") == "test_value"
    assert ctx.get("nonexistent") is None
    assert ctx.get("nonexistent", "default") == "default"


def test_context_logging():
    """Test logging functionality."""
    ctx = Context(target="test.com")

    ctx.log("Info message", level="INFO")
    ctx.log("Warning message", level="WARNING")
    ctx.log("Error message", level="ERROR")

    assert len(ctx.logs) == 3
    assert ctx.logs[0]["level"] == "INFO"
    assert ctx.logs[1]["level"] == "WARNING"
    assert ctx.logs[2]["level"] == "ERROR"
    assert "timestamp" in ctx.logs[0]


def test_context_get_logs_filtered():
    """Test filtering logs by level."""
    ctx = Context()

    ctx.log("Info 1", level="INFO")
    ctx.log("Warning 1", level="WARNING")
    ctx.log("Info 2", level="INFO")
    ctx.log("Error 1", level="ERROR")

    info_logs = ctx.get_logs(level="INFO")
    warning_logs = ctx.get_logs(level="WARNING")
    error_logs = ctx.get_logs(level="ERROR")

    assert len(info_logs) == 2
    assert len(warning_logs) == 1
    assert len(error_logs) == 1


def test_context_get_all_logs():
    """Test getting all logs without filter."""
    ctx = Context()

    ctx.log("Message 1", level="INFO")
    ctx.log("Message 2", level="WARNING")

    all_logs = ctx.get_logs()
    assert len(all_logs) == 2


def test_context_to_dict():
    """Test converting context to dictionary."""
    ctx = Context(target="example.com")
    ctx.add("data_key", "data_value")
    ctx.log("Test log", level="INFO")

    ctx_dict = ctx.to_dict()

    assert "target" in ctx_dict
    assert "metadata" in ctx_dict
    assert "data" in ctx_dict
    assert "logs" in ctx_dict
    assert ctx_dict["target"] == "example.com"
    assert ctx_dict["data"]["data_key"] == "data_value"
    # Note: .add() creates a DEBUG log, so we expect at least 2 logs
    assert len(ctx_dict["logs"]) >= 1


def test_context_to_json():
    """Test converting context to JSON."""
    ctx = Context(target="test.com")
    ctx.add("key", "value")

    json_str = ctx.to_json()

    assert isinstance(json_str, str)
    assert "test.com" in json_str
    assert "key" in json_str
    assert "value" in json_str


def test_context_repr():
    """Test Context string representation."""
    ctx = Context(target="example.com")
    ctx.add("key1", "value1")
    ctx.add("key2", "value2")

    repr_str = repr(ctx)

    assert "Context" in repr_str
    assert "example.com" in repr_str
    assert "key1" in repr_str
    assert "key2" in repr_str


def test_context_log_with_metadata():
    """Test logging with additional metadata."""
    ctx = Context()
    ctx.log("Test message", level="INFO", module="test_module", step=1)

    log_entry = ctx.logs[0]
    assert log_entry["message"] == "Test message"
    assert log_entry["level"] == "INFO"
    assert log_entry["module"] == "test_module"
    assert log_entry["step"] == 1


def test_context_data_persistence():
    """Test that data persists across operations."""
    ctx = Context(target="persistence_test")

    # Add initial data
    ctx.add("counter", 1)
    assert ctx.get("counter") == 1

    # Update data
    ctx.add("counter", 2)
    assert ctx.get("counter") == 2

    # Add more data
    ctx.add("list", [1, 2, 3])
    assert ctx.get("counter") == 2
    assert ctx.get("list") == [1, 2, 3]


def test_context_save_creates_checkpoint():
    """Test that save() creates a deep-copy checkpoint."""
    ctx = Context(target="test.com")
    ctx.add("key", "value")
    initial_logs = len(ctx.logs)

    ctx.save()
    assert len(ctx._checkpoints) == 1

    # Mutate data after save
    ctx.add("key", "mutated")
    assert ctx.get("key") == "mutated"

    # Rollback should restore data but preserve logs (audit trail)
    ctx.rollback()
    assert ctx.get("key") == "value"
    assert len(ctx._checkpoints) == 0

    # Logs are preserved (not rolled back) — should include post-save logs plus rollback log
    rollback_logs = [log for log in ctx.logs if "rolled back" in log.get("message", "")]
    assert len(rollback_logs) == 1
    # The add log and rollback log should both be present
    assert any("Added data to context" in log.get("message", "") for log in ctx.logs)


def test_context_rollback_no_checkpoint_raises():
    """Test that rollback without save raises RuntimeError."""
    ctx = Context()
    with pytest.raises(RuntimeError, match="No checkpoints available"):
        ctx.rollback()


def test_context_nested_save_rollback():
    """Test nested save/rollback (stack behavior)."""
    ctx = Context()
    ctx.add("a", 1)
    ctx.save()  # checkpoint 1

    ctx.add("b", 2)
    ctx.save()  # checkpoint 2

    ctx.add("c", 3)
    assert ctx.get("a") == 1
    assert ctx.get("b") == 2
    assert ctx.get("c") == 3

    # Rollback to checkpoint 2
    ctx.rollback()
    assert ctx.get("a") == 1
    assert ctx.get("b") == 2
    assert ctx.get("c") is None

    # Rollback to checkpoint 1
    ctx.rollback()
    assert ctx.get("a") == 1
    assert ctx.get("b") is None
    assert ctx.get("c") is None


def test_context_clear_checkpoints():
    """Test clearing all checkpoints."""
    ctx = Context()
    ctx.save()
    ctx.save()
    assert len(ctx._checkpoints) == 2

    ctx.clear_checkpoints()
    assert len(ctx._checkpoints) == 0


def test_context_checkpoint_is_deep_copy():
    """Test that checkpoints are deep copies, not references."""
    ctx = Context()
    ctx.add("nested", {"inner": [1, 2]})
    ctx.save()

    # Mutate nested structure
    ctx.data["nested"]["inner"].append(3)
    assert ctx.data["nested"]["inner"] == [1, 2, 3]

    # Rollback should restore original nested structure
    ctx.rollback()
    assert ctx.data["nested"]["inner"] == [1, 2]
