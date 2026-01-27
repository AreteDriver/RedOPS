"""Tests for the BaseModule and ModuleRegistry classes."""

import pytest
from redops.core.context import Context
from redops.core.module_base import BaseModule, ModuleRegistry


class ConcreteModule(BaseModule):
    """Concrete implementation of BaseModule for testing."""

    def execute(self, ctx, params=None):
        """Simple execute implementation that adds data to context."""
        ctx.add("executed", True)
        if params:
            ctx.add("params", params)
        return ctx


class TestBaseModuleInit:
    """Tests for BaseModule initialization."""

    def test_init_with_default_name(self):
        """Test that default name uses class name."""
        module = ConcreteModule()
        assert module.name == "ConcreteModule"

    def test_init_with_custom_name(self):
        """Test that custom name overrides class name."""
        module = ConcreteModule(name="CustomName")
        assert module.name == "CustomName"

    def test_init_with_none_name_uses_class_name(self):
        """Test that None name falls back to class name."""
        module = ConcreteModule(name=None)
        assert module.name == "ConcreteModule"


class TestBaseModuleAbstract:
    """Tests for BaseModule abstract behavior."""

    def test_cannot_instantiate_base_module(self):
        """Test that BaseModule cannot be instantiated directly."""
        with pytest.raises(TypeError) as exc_info:
            BaseModule()

        assert "abstract" in str(exc_info.value).lower()

    def test_subclass_must_implement_execute(self):
        """Test that subclasses must implement execute method."""

        class IncompleteModule(BaseModule):
            pass

        with pytest.raises(TypeError) as exc_info:
            IncompleteModule()

        assert "abstract" in str(exc_info.value).lower()


class TestBaseModuleExecute:
    """Tests for BaseModule execute method."""

    def test_execute_returns_context(self):
        """Test that execute returns the context."""
        module = ConcreteModule()
        ctx = Context(target="example.com")

        result = module.execute(ctx)

        assert result is ctx
        assert ctx.data.get("executed") is True

    def test_execute_with_params(self):
        """Test execute with parameters."""
        module = ConcreteModule()
        ctx = Context(target="example.com")
        params = {"key": "value", "count": 42}

        result = module.execute(ctx, params=params)

        assert result is ctx
        assert ctx.data.get("params") == params

    def test_execute_without_params(self):
        """Test execute without parameters."""
        module = ConcreteModule()
        ctx = Context(target="example.com")

        module.execute(ctx)

        assert "params" not in ctx.data


class TestBaseModuleCallable:
    """Tests for BaseModule __call__ method."""

    def test_call_delegates_to_execute(self):
        """Test that __call__ delegates to execute."""
        module = ConcreteModule()
        ctx = Context(target="example.com")

        result = module(ctx)

        assert result is ctx
        assert ctx.data.get("executed") is True

    def test_call_with_params(self):
        """Test __call__ with parameters."""
        module = ConcreteModule()
        ctx = Context(target="example.com")
        params = {"option": "enabled"}

        module(ctx, params=params)

        assert ctx.data.get("params") == params

    def test_call_is_equivalent_to_execute(self):
        """Test that calling module directly is same as calling execute."""
        module = ConcreteModule()
        ctx1 = Context(target="test1.com")
        ctx2 = Context(target="test2.com")
        params = {"test": True}

        module.execute(ctx1, params)
        module(ctx2, params)

        assert ctx1.data == ctx2.data


class TestBaseModuleLogging:
    """Tests for BaseModule logging helper methods."""

    def test_log_info(self):
        """Test log_info helper method."""
        module = ConcreteModule(name="TestModule")
        ctx = Context(target="example.com")

        module.log_info(ctx, "Test message")

        logs = ctx.get_logs(level="INFO")
        assert len(logs) == 1
        assert "[TestModule] Test message" in logs[0]["message"]

    def test_log_warning(self):
        """Test log_warning helper method."""
        module = ConcreteModule(name="TestModule")
        ctx = Context(target="example.com")

        module.log_warning(ctx, "Warning message")

        logs = ctx.get_logs(level="WARNING")
        assert len(logs) == 1
        assert "[TestModule] Warning message" in logs[0]["message"]

    def test_log_error(self):
        """Test log_error helper method."""
        module = ConcreteModule(name="TestModule")
        ctx = Context(target="example.com")

        module.log_error(ctx, "Error message")

        logs = ctx.get_logs(level="ERROR")
        assert len(logs) == 1
        assert "[TestModule] Error message" in logs[0]["message"]

    def test_log_debug(self):
        """Test log_debug helper method."""
        module = ConcreteModule(name="TestModule")
        ctx = Context(target="example.com")

        module.log_debug(ctx, "Debug message")

        logs = ctx.get_logs(level="DEBUG")
        assert len(logs) == 1
        assert "[TestModule] Debug message" in logs[0]["message"]

    def test_log_with_kwargs(self):
        """Test logging with additional kwargs."""
        module = ConcreteModule(name="TestModule")
        ctx = Context(target="example.com")

        # The log method should accept kwargs
        module.log_info(ctx, "Message with data", extra_key="extra_value")

        logs = ctx.get_logs(level="INFO")
        assert len(logs) == 1

    def test_log_uses_module_name(self):
        """Test that log messages include the module name."""
        module1 = ConcreteModule(name="Module1")
        module2 = ConcreteModule(name="Module2")
        ctx = Context(target="example.com")

        module1.log_info(ctx, "From module 1")
        module2.log_info(ctx, "From module 2")

        logs = ctx.get_logs(level="INFO")
        assert "[Module1]" in logs[0]["message"]
        assert "[Module2]" in logs[1]["message"]


class TestModuleRegistry:
    """Tests for ModuleRegistry class."""

    def setup_method(self):
        """Clear the registry before each test."""
        ModuleRegistry._modules = {}

    def test_register_module(self):
        """Test registering a module."""
        module = ConcreteModule(name="TestModule")

        ModuleRegistry.register("test", module)

        assert "test" in ModuleRegistry._modules
        assert ModuleRegistry._modules["test"] is module

    def test_get_registered_module(self):
        """Test retrieving a registered module."""
        module = ConcreteModule(name="TestModule")
        ModuleRegistry.register("test", module)

        result = ModuleRegistry.get("test")

        assert result is module

    def test_get_nonexistent_module(self):
        """Test retrieving a module that doesn't exist."""
        result = ModuleRegistry.get("nonexistent")

        assert result is None

    def test_list_modules_empty(self):
        """Test listing modules when registry is empty."""
        result = ModuleRegistry.list_modules()

        assert result == []

    def test_list_modules_with_registered(self):
        """Test listing modules when some are registered."""
        module1 = ConcreteModule(name="Module1")
        module2 = ConcreteModule(name="Module2")
        ModuleRegistry.register("first", module1)
        ModuleRegistry.register("second", module2)

        result = ModuleRegistry.list_modules()

        assert len(result) == 2
        assert "first" in result
        assert "second" in result

    def test_register_overwrites_existing(self):
        """Test that registering with same name overwrites."""
        module1 = ConcreteModule(name="Module1")
        module2 = ConcreteModule(name="Module2")
        ModuleRegistry.register("test", module1)
        ModuleRegistry.register("test", module2)

        result = ModuleRegistry.get("test")

        assert result is module2
        assert len(ModuleRegistry.list_modules()) == 1

    def test_registry_is_class_level(self):
        """Test that registry is shared across all instances."""
        module = ConcreteModule(name="TestModule")
        ModuleRegistry.register("shared", module)

        # Access through class directly
        assert ModuleRegistry.get("shared") is module

        # Verify it's a class-level dict
        assert "shared" in ModuleRegistry._modules


class TestModuleIntegration:
    """Integration tests for BaseModule and ModuleRegistry."""

    def setup_method(self):
        """Clear the registry before each test."""
        ModuleRegistry._modules = {}

    def test_register_and_execute(self):
        """Test registering a module and executing it."""
        module = ConcreteModule(name="IntegrationModule")
        ModuleRegistry.register("integration", module)

        ctx = Context(target="example.com")
        registered_module = ModuleRegistry.get("integration")
        result = registered_module(ctx, params={"test": True})

        assert result is ctx
        assert ctx.data.get("executed") is True
        assert ctx.data.get("params") == {"test": True}

    def test_multiple_modules_in_sequence(self):
        """Test executing multiple registered modules in sequence."""

        class AddDataModule(BaseModule):
            def execute(self, ctx, params=None):
                key = params.get("key", "default")
                value = params.get("value", 0)
                ctx.add(key, value)
                return ctx

        module1 = AddDataModule(name="Adder1")
        module2 = AddDataModule(name="Adder2")
        ModuleRegistry.register("adder1", module1)
        ModuleRegistry.register("adder2", module2)

        ctx = Context(target="example.com")

        ModuleRegistry.get("adder1")(ctx, {"key": "count1", "value": 10})
        ModuleRegistry.get("adder2")(ctx, {"key": "count2", "value": 20})

        assert ctx.data.get("count1") == 10
        assert ctx.data.get("count2") == 20
