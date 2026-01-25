"""
Tests for RedOPS Plugin System.
"""

import tempfile
from pathlib import Path

import pytest

from redops.core.context import Context as PipelineContext
from redops.core.plugin_system import (
    BasePlugin,
    EnricherPlugin,
    HookPlugin,
    HookPoint,
    ModulePlugin,
    PluginError,
    PluginInfo,
    PluginLoadError,
    PluginMetadata,
    PluginNotFoundError,
    PluginRegistry,
    PluginState,
    PluginType,
    PluginValidationError,
    ReporterPlugin,
    TransformerPlugin,
    ValidatorPlugin,
    execute_hooks,
    get_plugin,
    get_plugin_registry,
    plugin,
    register_plugin,
)


# Test plugin implementations
class SampleModulePlugin(ModulePlugin):
    """Sample module plugin for testing."""

    @classmethod
    def get_metadata(cls) -> PluginMetadata:
        return PluginMetadata(
            name="sample_module",
            version="1.0.0",
            description="A sample module plugin",
            author="Test Author",
            plugin_type=PluginType.MODULE,
            tags=["test", "sample"],
        )

    def execute(self, ctx: PipelineContext) -> dict:
        return {"status": "success", "data": "sample_data"}


class SampleReporterPlugin(ReporterPlugin):
    """Sample reporter plugin for testing."""

    @classmethod
    def get_metadata(cls) -> PluginMetadata:
        return PluginMetadata(
            name="sample_reporter",
            version="1.0.0",
            description="A sample reporter plugin",
            plugin_type=PluginType.REPORTER,
        )

    def generate(self, ctx: PipelineContext, output_path: Path) -> Path:
        report_path = output_path / "report.txt"
        report_path.write_text("Sample Report")
        return report_path

    def get_format(self) -> str:
        return "txt"


class SampleEnricherPlugin(EnricherPlugin):
    """Sample enricher plugin for testing."""

    @classmethod
    def get_metadata(cls) -> PluginMetadata:
        return PluginMetadata(
            name="sample_enricher",
            version="1.0.0",
            description="A sample enricher plugin",
            plugin_type=PluginType.ENRICHER,
        )

    def enrich(self, data: dict, ctx: PipelineContext) -> dict:
        data["enriched"] = True
        return data


class SampleValidatorPlugin(ValidatorPlugin):
    """Sample validator plugin for testing."""

    @classmethod
    def get_metadata(cls) -> PluginMetadata:
        return PluginMetadata(
            name="sample_validator",
            version="1.0.0",
            description="A sample validator plugin",
            plugin_type=PluginType.VALIDATOR,
        )

    def validate(self, data: dict, ctx: PipelineContext) -> tuple[bool, list[str]]:
        if "required_field" not in data:
            return False, ["Missing required_field"]
        return True, []


class SampleTransformerPlugin(TransformerPlugin):
    """Sample transformer plugin for testing."""

    @classmethod
    def get_metadata(cls) -> PluginMetadata:
        return PluginMetadata(
            name="sample_transformer",
            version="1.0.0",
            description="A sample transformer plugin",
            plugin_type=PluginType.TRANSFORMER,
        )

    def transform(self, data: dict, ctx: PipelineContext) -> dict:
        return {k.upper(): v for k, v in data.items()}


class SampleHookPlugin(HookPlugin):
    """Sample hook plugin for testing."""

    def __init__(self):
        super().__init__()
        self.calls = []

    @classmethod
    def get_metadata(cls) -> PluginMetadata:
        return PluginMetadata(
            name="sample_hook",
            version="1.0.0",
            description="A sample hook plugin",
            plugin_type=PluginType.HOOK,
        )

    def get_hook_points(self) -> list[HookPoint]:
        return [
            HookPoint.BEFORE_PIPELINE,
            HookPoint.AFTER_PIPELINE,
            HookPoint.BEFORE_MODULE,
            HookPoint.AFTER_MODULE,
            HookPoint.ON_ERROR,
        ]

    def on_before_pipeline(self, ctx: PipelineContext) -> None:
        self.calls.append(("before_pipeline", ctx.target))

    def on_after_pipeline(self, ctx: PipelineContext) -> None:
        self.calls.append(("after_pipeline", ctx.target))

    def on_before_module(self, module_name: str, ctx: PipelineContext) -> None:
        self.calls.append(("before_module", module_name))

    def on_after_module(self, module_name: str, result: dict, ctx: PipelineContext) -> None:
        self.calls.append(("after_module", module_name, result))

    def on_error(self, error: Exception, ctx: PipelineContext) -> None:
        self.calls.append(("on_error", str(error)))


class DependentPlugin(ModulePlugin):
    """Plugin with dependencies."""

    @classmethod
    def get_metadata(cls) -> PluginMetadata:
        return PluginMetadata(
            name="dependent_plugin",
            version="1.0.0",
            dependencies=["sample_module"],
            plugin_type=PluginType.MODULE,
        )

    def execute(self, ctx: PipelineContext) -> dict:
        return {"status": "dependent"}


class TestPluginMetadata:
    """Tests for PluginMetadata dataclass."""

    def test_default_values(self):
        """Test default PluginMetadata values."""
        metadata = PluginMetadata(name="test", version="1.0.0")
        assert metadata.name == "test"
        assert metadata.version == "1.0.0"
        assert metadata.description == ""
        assert metadata.author == ""
        assert metadata.plugin_type == PluginType.MODULE
        assert metadata.dependencies == []
        assert metadata.tags == []

    def test_full_metadata(self):
        """Test PluginMetadata with all fields."""
        metadata = PluginMetadata(
            name="full_test",
            version="2.0.0",
            description="Full description",
            author="Author Name",
            plugin_type=PluginType.REPORTER,
            dependencies=["dep1", "dep2"],
            config_schema={"key": "value"},
            tags=["tag1", "tag2"],
            homepage="https://example.com",
            license="MIT",
        )
        assert metadata.name == "full_test"
        assert metadata.version == "2.0.0"
        assert metadata.description == "Full description"
        assert metadata.author == "Author Name"
        assert metadata.plugin_type == PluginType.REPORTER
        assert metadata.dependencies == ["dep1", "dep2"]
        assert metadata.config_schema == {"key": "value"}
        assert metadata.tags == ["tag1", "tag2"]
        assert metadata.homepage == "https://example.com"
        assert metadata.license == "MIT"


class TestPluginInfo:
    """Tests for PluginInfo dataclass."""

    def test_default_values(self):
        """Test default PluginInfo values."""
        metadata = PluginMetadata(name="test", version="1.0.0")
        info = PluginInfo(metadata=metadata, state=PluginState.DISCOVERED)

        assert info.metadata == metadata
        assert info.state == PluginState.DISCOVERED
        assert info.instance is None
        assert info.path is None
        assert info.error is None
        assert info.load_order == 0


class TestPluginType:
    """Tests for PluginType enum."""

    def test_plugin_types(self):
        """Test all plugin types exist."""
        assert PluginType.MODULE.value == "module"
        assert PluginType.REPORTER.value == "reporter"
        assert PluginType.ENRICHER.value == "enricher"
        assert PluginType.VALIDATOR.value == "validator"
        assert PluginType.TRANSFORMER.value == "transformer"
        assert PluginType.HOOK.value == "hook"


class TestPluginState:
    """Tests for PluginState enum."""

    def test_plugin_states(self):
        """Test all plugin states exist."""
        assert PluginState.DISCOVERED.value == "discovered"
        assert PluginState.LOADED.value == "loaded"
        assert PluginState.INITIALIZED.value == "initialized"
        assert PluginState.ACTIVE.value == "active"
        assert PluginState.DISABLED.value == "disabled"
        assert PluginState.ERROR.value == "error"


class TestHookPoint:
    """Tests for HookPoint enum."""

    def test_hook_points(self):
        """Test all hook points exist."""
        assert HookPoint.BEFORE_PIPELINE.value == "before_pipeline"
        assert HookPoint.AFTER_PIPELINE.value == "after_pipeline"
        assert HookPoint.BEFORE_MODULE.value == "before_module"
        assert HookPoint.AFTER_MODULE.value == "after_module"
        assert HookPoint.ON_ERROR.value == "on_error"
        assert HookPoint.ON_FINDING.value == "on_finding"
        assert HookPoint.ON_DATA.value == "on_data"


class TestBasePlugin:
    """Tests for BasePlugin class."""

    def test_initialize_with_config(self):
        """Test plugin initialization with config."""
        plugin = SampleModulePlugin()
        plugin.initialize({"key": "value"})
        assert plugin.config == {"key": "value"}

    def test_initialize_without_config(self):
        """Test plugin initialization without config."""
        plugin = SampleModulePlugin()
        plugin.initialize()
        assert plugin.config == {}

    def test_shutdown(self):
        """Test plugin shutdown."""
        plugin = SampleModulePlugin()
        plugin.shutdown()  # Should not raise


class TestModulePlugin:
    """Tests for ModulePlugin class."""

    def test_execute(self):
        """Test module plugin execution."""
        plugin = SampleModulePlugin()
        ctx = PipelineContext(target="test.com")

        result = plugin.execute(ctx)

        assert result["status"] == "success"
        assert result["data"] == "sample_data"

    def test_validate_target_default(self):
        """Test default target validation."""
        plugin = SampleModulePlugin()
        assert plugin.validate_target("any_target") is True

    def test_get_metadata(self):
        """Test getting module metadata."""
        metadata = SampleModulePlugin.get_metadata()

        assert metadata.name == "sample_module"
        assert metadata.version == "1.0.0"
        assert metadata.plugin_type == PluginType.MODULE


class TestReporterPlugin:
    """Tests for ReporterPlugin class."""

    def test_generate(self):
        """Test reporter plugin generation."""
        plugin = SampleReporterPlugin()
        ctx = PipelineContext(target="test.com")

        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir)
            result = plugin.generate(ctx, output_path)

            assert result.exists()
            assert result.read_text() == "Sample Report"

    def test_get_format(self):
        """Test getting report format."""
        plugin = SampleReporterPlugin()
        assert plugin.get_format() == "txt"


class TestEnricherPlugin:
    """Tests for EnricherPlugin class."""

    def test_enrich(self):
        """Test data enrichment."""
        plugin = SampleEnricherPlugin()
        ctx = PipelineContext(target="test.com")

        result = plugin.enrich({"key": "value"}, ctx)

        assert result["key"] == "value"
        assert result["enriched"] is True


class TestValidatorPlugin:
    """Tests for ValidatorPlugin class."""

    def test_validate_success(self):
        """Test successful validation."""
        plugin = SampleValidatorPlugin()
        ctx = PipelineContext(target="test.com")

        is_valid, errors = plugin.validate({"required_field": "value"}, ctx)

        assert is_valid is True
        assert errors == []

    def test_validate_failure(self):
        """Test validation failure."""
        plugin = SampleValidatorPlugin()
        ctx = PipelineContext(target="test.com")

        is_valid, errors = plugin.validate({}, ctx)

        assert is_valid is False
        assert "Missing required_field" in errors


class TestTransformerPlugin:
    """Tests for TransformerPlugin class."""

    def test_transform(self):
        """Test data transformation."""
        plugin = SampleTransformerPlugin()
        ctx = PipelineContext(target="test.com")

        result = plugin.transform({"key": "value", "other": 123}, ctx)

        assert result == {"KEY": "value", "OTHER": 123}


class TestHookPlugin:
    """Tests for HookPlugin class."""

    def test_get_hook_points(self):
        """Test getting hook points."""
        plugin = SampleHookPlugin()
        points = plugin.get_hook_points()

        assert HookPoint.BEFORE_PIPELINE in points
        assert HookPoint.AFTER_PIPELINE in points

    def test_on_before_pipeline(self):
        """Test before pipeline hook."""
        plugin = SampleHookPlugin()
        ctx = PipelineContext(target="test.com")

        plugin.on_before_pipeline(ctx)

        assert ("before_pipeline", "test.com") in plugin.calls

    def test_on_after_pipeline(self):
        """Test after pipeline hook."""
        plugin = SampleHookPlugin()
        ctx = PipelineContext(target="test.com")

        plugin.on_after_pipeline(ctx)

        assert ("after_pipeline", "test.com") in plugin.calls

    def test_on_before_module(self):
        """Test before module hook."""
        plugin = SampleHookPlugin()
        ctx = PipelineContext(target="test.com")

        plugin.on_before_module("test_module", ctx)

        assert ("before_module", "test_module") in plugin.calls

    def test_on_after_module(self):
        """Test after module hook."""
        plugin = SampleHookPlugin()
        ctx = PipelineContext(target="test.com")

        plugin.on_after_module("test_module", {"result": "data"}, ctx)

        assert ("after_module", "test_module", {"result": "data"}) in plugin.calls

    def test_on_error(self):
        """Test error hook."""
        plugin = SampleHookPlugin()
        ctx = PipelineContext(target="test.com")

        plugin.on_error(Exception("Test error"), ctx)

        assert ("on_error", "Test error") in plugin.calls


class TestPluginRegistry:
    """Tests for PluginRegistry class."""

    def test_initialization(self):
        """Test registry initialization."""
        registry = PluginRegistry()

        assert registry.plugins == {}
        assert len(registry._hooks) == len(HookPoint)

    def test_register_plugin(self):
        """Test registering a plugin."""
        registry = PluginRegistry()

        name = registry.register(SampleModulePlugin)

        assert name == "sample_module"
        assert "sample_module" in registry.plugins
        assert registry.plugins["sample_module"].state == PluginState.ACTIVE

    def test_register_with_config(self):
        """Test registering a plugin with config."""
        registry = PluginRegistry()

        registry.register(SampleModulePlugin, config={"option": "value"})

        plugin = registry.get_instance("sample_module")
        assert plugin.config == {"option": "value"}

    def test_register_invalid_class(self):
        """Test registering an invalid class."""
        registry = PluginRegistry()

        class NotAPlugin:
            pass

        with pytest.raises(PluginValidationError):
            registry.register(NotAPlugin)

    def test_register_with_missing_dependency(self):
        """Test registering plugin with missing dependency."""
        registry = PluginRegistry()

        with pytest.raises(PluginValidationError):
            registry.register(DependentPlugin)

    def test_register_with_satisfied_dependency(self):
        """Test registering plugin with satisfied dependency."""
        registry = PluginRegistry()

        registry.register(SampleModulePlugin)
        name = registry.register(DependentPlugin)

        assert name == "dependent_plugin"

    def test_unregister(self):
        """Test unregistering a plugin."""
        registry = PluginRegistry()
        registry.register(SampleModulePlugin)

        result = registry.unregister("sample_module")

        assert result is True
        assert "sample_module" not in registry.plugins

    def test_unregister_nonexistent(self):
        """Test unregistering nonexistent plugin."""
        registry = PluginRegistry()

        result = registry.unregister("nonexistent")

        assert result is False

    def test_get(self):
        """Test getting plugin info."""
        registry = PluginRegistry()
        registry.register(SampleModulePlugin)

        info = registry.get("sample_module")

        assert info is not None
        assert info.metadata.name == "sample_module"

    def test_get_nonexistent(self):
        """Test getting nonexistent plugin."""
        registry = PluginRegistry()

        info = registry.get("nonexistent")

        assert info is None

    def test_get_instance(self):
        """Test getting plugin instance."""
        registry = PluginRegistry()
        registry.register(SampleModulePlugin)

        instance = registry.get_instance("sample_module")

        assert instance is not None
        assert isinstance(instance, SampleModulePlugin)

    def test_get_by_type(self):
        """Test getting plugins by type."""
        registry = PluginRegistry()
        registry.register(SampleModulePlugin)
        registry.register(SampleReporterPlugin)

        modules = registry.get_by_type(PluginType.MODULE)
        reporters = registry.get_by_type(PluginType.REPORTER)

        assert len(modules) == 1
        assert len(reporters) == 1
        assert modules[0].metadata.name == "sample_module"

    def test_get_active(self):
        """Test getting active plugins."""
        registry = PluginRegistry()
        registry.register(SampleModulePlugin)
        registry.register(SampleReporterPlugin)

        active = registry.get_active()

        assert len(active) == 2

    def test_get_by_tag(self):
        """Test getting plugins by tag."""
        registry = PluginRegistry()
        registry.register(SampleModulePlugin)

        tagged = registry.get_by_tag("test")

        assert len(tagged) == 1
        assert tagged[0].metadata.name == "sample_module"

    def test_enable_disable(self):
        """Test enabling and disabling plugins."""
        registry = PluginRegistry()
        registry.register(SampleModulePlugin)

        # Disable
        result = registry.disable("sample_module")
        assert result is True
        assert registry.plugins["sample_module"].state == PluginState.DISABLED

        # Enable
        result = registry.enable("sample_module")
        assert result is True
        assert registry.plugins["sample_module"].state == PluginState.ACTIVE

    def test_is_enabled(self):
        """Test checking if plugin is enabled."""
        registry = PluginRegistry()
        registry.register(SampleModulePlugin)

        assert registry.is_enabled("sample_module") is True

        registry.disable("sample_module")
        assert registry.is_enabled("sample_module") is False

    def test_is_enabled_nonexistent(self):
        """Test checking nonexistent plugin."""
        registry = PluginRegistry()

        assert registry.is_enabled("nonexistent") is False

    def test_execute_hooks(self):
        """Test executing hooks."""
        registry = PluginRegistry()
        registry.register(SampleHookPlugin)
        ctx = PipelineContext(target="test.com")

        registry.execute_hooks(HookPoint.BEFORE_PIPELINE, ctx)
        registry.execute_hooks(HookPoint.AFTER_PIPELINE, ctx)

        hook = registry.get_instance("sample_hook")
        assert ("before_pipeline", "test.com") in hook.calls
        assert ("after_pipeline", "test.com") in hook.calls

    def test_execute_hooks_with_kwargs(self):
        """Test executing hooks with additional arguments."""
        registry = PluginRegistry()
        registry.register(SampleHookPlugin)
        ctx = PipelineContext(target="test.com")

        registry.execute_hooks(
            HookPoint.BEFORE_MODULE, ctx, module_name="test_module"
        )

        hook = registry.get_instance("sample_hook")
        assert ("before_module", "test_module") in hook.calls

    def test_execute_hooks_skips_disabled(self):
        """Test that disabled plugins are skipped in hooks."""
        registry = PluginRegistry()
        registry.register(SampleHookPlugin)
        registry.disable("sample_hook")
        ctx = PipelineContext(target="test.com")

        registry.execute_hooks(HookPoint.BEFORE_PIPELINE, ctx)

        hook = registry.get_instance("sample_hook")
        assert len(hook.calls) == 0

    def test_get_load_order(self):
        """Test getting plugins in load order."""
        registry = PluginRegistry()
        registry.register(SampleModulePlugin)
        registry.register(SampleReporterPlugin)

        order = registry.get_load_order()

        assert order == ["sample_module", "sample_reporter"]

    def test_validate_dependencies_success(self):
        """Test dependency validation success."""
        registry = PluginRegistry()
        registry.register(SampleModulePlugin)
        registry.register(DependentPlugin)

        errors = registry.validate_dependencies()

        assert errors == []

    def test_shutdown_all(self):
        """Test shutting down all plugins."""
        registry = PluginRegistry()
        registry.register(SampleModulePlugin)
        registry.register(SampleReporterPlugin)

        registry.shutdown_all()  # Should not raise


class TestPluginRegistryDiscovery:
    """Tests for plugin discovery."""

    def test_add_plugin_directory(self):
        """Test adding plugin directory."""
        registry = PluginRegistry()

        with tempfile.TemporaryDirectory() as tmpdir:
            registry.add_plugin_directory(tmpdir)
            assert Path(tmpdir) in registry._plugin_dirs

    def test_add_nonexistent_directory(self):
        """Test adding nonexistent directory."""
        registry = PluginRegistry()

        registry.add_plugin_directory("/nonexistent/path")
        assert len(registry._plugin_dirs) == 0

    def test_discover_plugins(self):
        """Test discovering plugins from directory."""
        registry = PluginRegistry()

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a plugin file
            plugin_file = Path(tmpdir) / "test_plugin.py"
            plugin_file.write_text("""
from redops.core.plugin_system import ModulePlugin, PluginMetadata, PluginType
from redops.core.context import Context as PipelineContext

class DiscoveredPlugin(ModulePlugin):
    @classmethod
    def get_metadata(cls):
        return PluginMetadata(
            name="discovered_plugin",
            version="1.0.0",
            plugin_type=PluginType.MODULE,
        )

    def execute(self, ctx):
        return {"discovered": True}
""")

            registry.add_plugin_directory(tmpdir)
            discovered = registry.discover_plugins()

            assert "discovered_plugin" in registry.plugins

    def test_register_from_file(self):
        """Test registering plugins from file."""
        registry = PluginRegistry()

        with tempfile.TemporaryDirectory() as tmpdir:
            plugin_file = Path(tmpdir) / "file_plugin.py"
            plugin_file.write_text("""
from redops.core.plugin_system import ModulePlugin, PluginMetadata, PluginType
from redops.core.context import Context as PipelineContext

class FilePlugin(ModulePlugin):
    @classmethod
    def get_metadata(cls):
        return PluginMetadata(
            name="file_plugin",
            version="1.0.0",
            plugin_type=PluginType.MODULE,
        )

    def execute(self, ctx):
        return {"from_file": True}
""")

            registered = registry.register_from_file(plugin_file)

            assert "file_plugin" in registered
            assert registry.is_enabled("file_plugin")

    def test_register_from_nonexistent_file(self):
        """Test registering from nonexistent file."""
        registry = PluginRegistry()

        with pytest.raises(PluginNotFoundError):
            registry.register_from_file("/nonexistent/plugin.py")


class TestPluginDecorator:
    """Tests for the @plugin decorator."""

    def test_plugin_decorator(self):
        """Test basic plugin decorator."""

        @plugin(name="decorated", version="1.0.0", description="Decorated plugin")
        class DecoratedPlugin(ModulePlugin):
            def execute(self, ctx: PipelineContext) -> dict:
                return {}

        metadata = DecoratedPlugin.get_metadata()

        assert metadata.name == "decorated"
        assert metadata.version == "1.0.0"
        assert metadata.description == "Decorated plugin"

    def test_plugin_decorator_full(self):
        """Test plugin decorator with all options."""

        @plugin(
            name="full_decorated",
            version="2.0.0",
            description="Full decorated plugin",
            plugin_type=PluginType.ENRICHER,
            author="Decorator Author",
            dependencies=["dep1"],
            tags=["tag1", "tag2"],
            homepage="https://example.com",
            license="MIT",
        )
        class FullDecoratedPlugin(EnricherPlugin):
            def enrich(self, data: dict, ctx: PipelineContext) -> dict:
                return data

        metadata = FullDecoratedPlugin.get_metadata()

        assert metadata.name == "full_decorated"
        assert metadata.version == "2.0.0"
        assert metadata.plugin_type == PluginType.ENRICHER
        assert metadata.author == "Decorator Author"
        assert metadata.dependencies == ["dep1"]
        assert metadata.tags == ["tag1", "tag2"]


class TestGlobalFunctions:
    """Tests for global convenience functions."""

    def test_get_plugin_registry(self):
        """Test getting global registry."""
        registry = get_plugin_registry()
        assert isinstance(registry, PluginRegistry)

    def test_register_plugin_global(self):
        """Test global plugin registration."""
        # Clear any existing registration
        registry = get_plugin_registry()
        if "sample_module" in registry.plugins:
            registry.unregister("sample_module")

        name = register_plugin(SampleModulePlugin)
        assert name == "sample_module"

    def test_get_plugin_global(self):
        """Test getting plugin from global registry."""
        registry = get_plugin_registry()
        if "sample_module" not in registry.plugins:
            register_plugin(SampleModulePlugin)

        plugin = get_plugin("sample_module")
        assert plugin is not None

    def test_execute_hooks_global(self):
        """Test executing hooks globally."""
        registry = get_plugin_registry()

        # Register hook if not exists
        if "sample_hook" not in registry.plugins:
            registry.register(SampleHookPlugin)

        ctx = PipelineContext(target="global_test.com")
        execute_hooks(HookPoint.BEFORE_PIPELINE, ctx)

        hook = registry.get_instance("sample_hook")
        assert any("global_test.com" in str(call) for call in hook.calls)


class TestPluginExceptions:
    """Tests for plugin exceptions."""

    def test_plugin_error(self):
        """Test base PluginError."""
        error = PluginError("Test error")
        assert str(error) == "Test error"

    def test_plugin_load_error(self):
        """Test PluginLoadError."""
        error = PluginLoadError("Failed to load")
        assert isinstance(error, PluginError)

    def test_plugin_not_found_error(self):
        """Test PluginNotFoundError."""
        error = PluginNotFoundError("Plugin not found")
        assert isinstance(error, PluginError)

    def test_plugin_validation_error(self):
        """Test PluginValidationError."""
        error = PluginValidationError("Validation failed")
        assert isinstance(error, PluginError)


class TestPluginLifecycle:
    """Tests for plugin lifecycle management."""

    def test_full_lifecycle(self):
        """Test complete plugin lifecycle."""
        registry = PluginRegistry()

        # Register
        name = registry.register(SampleModulePlugin)
        assert registry.plugins[name].state == PluginState.ACTIVE

        # Use
        plugin = registry.get_instance(name)
        ctx = PipelineContext(target="lifecycle.com")
        result = plugin.execute(ctx)
        assert result["status"] == "success"

        # Disable
        registry.disable(name)
        assert registry.plugins[name].state == PluginState.DISABLED

        # Re-enable
        registry.enable(name)
        assert registry.plugins[name].state == PluginState.ACTIVE

        # Unregister
        registry.unregister(name)
        assert name not in registry.plugins

    def test_hook_lifecycle(self):
        """Test hook plugin lifecycle."""
        registry = PluginRegistry()
        registry.register(SampleHookPlugin)
        ctx = PipelineContext(target="hook_lifecycle.com")

        # Hooks work
        registry.execute_hooks(HookPoint.BEFORE_PIPELINE, ctx)
        hook = registry.get_instance("sample_hook")
        initial_calls = len(hook.calls)

        # Disable - hooks should not fire
        registry.disable("sample_hook")
        registry.execute_hooks(HookPoint.BEFORE_PIPELINE, ctx)
        assert len(hook.calls) == initial_calls

        # Re-enable - hooks should fire again
        registry.enable("sample_hook")
        registry.execute_hooks(HookPoint.BEFORE_PIPELINE, ctx)
        assert len(hook.calls) > initial_calls
