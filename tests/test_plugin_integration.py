"""Tests for plugin system integration with pipeline runner."""

from unittest.mock import MagicMock, patch

from redops.core.context import Context
from redops.core.plugin_system import (
    PluginRegistry,
    PluginMetadata,
    PluginType,
    PluginState,
    HookPoint,
    ModulePlugin,
    HookPlugin,
    plugin,
)
from redops.pipelines.runner import PipelineRunner
from redops.pipelines.schemas import Pipeline, PipelineMetadata, PipelineStep


# Test plugins - defined with explicit get_metadata to avoid ABC issues
class SampleModulePlugin(ModulePlugin):
    """Test module plugin."""

    @classmethod
    def get_metadata(cls) -> PluginMetadata:
        return PluginMetadata(
            name="test_module",
            version="1.0.0",
            description="Test module plugin",
            plugin_type=PluginType.MODULE,
        )

    def execute(self, ctx):
        return {"test_result": "from_plugin"}


class SampleHookPlugin(HookPlugin):
    """Sample hook plugin for tracking hook calls."""

    @classmethod
    def get_metadata(cls) -> PluginMetadata:
        return PluginMetadata(
            name="test_hook",
            version="1.0.0",
            description="Test hook plugin",
            plugin_type=PluginType.HOOK,
        )

    def __init__(self):
        super().__init__()
        self.calls = []

    def get_hook_points(self):
        return [
            HookPoint.BEFORE_PIPELINE,
            HookPoint.AFTER_PIPELINE,
            HookPoint.BEFORE_MODULE,
            HookPoint.AFTER_MODULE,
        ]

    def on_before_pipeline(self, ctx):
        self.calls.append(("before_pipeline", ctx.target))

    def on_after_pipeline(self, ctx):
        self.calls.append(("after_pipeline", ctx.target))

    def on_before_module(self, module_name, ctx):
        self.calls.append(("before_module", module_name))

    def on_after_module(self, module_name, result, ctx):
        self.calls.append(("after_module", module_name, result))


class TestPluginRegistry:
    """Tests for PluginRegistry."""

    def test_register_module_plugin(self):
        """Test registering a module plugin."""
        registry = PluginRegistry()
        name = registry.register(SampleModulePlugin)

        assert name == "test_module"
        assert registry.is_enabled("test_module")

        info = registry.get("test_module")
        assert info is not None
        assert info.metadata.version == "1.0.0"
        assert info.metadata.plugin_type == PluginType.MODULE
        assert info.state == PluginState.ACTIVE

    def test_register_hook_plugin(self):
        """Test registering a hook plugin."""
        registry = PluginRegistry()
        name = registry.register(SampleHookPlugin)

        assert name == "test_hook"
        info = registry.get("test_hook")
        assert info.metadata.plugin_type == PluginType.HOOK

    def test_enable_disable_plugin(self):
        """Test enabling and disabling plugins."""
        registry = PluginRegistry()
        registry.register(SampleModulePlugin)

        assert registry.is_enabled("test_module")

        registry.disable("test_module")
        assert not registry.is_enabled("test_module")

        registry.enable("test_module")
        assert registry.is_enabled("test_module")

    def test_get_by_type(self):
        """Test getting plugins by type."""
        registry = PluginRegistry()
        registry.register(SampleModulePlugin)
        registry.register(SampleHookPlugin)

        modules = registry.get_by_type(PluginType.MODULE)
        assert len(modules) == 1
        assert modules[0].metadata.name == "test_module"

        hooks = registry.get_by_type(PluginType.HOOK)
        assert len(hooks) == 1
        assert hooks[0].metadata.name == "test_hook"

    def test_unregister_plugin(self):
        """Test unregistering a plugin."""
        registry = PluginRegistry()
        registry.register(SampleModulePlugin)

        assert registry.get("test_module") is not None

        result = registry.unregister("test_module")
        assert result is True
        assert registry.get("test_module") is None

    def test_execute_hooks(self):
        """Test executing hooks."""
        registry = PluginRegistry()
        registry.register(SampleHookPlugin)

        ctx = Context(target="example.com")
        hook_instance = registry.get_instance("test_hook")

        registry.execute_hooks(HookPoint.BEFORE_PIPELINE, ctx)
        assert ("before_pipeline", "example.com") in hook_instance.calls

        registry.execute_hooks(
            HookPoint.BEFORE_MODULE,
            ctx,
            module_name="test_step",
        )
        assert ("before_module", "test_step") in hook_instance.calls


class TestPipelineRunnerPluginIntegration:
    """Tests for PipelineRunner plugin integration."""

    def create_test_pipeline(self, steps=None):
        """Create a test pipeline."""
        if steps is None:
            steps = [
                PipelineStep(
                    name="test_step",
                    module="recon.domains.analyze_domain",
                    enabled=True,
                )
            ]

        return Pipeline(
            metadata=PipelineMetadata(
                name="Test Pipeline",
                version="1.0.0",
            ),
            steps=steps,
        )

    def test_runner_uses_plugin_registry(self):
        """Test that runner accepts and uses plugin registry."""
        registry = PluginRegistry()
        pipeline = self.create_test_pipeline()

        runner = PipelineRunner(pipeline, plugin_registry=registry)
        assert runner.plugins is registry

    def test_runner_uses_global_registry_by_default(self):
        """Test that runner uses global registry if none provided."""
        pipeline = self.create_test_pipeline()
        runner = PipelineRunner(pipeline)

        # Should not raise, should use global registry
        assert runner.plugins is not None

    def test_hook_execution_during_pipeline(self):
        """Test that hooks are executed during pipeline run."""
        registry = PluginRegistry()
        registry.register(SampleHookPlugin)
        hook_instance = registry.get_instance("test_hook")

        # Create pipeline with a step that uses a mocked module
        pipeline = self.create_test_pipeline()
        runner = PipelineRunner(pipeline, plugin_registry=registry)

        # Mock the module function
        with patch.object(runner, "_resolve_module_function") as mock_resolve:
            mock_func = MagicMock(return_value=Context(target="example.com"))
            mock_resolve.return_value = mock_func

            runner.run(target="example.com")

        # Check hooks were called
        assert ("before_pipeline", "example.com") in hook_instance.calls
        assert ("before_module", "test_step") in hook_instance.calls
        assert any(
            c[0] == "after_module" and c[1] == "test_step" for c in hook_instance.calls
        )
        assert ("after_pipeline", "example.com") in hook_instance.calls

    def test_plugin_module_execution(self):
        """Test that plugin-based modules can be executed."""
        registry = PluginRegistry()
        registry.register(SampleModulePlugin)

        # Create pipeline with plugin module
        steps = [
            PipelineStep(
                name="plugin_step",
                module="plugin:test_module",
                enabled=True,
            )
        ]
        pipeline = self.create_test_pipeline(steps)
        runner = PipelineRunner(pipeline, plugin_registry=registry)

        ctx = runner.run(target="example.com")

        # Check plugin was executed
        assert ctx.get("test_result") == "from_plugin"

    def test_plugin_module_not_found_fallback(self):
        """Test fallback to function module when plugin not found."""
        registry = PluginRegistry()
        pipeline = self.create_test_pipeline()
        runner = PipelineRunner(pipeline, plugin_registry=registry)

        # Without the plugin, should try function resolution
        with patch.object(runner, "_resolve_module_function") as mock_resolve:
            mock_func = MagicMock(return_value=Context(target="example.com"))
            mock_resolve.return_value = mock_func

            runner.run(target="example.com")
            mock_resolve.assert_called()

    def test_disabled_plugin_skipped(self):
        """Test that disabled plugins are skipped."""
        registry = PluginRegistry()
        registry.register(SampleModulePlugin)
        registry.disable("test_module")

        steps = [
            PipelineStep(
                name="plugin_step",
                module="plugin:test_module",
                enabled=True,
            )
        ]
        pipeline = self.create_test_pipeline(steps)
        runner = PipelineRunner(pipeline, plugin_registry=registry)

        # Should not find the disabled plugin
        plugin = runner._get_plugin_module("plugin:test_module")
        assert plugin is None


class TestPluginCLI:
    """Tests for plugin CLI commands."""

    def test_cmd_plugin_list_empty(self):
        """Test plugin list with no plugins."""
        from redops.cli.app import cmd_plugin, CLIConfig

        args = MagicMock()
        args.action = "list"
        config = CLIConfig()

        # Mock get_plugin_directories to return empty
        with patch("redops.cli.app.get_plugin_directories", return_value=[]):
            with patch("redops.core.plugin_system._global_registry", None):
                result = cmd_plugin(args, config)

        assert result == 0

    def test_cmd_plugin_info_not_found(self):
        """Test plugin info for non-existent plugin."""
        from redops.cli.app import cmd_plugin, CLIConfig

        args = MagicMock()
        args.action = "info"
        args.name = "nonexistent"
        config = CLIConfig()

        with patch("redops.cli.app.get_plugin_directories", return_value=[]):
            with patch("redops.core.plugin_system._global_registry", None):
                result = cmd_plugin(args, config)

        assert result == 1

    def test_cmd_plugin_enable_disable(self):
        """Test plugin enable/disable commands."""
        from redops.cli.app import cmd_plugin, CLIConfig
        import redops.core.plugin_system as ps

        # Create a registry with a plugin
        registry = PluginRegistry()
        registry.register(SampleModulePlugin)

        args = MagicMock()
        config = CLIConfig()

        # Patch the global registry
        old_registry = ps._global_registry
        ps._global_registry = registry

        try:
            with patch("redops.cli.app.get_plugin_directories", return_value=[]):
                # Disable
                args.action = "disable"
                args.name = "test_module"
                result = cmd_plugin(args, config)
                assert result == 0
                assert not registry.is_enabled("test_module")

                # Enable
                args.action = "enable"
                result = cmd_plugin(args, config)
                assert result == 0
                assert registry.is_enabled("test_module")
        finally:
            ps._global_registry = old_registry

    def test_get_plugin_directories(self):
        """Test plugin directory discovery."""
        from redops.cli.app import get_plugin_directories

        dirs = get_plugin_directories()
        # Should return a list (may be empty if no dirs exist)
        assert isinstance(dirs, list)


class TestPluginMetadataDecorator:
    """Tests for the @plugin decorator."""

    def test_plugin_decorator(self):
        """Test that @plugin decorator sets metadata correctly."""

        # Create a fresh plugin class with the decorator
        @plugin(
            name="decorated_plugin",
            version="1.0.0",
            description="Decorated plugin",
            plugin_type=PluginType.MODULE,
        )
        class DecoratedPlugin(ModulePlugin):
            def execute(self, ctx):
                return {}

        metadata = DecoratedPlugin.get_metadata()

        assert metadata.name == "decorated_plugin"
        assert metadata.version == "1.0.0"
        assert metadata.description == "Decorated plugin"
        assert metadata.plugin_type == PluginType.MODULE

    def test_plugin_decorator_with_extras(self):
        """Test @plugin decorator with extra fields."""

        @plugin(
            name="extra_plugin",
            version="2.0.0",
            description="Plugin with extras",
            plugin_type=PluginType.MODULE,
            author="Test Author",
            tags=["test", "example"],
            homepage="https://example.com",
            license="MIT",
        )
        class ExtraPlugin(ModulePlugin):
            def execute(self, ctx):
                return {}

        metadata = ExtraPlugin.get_metadata()

        assert metadata.name == "extra_plugin"
        assert metadata.version == "2.0.0"
        assert metadata.author == "Test Author"
        assert metadata.tags == ["test", "example"]
        assert metadata.homepage == "https://example.com"
        assert metadata.license == "MIT"
