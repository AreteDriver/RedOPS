"""
Plugin System for RedOPS.

Provides dynamic module loading, custom module registration,
plugin hooks, and lifecycle management.
"""

import importlib
import importlib.util
import inspect
import sys
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable

from redops.core.context import Context

# Alias for clarity in plugin system
PipelineContext = Context


class PluginType(Enum):
    """Types of plugins supported."""

    MODULE = "module"  # Analysis/recon modules
    REPORTER = "reporter"  # Output formatters
    ENRICHER = "enricher"  # Data enrichment
    VALIDATOR = "validator"  # Data validation
    TRANSFORMER = "transformer"  # Data transformation
    HOOK = "hook"  # Event hooks


class PluginState(Enum):
    """Plugin lifecycle states."""

    DISCOVERED = "discovered"
    LOADED = "loaded"
    INITIALIZED = "initialized"
    ACTIVE = "active"
    DISABLED = "disabled"
    ERROR = "error"


class HookPoint(Enum):
    """Available hook points in the pipeline."""

    BEFORE_PIPELINE = "before_pipeline"
    AFTER_PIPELINE = "after_pipeline"
    BEFORE_MODULE = "before_module"
    AFTER_MODULE = "after_module"
    ON_ERROR = "on_error"
    ON_FINDING = "on_finding"
    ON_DATA = "on_data"
    BEFORE_REPORT = "before_report"
    AFTER_REPORT = "after_report"


@dataclass
class PluginMetadata:
    """Metadata for a plugin."""

    name: str
    version: str
    description: str = ""
    author: str = ""
    plugin_type: PluginType = PluginType.MODULE
    dependencies: list[str] = field(default_factory=list)
    config_schema: dict = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)
    homepage: str = ""
    license: str = ""


@dataclass
class PluginInfo:
    """Information about a registered plugin."""

    metadata: PluginMetadata
    state: PluginState
    instance: Any = None
    path: Path | None = None
    error: str | None = None
    load_order: int = 0


class PluginError(Exception):
    """Base exception for plugin errors."""

    pass


class PluginLoadError(PluginError):
    """Raised when a plugin fails to load."""

    pass


class PluginNotFoundError(PluginError):
    """Raised when a plugin is not found."""

    pass


class PluginValidationError(PluginError):
    """Raised when plugin validation fails."""

    pass


class BasePlugin(ABC):
    """
    Base class for all RedOPS plugins.

    Plugins must inherit from this class and implement the required methods.
    """

    @classmethod
    @abstractmethod
    def get_metadata(cls) -> PluginMetadata:
        """Return plugin metadata."""
        pass

    def initialize(self, config: dict | None = None) -> None:
        """
        Initialize the plugin with configuration.

        Args:
            config: Plugin-specific configuration
        """
        self.config = config or {}

    def shutdown(self) -> None:
        """Clean up plugin resources."""
        pass


class ModulePlugin(BasePlugin):
    """Base class for analysis/recon module plugins."""

    @abstractmethod
    def execute(self, ctx: PipelineContext) -> dict:
        """
        Execute the module.

        Args:
            ctx: Pipeline context with target and data

        Returns:
            Results dictionary
        """
        pass

    def validate_target(self, target: str) -> bool:
        """
        Validate if the target is suitable for this module.

        Args:
            target: Target to validate

        Returns:
            True if target is valid
        """
        return True


class ReporterPlugin(BasePlugin):
    """Base class for reporter plugins."""

    @abstractmethod
    def generate(self, ctx: PipelineContext, output_path: Path) -> Path:
        """
        Generate a report.

        Args:
            ctx: Pipeline context with results
            output_path: Base output path

        Returns:
            Path to generated report
        """
        pass

    def get_format(self) -> str:
        """Return the report format identifier."""
        return "custom"


class EnricherPlugin(BasePlugin):
    """Base class for data enrichment plugins."""

    @abstractmethod
    def enrich(self, data: dict, ctx: PipelineContext) -> dict:
        """
        Enrich data with additional information.

        Args:
            data: Data to enrich
            ctx: Pipeline context

        Returns:
            Enriched data
        """
        pass


class ValidatorPlugin(BasePlugin):
    """Base class for validation plugins."""

    @abstractmethod
    def validate(self, data: dict, ctx: PipelineContext) -> tuple[bool, list[str]]:
        """
        Validate data.

        Args:
            data: Data to validate
            ctx: Pipeline context

        Returns:
            Tuple of (is_valid, error_messages)
        """
        pass


class TransformerPlugin(BasePlugin):
    """Base class for data transformation plugins."""

    @abstractmethod
    def transform(self, data: dict, ctx: PipelineContext) -> dict:
        """
        Transform data.

        Args:
            data: Data to transform
            ctx: Pipeline context

        Returns:
            Transformed data
        """
        pass


class HookPlugin(BasePlugin):
    """Base class for hook plugins."""

    def get_hook_points(self) -> list[HookPoint]:
        """Return list of hook points this plugin handles."""
        return []

    def on_before_pipeline(self, ctx: PipelineContext) -> None:
        """Called before pipeline execution."""
        pass

    def on_after_pipeline(self, ctx: PipelineContext) -> None:
        """Called after pipeline execution."""
        pass

    def on_before_module(self, module_name: str, ctx: PipelineContext) -> None:
        """Called before each module execution."""
        pass

    def on_after_module(
        self, module_name: str, result: dict, ctx: PipelineContext
    ) -> None:
        """Called after each module execution."""
        pass

    def on_error(self, error: Exception, ctx: PipelineContext) -> None:
        """Called when an error occurs."""
        pass

    def on_finding(self, finding: dict, ctx: PipelineContext) -> None:
        """Called when a finding is discovered."""
        pass

    def on_data(self, key: str, value: Any, ctx: PipelineContext) -> None:
        """Called when data is added to context."""
        pass


class PluginRegistry:
    """
    Central registry for all plugins.

    Handles plugin discovery, loading, registration, and lifecycle management.
    """

    def __init__(self):
        self._plugins: dict[str, PluginInfo] = {}
        self._hooks: dict[HookPoint, list[HookPlugin]] = {hp: [] for hp in HookPoint}
        self._plugin_dirs: list[Path] = []
        self._load_order_counter = 0

    @property
    def plugins(self) -> dict[str, PluginInfo]:
        """Get all registered plugins."""
        return self._plugins.copy()

    def add_plugin_directory(self, path: str | Path) -> None:
        """
        Add a directory to search for plugins.

        Args:
            path: Directory path
        """
        path = Path(path)
        if path.exists() and path.is_dir():
            if path not in self._plugin_dirs:
                self._plugin_dirs.append(path)

    def discover_plugins(self) -> list[str]:
        """
        Discover plugins in registered directories.

        Returns:
            List of discovered plugin names
        """
        discovered = []

        for plugin_dir in self._plugin_dirs:
            for plugin_path in plugin_dir.glob("*.py"):
                if plugin_path.name.startswith("_"):
                    continue

                try:
                    plugin_name = plugin_path.stem
                    self._discover_plugin_file(plugin_path)
                    discovered.append(plugin_name)
                except Exception as e:
                    # Record discovery error but continue
                    self._plugins[plugin_path.stem] = PluginInfo(
                        metadata=PluginMetadata(
                            name=plugin_path.stem,
                            version="0.0.0",
                            description="Failed to discover",
                        ),
                        state=PluginState.ERROR,
                        path=plugin_path,
                        error=str(e),
                    )

        return discovered

    def _discover_plugin_file(self, path: Path) -> None:
        """Discover a plugin from a file without fully loading it."""
        spec = importlib.util.spec_from_file_location(path.stem, path)
        if spec is None or spec.loader is None:
            raise PluginLoadError(f"Cannot load module spec from {path}")

        module = importlib.util.module_from_spec(spec)

        # Execute the module to discover plugin classes
        spec.loader.exec_module(module)

        # Find plugin classes
        for name, obj in inspect.getmembers(module, inspect.isclass):
            if self._is_plugin_class(obj):
                metadata = obj.get_metadata()
                self._plugins[metadata.name] = PluginInfo(
                    metadata=metadata,
                    state=PluginState.DISCOVERED,
                    path=path,
                )

    def _is_plugin_class(self, obj: type) -> bool:
        """Check if a class is a valid plugin class."""
        if not inspect.isclass(obj):
            return False

        # Must be a subclass of BasePlugin but not BasePlugin itself
        if not issubclass(obj, BasePlugin):
            return False

        if obj in (
            BasePlugin,
            ModulePlugin,
            ReporterPlugin,
            EnricherPlugin,
            ValidatorPlugin,
            TransformerPlugin,
            HookPlugin,
        ):
            return False

        # Must have get_metadata method
        if not hasattr(obj, "get_metadata"):
            return False

        # Must not be abstract
        if inspect.isabstract(obj):
            return False

        return True

    def register(
        self,
        plugin_class: type[BasePlugin],
        config: dict | None = None,
    ) -> str:
        """
        Register a plugin class.

        Args:
            plugin_class: Plugin class to register
            config: Optional configuration for the plugin

        Returns:
            Plugin name
        """
        if not self._is_plugin_class(plugin_class):
            raise PluginValidationError(
                f"{plugin_class.__name__} is not a valid plugin class"
            )

        metadata = plugin_class.get_metadata()

        # Check dependencies
        for dep in metadata.dependencies:
            if dep not in self._plugins:
                raise PluginValidationError(
                    f"Plugin '{metadata.name}' requires '{dep}' which is not registered"
                )

        # Create instance
        try:
            instance = plugin_class()
            instance.initialize(config)
        except Exception as e:
            raise PluginLoadError(f"Failed to initialize plugin: {e}")

        self._load_order_counter += 1

        self._plugins[metadata.name] = PluginInfo(
            metadata=metadata,
            state=PluginState.ACTIVE,
            instance=instance,
            load_order=self._load_order_counter,
        )

        # Register hooks if applicable
        if isinstance(instance, HookPlugin):
            for hook_point in instance.get_hook_points():
                self._hooks[hook_point].append(instance)

        return metadata.name

    def register_from_module(
        self,
        module_path: str,
        config: dict | None = None,
    ) -> list[str]:
        """
        Register plugins from a Python module path.

        Args:
            module_path: Dotted module path (e.g., "mypackage.plugins")
            config: Optional configuration

        Returns:
            List of registered plugin names
        """
        try:
            module = importlib.import_module(module_path)
        except ImportError as e:
            raise PluginLoadError(f"Cannot import module '{module_path}': {e}")

        registered = []
        for name, obj in inspect.getmembers(module, inspect.isclass):
            if self._is_plugin_class(obj):
                plugin_name = self.register(obj, config)
                registered.append(plugin_name)

        return registered

    def register_from_file(
        self,
        file_path: str | Path,
        config: dict | None = None,
    ) -> list[str]:
        """
        Register plugins from a Python file.

        Args:
            file_path: Path to Python file
            config: Optional configuration

        Returns:
            List of registered plugin names
        """
        path = Path(file_path)
        if not path.exists():
            raise PluginNotFoundError(f"Plugin file not found: {path}")

        spec = importlib.util.spec_from_file_location(path.stem, path)
        if spec is None or spec.loader is None:
            raise PluginLoadError(f"Cannot load module spec from {path}")

        module = importlib.util.module_from_spec(spec)
        sys.modules[path.stem] = module
        spec.loader.exec_module(module)

        registered = []
        for name, obj in inspect.getmembers(module, inspect.isclass):
            if self._is_plugin_class(obj):
                plugin_name = self.register(obj, config)
                # Update path info
                if plugin_name in self._plugins:
                    self._plugins[plugin_name].path = path
                registered.append(plugin_name)

        return registered

    def unregister(self, name: str) -> bool:
        """
        Unregister a plugin.

        Args:
            name: Plugin name

        Returns:
            True if plugin was unregistered
        """
        if name not in self._plugins:
            return False

        plugin_info = self._plugins[name]

        # Remove from hooks
        if plugin_info.instance and isinstance(plugin_info.instance, HookPlugin):
            for hook_list in self._hooks.values():
                if plugin_info.instance in hook_list:
                    hook_list.remove(plugin_info.instance)

        # Shutdown plugin
        if plugin_info.instance:
            try:
                plugin_info.instance.shutdown()
            except Exception:
                pass  # Ignore shutdown errors

        del self._plugins[name]
        return True

    def get(self, name: str) -> PluginInfo | None:
        """
        Get a plugin by name.

        Args:
            name: Plugin name

        Returns:
            PluginInfo or None
        """
        return self._plugins.get(name)

    def get_instance(self, name: str) -> BasePlugin | None:
        """
        Get a plugin instance by name.

        Args:
            name: Plugin name

        Returns:
            Plugin instance or None
        """
        info = self._plugins.get(name)
        return info.instance if info else None

    def get_by_type(self, plugin_type: PluginType) -> list[PluginInfo]:
        """
        Get all plugins of a specific type.

        Args:
            plugin_type: Type to filter by

        Returns:
            List of matching plugins
        """
        return [
            info
            for info in self._plugins.values()
            if info.metadata.plugin_type == plugin_type
        ]

    def get_active(self) -> list[PluginInfo]:
        """Get all active plugins."""
        return [
            info for info in self._plugins.values() if info.state == PluginState.ACTIVE
        ]

    def get_by_tag(self, tag: str) -> list[PluginInfo]:
        """
        Get all plugins with a specific tag.

        Args:
            tag: Tag to filter by

        Returns:
            List of matching plugins
        """
        return [info for info in self._plugins.values() if tag in info.metadata.tags]

    def enable(self, name: str) -> bool:
        """
        Enable a disabled plugin.

        Args:
            name: Plugin name

        Returns:
            True if plugin was enabled
        """
        if name not in self._plugins:
            return False

        plugin_info = self._plugins[name]
        if plugin_info.state == PluginState.DISABLED:
            plugin_info.state = PluginState.ACTIVE
            return True
        return False

    def disable(self, name: str) -> bool:
        """
        Disable an active plugin.

        Args:
            name: Plugin name

        Returns:
            True if plugin was disabled
        """
        if name not in self._plugins:
            return False

        plugin_info = self._plugins[name]
        if plugin_info.state == PluginState.ACTIVE:
            plugin_info.state = PluginState.DISABLED
            return True
        return False

    def is_enabled(self, name: str) -> bool:
        """Check if a plugin is enabled."""
        info = self._plugins.get(name)
        return info is not None and info.state == PluginState.ACTIVE

    def execute_hooks(
        self,
        hook_point: HookPoint,
        ctx: PipelineContext,
        **kwargs,
    ) -> None:
        """
        Execute all hooks for a given hook point.

        Args:
            hook_point: Hook point to execute
            ctx: Pipeline context
            **kwargs: Additional arguments for the hook
        """
        for hook in self._hooks[hook_point]:
            # Skip disabled plugins
            plugin_info = self._get_plugin_for_instance(hook)
            if plugin_info and plugin_info.state != PluginState.ACTIVE:
                continue

            try:
                if hook_point == HookPoint.BEFORE_PIPELINE:
                    hook.on_before_pipeline(ctx)
                elif hook_point == HookPoint.AFTER_PIPELINE:
                    hook.on_after_pipeline(ctx)
                elif hook_point == HookPoint.BEFORE_MODULE:
                    hook.on_before_module(kwargs.get("module_name", ""), ctx)
                elif hook_point == HookPoint.AFTER_MODULE:
                    hook.on_after_module(
                        kwargs.get("module_name", ""),
                        kwargs.get("result", {}),
                        ctx,
                    )
                elif hook_point == HookPoint.ON_ERROR:
                    hook.on_error(kwargs.get("error"), ctx)
                elif hook_point == HookPoint.ON_FINDING:
                    hook.on_finding(kwargs.get("finding", {}), ctx)
                elif hook_point == HookPoint.ON_DATA:
                    hook.on_data(
                        kwargs.get("key", ""),
                        kwargs.get("value"),
                        ctx,
                    )
            except Exception as e:
                # Log error but continue with other hooks
                ctx.log(
                    f"Hook error in {hook.__class__.__name__}: {e}",
                    level="ERROR",
                )

    def _get_plugin_for_instance(self, instance: BasePlugin) -> PluginInfo | None:
        """Get PluginInfo for a plugin instance."""
        for info in self._plugins.values():
            if info.instance is instance:
                return info
        return None

    def get_load_order(self) -> list[str]:
        """Get plugins in load order."""
        sorted_plugins = sorted(
            self._plugins.items(),
            key=lambda x: x[1].load_order,
        )
        return [name for name, _ in sorted_plugins]

    def validate_dependencies(self) -> list[str]:
        """
        Validate all plugin dependencies.

        Returns:
            List of error messages
        """
        errors = []

        for name, info in self._plugins.items():
            for dep in info.metadata.dependencies:
                if dep not in self._plugins:
                    errors.append(
                        f"Plugin '{name}' requires '{dep}' which is not registered"
                    )
                elif self._plugins[dep].state == PluginState.ERROR:
                    errors.append(
                        f"Plugin '{name}' depends on '{dep}' which has errors"
                    )

        return errors

    def shutdown_all(self) -> None:
        """Shutdown all plugins."""
        # Shutdown in reverse load order
        for name in reversed(self.get_load_order()):
            info = self._plugins.get(name)
            if info and info.instance:
                try:
                    info.instance.shutdown()
                except Exception:
                    pass


# Global registry instance
_global_registry: PluginRegistry | None = None


def get_plugin_registry() -> PluginRegistry:
    """Get the global plugin registry."""
    global _global_registry
    if _global_registry is None:
        _global_registry = PluginRegistry()
    return _global_registry


def register_plugin(
    plugin_class: type[BasePlugin],
    config: dict | None = None,
) -> str:
    """Register a plugin with the global registry."""
    return get_plugin_registry().register(plugin_class, config)


def get_plugin(name: str) -> BasePlugin | None:
    """Get a plugin instance from the global registry."""
    return get_plugin_registry().get_instance(name)


def execute_hooks(hook_point: HookPoint, ctx: PipelineContext, **kwargs) -> None:
    """Execute hooks using the global registry."""
    get_plugin_registry().execute_hooks(hook_point, ctx, **kwargs)


# Decorator for easy plugin registration
def plugin(
    name: str,
    version: str,
    description: str = "",
    plugin_type: PluginType = PluginType.MODULE,
    **kwargs,
) -> Callable:
    """
    Decorator to define plugin metadata.

    Usage:
        @plugin(name="my_plugin", version="1.0.0", description="My plugin")
        class MyPlugin(ModulePlugin):
            def execute(self, ctx):
                ...
    """

    def decorator(cls: type) -> type:
        # Store metadata on the class
        getattr(cls, "get_metadata", None)

        @classmethod
        def get_metadata(cls) -> PluginMetadata:
            return PluginMetadata(
                name=name,
                version=version,
                description=description,
                plugin_type=plugin_type,
                author=kwargs.get("author", ""),
                dependencies=kwargs.get("dependencies", []),
                config_schema=kwargs.get("config_schema", {}),
                tags=kwargs.get("tags", []),
                homepage=kwargs.get("homepage", ""),
                license=kwargs.get("license", ""),
            )

        cls.get_metadata = get_metadata
        return cls

    return decorator
