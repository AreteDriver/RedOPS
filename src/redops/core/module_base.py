"""
Base module class for all RedOps modules.

All modules should either extend BaseModule or implement
a simple fn(ctx, params) signature.
"""

from abc import ABC, abstractmethod
from typing import Any
from redops.core.context import Context


class BaseModule(ABC):
    """
    Base class for all RedOps modules.

    Modules must implement the execute method which receives
    a Context object and optional parameters.
    """

    def __init__(self, name: str | None = None):
        """
        Initialize the module.

        Args:
            name: Optional name for the module (defaults to class name)
        """
        self.name = name or self.__class__.__name__

    @abstractmethod
    def execute(self, ctx: Context, params: dict[str, Any] | None = None) -> Context:
        """
        Execute the module's main functionality.

        Args:
            ctx: The context object to operate on
            params: Optional parameters for the module

        Returns:
            The updated context object
        """
        pass

    def __call__(
        self, ctx: Context, params: dict[str, Any] | None = None
    ) -> Context:
        """
        Allow modules to be called as functions.

        Args:
            ctx: The context object to operate on
            params: Optional parameters for the module

        Returns:
            The updated context object
        """
        return self.execute(ctx, params)

    def log_info(self, ctx: Context, message: str, **kwargs):
        """Helper method to log info messages."""
        ctx.log(f"[{self.name}] {message}", level="INFO", **kwargs)

    def log_warning(self, ctx: Context, message: str, **kwargs):
        """Helper method to log warning messages."""
        ctx.log(f"[{self.name}] {message}", level="WARNING", **kwargs)

    def log_error(self, ctx: Context, message: str, **kwargs):
        """Helper method to log error messages."""
        ctx.log(f"[{self.name}] {message}", level="ERROR", **kwargs)

    def log_debug(self, ctx: Context, message: str, **kwargs):
        """Helper method to log debug messages."""
        ctx.log(f"[{self.name}] {message}", level="DEBUG", **kwargs)


class ModuleRegistry:
    """
    Optional registry for module discovery and registration.
    """

    _modules: dict[str, BaseModule] = {}

    @classmethod
    def register(cls, name: str, module: BaseModule) -> None:
        """
        Register a module with the registry.

        Args:
            name: The name to register the module under
            module: The module instance to register
        """
        cls._modules[name] = module

    @classmethod
    def get(cls, name: str) -> BaseModule | None:
        """
        Retrieve a module from the registry.

        Args:
            name: The name of the module to retrieve

        Returns:
            The module instance, or None if not found
        """
        return cls._modules.get(name)

    @classmethod
    def list_modules(cls) -> list:
        """
        List all registered module names.

        Returns:
            List of module names
        """
        return list(cls._modules.keys())
