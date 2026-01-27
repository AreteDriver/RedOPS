"""
Sample Hook Plugin for RedOPS.

This example demonstrates how to create hook plugins that execute
at specific points in the pipeline lifecycle.

To use this plugin:
1. Copy to ~/.config/redops/plugins/
2. Hooks are automatically registered and called during scans
"""

from datetime import datetime
from redops.core.plugin_system import (
    BasePlugin,
    PluginMetadata,
    PluginType,
    PipelineContext,
)


class SampleTimingHook(BasePlugin):
    """
    Sample hook that tracks pipeline timing.

    Demonstrates:
    - Hook plugin structure
    - Multiple hook points
    - State management between hooks
    """

    @classmethod
    def get_metadata(cls) -> PluginMetadata:
        return PluginMetadata(
            name="sample_timing_hook",
            version="1.0.0",
            description="Sample hook for tracking pipeline timing",
            author="RedOPS Examples",
            plugin_type=PluginType.HOOK,
            tags=["hook", "timing", "sample"],
        )

    def initialize(self, config: dict | None = None) -> None:
        """Initialize timing state."""
        super().initialize(config)
        self._start_time = None
        self._module_times = {}

    # Hook methods - named after HookPoint values
    # The plugin registry calls these methods when hooks fire

    def on_before_pipeline(self, ctx: PipelineContext, **kwargs) -> None:
        """Called before the pipeline starts."""
        self._start_time = datetime.now()
        ctx.log(f"[TimingHook] Pipeline started at {self._start_time}", level="DEBUG")

    def on_after_pipeline(self, ctx: PipelineContext, **kwargs) -> None:
        """Called after the pipeline completes."""
        if self._start_time:
            duration = (datetime.now() - self._start_time).total_seconds()
            ctx.log(f"[TimingHook] Pipeline completed in {duration:.2f}s", level="INFO")

            # Store timing data in context
            ctx.add(
                "timing_data",
                {
                    "total_duration_seconds": duration,
                    "module_times": self._module_times,
                },
            )

    def on_before_module(
        self, ctx: PipelineContext, module_name: str = None, **kwargs
    ) -> None:
        """Called before each module executes."""
        if module_name:
            self._module_times[module_name] = {"start": datetime.now().isoformat()}
            ctx.log(f"[TimingHook] Starting module: {module_name}", level="DEBUG")

    def on_after_module(
        self, ctx: PipelineContext, module_name: str = None, **kwargs
    ) -> None:
        """Called after each module completes."""
        if module_name and module_name in self._module_times:
            start = datetime.fromisoformat(self._module_times[module_name]["start"])
            duration = (datetime.now() - start).total_seconds()
            self._module_times[module_name]["duration_seconds"] = duration
            ctx.log(
                f"[TimingHook] Module {module_name} completed in {duration:.2f}s",
                level="DEBUG",
            )

    def on_on_error(
        self, ctx: PipelineContext, error: Exception = None, **kwargs
    ) -> None:
        """Called when an error occurs."""
        if error:
            ctx.log(f"[TimingHook] Error occurred: {error}", level="ERROR")


class SampleNotificationHook(BasePlugin):
    """
    Sample hook that sends notifications.

    Demonstrates webhook notifications on pipeline events.
    """

    @classmethod
    def get_metadata(cls) -> PluginMetadata:
        return PluginMetadata(
            name="sample_notification_hook",
            version="1.0.0",
            description="Sample hook for sending notifications",
            author="RedOPS Examples",
            plugin_type=PluginType.HOOK,
            tags=["hook", "notification", "sample"],
        )

    def initialize(self, config: dict | None = None) -> None:
        """Initialize with webhook configuration."""
        super().initialize(config)
        self.webhook_url = self.config.get("webhook_url")
        self.notify_on_complete = self.config.get("notify_on_complete", True)
        self.notify_on_error = self.config.get("notify_on_error", True)

    def on_after_pipeline(self, ctx: PipelineContext, **kwargs) -> None:
        """Send notification on pipeline completion."""
        if not self.notify_on_complete or not self.webhook_url:
            return

        # In real implementation, send actual HTTP request
        message = {
            "event": "pipeline_complete",
            "target": ctx.target,
            "status": "success",
        }
        ctx.log(f"[NotificationHook] Would send: {message}", level="DEBUG")

    def on_on_error(
        self, ctx: PipelineContext, error: Exception = None, **kwargs
    ) -> None:
        """Send notification on error."""
        if not self.notify_on_error or not self.webhook_url:
            return

        message = {
            "event": "pipeline_error",
            "target": ctx.target,
            "error": str(error) if error else "Unknown error",
        }
        ctx.log(f"[NotificationHook] Would send error: {message}", level="DEBUG")


__all__ = ["SampleTimingHook", "SampleNotificationHook"]
