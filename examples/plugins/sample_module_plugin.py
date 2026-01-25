"""
Sample Module Plugin for RedOPS.

This example demonstrates how to create a module plugin that performs
custom analysis on a target.

To use this plugin:
1. Copy to ~/.config/redops/plugins/
2. Run: redops plugin list  (should show the plugin)
3. Reference in pipeline as: plugin:sample_whois
"""

from redops.core.plugin_system import (
    ModulePlugin,
    PluginMetadata,
    PluginType,
    PipelineContext,
)


class SampleWhoisPlugin(ModulePlugin):
    """
    Sample WHOIS lookup module.

    Demonstrates:
    - Module plugin structure
    - Target validation
    - Context data access
    - Result formatting
    """

    @classmethod
    def get_metadata(cls) -> PluginMetadata:
        return PluginMetadata(
            name="sample_whois",
            version="1.0.0",
            description="Sample WHOIS lookup plugin (demo only)",
            author="RedOPS Examples",
            plugin_type=PluginType.MODULE,
            tags=["recon", "whois", "sample"],
        )

    def initialize(self, config: dict | None = None) -> None:
        """Initialize with optional configuration."""
        super().initialize(config)
        self.timeout = self.config.get("timeout", 30)
        self.verbose = self.config.get("verbose", False)

    def validate_target(self, target: str) -> bool:
        """Validate that target is a domain."""
        # Simple validation - check for dots and no spaces
        return "." in target and " " not in target

    def execute(self, ctx: PipelineContext) -> dict:
        """
        Perform WHOIS lookup.

        Args:
            ctx: Pipeline context with target

        Returns:
            WHOIS data dictionary
        """
        target = ctx.target

        if not target:
            return {"error": "No target specified"}

        if not self.validate_target(target):
            return {"error": f"Invalid target: {target}"}

        # In a real plugin, you would perform actual WHOIS lookup
        # This is just a demonstration with mock data
        result = {
            "domain": target,
            "status": "sample_data",
            "registrar": "Example Registrar Inc.",
            "created_date": "2020-01-15",
            "expiry_date": "2025-01-15",
            "nameservers": [
                "ns1.example.com",
                "ns2.example.com",
            ],
            "dnssec": False,
            "note": "This is sample data - implement actual WHOIS lookup",
        }

        # Store in context for other modules to access
        ctx.add("sample_whois", result)

        # Log activity
        ctx.log(f"Sample WHOIS lookup for {target}", level="INFO")

        return result


# Export the plugin class
# The plugin system looks for classes inheriting from BasePlugin
__all__ = ["SampleWhoisPlugin"]
