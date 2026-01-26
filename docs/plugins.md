# Plugin System

Guide to extending RedOPS with plugins.

## Plugin Types

RedOPS supports several plugin types:

- **ModulePlugin**: Custom pipeline modules
- **HookPlugin**: Lifecycle hooks for pipeline events
- **ExportPlugin**: Custom report formats

## Creating a Module Plugin

```python
from redops.core.plugin_system import ModulePlugin, PluginMetadata
from redops.core.context import Context

class ShodanPlugin(ModulePlugin):
    """Plugin for Shodan intelligence gathering."""

    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="shodan_recon",
            version="1.0.0",
            description="Shodan host intelligence",
            author="Your Name",
        )

    def validate_target(self, target: str) -> bool:
        """Check if target is valid for this plugin."""
        import re
        # Accept IPs or domains
        return bool(re.match(r'^[\w.-]+$', target))

    def execute(self, ctx: Context) -> dict:
        """Execute the plugin."""
        from shodan import Shodan

        api = Shodan(self.config.get("api_key"))
        host = api.host(ctx.target)

        return {
            "shodan_host": host,
            "shodan_ports": host.get("ports", []),
        }
```

## Plugin Discovery

Plugins are automatically discovered from:

- `~/.config/redops/plugins/`
- `./plugins/` (current directory)
- Registered via `redops plugin load`

## Using Plugins in Pipelines

Reference plugins with the `plugin:` prefix:

```json
{
  "steps": [
    {
      "name": "Shodan Recon",
      "module": "plugin:shodan_recon"
    }
  ]
}
```

## Plugin CLI Commands

```bash
# List plugins
redops plugin list

# Load a plugin
redops plugin load /path/to/plugin.py

# Enable/disable
redops plugin enable shodan_recon
redops plugin disable shodan_recon

# Show info
redops plugin info shodan_recon
```

## Lifecycle Hooks

Create hooks for pipeline events:

```python
from redops.core.plugin_system import HookPlugin, HookPoint

class AuditPlugin(HookPlugin):
    def get_hook_points(self) -> list:
        return [HookPoint.BEFORE_PIPELINE, HookPoint.AFTER_MODULE]

    def execute_hook(self, hook: HookPoint, ctx: Context, **kwargs):
        if hook == HookPoint.BEFORE_PIPELINE:
            self.log_start(ctx.target)
        elif hook == HookPoint.AFTER_MODULE:
            self.log_module(kwargs.get("module_name"))
```
