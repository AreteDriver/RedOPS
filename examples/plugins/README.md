# RedOPS Plugin Examples

This directory contains example plugins demonstrating the RedOPS plugin system.

## Plugin Types

### Module Plugins (`sample_module_plugin.py`)

Module plugins perform analysis or reconnaissance tasks. They:
- Inherit from `ModulePlugin`
- Implement `execute(ctx)` method
- Can validate targets
- Store results in context

```python
from redops.core.plugin_system import ModulePlugin, PluginMetadata

class MyModule(ModulePlugin):
    @classmethod
    def get_metadata(cls) -> PluginMetadata:
        return PluginMetadata(name="my_module", version="1.0.0")

    def execute(self, ctx):
        # Perform analysis
        result = {"data": "..."}
        ctx.add("my_module", result)
        return result
```

### Hook Plugins (`sample_hook_plugin.py`)

Hook plugins execute at specific pipeline lifecycle points. They:
- Inherit from `BasePlugin`
- Implement hook methods (`on_before_pipeline`, `on_after_module`, etc.)
- Can modify context or perform side effects

Available hook points:
- `on_before_pipeline` - Before pipeline starts
- `on_after_pipeline` - After pipeline completes
- `on_before_module` - Before each module runs
- `on_after_module` - After each module completes
- `on_on_error` - When an error occurs
- `on_on_finding` - When a finding is generated

### Enricher Plugins (`sample_enricher_plugin.py`)

Enricher plugins add additional context to data. They:
- Inherit from `BasePlugin`
- Implement `enrich(ctx)` method
- Read existing context data
- Add enriched data back to context

## Installation

1. Copy plugin files to `~/.config/redops/plugins/`
2. Verify with `redops plugin list`
3. Use in pipelines with `plugin:name` syntax

## Usage in Pipelines

Reference plugins by name in pipeline definitions:

```json
{
  "name": "my_pipeline",
  "modules": [
    {"name": "plugin:sample_whois", "type": "module"},
    {"name": "domain_profile", "type": "module"},
    {"name": "plugin:sample_ip_enricher", "type": "enricher"}
  ]
}
```

## Plugin Configuration

Plugins can accept configuration via their `initialize()` method:

```python
def initialize(self, config: dict | None = None) -> None:
    super().initialize(config)
    self.api_key = self.config.get("api_key")
    self.timeout = self.config.get("timeout", 30)
```

## Best Practices

1. **Always implement `get_metadata()`** - Provide accurate name, version, description
2. **Handle errors gracefully** - Don't crash the pipeline on failures
3. **Log appropriately** - Use `ctx.log()` with proper levels
4. **Store results in context** - Use `ctx.add()` for other modules to access
5. **Document dependencies** - List in metadata's `dependencies` field
6. **Test thoroughly** - Include unit tests for your plugins
