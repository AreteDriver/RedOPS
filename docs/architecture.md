# Architecture

Overview of RedOPS architecture and design principles.

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                         CLI / Web UI                         │
├─────────────────────────────────────────────────────────────┤
│                      Pipeline Runner                         │
├──────────┬──────────┬──────────┬──────────┬────────────────┤
│  Recon   │ Analysis │  Intel   │ Reporting│   AI Assistant │
│ Modules  │ Modules  │ Modules  │ Modules  │                │
├──────────┴──────────┴──────────┴──────────┴────────────────┤
│                         Core                                 │
│   Context  │  Config  │  Models  │  Plugin System           │
└─────────────────────────────────────────────────────────────┘
```

## Core Concepts

### Context

The `Context` object flows through the pipeline, accumulating data from each module:

```python
from redops.core.context import Context

ctx = Context(target="example.com")
ctx.add("dns_records", {...})
ctx.log("Found 5 DNS records", level="INFO")
```

### Pipeline

Pipelines define ordered execution of modules:

```python
from redops.pipelines.runner import PipelineRunner
from redops.pipelines.loader import PipelineLoader

pipeline = PipelineLoader.load("recon_pipeline.json")
runner = PipelineRunner(pipeline)
ctx = runner.run(target="example.com")
```

### Modules

Modules are pure functions that transform context:

```python
def my_module(ctx: Context, params: dict = None) -> Context:
    # Perform analysis
    result = do_something(ctx.target)

    # Store results
    ctx.add("my_result", result)

    return ctx
```

## Data Flow

1. **Input**: Target specification and configuration
2. **Pipeline Loading**: JSON pipeline parsed and validated
3. **Module Execution**: Each module processes context in order
4. **Data Accumulation**: Results stored in context.data
5. **Output**: Reports generated from accumulated data

## Plugin System

Plugins extend RedOPS with custom functionality:

```python
from redops.core.plugin_system import ModulePlugin, PluginMetadata

class MyPlugin(ModulePlugin):
    def get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="my_plugin",
            version="1.0.0",
            description="Custom module",
        )

    def execute(self, ctx: Context) -> dict:
        return {"custom_data": "value"}
```

## Thread Safety

- Context objects are not thread-safe by default
- Module execution is sequential within a pipeline
- Parallel execution requires separate context instances
