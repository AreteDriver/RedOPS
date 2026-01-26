# Writing Modules

Guide to creating custom RedOPS modules.

## Module Structure

A module is a Python function with this signature:

```python
from redops.core.context import Context
from typing import Optional, Dict, Any

def my_module(ctx: Context, params: Optional[Dict[str, Any]] = None) -> Context:
    """
    Module description.

    Args:
        ctx: Pipeline context
        params: Optional parameters from pipeline definition

    Returns:
        Updated context
    """
    params = params or {}

    # Access target
    target = ctx.target

    # Access previous module data
    previous_data = ctx.get("previous_key")

    # Perform your analysis
    result = analyze(target)

    # Store results
    ctx.add("my_module_result", result)

    # Log progress
    ctx.log(f"Analyzed {target}", level="INFO")

    return ctx
```

## Module Location

Place modules in the appropriate category:

```
src/redops/modules/
├── recon/          # Reconnaissance modules
├── analysis/       # Analysis and correlation
├── threat_intel/   # Threat intelligence
├── reporting/      # Report generation
├── simulation/     # Attack simulation
└── compliance/     # Compliance checking
```

## Using Findings

Create findings for issues discovered:

```python
from redops.core.models import Finding, RiskLevel

finding = Finding(
    module="my_module",
    title="Issue Title",
    description="Detailed description",
    severity=RiskLevel.HIGH,
    data={"key": "value"},
)

ctx.add(f"finding_{unique_id}", finding.model_dump())
```

## Error Handling

Handle errors gracefully:

```python
def my_module(ctx: Context, params: Optional[Dict[str, Any]] = None) -> Context:
    try:
        result = risky_operation()
        ctx.add("result", result)
    except NetworkError as e:
        ctx.log(f"Network error: {e}", level="ERROR")
        # Continue pipeline with partial results
    except Exception as e:
        ctx.log(f"Unexpected error: {e}", level="ERROR")
        raise  # Re-raise for critical errors

    return ctx
```

## Testing Modules

Create tests in `tests/test_my_module.py`:

```python
import pytest
from unittest.mock import patch
from redops.core.context import Context
from redops.modules.my_category.my_module import my_module

def test_my_module_basic():
    ctx = Context(target="example.com")

    result = my_module(ctx)

    assert result.get("my_module_result") is not None

@patch("redops.modules.my_category.my_module.external_api")
def test_my_module_with_mock(mock_api):
    mock_api.return_value = {"data": "mocked"}
    ctx = Context(target="example.com")

    result = my_module(ctx)

    assert result.get("my_module_result") == {"data": "mocked"}
```
