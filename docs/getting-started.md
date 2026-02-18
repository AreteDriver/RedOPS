# Getting Started

This guide will help you get up and running with RedOPS.

## Prerequisites

- Python 3.10 or higher
- pip package manager

## Installation

### Basic Installation

Install RedOPS with core dependencies:

```bash
pip install redops
```

### Full Installation

Install with all optional features:

```bash
pip install redops[all]
```

### Development Installation

For development with testing tools:

```bash
pip install redops[dev]
```

## First Scan

Run your first security scan:

```bash
# Quick reconnaissance scan
redops scan example.com --preset quick

# Full reconnaissance
redops scan example.com --preset recon
```

## Configuration

Create a configuration file at `~/.config/redops/config.yaml`:

```yaml
scope:
  authorized_targets:
    - "example.com"
    - "*.example.com"

output:
  output_dir: "./output"
  verbose: false

providers:
  anthropic:
    api_key: "${ANTHROPIC_API_KEY}"
```

## Web Dashboard

Start the web dashboard:

```bash
redops-web
```

Access the dashboard at http://localhost:8000

## Next Steps

- Read the [CLI Reference](cli-reference.md) for all available commands
- Explore [Scan Presets](presets.md) for different use cases
- Learn about [Configuration](configuration.md) options
