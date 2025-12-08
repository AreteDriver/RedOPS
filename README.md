# RedOps Framework

**Advanced modular AI-assisted recon, forensics, and exposure-analysis framework**

> ⚠️ **Important:** RedOps is NOT a hacking tool. It is a professional OSINT + metadata + threat-modeling automation system designed for authorized security assessments only.

## Overview

RedOps is a comprehensive security assessment framework that combines:

- **OSINT (Open-Source Intelligence)** - Gather public information about targets
- **Metadata Analysis** - Extract and analyze metadata from documents, images, and code
- **Threat Modeling** - Simulate attack paths and map to MITRE ATT&CK framework
- **Risk Assessment** - Score and prioritize security risks
- **Automated Reporting** - Generate executive summaries and technical reports

## Features

### 🔍 Reconnaissance
- Domain profiling with DNS enumeration
- Technology stack fingerprinting
- Social OSINT (public profiles only)
- Subdomain discovery (placeholder)

### 📄 Metadata & Forensics
- EXIF extraction from images
- Document metadata analysis (PDF, Office)
- Code repository fingerprinting
- Dependency extraction

### 🧠 Intelligence
- Entity extraction (organizations, people, locations)
- Pattern clustering and analysis
- Risk scoring (likelihood × impact)
- Asset graph building

### 🎯 Simulation
- Attack path inference (non-intrusive)
- Scenario generation
- MITRE ATT&CK technique mapping

### 📊 Reporting
- Executive summaries (Markdown/HTML)
- Technical detail reports
- JSON/CSV data export
- Customizable templates

### 🛡️ Compliance
- Scope validation (explicit allow-lists)
- Audit logging
- Safe-by-default configuration

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/AreteDriver/RedOPS.git
cd RedOPS

# Install in development mode
pip install -e .

# Or install with all optional dependencies
pip install -e ".[full]"
```

### Using pip

```bash
pip install redops
```

## Quick Start

### 1. List Available Pipelines

```bash
redops list
```

### 2. Run a Pipeline

```bash
# Reconnaissance pipeline
redops run config/pipelines/recon_pipeline.json example.com

# Forensic analysis pipeline
redops run config/pipelines/forensic_pipeline.json /path/to/directory

# Corporate assessment pipeline
redops run config/pipelines/corp_assessment.json company.com --output-dir ./reports
```

### 3. View Results

Reports are saved to the `./output` directory (or your specified `--output-dir`):

- `executive_summary_*.md` - High-level overview
- `technical_report_*.md` - Detailed findings
- `report_*.html` - HTML report with styling
- `data_*.json` - Complete data export

## Architecture

### Project Structure

```
redops/
├── src/redops/
│   ├── core/               # Core components
│   │   ├── context.py      # Pipeline context object
│   │   ├── module_base.py  # Base module class
│   │   ├── models.py       # Pydantic data models
│   │   └── config.py       # Configuration management
│   ├── pipelines/          # Pipeline system
│   │   ├── schemas.py      # Pipeline validation
│   │   ├── loader.py       # JSON loader
│   │   └── runner.py       # Pipeline executor
│   ├── modules/            # Feature modules
│   │   ├── recon/          # Reconnaissance
│   │   ├── metadata/       # Metadata extraction
│   │   ├── intel/          # Intelligence analysis
│   │   ├── simulation/     # Attack modeling
│   │   ├── reporting/      # Report generation
│   │   ├── corp_assessment/# Corporate assessment
│   │   └── compliance/     # Scope & audit
│   └── main.py            # CLI entry point
├── config/pipelines/       # Pipeline definitions
│   ├── recon_pipeline.json
│   ├── forensic_pipeline.json
│   └── corp_assessment.json
└── output/                 # Generated reports
```

### Pipeline System

Pipelines are JSON-defined workflows that run sequentially:

```json
{
  "metadata": {
    "name": "My Pipeline",
    "description": "Custom assessment pipeline",
    "version": "1.0"
  },
  "steps": [
    {
      "name": "Validate Scope",
      "module": "compliance.scope_guard.validate_scope",
      "params": {},
      "enabled": true
    },
    {
      "name": "Profile Domain",
      "module": "recon.domains.profile_domain",
      "params": {},
      "enabled": true
    }
  ]
}
```

### Context Object

The `Context` object flows through each pipeline step:

```python
from redops.core.context import Context

ctx = Context(target="example.com")
ctx.add("key", "value")      # Store data
value = ctx.get("key")       # Retrieve data
ctx.log("message", "INFO")   # Add log entry
```

### Module System

All modules follow a simple interface:

```python
from redops.core.context import Context
from typing import Optional, Dict, Any

def my_module(ctx: Context, params: Optional[Dict[str, Any]] = None) -> Context:
    """Module implementation."""
    ctx.log("Starting module", level="INFO")
    
    # Do work...
    result = do_analysis(ctx.target)
    
    ctx.add("my_result", result)
    return ctx
```

## Configuration

Create a `config.json` file:

```json
{
  "scope": {
    "allowed_domains": ["example.com", "test.com"],
    "allowed_ips": ["192.168.1.1"],
    "allowed_directories": ["/home/user/projects"],
    "strict_mode": true
  },
  "output": {
    "output_dir": "./output",
    "format": "markdown",
    "include_logs": true,
    "verbose": false
  },
  "modules": {
    "timeout": 300,
    "max_retries": 3,
    "user_agent": "RedOps/1.0 (OSINT Framework)"
  }
}
```

Use with:

```bash
redops run pipeline.json target --config config.json
```

## Environment Variables

- `REDOPS_OUTPUT_DIR` - Override output directory
- `REDOPS_VERBOSE` - Enable verbose logging (true/false)
- `REDOPS_STRICT_SCOPE` - Enable strict scope validation (true/false)

## Creating Custom Pipelines

1. Create a JSON file in `config/pipelines/`
2. Define metadata and steps
3. Reference modules using dotted paths (e.g., `recon.domains.profile_domain`)
4. Run with `redops run`

Example:

```json
{
  "metadata": {
    "name": "Quick Scan",
    "description": "Fast reconnaissance scan"
  },
  "steps": [
    {
      "name": "DNS Lookup",
      "module": "recon.domains.enumerate_dns",
      "enabled": true
    },
    {
      "name": "Generate Report",
      "module": "reporting.markdown_report.generate_exec_summary",
      "enabled": true
    }
  ]
}
```

## Security & Ethics

### ⚠️ Legal & Ethical Use Only

RedOps is designed for:
- ✅ Authorized security assessments
- ✅ Your own infrastructure
- ✅ Explicitly permitted targets
- ✅ OSINT on public data only

**Never use RedOps to:**
- ❌ Attack systems without authorization
- ❌ Scan targets without permission
- ❌ Exploit vulnerabilities
- ❌ Access private/confidential data
- ❌ Violate any laws or regulations

### Scope Validation

RedOps enforces scope through:
- Explicit allow-lists (domains, IPs, directories)
- Pipeline-level scope validation
- Audit logging of all operations

### What RedOps Does NOT Do

- ❌ No exploitation or intrusion
- ❌ No vulnerability scanning (use dedicated tools)
- ❌ No credential harvesting
- ❌ No brute forcing
- ❌ No network attacks
- ❌ No payload generation

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Follow the existing code structure
4. Add tests if applicable
5. Submit a pull request

## License

MIT License - see LICENSE file for details

## Disclaimer

This tool is provided for educational and authorized security assessment purposes only. Users are responsible for complying with all applicable laws and regulations. The authors assume no liability for misuse of this software.

---

**RedOps** - Professional OSINT & Threat Modeling Framework
