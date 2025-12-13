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

### 4. Verify Installation

```bash
# Check version
redops --version

# List available pipelines
redops list

# Test with example pipeline (replace with your authorized domain)
redops run config/pipelines/recon_pipeline.json yourdomain.com
```

## Use Cases

### 🎯 Corporate Security Assessment

Assess your organization's external attack surface:

```bash
# Run corporate assessment on your domain
redops run config/pipelines/corp_assessment.json company.com --output-dir ./assessment

# Review exposure summary
cat ./assessment/executive_summary_*.md
```

**What it analyzes:**
- Public DNS records and IP exposure
- Technology stack fingerprinting
- Publicly accessible metadata
- Risk scoring and prioritization

### 🔍 Forensic Analysis

Analyze metadata from documents and images in a directory:

```bash
# Analyze a directory of files
redops run config/pipelines/forensic_pipeline.json /path/to/documents

# Extract EXIF data, document metadata, and hidden information
```

**What it extracts:**
- EXIF data from images (GPS, camera info, timestamps)
- Document metadata (authors, creation dates, edit history)
- Code repository artifacts
- Dependency information

### 🧪 Threat Modeling

Model potential attack paths for your infrastructure:

```bash
# Generate threat model
redops run config/pipelines/recon_pipeline.json target.com

# Review MITRE ATT&CK mappings in report
```

**What it generates:**
- Attack path scenarios
- MITRE ATT&CK technique mappings
- Risk assessment matrix
- Defensive recommendations

## Practical Examples

### Example 1: Domain Reconnaissance

```bash
# Reconnaissance on authorized domain
redops run config/pipelines/recon_pipeline.json example.com --output-dir ./recon_results
```

**Sample Output:**
```
[RedOps] Loading pipeline: config/pipelines/recon_pipeline.json
[RedOps] Pipeline: Domain Reconnaissance
[RedOps] Target: example.com
[RedOps] Steps: 6

[RedOps] Starting pipeline execution...
  ✓ Scope validation passed
  ✓ DNS enumeration completed (4 A records found)
  ✓ Technology stack fingerprinted
  ✓ Risk scoring completed
  ✓ Executive summary generated
  ✓ HTML report generated

[RedOps] Pipeline completed successfully!

=== Output Files ===
  executive_summary_path: ./recon_results/executive_summary_20250113.md
  technical_report_path: ./recon_results/technical_report_20250113.md
  html_report_path: ./recon_results/report_20250113.html
  data_export_path: ./recon_results/data_20250113.json
```

### Example 2: Document Metadata Analysis

```bash
# Analyze metadata from a directory
redops run config/pipelines/forensic_pipeline.json ~/Documents/project_files
```

**Findings might include:**
```
📄 Document Metadata Summary:
  - 15 PDF files analyzed
  - 8 unique authors identified
  - 3 documents contain GPS coordinates
  - 12 images with camera EXIF data
  - Creation dates spanning 2022-2025

⚠️ Privacy Concerns:
  - Report_Final.pdf contains author: "John Smith"
  - IMG_1234.jpg contains GPS: 37.7749° N, 122.4194° W
  - Proposal.docx has edit history with 4 contributors
```

### Example 3: Custom Pipeline

Create your own pipeline for specific needs:

```json
{
  "metadata": {
    "name": "Quick Security Scan",
    "description": "Fast security assessment for authorized targets",
    "version": "1.0"
  },
  "steps": [
    {
      "name": "Validate Scope",
      "module": "compliance.scope_guard.validate_scope",
      "enabled": true
    },
    {
      "name": "DNS Enumeration",
      "module": "recon.domains.enumerate_dns",
      "enabled": true
    },
    {
      "name": "Risk Assessment",
      "module": "intel.risk_scoring.calculate_risk",
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

Save as `config/pipelines/quick_scan.json` and run:

```bash
redops run config/pipelines/quick_scan.json target.com
```

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

We welcome contributions from the community! RedOps is designed to be a professional, ethical security assessment framework.

### How to Contribute

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Follow the coding standards and write tests
4. Commit your changes (`git commit -m 'feat: add amazing feature'`)
5. Push to your branch (`git push origin feature/amazing-feature`)
6. Open a Pull Request

### Contribution Guidelines

Please read our [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines on:

- Development setup and workflow
- Coding standards and style guide
- Testing requirements
- Pull request process
- Security considerations

### What We're Looking For

- 🐛 Bug fixes and improvements
- 📚 Documentation enhancements
- 🧪 Additional test coverage
- 🔧 New analysis modules (OSINT, metadata, intelligence)
- 📊 Reporting enhancements
- 🛡️ Security and scope validation improvements

### Code of Conduct

Be respectful, professional, and constructive. We're building tools for security professionals, and we expect contributors to maintain high ethical standards.

## License

MIT License - see LICENSE file for details

## Disclaimer

This tool is provided for educational and authorized security assessment purposes only. Users are responsible for complying with all applicable laws and regulations. The authors assume no liability for misuse of this software.

---

**RedOps** - Professional OSINT & Threat Modeling Framework
