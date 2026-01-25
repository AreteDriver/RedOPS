# RedOps Installation & Setup Guide

This guide provides detailed instructions for installing and configuring RedOps on various platforms.

## Table of Contents

- [System Requirements](#system-requirements)
- [Installation Methods](#installation-methods)
- [Dependency Installation](#dependency-installation)
- [Verification](#verification)
- [Configuration](#configuration)
- [Troubleshooting](#troubleshooting)

## System Requirements

### Minimum Requirements

- **Python**: 3.8 or higher
- **Operating System**: Linux, macOS, or Windows
- **Memory**: 512 MB RAM (2 GB recommended)
- **Disk Space**: 500 MB

### Recommended Requirements

- **Python**: 3.10 or higher
- **Memory**: 4 GB RAM
- **Disk Space**: 2 GB (for dependencies and output files)

## Installation Methods

### Method 1: Installation from Source (Recommended for Development)

```bash
# 1. Clone the repository
git clone https://github.com/AreteDriver/RedOPS.git
cd RedOPS

# 2. Create a virtual environment (recommended)
python3 -m venv venv

# 3. Activate the virtual environment
# On Linux/macOS:
source venv/bin/activate
# On Windows:
venv\Scripts\activate

# 4. Install RedOps in development mode
pip install -e .

# 5. Verify installation
redops --version
```

### Method 2: Install with All Features

For full functionality including image analysis, document parsing, and advanced reporting:

```bash
# After cloning and activating virtual environment
pip install -e ".[full]"
```

This installs additional dependencies:
- Pillow (image processing)
- dnspython (DNS enumeration)
- requests (HTTP requests)
- jinja2 (report templating)
- fpdf2 (PDF report generation)

### Method 3: Install with AI Features

For AI-powered analysis (requires API key):

```bash
pip install -e ".[ai]"
```

This installs:
- anthropic (Claude AI)
- openai (GPT models)

### Method 4: Install Everything

```bash
pip install -e ".[all]"
```

### Method 5: Docker Installation

```bash
# Build image
docker build -t redops .

# Run container
docker run --rm redops --help

# Run with environment variables
docker run --rm \
  -e ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY \
  -v $(pwd)/output:/app/output \
  redops scan example.com --preset quick
```

Using Docker Compose:

```bash
docker-compose run redops scan example.com --preset quick
```

### Method 6: Install from PyPI

```bash
# Minimal installation
pip install redops

# Full installation
pip install redops[full]
```

## Dependency Installation

### Core Dependencies

The minimal installation includes:
- `pydantic>=2.0.0` - Data validation and settings management

### Optional Dependencies

Install these for specific features:

#### Image Metadata Analysis

```bash
pip install Pillow exifread
```

#### Document Analysis (PDF, Word, Excel)

```bash
pip install PyPDF2 python-docx openpyxl python-pptx
```

#### DNS and Network Reconnaissance

```bash
pip install dnspython requests
```

#### Data Analysis and Risk Scoring

```bash
pip install scikit-learn numpy pandas
```

#### Report Generation and Visualization

```bash
pip install jinja2 matplotlib networkx
```

#### Natural Language Processing (Advanced)

```bash
# Install spaCy
pip install spacy

# Download English language model
python -m spacy download en_core_web_sm
```

### Development Dependencies

For contributing to RedOps:

```bash
pip install pytest pytest-cov black flake8 mypy
```

## Verification

### 1. Check Installation

```bash
# Verify CLI is available
redops --version

# Should output: RedOps 1.0.0
```

### 2. List Available Pipelines

```bash
redops list

# Should display available pipelines
```

### 3. Run Tests (Development Installation)

```bash
# Run all tests
pytest tests/

# Run with coverage
pytest tests/ --cov=redops

# Expected: 62 passed tests
```

### 4. Test a Simple Pipeline

```bash
# Create a test configuration (in permissive mode for testing)
mkdir -p output

# Run a reconnaissance pipeline (replace with your authorized domain)
redops run config/pipelines/recon_pipeline.json example.com --output-dir ./output
```

## Configuration

### Basic Configuration

Create a `config.json` file in your project directory:

```json
{
  "scope": {
    "allowed_domains": ["yourdomain.com"],
    "allowed_ips": [],
    "allowed_directories": ["/home/user/projects"],
    "strict_mode": true
  },
  "output": {
    "output_dir": "./output",
    "format": "markdown",
    "include_logs": true,
    "verbose": false
  }
}
```

### Environment Variables

Configure RedOps using environment variables:

```bash
# Output directory
export REDOPS_OUTPUT_DIR="./reports"

# Enable verbose logging
export REDOPS_VERBOSE="true"

# Enable strict scope validation
export REDOPS_STRICT_SCOPE="true"

# AI API Keys (for AI-powered features)
export ANTHROPIC_API_KEY="your-key-here"
export OPENAI_API_KEY="your-key-here"

# Notification Webhooks
export SLACK_WEBHOOK_URL="https://hooks.slack.com/..."
export DISCORD_WEBHOOK_URL="https://discord.com/api/webhooks/..."
```

### API Key Configuration

Configure AI API keys for AI-powered analysis:

```bash
# Interactive setup
redops apikey set -p anthropic

# List configured keys
redops apikey list

# Or use the settings menu
redops settings
```

### Shell Completions

Enable tab completion for bash or zsh:

```bash
# Bash
source completions/redops.bash

# Or add to ~/.bashrc
echo 'source /path/to/RedOPS/completions/redops.bash' >> ~/.bashrc

# Zsh - add to fpath
fpath=(/path/to/RedOPS/completions $fpath)
autoload -Uz compinit && compinit
```

### Scope Configuration

**Important**: Always configure scope before running assessments:

```json
{
  "scope": {
    "allowed_domains": [
      "example.com",
      "test.example.com"
    ],
    "allowed_ips": [
      "192.168.1.0/24"
    ],
    "allowed_directories": [
      "/home/user/authorized/projects"
    ],
    "strict_mode": true
  }
}
```

## Troubleshooting

### Common Issues

#### 1. `redops: command not found`

**Solution**:
- Ensure virtual environment is activated
- Verify installation: `pip show redops`
- Check PATH includes Python scripts directory

```bash
# Reinstall in development mode
pip install -e .
```

#### 2. Import Errors for Optional Dependencies

**Error**: `ModuleNotFoundError: No module named 'Pillow'`

**Solution**: Install optional dependencies

```bash
pip install -e ".[full]"
```

#### 3. Permission Denied Errors

**Solution**: Check directory permissions

```bash
# Create output directory with correct permissions
mkdir -p output
chmod 755 output
```

#### 4. Scope Validation Failures

**Error**: `ScopeViolationError: Target out of scope`

**Solution**: Add target to allowed scope in config

```bash
# Option 1: Use permissive mode for testing (NOT for production)
export REDOPS_STRICT_SCOPE="false"

# Option 2: Add domain to config.json
# Edit config.json and add your domain to allowed_domains
```

#### 5. Pipeline Execution Errors

**Issue**: Pipeline fails with missing module errors

**Solution**: Check pipeline configuration and dependencies

```bash
# Verify pipeline file exists
ls -la config/pipelines/

# Check pipeline JSON syntax
python -m json.tool config/pipelines/recon_pipeline.json
```

### Platform-Specific Issues

#### Windows

- Use `python` instead of `python3`
- Activate virtual environment: `venv\Scripts\activate`
- Path separators: use `\` or `\\` in paths

#### macOS

- May need to install Command Line Tools:
  ```bash
  xcode-select --install
  ```

#### Linux

- Ensure Python 3.8+ is installed:
  ```bash
  python3 --version
  ```
- Install pip if needed:
  ```bash
  sudo apt-get install python3-pip
  ```

### Getting Help

If you encounter issues:

1. Check the [README.md](README.md) for general documentation
2. Review [CONTRIBUTING.md](CONTRIBUTING.md) for development setup
3. Search existing [GitHub Issues](https://github.com/AreteDriver/RedOPS/issues)
4. Open a new issue with:
   - Python version (`python --version`)
   - Operating system
   - Error messages
   - Steps to reproduce

## Post-Installation Steps

### 1. Configure Scope

Edit `config/config.json` or create a new configuration file with your authorized targets.

### 2. Customize Pipelines

Create custom pipelines in `config/pipelines/` directory. See the [README](README.md#creating-custom-pipelines) for examples.

### 3. Review Security Guidelines

Read the [Security & Ethics](README.md#security--ethics) section in the README to understand proper usage.

### 4. Test Your Setup

```bash
# Run with verbose output to verify everything works
export REDOPS_VERBOSE="true"
redops run config/pipelines/recon_pipeline.json yourdomain.com

# Review logs in output directory
cat output/*.log
```

## Scheduled Scans

### Using systemd (Linux)

```bash
# Copy service and timer files
sudo cp config/systemd/redops-scan.service /etc/systemd/system/
sudo cp config/systemd/redops-scan.timer /etc/systemd/system/

# Create environment file
sudo mkdir -p /etc/redops
sudo cp config/systemd/redops.env.example /etc/redops/env
sudo nano /etc/redops/env  # Configure your settings

# Enable and start timer
sudo systemctl daemon-reload
sudo systemctl enable --now redops-scan.timer

# Check status
sudo systemctl status redops-scan.timer
```

### Using cron

```bash
# Edit crontab
crontab -e

# Add daily scan at 2 AM
0 2 * * * /path/to/venv/bin/redops scan example.com --preset quick -o /var/lib/redops/output
```

See `config/cron.example` for more examples.

## Notifications

Configure notifications to receive scan results:

```bash
# Set webhook URLs
export SLACK_WEBHOOK_URL="https://hooks.slack.com/..."
export DISCORD_WEBHOOK_URL="https://discord.com/api/webhooks/..."

# Notifications are sent automatically after scheduled scans
# Or use the notification script manually
./scripts/notify.sh
```

## Next Steps

- Review available [pipelines](config/pipelines/)
- Read the [API documentation](README.md#module-system)
- Explore [example usage scenarios](README.md#practical-examples)
- Configure [AI features](#api-key-configuration) for enhanced analysis
- Set up [scheduled scans](#scheduled-scans) for continuous monitoring
- Join the community and contribute

---

**Remember**: RedOps is for authorized security assessments only. Always obtain proper authorization before scanning or analyzing any target.
