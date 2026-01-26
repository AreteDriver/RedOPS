# CLI Reference

Complete reference for RedOPS command-line interface.

## Global Options

```
--version           Show version
--help              Show help message
-v, --verbose       Enable verbose output
-c, --config FILE   Path to configuration file
```

## Commands

### scan

Run a security scan on a target.

```bash
redops scan TARGET [OPTIONS]
```

**Arguments:**
- `TARGET`: Domain, URL, or IP to scan

**Options:**
- `--preset PRESET`: Scan preset (quick, recon, full, ai_enhanced)
- `--output-dir DIR`: Output directory
- `--modules MODULES`: Comma-separated list of modules

**Examples:**
```bash
redops scan example.com --preset quick
redops scan example.com --preset recon --output-dir ./reports
redops scan example.com --modules "domain_profile,tech_stack"
```

### explain

Get AI explanation of a security concept.

```bash
redops explain TOPIC [OPTIONS]
```

**Arguments:**
- `TOPIC`: Security concept to explain

**Options:**
- `--provider PROVIDER`: AI provider
- `--model MODEL`: Model to use

**Examples:**
```bash
redops explain "SQL injection"
redops explain "XSS prevention" --provider anthropic
```

### analyze

Analyze security findings.

```bash
redops analyze SCAN_ID [OPTIONS]
```

**Arguments:**
- `SCAN_ID`: ID of scan to analyze

**Options:**
- `--provider PROVIDER`: AI provider
- `--model MODEL`: Model to use

### suggest

Get remediation suggestions.

```bash
redops suggest SCAN_ID [OPTIONS]
```

**Arguments:**
- `SCAN_ID`: ID of scan for suggestions

### summarize

Generate executive summary.

```bash
redops summarize SCAN_ID [OPTIONS]
```

**Arguments:**
- `SCAN_ID`: ID of scan to summarize

### chat

Start interactive AI chat session.

```bash
redops chat [OPTIONS]
```

**Options:**
- `--provider PROVIDER`: AI provider
- `--context SCAN_ID`: Scan context to load

### settings

Configure API keys and providers.

```bash
redops settings
```

Opens interactive settings menu.

### plugin

Manage plugins.

```bash
redops plugin COMMAND [OPTIONS]
```

**Subcommands:**
- `list`: List available plugins
- `load NAME`: Load a plugin
- `enable NAME`: Enable a plugin
- `disable NAME`: Disable a plugin
- `info NAME`: Show plugin information

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | General error |
| 2 | Configuration error |
| 3 | Target out of scope |
| 4 | Network error |
| 5 | AI provider error |
