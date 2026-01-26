# Scan Presets

RedOPS provides several pre-configured scan presets for common use cases.

## Available Presets

### quick

Fast reconnaissance with basic modules. Ideal for initial assessment.

**Modules:**
- Domain profiling
- Basic DNS enumeration

**Duration:** ~30 seconds

```bash
redops scan example.com --preset quick
```

### recon

Comprehensive reconnaissance without AI analysis.

**Modules:**
- Domain profiling
- Technology stack detection
- DNS enumeration
- Subdomain discovery
- Infrastructure analysis

**Duration:** 2-5 minutes

```bash
redops scan example.com --preset recon
```

### full

Complete security assessment with all modules.

**Modules:**
- All reconnaissance modules
- Threat intelligence lookups
- Compliance mapping
- Risk scoring

**Duration:** 5-10 minutes

```bash
redops scan example.com --preset full
```

### ai_enhanced

Full assessment with AI-powered analysis.

**Modules:**
- All `full` preset modules
- AI finding analysis
- Remediation suggestions
- Executive summary generation

**Requirements:** AI provider API key configured

**Duration:** 10-15 minutes

```bash
redops scan example.com --preset ai_enhanced
```

## Custom Module Selection

Run specific modules instead of a preset:

```bash
redops scan example.com --modules "domain_profile,tech_stack,cert_transparency"
```

## Pipeline Files

For advanced customization, create a pipeline JSON file:

```json
{
  "metadata": {
    "name": "Custom Assessment",
    "version": "1.0",
    "description": "Custom security assessment pipeline"
  },
  "steps": [
    {
      "name": "Domain Profile",
      "module": "recon.domains.profile_domain",
      "enabled": true
    },
    {
      "name": "Check IP Reputation",
      "module": "threat_intel.greynoise.query_greynoise",
      "enabled": true
    }
  ]
}
```

Run with:

```bash
redops run custom_pipeline.json example.com
```
