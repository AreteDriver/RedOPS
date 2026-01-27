# Configuration

RedOPS can be configured via environment variables, configuration files, or command-line arguments.

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `REDOPS_CONFIG` | Path to config file | `~/.config/redops/config.yaml` |
| `REDOPS_OUTPUT_DIR` | Output directory | `./output` |
| `REDOPS_VERBOSE` | Enable verbose output | `false` |
| `ANTHROPIC_API_KEY` | Anthropic API key | - |
| `OPENAI_API_KEY` | OpenAI API key | - |
| `GROQ_API_KEY` | Groq API key | - |

### Web Dashboard Authentication

| Variable | Description | Default |
|----------|-------------|---------|
| `REDOPS_AUTH_ENABLED` | Enable authentication | `false` |
| `REDOPS_API_KEY` | API key for programmatic access | - |
| `REDOPS_ADMIN_USER` | Admin username | `admin` |
| `REDOPS_ADMIN_PASSWORD` | Admin password | - |
| `REDOPS_SESSION_EXPIRY_HOURS` | Session expiry time | `24` |
| `REDOPS_JWT_SECRET` | JWT signing key (required for API auth) | - |
| `DATABASE_URL` | PostgreSQL connection string (required) | - |
| `REDOPS_CORS_ORIGINS` | Comma-separated allowed origins | `http://localhost:8000` |
| `REDOPS_HTTPS` | Enable secure cookies | `false` |
| `REDOPS_SESSION_SECRET` | Session signing key | Auto-generated |

## Configuration File

Create `~/.config/redops/config.yaml`:

```yaml
# Scope configuration
scope:
  authorized_targets:
    - "example.com"
    - "*.example.com"
  excluded_targets:
    - "internal.example.com"

# Output settings
output:
  output_dir: "./output"
  verbose: false
  formats:
    - json
    - html

# AI provider settings
ai:
  default_provider: "anthropic"
  default_model: "claude-sonnet-4-20250514"

# Threat intelligence API keys
threat_intel:
  greynoise_api_key: "${GREYNOISE_API_KEY}"
  abuseipdb_api_key: "${ABUSEIPDB_API_KEY}"

# Rate limiting
rate_limit:
  requests_per_second: 10
  burst_limit: 50
```

## Command-Line Overrides

Most configuration options can be overridden via CLI:

```bash
# Override output directory
redops scan example.com --output-dir ./reports

# Use specific AI provider
redops explain "SQL injection" --provider openai --model gpt-4

# Verbose output
redops scan example.com -v
```

## Priority Order

Configuration is applied in this order (later overrides earlier):

1. Default values
2. Configuration file
3. Environment variables
4. Command-line arguments
