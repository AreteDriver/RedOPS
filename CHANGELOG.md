# Changelog

All notable changes to RedOPS will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Plugin System Integration**
  - Plugin CLI: `redops plugin list|load|enable|disable|info`
  - Pipeline hooks: BEFORE_PIPELINE, AFTER_PIPELINE, BEFORE_MODULE, AFTER_MODULE, ON_ERROR
  - Plugin-based modules via `plugin:name` references in pipelines
  - Auto-discovery from `~/.config/redops/plugins/` and `./plugins/`

- **Shodan Intelligence Module**
  - Host information (ports, services, banners)
  - DNS records and subdomain discovery
  - Vulnerability detection (CVEs)
  - Search capabilities

- **Censys Intelligence Module**
  - Host/IP information
  - Certificate transparency data
  - Certificate search
  - ASN and organization data

## [1.2.0] - 2026-01-24

### Added
- **AI Providers**
  - Groq provider for fast inference (llama-3.3-70b, mixtral-8x7b, gemma2-9b)
  - Now supports 6 providers: OpenAI, Anthropic, Gemini, Ollama, Groq

- **Web Dashboard**
  - FastAPI-based REST API (`redops-web`)
  - Interactive web dashboard with real-time scan progress
  - API documentation at /api/docs (Swagger UI)
  - Background scan execution with progress tracking
  - `[web]` optional dependencies (fastapi, uvicorn)

- **MCP Server**
  - Model Context Protocol server for Claude Code integration (`redops-mcp`)
  - Tools: redops_scan, redops_explain, redops_analyze, redops_suggest, redops_summarize
  - JSON-RPC over stdio transport

### Fixed
- AI summarizer tests now properly mock AIAssistant

## [1.1.0] - 2025-01-25

### Added
- **Docker Support**
  - Multi-stage Dockerfile with non-root user
  - docker-compose.yml for easy deployment
  - GHCR publishing in release workflow

- **Scheduling & Notifications**
  - systemd service and timer for scheduled scans
  - Cron examples for various schedules
  - Slack webhook notifications
  - Discord webhook notifications
  - Email notifications via SMTP
  - Generic webhook support

- **Reporting**
  - PDF report generation with fpdf2
  - STIX 2.1 threat intelligence export
  - Professional report formatting with severity badges

- **CLI Enhancements**
  - `--provider` and `--model` flags for AI commands
  - Bash completion script
  - Zsh completion script
  - Man page (redops.1)

- **Documentation**
  - CHANGELOG.md
  - Example scripts (quick_scan.py, ai_analysis.py, generate_reports.py)
  - Updated SETUP.md with Docker, AI, scheduling docs
  - CI badges in README

- **Development**
  - `[dev]` optional dependencies group
  - `[ai]` optional dependencies group
  - PyPI publishing workflow with OIDC
  - Integration test for ai_enhanced preset

### Changed
- Updated Anthropic model names to current versions (claude-sonnet-4)
- Added fpdf2 to `[full]` dependencies
- Improved release workflow with GHCR and better install instructions

## [1.0.0] - 2025-01-24

### Added
- **Core Framework**
  - Pipeline-based modular architecture
  - Context object for data flow between modules
  - Comprehensive configuration management
  - Plugin system for extensibility

- **Reconnaissance Modules**
  - Domain profiling (DNS, WHOIS)
  - Technology stack detection
  - Social OSINT gathering
  - Exposure scanning
  - Infrastructure analysis

- **Analysis Modules**
  - Threat intelligence correlation
  - Risk scoring engine
  - Compliance mapping
  - Finding correlation

- **AI Integration**
  - AI-powered finding analysis
  - Security concept explanations
  - Remediation suggestions
  - Executive summary generation
  - Interactive chat mode
  - Support for OpenAI and Anthropic

- **Reporting**
  - Executive reports (Markdown/HTML)
  - Technical reports
  - JSON/CSV data export
  - Multiple output formats

- **CLI**
  - Unified command-line interface
  - Scan presets (quick, recon, full, ai_enhanced)
  - Interactive settings menu
  - API key management

- **Infrastructure**
  - Async processing support
  - Caching layer
  - Rate limiting
  - Audit logging
  - Scope validation

- **DevOps**
  - GitHub Actions CI pipeline
  - Automated testing (1700+ tests)
  - Linting and type checking
  - Desktop launcher

### Security
- Non-root Docker user
- Scope enforcement for authorized targets
- Safe-by-default configuration
- Audit trail for all operations

[Unreleased]: https://github.com/AreteDriver/RedOPS/compare/v1.2.0...HEAD
[1.2.0]: https://github.com/AreteDriver/RedOPS/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/AreteDriver/RedOPS/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/AreteDriver/RedOPS/releases/tag/v1.0.0
