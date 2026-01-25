# Changelog

All notable changes to RedOPS will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Docker containerization with multi-stage build
- PyPI publishing workflow with trusted publishing (OIDC)
- CI badges in README (pipeline status, Python version, license)
- `[dev]` optional dependencies group (pytest, ruff, mypy)
- `--provider` and `--model` flags for AI commands
- AI features documentation in README
- Integration test for ai_enhanced preset

### Changed
- Updated Anthropic model names to current versions
- Improved release workflow with better install instructions

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

[Unreleased]: https://github.com/AreteDriver/RedOPS/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/AreteDriver/RedOPS/releases/tag/v1.0.0
