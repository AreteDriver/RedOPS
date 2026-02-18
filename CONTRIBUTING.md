# Contributing to RedOps

Thank you for your interest in contributing to RedOps! This document provides guidelines and instructions for contributing to the project.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [How to Contribute](#how-to-contribute)
- [Coding Standards](#coding-standards)
- [Testing Guidelines](#testing-guidelines)
- [Pull Request Process](#pull-request-process)
- [Security Guidelines](#security-guidelines)

## Code of Conduct

### Our Pledge

We are committed to providing a welcoming and inclusive environment for all contributors. Please be respectful, professional, and constructive in all interactions.

### Expected Behavior

- Use welcoming and inclusive language
- Respect differing viewpoints and experiences
- Accept constructive criticism gracefully
- Focus on what is best for the community
- Show empathy towards other community members

## Getting Started

### Prerequisites

- Python 3.10 or higher
- Git
- Basic understanding of OSINT, security assessment, or related fields
- Familiarity with modular Python development

### Finding Ways to Contribute

- Browse open issues labeled `good first issue` or `help wanted`
- Check the project roadmap for planned features
- Report bugs or suggest enhancements
- Improve documentation
- Write tests for existing code
- Review pull requests

## Development Setup

### 1. Fork and Clone

```bash
# Fork the repository on GitHub, then clone your fork
git clone https://github.com/YOUR_USERNAME/RedOPS.git
cd RedOPS
```

### 2. Create a Virtual Environment

```bash
# Create virtual environment
python3 -m venv venv

# Activate virtual environment
# On Linux/macOS:
source venv/bin/activate
# On Windows:
venv\Scripts\activate
```

### 3. Install Dependencies

```bash
# Install in development mode with all dependencies
pip install -e ".[full]"

# Install development dependencies
pip install pytest pytest-cov black flake8 mypy
```

### 4. Verify Installation

```bash
# Test the CLI
redops --version
redops list

# Run existing tests
pytest tests/
```

## How to Contribute

### Reporting Bugs

Before submitting a bug report:
1. Check if the issue already exists
2. Verify you're using the latest version
3. Collect relevant information (Python version, OS, error messages)

When submitting a bug report, include:
- Clear, descriptive title
- Steps to reproduce
- Expected vs actual behavior
- System information
- Relevant logs or screenshots

### Suggesting Enhancements

Enhancement suggestions are welcome! Please include:
- Clear use case and motivation
- Proposed solution or implementation approach
- Any alternatives considered
- Impact on existing functionality

### Submitting Code Changes

1. **Create a feature branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes**
   - Write clear, focused commits
   - Follow coding standards (see below)
   - Add tests for new functionality
   - Update documentation as needed

3. **Test your changes**
   ```bash
   # Run tests
   pytest tests/
   
   # Check code style
   black src/ tests/
   flake8 src/ tests/
   
   # Type checking (optional but recommended)
   mypy src/
   ```

4. **Commit your changes**
   ```bash
   git add .
   git commit -m "feat: add new feature description"
   ```

5. **Push to your fork**
   ```bash
   git push origin feature/your-feature-name
   ```

6. **Open a Pull Request**

## Coding Standards

### Python Style

- Follow [PEP 8](https://pep8.org/) style guide
- Use [Black](https://black.readthedocs.io/) for code formatting (line length: 100)
- Use type hints for function signatures
- Write docstrings for all public functions and classes

### Docstring Format

```python
def my_function(ctx: Context, params: Optional[Dict[str, Any]] = None) -> Context:
    """
    Short description of the function.
    
    Longer description if needed, explaining the purpose and behavior.
    
    Args:
        ctx: Pipeline context object
        params: Optional parameters dictionary
        
    Returns:
        Updated context object
        
    Raises:
        ValueError: If validation fails
    """
    pass
```

### Module Structure

All pipeline modules must follow this interface:

```python
from redops.core.context import Context
from typing import Optional, Dict, Any

def module_name(ctx: Context, params: Optional[Dict[str, Any]] = None) -> Context:
    """Module implementation."""
    # 1. Validate inputs
    # 2. Log start
    # 3. Perform work
    # 4. Store results in context
    # 5. Log completion
    return ctx
```

### Commit Message Format

Follow [Conventional Commits](https://www.conventionalcommits.org/):

- `feat:` New feature
- `fix:` Bug fix
- `docs:` Documentation changes
- `test:` Adding or updating tests
- `refactor:` Code refactoring
- `style:` Formatting changes
- `chore:` Maintenance tasks

Example:
```
feat: add subdomain enumeration module

Implements subdomain discovery using certificate transparency
logs and DNS brute-forcing with user-provided wordlists.
```

## Testing Guidelines

### Writing Tests

- Write tests for all new functionality
- Use pytest framework
- Follow existing test patterns
- Aim for meaningful test coverage, not just high percentages

### Test Structure

```python
import pytest
from redops.core.context import Context
from redops.modules.your_module import your_function

def test_your_function_success():
    """Test successful execution."""
    ctx = Context(target="example.com")
    result = your_function(ctx)
    assert result is not None
    assert "expected_key" in result.data

def test_your_function_edge_case():
    """Test edge case handling."""
    ctx = Context(target="")
    result = your_function(ctx)
    # Verify appropriate handling
```

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=redops --cov-report=html

# Run specific test file
pytest tests/test_your_module.py

# Run specific test
pytest tests/test_your_module.py::test_your_function
```

## Pull Request Process

### Before Submitting

- [ ] Code follows project style guidelines
- [ ] All tests pass
- [ ] New tests added for new functionality
- [ ] Documentation updated
- [ ] Commit messages follow convention
- [ ] No merge conflicts with main branch

### PR Description

Include:
- Summary of changes
- Related issue number (if applicable)
- Type of change (bug fix, feature, docs, etc.)
- Testing performed
- Screenshots (if UI changes)

### Review Process

1. Automated checks will run on your PR
2. Maintainers will review your code
3. Address any feedback or requested changes
4. Once approved, your PR will be merged

### After Merge

- Your contribution will be credited in release notes
- Delete your feature branch
- Pull the latest changes to your fork

## Security Guidelines

### Responsible Development

RedOps is a security assessment tool. All contributions must:

- **Never** include exploits or vulnerability scanning
- **Never** include credential harvesting or brute-force capabilities
- **Always** respect scope validation and ethical boundaries
- **Always** operate on authorized targets only
- Focus on OSINT, metadata analysis, and threat modeling

### Security Vulnerabilities

If you discover a security vulnerability:

1. **DO NOT** open a public issue
2. Email the maintainers privately
3. Provide details about the vulnerability
4. Wait for acknowledgment before public disclosure

### Code Review Checklist

When reviewing security-related code:
- Validates input appropriately
- Respects scope boundaries
- Logs all operations for audit
- Contains no hardcoded credentials
- Uses safe-by-default configurations

## Project Structure

Understanding the codebase:

```
RedOPS/
├── src/redops/
│   ├── core/              # Core components (Context, Config, Models)
│   ├── pipelines/         # Pipeline system (Loader, Runner, Schemas)
│   ├── modules/           # Feature modules
│   │   ├── recon/         # Reconnaissance modules
│   │   ├── metadata/      # Metadata extraction
│   │   ├── intel/         # Intelligence analysis
│   │   ├── simulation/    # Threat modeling
│   │   ├── reporting/     # Report generation
│   │   ├── compliance/    # Scope validation & audit
│   │   └── corp_assessment/ # Corporate assessment tools
│   └── main.py           # CLI entry point
├── tests/                 # Test suite
├── config/               # Configuration and pipeline definitions
└── docs/                 # Documentation
```

## Getting Help

- Check the [README.md](README.md) for general documentation
- Browse existing issues and discussions
- Ask questions in issue comments
- Reach out to maintainers for guidance

## License

By contributing to RedOps, you agree that your contributions will be licensed under the MIT License.

---

Thank you for contributing to RedOps! Together we can build a powerful, ethical, and professional security assessment framework.
