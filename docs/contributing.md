# Contributing

Guidelines for contributing to RedOPS.

## Development Setup

1. Clone the repository:
```bash
git clone https://github.com/AreteDriver/RedOPS.git
cd RedOPS
```

2. Create virtual environment:
```bash
python -m venv .venv
source .venv/bin/activate
```

3. Install development dependencies:
```bash
pip install -e ".[dev,docs]"
```

4. Run tests:
```bash
pytest
```

## Code Style

We use `ruff` for linting and formatting:

```bash
# Check
ruff check .

# Fix auto-fixable issues
ruff check . --fix

# Format
ruff format .
```

## Testing

- Write tests for new functionality
- Maintain >80% coverage for new code
- Use pytest fixtures and mocks appropriately

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=redops --cov-report=html

# Run specific test
pytest tests/test_my_module.py -v
```

## Documentation

Build documentation locally:

```bash
cd docs
make html
```

View at `docs/_build/html/index.html`

## Pull Request Process

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests and linting
5. Submit a pull request

### PR Checklist

- [ ] Tests pass (`pytest`)
- [ ] Linting passes (`ruff check .`)
- [ ] Documentation updated if needed
- [ ] Changelog entry added for significant changes
- [ ] Commit messages follow conventional commits

## Commit Messages

Use conventional commit format:

```
feat: add subdomain enumeration module
fix: handle timeout in DNS queries
docs: update getting started guide
refactor: simplify pipeline runner logic
test: add integration tests for pipelines
```
