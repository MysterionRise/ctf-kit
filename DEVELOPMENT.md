# Development Guide

## Setup

### Prerequisites

- Python 3.11 or higher
- Git

### Initial Setup

```bash
# Clone the repository
git clone <repo-url>
cd ctf-kit

# Create virtual environment
python3.11 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install development dependencies
pip install -e ".[dev]"

# Install pre-commit hooks
pre-commit install
```

## Quality Checks

### Pre-commit Hooks

Pre-commit hooks are automatically installed and run before each commit. They include:

- **Ruff**: Fast Python linter and formatter
- **MyPy**: Static type checking
- **Bandit**: Security vulnerability scanning
- **pytest**: Automated tests with 80% coverage requirement
- **Markdown linting**: Ensures documentation quality

### Manual Checks

```bash
# Run all checks
make check

# Individual checks
make lint          # Ruff linting
make format        # Auto-format code
make type-check    # MyPy type checking
make test          # Run tests
make security      # Security scan
```

### Pre-commit Commands

```bash
# Run all hooks on all files
pre-commit run --all-files

# Run specific hook
pre-commit run ruff --all-files
pre-commit run mypy --all-files

# Update hooks to latest versions
pre-commit autoupdate
```

## Development Workflow

### 1. Before Making Changes

```bash
# Ensure you're on latest main
git checkout main
git pull

# Create feature branch
git checkout -b feature/your-feature-name
```

### 2. During Development

```bash
# Run tests frequently
make test

# Check types
make type-check

# Format code
make format
```

### 3. Before Committing

Pre-commit hooks will run automatically, but you can run them manually:

```bash
make check
```

### 4. Commit Standards

- **Clear commit messages**: Describe what and why
- **Small commits**: One logical change per commit
- **All checks passing**: Pre-commit hooks must pass

Example commit messages:

```text
feat: add file type detection tool
fix: handle missing binary in tool wrapper
docs: update installation instructions
test: add tests for analyze command
```

## Code Standards

### Type Hints

All functions must have type hints:

```python
def analyze_file(path: Path) -> ToolResult:
    """Analyze a file."""
    ...
```

### Error Handling

Use specific exceptions:

```python
from ctf_kit.exceptions import ToolNotFoundError

if not self.is_installed:
    raise ToolNotFoundError(f"{self.name} is not installed")
```

### Testing

All new code must include tests:

```python
def test_file_tool_detects_type():
    """Test that FileTool correctly identifies file types."""
    tool = FileTool()
    result = tool.run(Path("test.txt"))
    assert result.success
    assert "text" in result.parsed_data["type"]
```

### Documentation

- **Docstrings**: All public functions and classes
- **Type hints**: All parameters and return values
- **Comments**: Only for complex logic

## Testing

### Running Tests

```bash
# All tests
make test

# Specific test file
pytest tests/test_file_tool.py

# Specific test
pytest tests/test_file_tool.py::test_file_detection

# With coverage report
pytest --cov=ctf_kit --cov-report=html
# Open htmlcov/index.html in browser

# Skip slow tests
pytest -m "not slow"

# Skip integration tests (require tools installed)
pytest -m "not integration"
```

### Writing Tests

Tests are organized by module:

```text
tests/
├── test_cli.py                 # CLI tests
├── test_commands.py            # Command tests
├── test_integrations.py        # Tool integration tests
└── fixtures/                   # Test files and data
```

Use fixtures for common setup:

```python
@pytest.fixture
def tmp_challenge_dir(tmp_path: Path) -> Path:
    """Create a temporary challenge directory."""
    challenge_dir = tmp_path / "test-challenge"
    challenge_dir.mkdir()
    (challenge_dir / "file.txt").write_text("test")
    return challenge_dir
```

## Coverage Requirements

- **Minimum**: 80% overall coverage
- **Target**: 90%+ for core modules
- **Exclusions**: Tests, abstract methods, CLI entry points

Check coverage:

```bash
pytest --cov=ctf_kit --cov-report=term-missing
```

## Linting Rules

### Ruff Configuration

Ruff enforces:

- **PEP 8**: Code style
- **Security**: flake8-bandit rules
- **Type checking**: Type annotation enforcement
- **Complexity**: Max complexity limits
- **Best practices**: Modern Python idioms

See `pyproject.toml` for full configuration.

### Ignoring Rules

Only when absolutely necessary:

```python
# noqa: S101 - Allow assert in this specific case
assert condition, "This is safe"
```

## Common Issues

### Pre-commit Hook Failures

**Ruff formatting issues:**

```bash
make format
git add -u
git commit
```

**Type checking errors:**

```bash
mypy src/
# Fix reported issues
```

**Test failures:**

```bash
pytest -v
# Fix failing tests
```

**Coverage below 80%:**

```bash
# Add tests for uncovered code
pytest --cov=ctf_kit --cov-report=html
# Open htmlcov/index.html to see what's missing
```

### MyPy Issues

**Import not found:**

```bash
# Install type stubs
pip install types-<package>
```

**Untyped call:**

Add type annotations or use `# type: ignore[...]` with explanation.

## Release Process

```bash
# Update version in pyproject.toml
# Update CHANGELOG.md

# Run all checks
make check

# Build distribution
make build

# Tag release
git tag -a v0.1.0 -m "Release v0.1.0"
git push origin v0.1.0
```

## CI/CD

GitHub Actions runs on every push:

1. Linting (ruff, bandit)
2. Type checking (mypy)
3. Tests (pytest) on Python 3.11 and 3.12
4. Build distribution

See `.github/workflows/ci.yml` for details.

## Troubleshooting

### Pre-commit Installation Issues

```bash
# Clean and reinstall
rm -rf ~/.cache/pre-commit
pre-commit clean
pre-commit install --install-hooks
```

### Virtual Environment Issues

```bash
# Recreate venv
rm -rf .venv
python3.11 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

### Tool Installation

```bash
# Install system tools (Linux)
make install-tools

# Or manually
sudo apt-get install file binutils exiftool

# Mac
brew install file binutils exiftool
```

## Resources

- [Ruff Documentation](https://docs.astral.sh/ruff/)
- [MyPy Documentation](https://mypy.readthedocs.io/)
- [pytest Documentation](https://docs.pytest.org/)
- [Pre-commit Documentation](https://pre-commit.com/)
