.PHONY: help install dev-install test test-all lint format type-check security check clean pre-commit-install

help:  ## Show this help message
	@echo "CTF Kit - Development Commands"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

install:  ## Install package in editable mode
	uv pip install -e .

dev-install:  ## Install with development dependencies
	uv pip install -e ".[dev]"
	pre-commit install

test:  ## Run tests (excluding slow/integration tests)
	pytest -m "not slow and not integration"

test-all:  ## Run all tests including slow and integration
	pytest

test-watch:  ## Run tests in watch mode
	pytest-watch

lint:  ## Run linting checks
	@echo "Running ruff..."
	ruff check src/ tests/
	@echo "Running bandit..."
	bandit -r src/ -c pyproject.toml

format:  ## Format code with ruff
	ruff check --fix src/ tests/
	ruff format src/ tests/

type-check:  ## Run type checking with mypy
	mypy src/

security:  ## Run security checks
	bandit -r src/ -c pyproject.toml

check: lint type-check test  ## Run all checks (lint, type, test)
	@echo "✅ All checks passed!"

clean:  ## Clean build artifacts and cache
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info
	rm -rf .pytest_cache/
	rm -rf .mypy_cache/
	rm -rf .ruff_cache/
	rm -rf htmlcov/
	rm -rf .coverage
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete

pre-commit-install:  ## Install pre-commit hooks
	pre-commit install
	pre-commit install --hook-type commit-msg

pre-commit-run:  ## Run pre-commit on all files
	pre-commit run --all-files

build:  ## Build distribution packages
	python -m build

install-tools:  ## Install common CTF tools (Linux/Mac)
	@echo "Installing common CTF tools..."
	@echo "Note: This requires sudo for some tools"
	@if [ "$$(uname)" = "Linux" ]; then \
		sudo apt-get update && \
		sudo apt-get install -y file binutils strings exiftool; \
	elif [ "$$(uname)" = "Darwin" ]; then \
		brew install file binutils exiftool; \
	else \
		echo "Unsupported OS. Please install tools manually."; \
	fi

.DEFAULT_GOAL := help
