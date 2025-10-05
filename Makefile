# Makefile for PII Incident Redaction Pipeline

.PHONY: help install install-dev test lint format clean docs run-example

# Default target
help:
	@echo "PII Incident Redaction Pipeline - Development Commands"
	@echo "======================================================"
	@echo ""
	@echo "Available commands:"
	@echo "  install      Install production dependencies"
	@echo "  install-dev  Install development dependencies"
	@echo "  test         Run test suite"
	@echo "  lint         Run code linting"
	@echo "  format       Format code with black"
	@echo "  clean        Clean up temporary files"
	@echo "  docs         Generate documentation"
	@echo "  run-example  Run basic usage example"
	@echo "  setup        Complete development setup"
	@echo ""

# Installation targets
install:
	pip install -e .
	python -m spacy download en_core_web_sm

install-dev: install
	pip install pytest pytest-asyncio pytest-cov black flake8 mypy pre-commit
	pre-commit install

# Development setup
setup: install-dev
	@echo "Setting up development environment..."
	@echo "✅ Dependencies installed"
	@echo "✅ Pre-commit hooks installed"
	@echo "✅ spaCy model downloaded"
	@echo ""
	@echo "Development environment ready!"
	@echo "Run 'make test' to verify installation"

# Testing
test:
	python tests/test_pipeline.py

test-verbose:
	python tests/test_pipeline.py --verbose

# Code quality
lint:
	flake8 src/ main.py examples/ tests/
	mypy src/ main.py

format:
	black src/ main.py examples/ tests/
	isort src/ main.py examples/ tests/

format-check:
	black --check src/ main.py examples/ tests/
	isort --check-only src/ main.py examples/ tests/

# Documentation
docs:
	@echo "Documentation is available in README.md"
	@echo "Run 'python process_incidents.py --help' for usage information"

# Examples
run-example:
	python examples/basic_usage.py

run-cli-example:
	python process_incidents.py data/test_samples/pagerduty_samples.jsonl --llm-simulation

# Cleanup
clean:
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -delete
	find . -type d -name "*.egg-info" -exec rm -rf {} +
	find . -type f -name "*.log" -delete
	rm -rf build/ dist/ .coverage htmlcov/ .pytest_cache/
	rm -rf output/ example_output/ test_results.json

# Security
security:
	bandit -r src/ main.py
	safety check

# Performance
profile:
	python -m cProfile -o profile.stats main.py --text "Sample text for profiling"

# Release
release-check:
	@echo "Checking release readiness..."
	python tests/test_pipeline.py
	make lint
	make format-check
	make security
	@echo "✅ Release checks passed"

# Docker (if needed)
docker-build:
	docker build -t pii-redaction .

docker-run:
	docker run -it pii-redaction

# CI/CD helpers
ci-test:
	python tests/test_pipeline.py --verbose

ci-lint:
	flake8 src/ main.py examples/ tests/
	mypy src/ main.py

ci-format-check:
	black --check src/ main.py examples/ tests/
	isort --check-only src/ main.py examples/ tests/
