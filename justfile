# List available commands
@default:
    just --list


# Run tests
@test:
    pytest

# Run tests with coverage as configured in pyproject.toml
@test-cov:
    pytest -xvs --cov=aws_policies_analyzer --cov-report=term-missing

# Format code with black and isort
@format:
    isort src tests
    black src tests

# Check formatting without making changes
@check-format:
    isort --check src tests
    black --check src tests

# Run linting checks
@lint:
    flake8 --ignore=E501 src tests
    mypy src 

# Run all checks (format verification, lint, test)
@check: check-format lint test

# Clean build artifacts
@clean:
    rm -rf build dist *.egg-info
    find . -type d -name "__pycache__" -exec rm -rf {} +
    find . -type f -name "*.pyc" -delete

# Install the package
@install:
    [ -d .venv ] || python -m venv .venv
    source .venv/bin/activate && pip install .

# Install the package in development mode
@dev:
    [ -d .venv ] || python -m venv .venv
    source .venv/bin/activate && pip install -e ".[dev]"
