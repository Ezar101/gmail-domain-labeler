# Contributing to Gmail Domain Labeler

Thank you for your interest in contributing to Gmail Domain Labeler! This document provides guidelines and instructions for contributing.

## Development Setup

1. Fork the repository
2. Clone your fork:

```bash
git clone https://github.com/Ezar101/gmail-domain-labeler.git
cd gmail-domain-labeler
```

1. Create a virtual environment ([docs here](https://packaging.python.org/en/latest/guides/installing-using-pip-and-virtual-environments/)):

```bash
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
```

1. Install development dependencies:

```bash
pip install -r requirements-dev.txt
```

1. Install pre-commit hooks:

```bash
pre-commit install
```

## Code Style

- Follow PEP 8 guidelines
- Use type hints
- Write docstrings for all functions and classes
- Run black for code formatting
- Use flake8 for linting
- Use mypy for type checking

## Testing

- Write tests for all new features
- Maintain or improve test coverage
- Run tests before submitting PR:

```bash
# Run tests with coverage
pytest --cov=src tests/

# Run tests with detailed report
pytest -v tests/
```

## Pull Request Process

1. Create a new branch for your feature/fix
2. Make your changes
3. Add tests for new functionality
4. Update documentation if needed
5. Ensure all tests pass
6. Submit a PR with a clear description of changes

## Code Review

- All submissions must be reviewed
- Update your PR based on review feedback
- Maintain a professional and respectful tone

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
