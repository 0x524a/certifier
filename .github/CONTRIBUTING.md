# Contributing to Certifier

Thank you for your interest in contributing to Certifier! We welcome contributions from the community.

## Code of Conduct

Please be respectful and constructive in all interactions with the community.

## How Can I Contribute?

### Reporting Bugs

Before creating bug reports, please check the existing issues to avoid duplicates. When you create a bug report, include as many details as possible:

- Use a clear and descriptive title
- Describe the exact steps to reproduce the problem
- Provide specific examples to demonstrate the steps
- Describe the behavior you observed and what you expected to see
- Include code samples and error messages
- Specify your environment (Go version, OS, certifier version)

### Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues. When creating an enhancement suggestion:

- Use a clear and descriptive title
- Provide a detailed description of the proposed feature
- Explain why this enhancement would be useful
- List any alternatives you've considered

### Pull Requests

1. **Fork the repository** and create your branch from `main`
2. **Make your changes** following our coding standards
3. **Add tests** for any new functionality
4. **Ensure all tests pass**: `go test ./...`
5. **Run linting**: `golangci-lint run`
6. **Format your code**: `gofmt -w .`
7. **Commit your changes** with clear, descriptive messages
8. **Push to your fork** and submit a pull request

## Development Setup

### Prerequisites

- Go 1.22 or higher
- golangci-lint (for linting)

### Getting Started

```bash
# Clone the repository
git clone https://github.com/0x524a/certifier.git
cd certifier

# Install dependencies
go mod download

# Run tests
go test -v ./...

# Build the CLI
make build
```

## Coding Guidelines

### Go Code Style

- Follow standard Go conventions and idioms
- Use `gofmt` for formatting
- Keep functions focused and modular
- Add comments for exported functions and complex logic
- Use meaningful variable and function names

### Testing

- Write unit tests for all new functionality
- Aim for high test coverage (we maintain >85% coverage)
- Use table-driven tests where appropriate
- Include both positive and negative test cases

### Documentation

- Update README.md for user-facing changes
- Add godoc comments for all exported functions, types, and constants
- Update examples when API changes
- Keep documentation clear and concise

### Commit Messages

Follow conventional commit format:

```
<type>(<scope>): <subject>

<body>

<footer>
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation only changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring
- `perf`: Performance improvements
- `test`: Adding or updating tests
- `chore`: Maintenance tasks

Example:
```
feat(cert): add RSA-PSS signature support

Add support for RSA-PSS probabilistic signature scheme for enhanced
security. This includes a new UseRSAPSS flag in CertificateConfig and
updates to signature algorithm selection.

Fixes #123
```

## Project Structure

```
.
├── cmd/certifier/          # CLI application
├── pkg/                    # Public library packages
│   ├── cert/              # Certificate operations
│   ├── crl/               # CRL management
│   ├── encoding/          # Format encoding/decoding
│   ├── ocsp/              # OCSP support
│   └── validation/        # Validation logic
├── internal/              # Internal packages
│   └── cli/              # CLI implementation
├── .github/              # GitHub templates and workflows
└── test/                 # Integration tests
```

## Review Process

1. **Automated Checks**: Your PR will run through automated tests, linting, and code quality checks
2. **Code Review**: Maintainers will review your code for quality, style, and correctness
3. **Feedback**: Address any requested changes
4. **Approval**: Once approved, a maintainer will merge your PR

## Getting Help

- **Questions**: Open a [Discussion](https://github.com/0x524a/certifier/discussions)
- **Chat**: Join our community discussions
- **Documentation**: Check the [README](../README.md) and code documentation

## Recognition

Contributors will be recognized in our release notes and README.

Thank you for contributing to Certifier! 🎉
