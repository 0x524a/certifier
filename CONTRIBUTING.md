# Contributing to Certifier

Thank you for your interest in contributing! This document provides guidelines for contributing to the certifier project.

## Development Setup

### Prerequisites
- Go 1.22 or later
- Git

### Building from Source
```bash
git clone https://github.com/0x524a/certifier.git
cd certifier
go build -o bin/certifier ./cmd/certifier
```

### Running Tests
```bash
# Run all tests
go test -v ./...

# Run tests with coverage
go test -v -coverprofile=coverage.out ./...
go tool cover -html=coverage.out

# Run specific test
go test -v -run TestName ./pkg/cert
```

### Code Quality

We use the following tools to maintain code quality:

#### golangci-lint
```bash
golangci-lint run
```

#### gofmt
```bash
gofmt -s -w .
```

#### go vet
```bash
go vet ./...
```

## Project Structure

```
certifier/
├── cmd/certifier/          # CLI executable
├── pkg/
│   ├── cert/              # Core certificate generation and validation
│   ├── encoding/          # PEM/DER/PKCS12 encoding and decoding
│   ├── validation/        # Certificate validation logic
│   ├── crl/              # Certificate Revocation List support
│   └── ocsp/             # OCSP support (placeholder)
├── internal/
│   └── cli/              # CLI command implementations
├── test/                 # Integration tests
└── .github/workflows/    # GitHub Actions workflows
```

## Coding Standards

1. **Code Style**: Follow Go's standard code formatting (gofmt)
2. **Comments**: 
   - Export public functions and types with comments
   - Use clear, concise comments
   - Include examples in documentation
3. **Error Handling**: 
   - Return errors explicitly
   - Use `fmt.Errorf()` with context
4. **Testing**: 
   - Write tests for new functions
   - Maintain >60% code coverage
   - Use table-driven tests where appropriate
5. **Performance**: 
   - Use efficient data structures
   - Avoid unnecessary allocations
   - Profile with `pprof` if needed

## Pull Request Process

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Make your changes
4. Add or update tests as needed
5. Run `golangci-lint run` to check code quality
6. Run `go test -v ./...` to verify tests pass
7. Commit your changes with descriptive messages
8. Push to your branch
9. Open a Pull Request with a clear description

## Commit Messages

Follow conventional commit format:

```
<type>(<scope>): <subject>

<body>

<footer>
```

Types:
- `feat`: A new feature
- `fix`: A bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc)
- `refactor`: Code refactoring
- `perf`: Performance improvements
- `test`: Adding or updating tests
- `chore`: Build process, dependencies, etc

Example:
```
feat(cert): add certificate expiration validation

Add expiration checking to ValidateCertificate function.
Validates NotBefore and NotAfter times.

Fixes #123
```

## Feature Development Guidelines

### Adding a New Command
1. Add command function in `internal/cli/commands.go`
2. Add flag parsing with clear default values
3. Add input validation
4. Return clear error messages
5. Add tests for the command

### Adding Library Functionality
1. Implement in appropriate `pkg/` subpackage
2. Add comprehensive tests
3. Update documentation
4. Add examples if appropriate
5. Ensure <5% performance degradation on benchmarks

## Reporting Issues

- Use GitHub Issues for bug reports
- Include reproduction steps
- Specify Go version and OS
- Include error messages and stack traces if applicable

## Security

For security vulnerabilities, please email security@0x524a.com instead of using the public issue tracker.

## License

By contributing, you agree that your contributions will be licensed under the same license as the project (see LICENSE file).

## Additional Resources

- [Go Documentation](https://golang.org/doc/)
- [Effective Go](https://golang.org/doc/effective_go)
- [Go Code Review Comments](https://github.com/golang/go/wiki/CodeReviewComments)

Thank you for contributing to Certifier!
