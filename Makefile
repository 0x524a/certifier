.PHONY: help build test lint fmt vet coverage clean install

help:
	@echo "Certifier - X.509 Certificate Management"
	@echo ""
	@echo "Available targets:"
	@echo "  build      - Build the certifier executable"
	@echo "  test       - Run all tests"
	@echo "  test-cov   - Run tests with coverage report"
	@echo "  lint       - Run golangci-lint"
	@echo "  fmt        - Format code with gofmt"
	@echo "  vet        - Run go vet"
	@echo "  coverage   - Generate coverage HTML report"
	@echo "  clean      - Clean build artifacts"
	@echo "  install    - Install certifier binary to GOPATH/bin"
	@echo "  help       - Show this help message"

build:
	@echo "Building certifier..."
	@mkdir -p bin
	@go build -o bin/certifier ./cmd/certifier

test:
	@echo "Running tests..."
	@go test -v ./...

test-cov:
	@echo "Running tests with coverage..."
	@go test -v -coverprofile=coverage.out ./...

coverage: test-cov
	@echo "Generating coverage report..."
	@go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

lint:
	@echo "Running golangci-lint..."
	@golangci-lint run

fmt:
	@echo "Formatting code..."
	@gofmt -s -w .

vet:
	@echo "Running go vet..."
	@go vet ./...

clean:
	@echo "Cleaning build artifacts..."
	@rm -f bin/certifier
	@rm -f coverage.out coverage.html
	@go clean

install: build
	@echo "Installing certifier..."
	@go install ./cmd/certifier

all: fmt vet lint test build

.DEFAULT_GOAL := help
