# Certifier - X.509 Certificate Management Library and CLI

A performant and optimized Go library for generating, validating, and managing X.509 certificates, Certificate Authorities (CAs), and related cryptographic operations.

## Features

### Core Library Features
- **Certificate Generation**
  - Self-signed certificates
  - CA certificates
  - Server/Client certificates
  - Certificate Signing Requests (CSR)

- **Key Management**
  - RSA (2048, 4096 bits)
  - ECDSA (P-256, P-384, P-521)
  - Ed25519

- **Encoding/Decoding**
  - PEM format support
  - DER format support
  - PKCS#12 (P12/PFX) bundle support

- **Validation**
  - Chain of trust verification
  - Expiration checking
  - Hostname verification
  - Custom validation rules

- **Advanced Features**
  - Certificate Revocation List (CRL) generation and management
  - OCSP (Online Certificate Status Protocol) support
  - CRL validation

### CLI Tool
The executable supports all library operations:
- Generate CA certificates
- Generate server/client certificates
- Sign certificates with CA
- Validate certificates
- View certificate details
- Batch operations via config files

### Deployment
- **Multi-platform Support**: Windows, Linux, macOS
- **GitHub Actions**: Automated linting, security scanning (SonarQube), and multi-platform binary releases
- **Package Distribution**: Published to Go pkg registry on releases

## Project Structure

```
.
├── cmd/certifier/              # Executable
├── pkg/
│   ├── cert/                   # Core certificate operations
│   ├── encoding/               # PEM/DER/PKCS12 encoding
│   ├── validation/             # Certificate validation
│   ├── crl/                    # CRL management
│   └── ocsp/                   # OCSP support
├── internal/
│   └── cli/                    # CLI command implementations
├── test/                       # Integration tests
├── .github/workflows/          # GitHub Actions
└── go.mod
```

## Installation

### From Source
```bash
go install github.com/0x524a/certifier/cmd/certifier@latest
```

### From Releases
Download pre-built binaries from [GitHub Releases](https://github.com/0x524a/certifier/releases)

## Quick Start

### Library Usage

```go
package main

import (
	"log"
	"github.com/0x524a/certifier/pkg/cert"
)

func main() {
	// Generate a self-signed certificate
	config := &cert.CertificateConfig{
		CommonName: "example.com",
		Country:    "US",
		Validity:   365,
	}

	cert, key, err := cert.GenerateSelfSignedCertificate(config)
	if err != nil {
		log.Fatal(err)
	}

	// Use cert and key...
}
```

### CLI Usage

```bash
# Generate a CA certificate
certifier ca generate --cn "My CA" --output ca.crt --key-output ca.key

# Generate a server certificate signed by CA
certifier cert generate \
  --cn "example.com" \
  --ca-cert ca.crt \
  --ca-key ca.key \
  --output server.crt \
  --key-output server.key

# Validate a certificate
certifier cert validate --cert server.crt --ca-cert ca.crt

# View certificate details
certifier cert view --cert server.crt
```

## Development

### Building
```bash
go build -o bin/certifier ./cmd/certifier
```

### Testing
```bash
go test -v -cover ./...
```

### Linting
```bash
golangci-lint run
```

## Performance

This library is optimized for:
- Fast certificate generation using efficient key generation algorithms
- Minimal memory allocations
- Concurrent certificate operations where applicable
- Cache-friendly data structures

## Contributing

Contributions are welcome! Please ensure:
1. All tests pass
2. Code passes golangci-lint checks
3. New features include tests and documentation

## License

See LICENSE file for details.

## Support

For issues and feature requests, please open a GitHub issue.
