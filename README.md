# Certifier - X.509 Certificate Management Library and CLI

[![Go Version](https://img.shields.io/github/go-mod/go-version/0x524a/certifier)](https://go.dev/)
[![License](https://img.shields.io/github/license/0x524a/certifier)](LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/0x524a/certifier)](https://goreportcard.com/report/github.com/0x524a/certifier)
[![codecov](https://codecov.io/gh/0x524a/certifier/branch/main/graph/badge.svg)](https://codecov.io/gh/0x524a/certifier)
[![CI](https://github.com/0x524a/certifier/actions/workflows/lint.yml/badge.svg)](https://github.com/0x524a/certifier/actions)
[![Release](https://img.shields.io/github/v/release/0x524a/certifier)](https://github.com/0x524a/certifier/releases)
[![GoDoc](https://godoc.org/github.com/0x524a/certifier?status.svg)](https://godoc.org/github.com/0x524a/certifier)

A performant and optimized Go library for generating, validating, and managing X.509 certificates, Certificate Authorities (CAs), and related cryptographic operations.

---

## ✨ Features

### 🔐 Core Library Features
- **Certificate Generation**
  - Self-signed certificates
  - CA certificates with path length constraints
  - Server/Client certificates
  - Certificate Signing Requests (CSR)
  - RSA-PSS support for enhanced security

- **🔑 Key Management**
  - RSA (2048, 4096 bits)
  - ECDSA (P-256, P-384, P-521)
  - Ed25519
  - Secure key generation using `crypto/rand`

- **📝 Encoding/Decoding**
  - PEM format support
  - DER format support
  - PKCS#12 (P12/PFX) bundle support

- **✅ Validation**
  - Chain of trust verification
  - Expiration checking
  - Hostname verification
  - Signature algorithm validation
  - Custom validation rules

- **🔄 Advanced Features**
  - Certificate Revocation List (CRL) generation and management
  - OCSP (Online Certificate Status Protocol) support
  - CRL validation and revocation checking
  - Extension support (Key Usage, Extended Key Usage, SAN, etc.)

### 💻 CLI Tool
The executable supports all library operations:
- Generate CA certificates
- Generate server/client certificates
- Sign certificates with CA
- Validate certificates and chains
- View certificate details
- CRL and OCSP operations
- Batch operations via config files

### 🚀 Deployment
- **Multi-platform Support**: Windows, Linux, macOS (AMD64, ARM64)
- **GitHub Actions**: Automated linting, testing, security scanning (SonarQube), and releases
- **Package Distribution**: Published to Go pkg registry on releases
- **Docker Support**: Container-ready

---

## 📦 Installation

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

### As a Library
```bash
go get github.com/0x524a/certifier
```

---

## 🚀 Quick Start

### Library Usage

```go
package main

import (
	"log"
	"github.com/0x524a/certifier/pkg/cert"
)

func main() {
	// Generate a self-signed certificate with RSA-PSS for enhanced security
	config := &cert.CertificateConfig{
		CommonName:   "example.com",
		Organization: "Example Corp",
		Country:      "US",
		Validity:     365,
		KeyType:      cert.KeyTypeRSA2048,
		UseRSAPSS:    true, // Enable RSA-PSS for better security
		DNSNames:     []string{"example.com", "www.example.com"},
	}

	cert, key, err := cert.GenerateSelfSignedCertificate(config)
	if err != nil {
		log.Fatal(err)
	}

	// Encode to PEM
	certPEM, _ := encoding.EncodeCertificateToPEM(cert)
	keyPEM, _ := encoding.EncodePrivateKeyToPEM(key)
	
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

---

## 📚 Documentation

- **[API Documentation](https://pkg.go.dev/github.com/0x524a/certifier)** - Complete package documentation
- **[Quick Start Guide](QUICKSTART.md)** - Get started quickly
- **[Contributing Guide](.github/CONTRIBUTING.md)** - How to contribute
- **[Security Policy](.github/SECURITY.md)** - Security practices and reporting
- **[Roadmap](ROADMAP.md)** - Future plans and features

---

## 🏗️ Project Structure

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

---

## ⚡ Performance

This library is optimized for:
- Fast certificate generation using efficient key generation algorithms
- Minimal memory allocations
- Concurrent certificate operations where applicable
- Cache-friendly data structures

**Benchmarks:**
- Certificate generation: < 100ms (RSA 2048-bit)
- Certificate validation: < 10ms
- CRL generation: < 50ms (1000 revoked certificates)

---

## 🤝 Contributing

Contributions are welcome! Please see our [Contributing Guide](.github/CONTRIBUTING.md) for details.

### Quick Guidelines
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'feat: add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

**Before submitting:**
- ✅ All tests pass (`go test ./...`)
- ✅ Code passes linting (`golangci-lint run`)
- ✅ Code is formatted (`gofmt -w .`)
- ✅ Documentation is updated

---

## 🔒 Security

Security is a top priority. See our [Security Policy](.github/SECURITY.md) for:
- Reporting vulnerabilities
- Supported versions
- Security best practices

**Key Security Features:**
- 🔐 RSA-PSS support for enhanced signature security
- 🎲 Cryptographically secure random number generation
- 🔍 Certificate chain validation
- 📋 CRL and OCSP support
- 🛡️ No external crypto dependencies
- 📌 Pinned GitHub Actions (supply chain security)

---

## 📊 Project Stats

- **Test Coverage**: >85%
- **Test Functions**: 226+
- **Supported Platforms**: Linux, macOS, Windows (AMD64, ARM64)
- **Go Version**: 1.22+
- **CI/CD**: GitHub Actions with SonarQube integration

---

## 📄 License

See LICENSE file for details.

---

## 💬 Support

- **Issues**: [GitHub Issues](https://github.com/0x524a/certifier/issues)
- **Discussions**: [GitHub Discussions](https://github.com/0x524a/certifier/discussions)
- **Security**: See [Security Policy](.github/SECURITY.md)

---

## 🌟 Star History

If you find this project useful, please consider giving it a star! ⭐

---

## 📝 Changelog

See [Releases](https://github.com/0x524a/certifier/releases) for detailed changelog.

---

**Made with ❤️ by the Certifier community**
