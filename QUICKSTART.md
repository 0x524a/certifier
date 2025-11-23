# Quick Start Guide

Welcome to Certifier! This guide will get you up and running in minutes.

## Installation

### From Source
```bash
git clone https://github.com/0x524a/certifier.git
cd certifier
make build
./bin/certifier --version
```

### From Releases
Download pre-built binaries from [GitHub Releases](https://github.com/0x524a/certifier/releases)

```bash
# Linux
wget https://github.com/0x524a/certifier/releases/download/v1.0.0/certifier-linux-amd64
chmod +x certifier-linux-amd64
./certifier-linux-amd64 --help

# macOS
brew install 0x524a/tap/certifier  # If available

# Windows
# Download certifier-windows-amd64.exe from releases
```

## Basic Usage

### 1. Generate a Root CA Certificate

```bash
certifier ca generate \
  --cn "My Root CA" \
  --org "My Organization" \
  --output ca.crt \
  --key-output ca.key
```

This creates:
- `ca.crt` - The public certificate
- `ca.key` - The private key (keep this secure!)

### 2. View Certificate Details

```bash
certifier cert view --cert ca.crt
```

Output example:
```
Certificate Details:
====================
Serial Number: 132431717502916343574010659965945534283
Subject: CN=My Root CA,O=My Organization,C=US
Issuer: CN=My Root CA,O=My Organization,C=US
Valid From: 2025-11-23 03:43:51 +0000 UTC
Valid Until: 2035-11-21 03:43:51 +0000 UTC
Is CA: true
Public Key Algorithm: RSA
Signature Algorithm: SHA256-RSA
```

### 3. Generate a Server Certificate

```bash
certifier cert generate \
  --cn "example.com" \
  --dns "example.com,www.example.com" \
  --ca-cert ca.crt \
  --ca-key ca.key \
  --output server.crt \
  --key-output server.key
```

### 4. Generate a Certificate Signing Request (CSR)

For scenarios where you want someone else to sign your certificate:

```bash
certifier csr generate \
  --cn "api.example.com" \
  --dns "api.example.com" \
  --output api.csr \
  --key-output api.key
```

Send `api.csr` to your CA for signing.

## Advanced Usage

### Different Key Types

By default, certificates use RSA-2048. You can choose other options:

```bash
# RSA 4096 (stronger)
certifier ca generate --cn "Strong CA" --key-type rsa4096 \
  --output strong-ca.crt --key-output strong-ca.key

# ECDSA P-256 (faster, smaller keys)
certifier cert generate --cn "fast.example.com" --key-type ecdsa-p256 \
  --output fast.crt --key-output fast.key

# Ed25519 (modern, secure)
certifier ca generate --cn "Modern CA" --key-type ed25519 \
  --output modern-ca.crt --key-output modern-ca.key
```

Available key types:
- `rsa2048` (default)
- `rsa4096`
- `ecdsa-p256`
- `ecdsa-p384`
- `ecdsa-p521`
- `ed25519`

### Customize Certificate Validity

```bash
# 10 years (default for CA)
certifier ca generate --cn "CA" --validity 3650 \
  --output ca.crt --key-output ca.key

# 2 years for server cert
certifier cert generate --cn "example.com" --validity 730 \
  --output server.crt --key-output server.key
```

### Add More Subject Information

```bash
certifier ca generate \
  --cn "My Organization CA" \
  --country "US" \
  --org "My Company" \
  --ou "IT Department" \
  --locality "New York" \
  --province "NY" \
  --output ca.crt \
  --key-output ca.key
```

### Multiple DNS Names and IP Addresses

```bash
certifier cert generate \
  --cn "api.example.com" \
  --dns "api.example.com,api.example.local,api.prod.example.com" \
  --ip "192.168.1.100,10.0.0.50" \
  --ca-cert ca.crt \
  --ca-key ca.key \
  --output api.crt \
  --key-output api.key
```

## Use Cases

### Self-Signed Certificate for HTTPS Development

```bash
# Create self-signed cert valid for 1 year
certifier cert generate \
  --cn "localhost" \
  --dns "localhost,127.0.0.1" \
  --output dev.crt \
  --key-output dev.key \
  --validity 365
```

Then use in your web server:
```nginx
server {
    listen 443 ssl;
    ssl_certificate dev.crt;
    ssl_certificate_key dev.key;
}
```

### Internal PKI Setup

```bash
# 1. Create Root CA (10-year validity)
certifier ca generate --cn "Internal Root CA" --validity 3650 \
  --output root-ca.crt --key-output root-ca.key

# 2. Create Intermediate CA (5-year validity)
certifier cert generate --cn "Intermediate CA" --validity 1825 \
  --ca-cert root-ca.crt --ca-key root-ca.key \
  --output intermediate-ca.crt --key-output intermediate-ca.key

# 3. Issue end-entity certificates
certifier cert generate --cn "server1.internal" \
  --ca-cert intermediate-ca.crt --ca-key intermediate-ca.key \
  --output server1.crt --key-output server1.key
```

### API Client Certificates

```bash
# Generate client certificate for mTLS
certifier csr generate --cn "api-client" --output client.csr --key-output client.key

# CA signs the CSR (requires parsing CSR and signing - use library)
# Or generate directly with CA
certifier cert generate --cn "api-client" \
  --ca-cert ca.crt --ca-key ca.key \
  --output client.crt --key-output client.key
```

## Library Usage (Go)

```go
package main

import (
	"log"
	"github.com/0x524a/certifier/pkg/cert"
	"github.com/0x524a/certifier/pkg/encoding"
)

func main() {
	// Generate a self-signed certificate
	config := &cert.CertificateConfig{
		CommonName:    "example.com",
		Organization:  "My Org",
		KeyType:       cert.KeyTypeRSA2048,
		Validity:      365,
	}

	certificate, privateKey, err := cert.GenerateSelfSignedCertificate(config)
	if err != nil {
		log.Fatal(err)
	}

	// Encode to PEM
	certPEM, _ := encoding.EncodeCertificateToPEM(certificate)
	keyPEM, _ := encoding.EncodePrivateKeyToPEM(privateKey)

	// Use cert and key...
}
```

## Troubleshooting

### Permission Denied on key files
Make sure key files have restricted permissions:
```bash
chmod 600 *.key
```

### Certificate Not Trusted
For self-signed certificates, you need to add them to your trust store:
```bash
# Linux
sudo cp ca.crt /usr/local/share/ca-certificates/
sudo update-ca-certificates

# macOS
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ca.crt

# Windows
certutil -addstore -f "Root" ca.crt
```

### Verify Certificate Chain
```bash
# Check if a cert is signed by a CA
openssl verify -CAfile ca.crt server.crt
```

## Next Steps

1. Read the [full documentation](README.md)
2. Check [examples](examples/) directory
3. Review the [contributing guide](CONTRIBUTING.md) to contribute

## Getting Help

- **Issues**: [GitHub Issues](https://github.com/0x524a/certifier/issues)
- **Documentation**: [Full README](README.md)
- **Examples**: Look in the repository for example certificates and scripts

## License

Certifier is licensed under the same license as specified in the LICENSE file.
