# Quick Reference: Extended Key Usage OIDs and Batch Generation

## Quick Start

### Generate Certificate with Custom OID (Non-Interactive)

```bash
certifier cert --cn "Module Signer" \
  --ext-oid "2.5.29.37.0" \
  --output signer.crt \
  --key-output signer.key \
  --non-interactive
```

### Generate Multiple Certificates from File

```bash
certifier cert -f certificates.yaml
# or
certifier cert -f certificates.json
```

### Generate with Multiple OIDs

```bash
certifier cert --cn "Multi-Signer" \
  --ext-oid "2.5.29.37.0" \
  --ext-oid "1.3.6.1.4.1.57453.1.1" \
  --output multi.crt \
  --key-output multi.key \
  --non-interactive
```

## Common EKU OIDs

| Purpose | OID |
|---------|-----|
| Server Auth (TLS) | 1.3.6.1.5.5.7.3.1 |
| Client Auth | 1.3.6.1.5.5.7.3.2 |
| Code Signing | 1.3.6.1.3.6.1.5.5.7.3.3 |
| Email Protection | 1.3.6.1.5.5.7.3.4 |
| Time Stamping | 1.3.6.1.5.5.7.3.8 |
| OCSP Signing | 1.3.6.1.5.5.7.3.9 |
| **Kernel Module Signing** | **2.5.29.37.0** |
| Custom Signing #1 | 1.3.6.1.4.1.57453.1.1 |
| Custom Signing #2 | 1.3.6.1.4.1.57453.1.2 |

## Configuration File Format

### Minimal YAML

```yaml
certificates:
  - commonName: "My Certificate"
    certificateOutputFile: "cert.crt"
    privateKeyOutputFile: "cert.key"
```

### Complete YAML with Custom OID

```yaml
certificates:
  - commonName: "Module Signer"
    organization: "My Company"
    organizationalUnit: "Security"
    country: "US"
    locality: "San Francisco"
    province: "CA"
    validity: 3650
    keyType: "rsa4096"
    certificateType: "server"
    extendedKeyUsageOIDs:
      - "2.5.29.37.0"
    certificateOutputFile: "module-signer.crt"
    privateKeyOutputFile: "module-signer.key"
```

### Minimal JSON

```json
{
  "certificates": [
    {
      "commonName": "My Certificate",
      "certificateOutputFile": "cert.crt",
      "privateKeyOutputFile": "cert.key"
    }
  ]
}
```

## Verify Generated Certificates

```bash
# View certificate details
openssl x509 -in cert.crt -text -noout

# Check Extended Key Usage
openssl x509 -in cert.crt -text -noout | grep "Extended Key"

# Verify certificate validity
openssl x509 -in cert.crt -noout -dates

# Check specific OID
openssl x509 -in cert.crt -text -noout | grep "2.5.29.37"
```

## Key Types Supported

- `rsa2048` - RSA 2048-bit (default)
- `rsa4096` - RSA 4096-bit
- `ecdsa-p256` - ECDSA P-256
- `ecdsa-p384` - ECDSA P-384
- `ecdsa-p521` - ECDSA P-521
- `ed25519` - Ed25519

## Certificate Types

- `server` - Server authentication (default)
- `client` - Client authentication
- `both` - Both server and client

## Common Scenarios

### Kernel Module Signing

```yaml
certificates:
  - commonName: "Kernel Module Signer"
    validity: 3650
    keyType: "rsa4096"
    extendedKeyUsageOIDs: ["2.5.29.37.0"]
    certificateOutputFile: "kernel-signer.crt"
    privateKeyOutputFile: "kernel-signer.key"
```

### Firmware Signing

```yaml
certificates:
  - commonName: "Firmware Signer"
    validity: 1825
    keyType: "ecdsa-p256"
    extendedKeyUsageOIDs: ["2.5.29.37.0"]
    certificateOutputFile: "firmware-signer.crt"
    privateKeyOutputFile: "firmware-signer.key"
```

### Mutual TLS (mTLS)

```yaml
certificates:
  - commonName: "Server"
    certificateType: "both"
    dnsNames: ["server.example.com"]
    certificateOutputFile: "server.crt"
    privateKeyOutputFile: "server.key"

  - commonName: "Client"
    certificateType: "client"
    certificateOutputFile: "client.crt"
    privateKeyOutputFile: "client.key"
```

### Web Server

```yaml
certificates:
  - commonName: "Web Server"
    certificateType: "server"
    dnsNames: ["example.com", "www.example.com"]
    validity: 365
    certificateOutputFile: "webserver.crt"
    privateKeyOutputFile: "webserver.key"
```

## Batch Generation Output

```
Generating 3 certificate(s) from configuration file...

═══════════════════════════════════════════════════════════
Certificate 1: Module Signer
═══════════════════════════════════════════════════════════
✓ Certificate generated successfully!
  Certificate: module-signer.crt
  Private Key: module-signer.key
  Serial Number: ...
  Valid From: ...
  Valid Until: ...

...

═══════════════════════════════════════════════════════════
Summary: 3 succeeded, 0 failed
```

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Configuration file not found | Check file path and permissions |
| Invalid YAML/JSON syntax | Validate syntax with `yamllint` or `jq` |
| Missing required fields | Add `commonName`, `certificateOutputFile`, `privateKeyOutputFile` |
| OID not in certificate | Verify OID format is `X.X.X.X...` (dotted decimal) |
| Permission denied writing files | Check directory permissions, ensure write access |

## Environment Variables

```bash
# No environment variables needed
# All configuration via command-line flags or files
```

## Examples Location

See `/workspaces/certifier/examples/` for sample configuration files:
- `module-signing-certs.yaml` - Module signing certificates
- `batch-certs.json` - Standard batch certificates

## For More Information

- Full documentation: `BATCH_GENERATION.md`
- EKU concepts: `EKU_MANAGEMENT.md`
- Quick start guide: `QUICKSTART.md`
