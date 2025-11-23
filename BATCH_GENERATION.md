# Extended Key Usage (EKU) OID and Batch Certificate Generation

This document explains how to use the Certifier tool to generate certificates with custom Extended Key Usage (EKU) OIDs and how to perform batch certificate generation from configuration files.

## Table of Contents

1. [Extended Key Usage (EKU) Overview](#extended-key-usage-overview)
2. [Custom EKU OIDs](#custom-eku-oids)
3. [Batch Certificate Generation](#batch-certificate-generation)
4. [Configuration File Format](#configuration-file-format)
5. [Usage Examples](#usage-examples)
6. [Best Practices](#best-practices)

## Extended Key Usage Overview

Extended Key Usage (EKU) is an X.509 certificate extension that specifies the approved uses for a public key. EKU restricts the purposes for which a certificate can be used.

### Common EKU Values

| EKU Name | OID | Use Case |
|----------|-----|----------|
| Server Authentication | 1.3.6.1.5.5.7.3.1 | TLS web servers, HTTPS |
| Client Authentication | 1.3.6.1.5.5.7.3.2 | Mutual TLS, client certificates |
| Code Signing | 1.3.6.1.3.6.1.5.5.7.3.3 | Software code signing |
| Email Protection | 1.3.6.1.5.5.7.3.4 | S/MIME email certificates |
| Time Stamping | 1.3.6.1.5.5.7.3.8 | Timestamp authority certificates |
| OCSP Signing | 1.3.6.1.5.5.7.3.9 | OCSP responder certificates |

## Custom EKU OIDs

The Certifier tool allows you to specify custom EKU OIDs for specialized use cases such as:

- **Kernel Module Signing** (OID: 2.5.29.37.0)
- **Custom Code Signing** (OID: 1.3.6.1.4.1.57453.1.1)
- **Firmware Signing** (OID: 1.3.6.1.4.1.57453.1.2)
- Any other custom OID your system requires

### Method 1: Command-Line Flag (Non-Interactive)

Use the `--ext-oid` flag to specify custom OIDs:

```bash
# Single custom OID
certifier cert --cn "Module Signer" \
  --ext-oid "2.5.29.37.0" \
  --output module-signer.crt \
  --key-output module-signer.key \
  --non-interactive

# Multiple custom OIDs
certifier cert --cn "Multi-Purpose Signer" \
  --ext-oid "2.5.29.37.0" \
  --ext-oid "1.3.6.1.4.1.57453.1.1" \
  --output multi-signer.crt \
  --key-output multi-signer.key \
  --non-interactive
```

### Method 2: Interactive Mode

When using interactive mode, you will be prompted for Extended Key Usage OIDs:

```bash
certifier cert

# After selecting certificate type and other options, you'll be asked:
# --- Extended Key Usage (EKU) OIDs ---
# Add custom Extended Key Usage OIDs for specialized uses:
#   2.5.29.37.0     - Kernel Module Signing
#   1.3.6.1.4.1.57453.1.1 - Custom Code Signing
#   1.3.6.1.4.1.57453.1.2 - Custom Firmware Signing
# (Enter empty line to skip)
#
# Extended Key Usage OIDs: 2.5.29.37.0
# Added: 2.5.29.37.0
#
# Extended Key Usage OIDs:
```

### Method 3: Configuration File (Batch Generation)

For generating multiple certificates with custom OIDs, use a configuration file (see below).

## Batch Certificate Generation

Generate multiple certificates at once using a configuration file in YAML format.

### Basic Usage

```bash
# Generate certificates from YAML file
certifier cert -f certificates.yaml

# Generate CSRs from YAML file
certifier csr generate -f csrs.yaml

# Generate CAs from YAML file (use cert generate with isCA: true)
certifier cert -f ca-certs.yaml
```

### Benefits of Batch Generation

- **Efficiency**: Generate multiple certificates in one operation
- **Consistency**: Ensure all certificates follow the same configuration pattern
- **Automation**: Easily integrate into deployment pipelines
- **Reproducibility**: Keep configuration files in version control

### Process Flow

1. Load configuration file
2. Validate all certificate configurations
3. For each certificate:
   - Generate private key and certificate
   - Encode to PEM format
   - Write to specified output files
4. Display summary with success/failure count

## Configuration File Format

### YAML Format

```yaml
certificates:
  - commonName: "Module Signer"
    organization: "MyOrg"
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
    isCA: false

  - commonName: "Code Signer"
    organization: "MyOrg"
    organizationalUnit: "Security"
    country: "US"
    validity: 1825
    keyType: "rsa2048"
    certificateType: "server"
    extendedKeyUsageOIDs:
      - "2.5.29.37.0"
      - "1.3.6.1.4.1.57453.1.1"
    certificateOutputFile: "code-signer.crt"
    privateKeyOutputFile: "code-signer.key"
    isCA: false
```

### Configuration Fields

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| commonName | string | Yes | - | Certificate Common Name (CN) |
| organization | string | No | - | Organization (O) |
| organizationalUnit | string | No | - | Organizational Unit (OU) |
| country | string | No | US | Country code (C) |
| locality | string | No | - | Locality/City (L) |
| province | string | No | - | Province/State (ST) |
| streetAddress | string | No | - | Street address |
| postalCode | string | No | - | Postal code |
| keyType | string | No | rsa2048 | Key type (rsa2048, rsa4096, ecdsa-p256, ecdsa-p384, ecdsa-p521, ed25519) |
| certificateType | string | No | server | Certificate type (server, client, both) |
| validity | integer | No | 365 | Validity period in days |
| dnsNames | string[] | No | - | DNS names (SANs) |
| ipAddresses | string[] | No | - | IP addresses (SANs) |
| emailAddresses | string[] | No | - | Email addresses |
| extendedKeyUsageOIDs | string[] | No | - | Custom EKU OIDs |
| certificateOutputFile | string | Yes | - | Output certificate file path |
| privateKeyOutputFile | string | Yes | - | Output private key file path |
| isCA | boolean | No | false | Whether this is a CA certificate |
| maxPathLength | integer | No | -1 | Path length constraint for CA certificates |
| crlDistributionPoints | string[] | No | - | CRL distribution point URLs |
| ocspServer | string[] | No | - | OCSP server URLs |
| issuingCertificateURL | string[] | No | - | Issuing certificate URLs |
| authorityInfoAccessOCSP | string[] | No | - | Authority Info Access OCSP URLs |

## Usage Examples

### Example 1: Generate Module Signing Certificates

**YAML Configuration (module-signing.yaml):**

```yaml
certificates:
  - commonName: "Kernel Module Signer"
    organization: "Linux Foundation"
    organizationalUnit: "Kernel Security"
    country: "US"
    validity: 3650
    keyType: "rsa4096"
    extendedKeyUsageOIDs:
      - "2.5.29.37.0"
    certificateOutputFile: "kernel-module-signer.crt"
    privateKeyOutputFile: "kernel-module-signer.key"
```

**Generate:**

```bash
certifier cert -f module-signing.yaml
```

**Verify with OpenSSL:**

```bash
openssl x509 -in kernel-module-signer.crt -text -noout | grep "Extended Key Usage" -A5
```

### Example 2: Generate Multiple Certificates for Mutual TLS

**YAML Configuration (mtls-setup.yaml):**

```yaml
certificates:
  - commonName: "Server"
    organization: "MyApp"
    country: "US"
    dnsNames:
      - "server.example.com"
      - "localhost"
    ipAddresses:
      - "127.0.0.1"
      - "192.168.1.100"
    validity: 365
    keyType: "rsa2048"
    certificateType: "both"
    certificateOutputFile: "server.crt"
    privateKeyOutputFile: "server.key"

  - commonName: "Client"
    organization: "MyApp"
    country: "US"
    emailAddresses:
      - "client@example.com"
    validity: 365
    keyType: "rsa2048"
    certificateType: "client"
    certificateOutputFile: "client.crt"
    privateKeyOutputFile: "client.key"
```

**Generate:**

```bash
certifier cert -f mtls-setup.yaml
```

### Example 3: Mixed Certificate Types

**YAML Configuration (mixed-certs.yaml):**

```yaml
certificates:
  - commonName: "Web Server"
    organization: "MyApp"
    certificateType: "server"
    dnsNames: ["example.com", "www.example.com"]
    validity: 365
    certificateOutputFile: "web.crt"
    privateKeyOutputFile: "web.key"

  - commonName: "Code Signer"
    organization: "MyApp"
    certificateType: "server"
    extendedKeyUsageOIDs: ["2.5.29.37.0"]
    validity: 1825
    keyType: "rsa4096"
    certificateOutputFile: "code-signer.crt"
    privateKeyOutputFile: "code-signer.key"

  - commonName: "Admin Client"
    organization: "MyApp"
    certificateType: "client"
    emailAddresses: ["admin@example.com"]
    validity: 365
    certificateOutputFile: "admin.crt"
    privateKeyOutputFile: "admin.key"
```

**Generate:**

```bash
certifier cert -f mixed-certs.yaml
```

**Output:**

```
Generating 3 certificate(s) from configuration file...

═══════════════════════════════════════════════════════════
Certificate 1: Web Server
═══════════════════════════════════════════════════════════
✓ Certificate generated successfully!
  Certificate: web.crt
  Private Key: web.key
  Serial Number: 123456789...
  Valid From: 2025-11-23 14:54:18 +0000 UTC
  Valid Until: 2026-11-23 14:54:18 +0000 UTC
  Extended Key Usages: [1]

═══════════════════════════════════════════════════════════
Certificate 2: Code Signer
═══════════════════════════════════════════════════════════
✓ Certificate generated successfully!
...
```

### Example 4: Using Custom OIDs from Command Line

```bash
# Single OID
certifier cert --cn "Firmware Signer" \
  --ext-oid "2.5.29.37.0" \
  --output firmware.crt \
  --key-output firmware.key \
  --non-interactive

# Multiple OIDs
certifier cert --cn "Multi Signer" \
  --ext-oid "2.5.29.37.0" \
  --ext-oid "1.3.6.1.4.1.57453.1.1" \
  --ext-oid "1.3.6.1.4.1.57453.1.2" \
  --output multi.crt \
  --key-output multi.key \
  --non-interactive
```

## Best Practices

### 1. OID Validation

Always verify OIDs are valid before adding them to certificates:

```bash
# Check if your certificate has the expected OID
openssl x509 -in mycert.crt -text -noout | grep -A2 "Extended Key"
```

### 2. Key Size Recommendations

- **Development/Testing**: RSA 2048-bit or ECDSA P-256
- **Production**: RSA 4096-bit or ECDSA P-384
- **Maximum Security**: ECDSA P-521 or Ed25519

### 3. Validity Period Guidelines

- **Development Certificates**: 30-90 days
- **Production Certificates**: 90 days to 1 year
- **CA Certificates**: 5-10 years
- **Special Purpose Certs**: Based on use case

### 4. Configuration File Management

```bash
# Store configuration files in version control
git add certificates.yaml
git commit -m "Add batch certificate configurations"

# Create separate configs for different environments
- dev-certs.yaml      # Development certificates
- staging-certs.yaml  # Staging certificates
- prod-certs.yaml     # Production certificates
```

### 5. Certificate Verification

Always verify generated certificates before deployment:

```bash
# Check certificate details
openssl x509 -in cert.crt -text -noout

# Verify certificate chain
openssl verify -CAfile ca.crt cert.crt

# Check certificate with specific date
openssl x509 -in cert.crt -noout -dates
```

### 6. Error Handling in Batch Generation

The batch generator will:
- Continue processing if a certificate fails
- Report success/failure count at the end
- Exit with error code 1 if any certificates failed

```bash
# Check exit code
certifier cert -f certificates.yaml
if [ $? -ne 0 ]; then
  echo "Some certificates failed to generate"
  exit 1
fi
```

## Security Considerations

1. **Private Key Protection**
   - Store private keys securely
   - Use appropriate file permissions (0600)
   - Never commit private keys to version control

2. **OID Selection**
   - Use standard OIDs when applicable
   - Document custom OID purposes
   - Ensure OIDs align with system requirements

3. **Certificate Authority**
   - CA certificates should have long validity periods
   - Use stronger key sizes for CAs
   - Protect CA private keys with offline storage

4. **Batch Operations**
   - Validate configuration files before generation
   - Run in controlled environments
   - Keep audit logs of batch operations

## Common Issues

### Issue: Certificate not recognized by application

**Solution**: Verify the certificate has required EKU values:

```bash
openssl x509 -in cert.crt -text -noout | grep "Extended Key"
```

### Issue: Batch generation fails for some certificates

**Solution**: Check configuration file syntax and required fields:

```bash
# Validate YAML syntax
yamllint certificates.yaml

# Ensure all required fields are present
# - commonName
# - certificateOutputFile
# - privateKeyOutputFile
```

### Issue: Custom OID not appearing in certificate

**Solution**: Ensure OID is in correct format (dotted decimal notation):

```bash
# Correct format
"2.5.29.37.0"

# Incorrect formats
"2.5.29.37" (incomplete)
"2-5-29-37-0" (wrong separator)
```

## Related Documentation

- [EKU Management](EKU_MANAGEMENT.md) - Extended Key Usage concepts and implementation
- [Certificate Generation](QUICKSTART.md) - Quick start guide for certificate generation
- [CLI Enhancements](CLI_ENHANCEMENTS.md) - CLI features and options

## References

- [RFC 5280 - Internet X.509 PKI Certificate and CRL Profile](https://tools.ietf.org/html/rfc5280)
- [OID Database](https://oidref.com/)
- [Extended Key Usage OID Registry](https://www.oid-info.com/get/1.3.6.1.5.5.7.3)
