# Extended Key Usage (EKU) Management Guide

## Overview

Extended Key Usage (EKU) is a critical X.509 certificate extension that specifies the permitted uses for a certificate's public key. This guide explains how Certifier manages EKU for different certificate types.

## What is Extended Key Usage?

EKU restricts a certificate's purposes through specific Object Identifiers (OIDs):

| EKU Type | OID | Purpose |
|----------|-----|---------|
| **ServerAuth** | 1.3.6.1.5.5.7.3.1 | Server SSL/TLS authentication (HTTPS, LDAPS, etc.) |
| **ClientAuth** | 1.3.6.1.5.5.7.3.2 | Client certificate authentication (mutual TLS, mTLS) |
| **CodeSigning** | 1.3.6.1.5.5.7.3.3 | Software code signing |
| **EmailProtection** | 1.3.6.1.5.5.7.3.4 | Email (S/MIME) protection |
| **TimeStamping** | 1.3.6.1.5.5.7.3.8 | Time stamping authority |
| **ModuleSigning** | 1.3.6.1.4.1.2312.16.1.2 | Linux kernel module signing |

## How Certifier Manages EKU

### Certificate Types

Certifier supports three certificate types with automatic EKU assignment:

#### 1. **Server Certificate**
```
Certificate Type: server
Extended Key Usage: serverAuth (1.3.6.1.5.5.7.3.1)
Use Cases:
  - HTTPS web servers
  - TLS APIs
  - Any service requiring server authentication
```

#### 2. **Client Certificate**
```
Certificate Type: client
Extended Key Usage: clientAuth (1.3.6.1.5.5.7.3.2)
Use Cases:
  - Client-side mTLS authentication
  - VPN client certificates
  - Application-to-application authentication
```

#### 3. **Both (Server + Client)**
```
Certificate Type: both
Extended Key Usage: serverAuth + clientAuth
Use Cases:
  - Dual-purpose certificates for bidirectional authentication
  - Services that need both roles
  - End-to-end encrypted communication
```

## Generation Methods

### Interactive Mode

In interactive mode, you'll be prompted to select the certificate type:

```bash
./certifier
# Select: 2. Certificate Operations → 1. Generate certificate
# Follow prompts...
# When asked:
#   --- Certificate Type ---
#   What type of certificate do you need?
#     1. Server (web servers, APIs)
#     2. Client (client authentication, mutual TLS)
#     3. Both (server and client authentication)
#   Select certificate type [1]: 1
```

### Non-Interactive Mode

Use the `--cert-type` flag:

```bash
# Server certificate
./certifier cert --cn example.com \
  --dns example.com,www.example.com \
  --cert-type server \
  --ca-cert ca.crt --ca-key ca.key

# Client certificate
./certifier cert --cn "client-user" \
  --email user@example.com \
  --cert-type client \
  --ca-cert ca.crt --ca-key ca.key

# Both server and client
./certifier cert --cn example.com \
  --dns example.com \
  --cert-type both \
  --ca-cert ca.crt --ca-key ca.key
```

## Implementation Details

### Code Structure

The EKU management is implemented in three key files:

#### 1. **pkg/cert/types.go** - Type Definitions

```go
type CertificateType string

const (
    CertTypeClient  CertificateType = "client"
    CertTypeServer  CertificateType = "server"
    CertTypeBoth    CertificateType = "both"
)

type CertificateConfig struct {
    CertType CertificateType // Certificate type for EKU assignment
    // ... other fields
}
```

#### 2. **pkg/cert/generate.go** - EKU Assignment Logic

```go
func setExtendedKeyUsage(template *x509.Certificate, 
    certType CertificateType, isCA bool) {
    
    if isCA {
        // CA certificates don't have EKU
        return
    }
    
    switch certType {
    case CertTypeClient:
        template.ExtKeyUsage = []x509.ExtKeyUsage{
            x509.ExtKeyUsageClientAuth
        }
    case CertTypeServer:
        template.ExtKeyUsage = []x509.ExtKeyUsage{
            x509.ExtKeyUsageServerAuth
        }
    case CertTypeBoth:
        template.ExtKeyUsage = []x509.ExtKeyUsage{
            x509.ExtKeyUsageServerAuth,
            x509.ExtKeyUsageClientAuth,
        }
    default:
        template.ExtKeyUsage = []x509.ExtKeyUsage{
            x509.ExtKeyUsageServerAuth
        }
    }
}
```

This function is called in both:
- `GenerateSelfSignedCertificate()`
- `GenerateCASignedCertificate()`

#### 3. **internal/cli/interactive.go** - User Prompting

```go
func (im *InteractiveMode) PromptCertificateType() string {
    fmt.Println("\n--- Certificate Type ---")
    fmt.Println("What type of certificate do you need?")
    fmt.Println("  1. Server (web servers, APIs)")
    fmt.Println("  2. Client (client authentication, mutual TLS)")
    fmt.Println("  3. Both (server and client authentication)")
    
    choice := im.PromptString("Select certificate type", "1")
    
    switch choice {
    case "1":
        return "server"
    case "2":
        return "client"
    case "3":
        return "both"
    default:
        return "server"
    }
}
```

## Key Usage vs Extended Key Usage

**Important Distinction:**

| Aspect | Key Usage | Extended Key Usage |
|--------|-----------|-------------------|
| **Purpose** | Constrains cryptographic operations | Specifies certificate purpose/application |
| **Example** | Sign, Encrypt, CertSign | ServerAuth, ClientAuth |
| **For Server Certs** | DigitalSignature + KeyEncipherment | ServerAuth |
| **For Client Certs** | DigitalSignature | ClientAuth |
| **For CA Certs** | CertSign + CRLSign | (none) |

### Default Values in Certifier

**Non-CA Certificates:**
```
KeyUsage = DigitalSignature | KeyEncipherment
ExtKeyUsage = ServerAuth (by default)
           or ClientAuth (if --cert-type client)
           or both (if --cert-type both)
```

**CA Certificates:**
```
KeyUsage = CertSign | CRLSign
ExtKeyUsage = (none - CAs don't have EKU)
```

## Practical Examples

### Example 1: Web Server Certificate

```bash
./certifier cert \
  --cn example.com \
  --dns example.com,www.example.com \
  --cert-type server \
  --ca-cert ca.crt \
  --ca-key ca.key
```

**Result:**
- ✅ Key Usage: DigitalSignature, KeyEncipherment
- ✅ Extended Key Usage: serverAuth
- ✅ Subject Alt Names: example.com, www.example.com
- 📋 Use for: HTTPS server

### Example 2: mTLS Client Certificate

```bash
./certifier cert \
  --cn client-service \
  --email client@company.com \
  --cert-type client \
  --ca-cert ca.crt \
  --ca-key ca.key
```

**Result:**
- ✅ Key Usage: DigitalSignature
- ✅ Extended Key Usage: clientAuth
- ✅ Subject CN: client-service
- 📋 Use for: Client authentication in mTLS setup

### Example 3: Bidirectional Authentication

```bash
./certifier cert \
  --cn api-gateway \
  --dns api.example.com \
  --cert-type both \
  --ca-cert ca.crt \
  --ca-key ca.key
```

**Result:**
- ✅ Key Usage: DigitalSignature, KeyEncipherment
- ✅ Extended Key Usage: serverAuth, clientAuth
- ✅ Subject Alt Names: api.example.com
- 📋 Use for: Bidirectional TLS authentication

## Verification

### View EKU in Generated Certificate

```bash
# View certificate details
openssl x509 -in cert.crt -text -noout | grep -A1 "Extended Key Usage"

# Output examples:
# X509v3 Extended Key Usage: TLS Web Server Authentication
# X509v3 Extended Key Usage: TLS Web Client Authentication
# X509v3 Extended Key Usage: TLS Web Server Auth, TLS Web Client Auth
```

### Python Verification

```python
from cryptography import x509
from cryptography.hazmat.backends import default_backend

with open('cert.crt', 'rb') as f:
    cert = x509.load_pem_x509_certificate(f.read(), default_backend())
    
try:
    eku = cert.extensions.get_extension_for_oid(
        x509.oid.ExtensionOID.EXTENDED_KEY_USAGE
    ).value
    print("Extended Key Usages:")
    for usage in eku:
        print(f"  - {usage._name}")
except x509.ExtensionNotFound:
    print("No Extended Key Usage extension found")
```

### Go Verification

```go
cert, _ := x509.ParseCertificate(certBytes)
fmt.Println("Extended Key Usages:")
for _, eku := range cert.ExtKeyUsage {
    switch eku {
    case x509.ExtKeyUsageServerAuth:
        fmt.Println("  - ServerAuth")
    case x509.ExtKeyUsageClientAuth:
        fmt.Println("  - ClientAuth")
    }
}
```

## Module Signing and Custom OIDs

### Linux Kernel Module Signing

Certifier supports the Linux kernel module signing OID: `1.3.6.1.4.1.2312.16.1.2`

Generate a module signing certificate:

```bash
./certifier cert \
  --cn "Kernel Module Signer" \
  --org "Linux Foundation" \
  --ext-oid "1.3.6.1.4.1.2312.16.1.2" \
  --key-type rsa4096 \
  --validity 3650
```

Or using batch generation (YAML):

```yaml
certificates:
  - commonName: "Kernel Module Signer"
    organization: "Linux Foundation"
    organizationalUnit: "Security"
    country: "US"
    validity: 3650
    keyType: "rsa4096"
    certificateType: "server"
    extendedKeyUsageOIDs:
      - "1.3.6.1.4.1.2312.16.1.2"
    certificateOutputFile: "module-signer.crt"
    privateKeyOutputFile: "module-signer.key"
```

### Using Custom OIDs

Beyond the standard EKU values, Certifier allows you to specify custom OIDs for specialized applications:

```bash
# Single custom OID
./certifier cert \
  --cn "Custom Signer" \
  --ext-oid "1.3.6.1.4.1.2312.16.1.2" \
  --output custom.crt \
  --key-output custom.key

# Multiple custom OIDs
./certifier cert \
  --cn "Multi-Purpose Signer" \
  --ext-oid "1.3.6.1.4.1.2312.16.1.2" \
  --ext-oid "1.3.6.1.5.5.7.3.1" \
  --output multi.crt \
  --key-output multi.key
```

**Common Custom OIDs:**

| OID | Purpose |
|-----|---------|
| 1.3.6.1.4.1.2312.16.1.2 | Linux kernel module signing |
| 1.3.6.1.4.1.57453.1.1 | Custom code signing |
| 1.3.6.1.4.1.57453.1.2 | Custom firmware signing |
| 2.5.29.37.0 | Extended key usage (all purposes) |

## CA Certificates (Special Case)

**CA certificates do NOT have Extended Key Usage** in Certifier:

```go
// CA certificates skip EKU assignment
if isCA {
    return  // No EKU for CAs
}
```

This is correct because:
- CAs use their Key Usage (CertSign) to sign other certs
- The EKU of the CA doesn't apply to certs it signs
- Each issued certificate gets its own appropriate EKU

## Best Practices

1. **Always specify certificate type** - Don't rely on defaults for production
   ```bash
   # ✅ Good
   ./certifier cert --cn example.com --cert-type server
   
   # ⚠️ Avoid - relies on default "server"
   ./certifier cert --cn example.com
   ```

2. **Match EKU to actual usage**
   ```bash
   # ✅ Web server → server
   # ✅ Client app → client
   # ✅ Dual role → both
   ```

3. **Verify after generation**
   ```bash
   # Check what EKU was assigned
   openssl x509 -in cert.crt -text -noout | grep -A1 "Extended Key Usage"
   ```

4. **Use appropriate DNS/IP for servers**
   ```bash
   # ✅ Server certs should have DNS/IP
   --dns example.com,www.example.com
   
   # ✅ Client certs should have email
   --email user@company.com
   ```

## Troubleshooting

### Certificate Rejected by Server (EKU Mismatch)

**Problem:** Server rejects client certificate
```
tls: failed to verify certificate: x509: certificate with this name is not authorized for this use
```

**Solution:** Ensure certificate type is `client`
```bash
./certifier cert --cn client --cert-type client
```

### Certificate Not Suitable for Client Auth

**Problem:** Client application won't accept server certificate
```
x509: certificate is not authorized for this use
```

**Solution:** Server should be `server` or `both`, not `client`
```bash
./certifier cert --cn example.com --cert-type server
```

### Ambiguity with Bidirectional Auth

**Problem:** Unsure whether to use `server` or `both`

**Decision:**
- Use `server` if only servers need to identify themselves
- Use `both` if both client and server need mutual authentication
- Use `client` only for client-side certificates

## Summary

| Type | EKU | Key Usage | Best For |
|------|-----|-----------|----------|
| **server** | serverAuth | DigitalSignature + KeyEncipherment | HTTPS, APIs, TLS servers |
| **client** | clientAuth | DigitalSignature | mTLS client auth, VPN |
| **both** | serverAuth + clientAuth | DigitalSignature + KeyEncipherment | Bidirectional TLS |

Certifier automatically assigns the correct EKU based on your certificate type selection, making it easy to generate properly-configured certificates for any use case.
