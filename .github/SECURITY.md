# Security Policy

## Supported Versions

We release patches for security vulnerabilities for the following versions:

| Version | Supported          |
| ------- | ------------------ |
| main    | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

If you discover a security vulnerability, please send an email to the maintainers or use GitHub's private vulnerability reporting feature:

1. Go to the [Security Advisories](https://github.com/0x524a/certifier/security/advisories) page
2. Click "Report a vulnerability"
3. Provide detailed information about the vulnerability

### What to Include

- Type of vulnerability
- Full paths of source file(s) related to the vulnerability
- Location of the affected source code (tag/branch/commit or direct URL)
- Step-by-step instructions to reproduce the issue
- Proof-of-concept or exploit code (if possible)
- Impact of the vulnerability
- Suggested fix (if available)

### Response Timeline

- **Initial Response**: Within 48 hours
- **Assessment**: Within 1 week
- **Fix**: Depending on severity and complexity
  - Critical: Within 7 days
  - High: Within 14 days
  - Medium: Within 30 days
  - Low: Next minor release

## Security Best Practices

When using Certifier:

### Certificate Generation
- Use strong key types (RSA 2048+ bits, ECDSA P-256+, or Ed25519)
- Set appropriate validity periods (avoid overly long certificates)
- Enable RSA-PSS when possible for enhanced security: `UseRSAPSS: true`
- Use secure random number generation (handled automatically)

### Key Management
- Store private keys securely (encrypted at rest)
- Use appropriate file permissions (0600 for private keys)
- Rotate keys regularly
- Never commit private keys to version control

### Certificate Validation
- Always validate certificate chains
- Check certificate expiration
- Verify hostnames match expected values
- Validate against CRLs/OCSP when available

### CRL and OCSP
- Implement proper CRL/OCSP validation in production
- Keep CRLs updated
- Monitor for certificate revocations

## Security Features

Certifier includes several security features:

- **Secure Random Number Generation**: Uses `crypto/rand` for all cryptographic operations
- **Modern Algorithms**: Supports current cryptographic standards (RSA-PSS, ECDSA, Ed25519)
- **Signature Verification**: Validates certificate signatures and chains
- **CRL Support**: Manages certificate revocation lists
- **OCSP Support**: Online certificate status checking
- **Memory Safety**: Written in Go with built-in memory safety
- **No External Dependencies**: Minimizes supply chain risks for crypto operations

## Vulnerability Disclosure

Once a vulnerability is fixed:

1. We will publish a security advisory
2. Release a patched version
3. Notify users through GitHub release notes
4. Credit the reporter (unless they prefer to remain anonymous)

## Supply Chain Security

- All GitHub Actions are pinned to specific commit SHAs
- Dependencies are regularly updated and reviewed
- SonarQube scans run on all commits
- Code coverage is tracked and maintained

## Contact

For security-related questions or concerns, please contact the maintainers through GitHub's security advisory system.
