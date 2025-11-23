package validation

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/0x524a/certifier/pkg/cert"
)

// ValidateCertificate validates a certificate against the provided configuration
func ValidateCertificate(
	certificate *x509.Certificate,
	config *cert.ValidationConfig,
) *cert.ValidationResult {
	result := &cert.ValidationResult{
		Valid:              true,
		Errors:             []string{},
		Warnings:           []string{},
		SignatureAlgorithm: certificate.SignatureAlgorithm.String(),
		PublicKeyAlgorithm: certificate.PublicKeyAlgorithm.String(),
		ValidFrom:          certificate.NotBefore,
		ValidUntil:         certificate.NotAfter,
	}

	// Set current time
	now := time.Now()
	if !config.CurrentTime.IsZero() {
		now = config.CurrentTime
	}

	// Check expiration
	if config.CheckExpiration && !config.AllowExpired {
		if now.After(certificate.NotAfter) {
			result.Valid = false
			result.NotExpired = false
			result.Errors = append(result.Errors, "certificate has expired")
		} else if now.Before(certificate.NotBefore) {
			result.Valid = false
			result.NotExpired = false
			result.Errors = append(result.Errors, "certificate is not yet valid")
		} else {
			result.NotExpired = true
			result.ExpiresIn = certificate.NotAfter.Sub(now)
		}
	} else if config.CheckExpiration {
		result.ExpiresIn = certificate.NotAfter.Sub(now)
		if now.After(certificate.NotAfter) {
			result.Warnings = append(result.Warnings, "certificate has expired")
		}
	}

	// Verify hostname
	if config.DNSName != "" {
		if err := certificate.VerifyHostname(config.DNSName); err != nil {
			result.Valid = false
			result.HostnameValid = false
			result.Errors = append(result.Errors, fmt.Sprintf("hostname verification failed: %v", err))
		} else {
			result.HostnameValid = true
		}
	}

	// Get key size
	result.KeySize = getKeySize(certificate.PublicKey)

	// Validate signature algorithm strength
	validateSignatureAlgorithm(certificate, result)

	// Validate chain
	if len(config.RootCAs) > 0 {
		opts := x509.VerifyOptions{
			Roots:         createCertPool(config.RootCAs),
			Intermediates: createCertPool(config.IntermediateCAs),
			CurrentTime:   now,
		}

		if config.DNSName != "" {
			opts.DNSName = config.DNSName
		}

		if _, err := certificate.Verify(opts); err != nil {
			result.Valid = false
			result.ChainValid = false
			result.Errors = append(result.Errors, fmt.Sprintf("chain validation failed: %v", err))
		} else {
			result.ChainValid = true
		}
	}

	// Check basic constraints if CA
	if !certificate.IsCA && certificate.MaxPathLen >= 0 {
		result.Warnings = append(result.Warnings, "non-CA certificate has path length constraint")
	}

	// Store CRL and OCSP URLs
	if len(certificate.CRLDistributionPoints) > 0 {
		result.CRLDistributionURL = certificate.CRLDistributionPoints[0]
	}
	if len(certificate.OCSPServer) > 0 {
		result.OCSPURL = certificate.OCSPServer[0]
	}

	return result
}

// ValidateChain validates a certificate chain
func ValidateChain(
	leafCert *x509.Certificate,
	intermediateCerts []*x509.Certificate,
	rootCerts []*x509.Certificate,
) error {
	opts := x509.VerifyOptions{
		Roots:         createCertPool(rootCerts),
		Intermediates: createCertPool(intermediateCerts),
	}

	_, err := leafCert.Verify(opts)
	return err
}

// createCertPool creates an x509.CertPool from a slice of certificates
func createCertPool(certs []*x509.Certificate) *x509.CertPool {
	pool := x509.NewCertPool()
	for _, cert := range certs {
		pool.AddCert(cert)
	}
	return pool
}

// getKeySize returns the key size in bits
func getKeySize(publicKey interface{}) int {
	switch key := publicKey.(type) {
	case *rsa.PublicKey:
		return key.N.BitLen()
	case *ecdsa.PublicKey:
		return key.Curve.Params().BitSize
	case ed25519.PublicKey:
		return 256
	default:
		return 0
	}
}

// validateSignatureAlgorithm validates the signature algorithm strength
func validateSignatureAlgorithm(certificate *x509.Certificate, result *cert.ValidationResult) {
	switch certificate.SignatureAlgorithm {
	case x509.MD5WithRSA:
		result.Warnings = append(result.Warnings, "weak signature algorithm: MD5WithRSA")
	case x509.SHA1WithRSA:
		result.Warnings = append(result.Warnings, "weak signature algorithm: SHA1WithRSA")
	case x509.DSAWithSHA1:
		result.Warnings = append(result.Warnings, "weak signature algorithm: DSAWithSHA1")
	case x509.ECDSAWithSHA1:
		result.Warnings = append(result.Warnings, "weak signature algorithm: ECDSAWithSHA1")
	}

	// Check RSA key size
	if rsaKey, ok := certificate.PublicKey.(*rsa.PublicKey); ok {
		if rsaKey.N.BitLen() < 2048 {
			result.Warnings = append(result.Warnings, "RSA key size is less than 2048 bits")
		}
	}
}
