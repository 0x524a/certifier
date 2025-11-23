package crl

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"time"
)

// RevokedCertificate represents a revoked certificate entry
type RevokedCertificate struct {
	SerialNumber     *big.Int
	RevocationTime   time.Time
	RevocationReason int // CRL reason code
}

// CRLConfig holds configuration for CRL generation
type CRLConfig struct {
	// The CA certificate that will sign the CRL
	CAKeyPair *keyPair

	// CA Certificate
	CACertificate *x509.Certificate

	// List of revoked certificates
	RevokedCerts []*RevokedCertificate

	// CRL validity period
	ValidityDays int

	// CRL number (for incremental CRLs)
	Number int64

	// URLs for CRL distribution
	DistributionURL string
}

// keyPair represents a key pair (internal type)
type keyPair struct {
	PrivateKey crypto.PrivateKey
}

// GenerateCRL generates a Certificate Revocation List
func GenerateCRL(config *CRLConfig) ([]byte, error) {
	if config == nil {
		return nil, fmt.Errorf("CRL config is required")
	}
	if config.CACertificate == nil {
		return nil, fmt.Errorf("CA certificate is required")
	}
	if config.CAKeyPair == nil || config.CAKeyPair.PrivateKey == nil {
		return nil, fmt.Errorf("CA private key is required")
	}

	// Build revoked certificates list
	var revokedCerts []pkix.RevokedCertificate
	for _, revoked := range config.RevokedCerts {
		revokedCerts = append(revokedCerts, pkix.RevokedCertificate{
			SerialNumber:   revoked.SerialNumber,
			RevocationTime: revoked.RevocationTime,
		})
	}

	// Create CRL template
	now := time.Now()
	validity := 30 * 24 * time.Hour
	if config.ValidityDays > 0 {
		validity = time.Duration(config.ValidityDays) * 24 * time.Hour
	}

	crlTemplate := &x509.RevocationList{
		Issuer:              config.CACertificate.Subject,
		ThisUpdate:          now,
		NextUpdate:          now.Add(validity),
		RevokedCertificates: revokedCerts,
		Number:              big.NewInt(config.Number),
	}

	// Create CRL with a simple key wrapper
	signer := &simpleSigner{pk: config.CAKeyPair.PrivateKey}

	// Generate CRL
	crlBytes, err := x509.CreateRevocationList(
		rand.Reader,
		crlTemplate,
		config.CACertificate,
		signer,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create CRL: %w", err)
	}

	return crlBytes, nil
}

// ParseCRL parses a CRL from DER-encoded bytes
func ParseCRL(crlData []byte) (*x509.RevocationList, error) {
	return x509.ParseRevocationList(crlData)
}

// CheckRevocation checks if a certificate is revoked in the CRL
func CheckRevocation(cert *x509.Certificate, crl *x509.RevocationList) bool {
	if cert == nil || crl == nil {
		return false
	}

	for _, revoked := range crl.RevokedCertificateEntries {
		if revoked.SerialNumber.Cmp(cert.SerialNumber) == 0 {
			return true
		}
	}

	return false
}

// RevocationReason constants
const (
	ReasonUnspecified          = 0
	ReasonKeyCompromise        = 1
	ReasonCACompromise         = 2
	ReasonAffiliationChanged   = 3
	ReasonSuperseded           = 4
	ReasonCessationOfOperation = 5
	ReasonCertificateHold      = 6
	ReasonRemoveFromCRL        = 8
	ReasonPrivilegeWithdrawn   = 9
	ReasonAACompromise         = 10
)

// simpleSigner is a wrapper to make a private key compatible with crypto.Signer
type simpleSigner struct {
	pk crypto.PrivateKey
}

// Public returns the public key
func (ss *simpleSigner) Public() crypto.PublicKey {
	if rsaKey, ok := ss.pk.(*rsa.PrivateKey); ok {
		return rsaKey.Public()
	}
	// For other key types, try to get the public key if they implement Public()
	if pubGetter, ok := ss.pk.(interface{ Public() crypto.PublicKey }); ok {
		return pubGetter.Public()
	}
	return nil
}

// Sign signs the data using the appropriate signature algorithm
// For RSA keys:
// - If RSA-PSS is explicitly requested via PSSOptions, uses PSS padding for enhanced security
// - Otherwise uses PKCS#1 v1.5 for backward compatibility with existing certificates
// Security Note: To use the more secure RSA-PSS signature scheme for CRLs, generate the
// CA certificate with UseRSAPSS=true in CertificateConfig. This will automatically use
// PSS padding which provides better security properties than PKCS#1 v1.5.
func (ss *simpleSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if rsaKey, ok := ss.pk.(*rsa.PrivateKey); ok {
		// Check if PSS is explicitly requested via SignerOpts
		if pssOpts, ok := opts.(*rsa.PSSOptions); ok {
			// Use PSS padding when explicitly requested for enhanced security
			return rsa.SignPSS(rand, rsaKey, pssOpts.Hash, digest, pssOpts)
		}
		// Default to PKCS1v15 for compatibility with existing PKCS#1 v1.5 certificates
		// The signature algorithm is determined by the CA certificate's SignatureAlgorithm field
		// Note: To use PSS, the CA certificate must be created with PSS signature algorithm
		return rsa.SignPKCS1v15(rand, rsaKey, opts.HashFunc(), digest)
	}
	return nil, fmt.Errorf("signing with key type %T not supported", ss.pk)
}
