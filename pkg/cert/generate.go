package cert

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"time"
)

// GenerateSelfSignedCertificate generates a self-signed certificate
func GenerateSelfSignedCertificate(config *CertificateConfig) (*x509.Certificate, crypto.PrivateKey, error) {
	if config == nil {
		return nil, nil, fmt.Errorf("certificate config is required")
	}

	if config.CommonName == "" {
		return nil, nil, fmt.Errorf("common name is required")
	}

	// Generate private key
	privateKey, err := GeneratePrivateKey(config.KeyType)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	// Get signature algorithm
	sigAlg, err := GetSignatureAlgorithmForKey(privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get signature algorithm: %w", err)
	}

	// Create certificate template
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:         config.CommonName,
			Country:            makeStringSlice(config.Country),
			Organization:       makeStringSlice(config.Organization),
			OrganizationalUnit: makeStringSlice(config.OrganizationalUnit),
			Locality:           makeStringSlice(config.Locality),
			Province:           makeStringSlice(config.Province),
			StreetAddress:      makeStringSlice(config.StreetAddress),
			PostalCode:         makeStringSlice(config.PostalCode),
		},
		Issuer: pkix.Name{
			CommonName:         config.CommonName,
			Country:            makeStringSlice(config.Country),
			Organization:       makeStringSlice(config.Organization),
			OrganizationalUnit: makeStringSlice(config.OrganizationalUnit),
			Locality:           makeStringSlice(config.Locality),
			Province:           makeStringSlice(config.Province),
			StreetAddress:      makeStringSlice(config.StreetAddress),
			PostalCode:         makeStringSlice(config.PostalCode),
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour * time.Duration(config.Validity)),
		KeyUsage:              config.KeyUsage,
		BasicConstraintsValid: config.BasicConstraintsValid || config.IsCA,
		IsCA:                  config.IsCA,
		DNSNames:              config.DNSNames,
		EmailAddresses:        config.EmailAddresses,
		SignatureAlgorithm:    sigAlg,
	}

	if config.IsCA {
		if config.MaxPathLength < 0 {
			template.MaxPathLen = -1
		} else {
			template.MaxPathLen = config.MaxPathLength
		}
		template.MaxPathLenZero = (config.MaxPathLength == 0)
	}

	// Set default key usage if not provided
	if config.KeyUsage == 0 {
		if config.IsCA {
			template.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		} else {
			template.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
		}
	}

	// Add extensions
	if len(config.CRLDistributionPoints) > 0 {
		template.CRLDistributionPoints = config.CRLDistributionPoints
	}
	if len(config.OCSPServer) > 0 {
		template.OCSPServer = config.OCSPServer
	}
	if len(config.IssuingCertificateURL) > 0 {
		template.IssuingCertificateURL = config.IssuingCertificateURL
	}

	// Self-sign the certificate
	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, getPublicKey(privateKey), privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return cert, privateKey, nil
}

// GenerateCASignedCertificate generates a certificate signed by a CA
func GenerateCASignedCertificate(
	certConfig *CertificateConfig,
	caConfig *CertificateConfig,
	caPrivateKey crypto.PrivateKey,
	caCert *x509.Certificate,
) (*x509.Certificate, crypto.PrivateKey, error) {
	if certConfig == nil {
		return nil, nil, fmt.Errorf("certificate config is required")
	}
	if caPrivateKey == nil {
		return nil, nil, fmt.Errorf("CA private key is required")
	}
	if caCert == nil {
		return nil, nil, fmt.Errorf("CA certificate is required")
	}

	// Generate private key for new certificate
	privateKey, err := GeneratePrivateKey(certConfig.KeyType)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	// Get signature algorithm from CA key
	sigAlg, err := GetSignatureAlgorithmForKey(caPrivateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get signature algorithm: %w", err)
	}

	// Create certificate template
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	now := time.Now()
	validity := 365 * 24 * time.Hour
	if certConfig.Validity > 0 {
		validity = time.Duration(certConfig.Validity) * 24 * time.Hour
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:         certConfig.CommonName,
			Country:            makeStringSlice(certConfig.Country),
			Organization:       makeStringSlice(certConfig.Organization),
			OrganizationalUnit: makeStringSlice(certConfig.OrganizationalUnit),
			Locality:           makeStringSlice(certConfig.Locality),
			Province:           makeStringSlice(certConfig.Province),
			StreetAddress:      makeStringSlice(certConfig.StreetAddress),
			PostalCode:         makeStringSlice(certConfig.PostalCode),
		},
		NotBefore:          now,
		NotAfter:           now.Add(validity),
		KeyUsage:           certConfig.KeyUsage,
		IsCA:               certConfig.IsCA,
		DNSNames:           certConfig.DNSNames,
		EmailAddresses:     certConfig.EmailAddresses,
		SignatureAlgorithm: sigAlg,
	}

	// Set default key usage
	if template.KeyUsage == 0 {
		if certConfig.IsCA {
			template.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		} else {
			template.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
		}
	}

	if certConfig.IsCA {
		template.BasicConstraintsValid = true
		if certConfig.MaxPathLength < 0 {
			template.MaxPathLen = -1
		} else {
			template.MaxPathLen = certConfig.MaxPathLength
		}
		template.MaxPathLenZero = (certConfig.MaxPathLength == 0)
	}

	// Add extensions
	if len(certConfig.CRLDistributionPoints) > 0 {
		template.CRLDistributionPoints = certConfig.CRLDistributionPoints
	}
	if len(certConfig.OCSPServer) > 0 {
		template.OCSPServer = certConfig.OCSPServer
	}

	// Sign with CA
	certBytes, err := x509.CreateCertificate(rand.Reader, template, caCert, getPublicKey(privateKey), caPrivateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return cert, privateKey, nil
}

// GenerateCSR generates a Certificate Signing Request
func GenerateCSR(config *CSRConfig) (*x509.CertificateRequest, crypto.PrivateKey, error) {
	if config == nil {
		return nil, nil, fmt.Errorf("CSR config is required")
	}
	if config.CommonName == "" {
		return nil, nil, fmt.Errorf("common name is required")
	}

	// Generate private key
	privateKey, err := GeneratePrivateKey(config.KeyType)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	// Get signature algorithm
	sigAlg, err := GetSignatureAlgorithmForKey(privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get signature algorithm: %w", err)
	}

	csrTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: config.CommonName,
		},
		DNSNames:           config.DNSNames,
		SignatureAlgorithm: sigAlg,
	}

	if config.Country != "" {
		csrTemplate.Subject.Country = makeStringSlice(config.Country)
	}
	if config.Organization != "" {
		csrTemplate.Subject.Organization = makeStringSlice(config.Organization)
	}

	// Create CSR
	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create CSR: %w", err)
	}

	csr, err := x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse CSR: %w", err)
	}

	return csr, privateKey, nil
}

// makeStringSlice creates a string slice with one element if the input is non-empty
func makeStringSlice(s string) []string {
	if s == "" {
		return nil
	}
	return []string{s}
}

// getPublicKey extracts public key from any private key type
func getPublicKey(privateKey crypto.PrivateKey) crypto.PublicKey {
	switch key := privateKey.(type) {
	case interface{ Public() crypto.PublicKey }:
		return key.Public()
	default:
		return nil
	}
}
