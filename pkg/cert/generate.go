package cert

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"strings"
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
	sigAlg, err := GetSignatureAlgorithmForKeyWithPSS(privateKey, config.UseRSAPSS)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get signature algorithm: %w", err)
	}

	// Create certificate template
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	now := time.Now()
	subject := buildSubjectName(config)
	template := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               subject,
		Issuer:                subject,
		NotBefore:             now,
		NotAfter:              now.Add(24 * time.Hour * time.Duration(config.Validity)),
		KeyUsage:              config.KeyUsage,
		BasicConstraintsValid: config.BasicConstraintsValid || config.IsCA,
		IsCA:                  config.IsCA,
		DNSNames:              config.DNSNames,
		EmailAddresses:        config.EmailAddresses,
		IPAddresses:           config.IPAddresses,
		SignatureAlgorithm:    sigAlg,
	}

	// Set default key usage if not provided
	setDefaultKeyUsage(template, config.IsCA)

	// Set extended key usage based on certificate type and custom OIDs
	setExtendedKeyUsage(template, config.CertType, config.IsCA, config.ExtendedKeyUsageOIDs)

	// Configure CA-specific settings
	if config.IsCA {
		setCAConstraints(template, config.MaxPathLength)
	}

	// Add extensions
	addCertificateExtensions(template, config.CRLDistributionPoints, config.OCSPServer, config.IssuingCertificateURL)

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

	subject := buildSubjectName(certConfig)
	template := &x509.Certificate{
		SerialNumber:       serialNumber,
		Subject:            subject,
		NotBefore:          now,
		NotAfter:           now.Add(validity),
		KeyUsage:           certConfig.KeyUsage,
		IsCA:               certConfig.IsCA,
		DNSNames:           certConfig.DNSNames,
		EmailAddresses:     certConfig.EmailAddresses,
		IPAddresses:        certConfig.IPAddresses,
		SignatureAlgorithm: sigAlg,
	}

	// Set default key usage
	setDefaultKeyUsage(template, certConfig.IsCA)

	// Set extended key usage based on certificate type and custom OIDs
	setExtendedKeyUsage(template, certConfig.CertType, certConfig.IsCA, certConfig.ExtendedKeyUsageOIDs)

	// Configure CA-specific settings
	if certConfig.IsCA {
		template.BasicConstraintsValid = true
		setCAConstraints(template, certConfig.MaxPathLength)
	}

	// Add extensions
	addCertificateExtensions(template, certConfig.CRLDistributionPoints, certConfig.OCSPServer, nil)

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

// SignCSR signs a Certificate Signing Request with a CA, producing a certificate
// that uses the CSR's own public key (unlike GenerateCASignedCertificate, which
// always generates a fresh key pair).
func SignCSR(
	csr *x509.CertificateRequest,
	caPrivateKey crypto.PrivateKey,
	caCert *x509.Certificate,
	validityDays int,
) (*x509.Certificate, error) {
	if csr == nil {
		return nil, fmt.Errorf("CSR is required")
	}
	if caPrivateKey == nil {
		return nil, fmt.Errorf("CA private key is required")
	}
	if caCert == nil {
		return nil, fmt.Errorf("CA certificate is required")
	}

	sigAlg, err := GetSignatureAlgorithmForKey(caPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get signature algorithm: %w", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	now := time.Now()
	validity := 365 * 24 * time.Hour
	if validityDays > 0 {
		validity = time.Duration(validityDays) * 24 * time.Hour
	}

	template := &x509.Certificate{
		SerialNumber:       serialNumber,
		Subject:            csr.Subject,
		NotBefore:          now,
		NotAfter:           now.Add(validity),
		DNSNames:           csr.DNSNames,
		EmailAddresses:     csr.EmailAddresses,
		IPAddresses:        csr.IPAddresses,
		SignatureAlgorithm: sigAlg,
	}

	setDefaultKeyUsage(template, false)
	setExtendedKeyUsage(template, CertTypeServer, false, nil)

	certBytes, err := x509.CreateCertificate(rand.Reader, template, caCert, csr.PublicKey, caPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	signedCert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return signedCert, nil
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
		IPAddresses:        config.IPAddresses,
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

// buildSubjectName constructs a pkix.Name from certificate config
func buildSubjectName(config *CertificateConfig) pkix.Name {
	return pkix.Name{
		CommonName:         config.CommonName,
		Country:            makeStringSlice(config.Country),
		Organization:       makeStringSlice(config.Organization),
		OrganizationalUnit: makeStringSlice(config.OrganizationalUnit),
		Locality:           makeStringSlice(config.Locality),
		Province:           makeStringSlice(config.Province),
		StreetAddress:      makeStringSlice(config.StreetAddress),
		PostalCode:         makeStringSlice(config.PostalCode),
	}
}

// setDefaultKeyUsage sets default key usage based on whether cert is a CA
func setDefaultKeyUsage(template *x509.Certificate, isCA bool) {
	if template.KeyUsage == 0 {
		if isCA {
			template.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		} else {
			template.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
		}
	}
}

// setExtendedKeyUsage sets Extended Key Usage based on certificate type and custom OIDs
func setExtendedKeyUsage(template *x509.Certificate, certType CertificateType, isCA bool, customOIDs []string) {
	if isCA {
		// CA certificates don't typically have extended key usage
		return
	}

	// If custom OIDs are provided, use only those
	if len(customOIDs) > 0 {
		template.UnknownExtKeyUsage = append(template.UnknownExtKeyUsage, parseCustomOIDs(customOIDs)...)
		return
	}

	if len(template.ExtKeyUsage) > 0 {
		// Already set, don't override
		return
	}

	switch certType {
	case CertTypeClient:
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	case CertTypeServer:
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	case CertTypeBoth:
		template.ExtKeyUsage = []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		}
	default:
		// Default to server auth if type not specified
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}
}

// parseCustomOIDs converts OID strings to asn1.ObjectIdentifier values suitable
// for x509.Certificate.UnknownExtKeyUsage, so they get embedded as values inside
// the standard Extended Key Usage extension (OID 2.5.29.37) rather than written
// out as their own separate, unrecognized extensions.
// OID format: "2.5.29.37.0" for module signing, etc.
func parseCustomOIDs(oidStrings []string) []asn1.ObjectIdentifier {
	var oids []asn1.ObjectIdentifier
	for _, oidStr := range oidStrings {
		// Create OID from string (split by dots and convert to int values)
		parts := strings.Split(strings.TrimSpace(oidStr), ".")
		if len(parts) < 2 {
			continue // Invalid OID format
		}

		oid := make(asn1.ObjectIdentifier, 0, len(parts))
		for _, part := range parts {
			var val int
			_, err := fmt.Sscanf(part, "%d", &val)
			if err != nil {
				continue // Skip invalid parts
			}
			oid = append(oid, val)
		}

		if len(oid) >= 2 {
			oids = append(oids, oid)
		}
	}
	return oids
}

// setCAConstraints sets CA-specific path length constraints
func setCAConstraints(template *x509.Certificate, maxPathLength int) {
	if maxPathLength < 0 {
		template.MaxPathLen = -1
	} else {
		template.MaxPathLen = maxPathLength
	}
	template.MaxPathLenZero = (maxPathLength == 0)
}

// addCertificateExtensions adds CRL distribution and OCSP URLs to certificate
func addCertificateExtensions(template *x509.Certificate, crlDPs []string, ocspServers []string, issuingURL []string) {
	if len(crlDPs) > 0 {
		template.CRLDistributionPoints = crlDPs
	}
	if len(ocspServers) > 0 {
		template.OCSPServer = ocspServers
	}
	if len(issuingURL) > 0 {
		template.IssuingCertificateURL = issuingURL
	}
}
