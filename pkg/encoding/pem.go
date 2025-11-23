package encoding

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"software.sslmate.com/src/go-pkcs12"
)

// EncodeCertificateToPEM encodes a certificate to PEM format
func EncodeCertificateToPEM(cert *x509.Certificate) ([]byte, error) {
	if cert == nil {
		return nil, fmt.Errorf("certificate is nil")
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}), nil
}

// EncodeCertificateToDER encodes a certificate to DER format
func EncodeCertificateToDER(cert *x509.Certificate) ([]byte, error) {
	if cert == nil {
		return nil, fmt.Errorf("certificate is nil")
	}
	return cert.Raw, nil
}

// EncodePrivateKeyToPEM encodes a private key to PEM format
// Supports RSA, ECDSA, and Ed25519 keys
func EncodePrivateKeyToPEM(key crypto.PrivateKey) ([]byte, error) {
	if key == nil {
		return nil, fmt.Errorf("private key is nil")
	}

	keyBytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyBytes,
	}), nil
}

// EncodePrivateKeyToDER encodes a private key to DER format
func EncodePrivateKeyToDER(key crypto.PrivateKey) ([]byte, error) {
	if key == nil {
		return nil, fmt.Errorf("private key is nil")
	}

	return x509.MarshalPKCS8PrivateKey(key)
}

// EncodeCSRToPEM encodes a Certificate Signing Request to PEM format
func EncodeCSRToPEM(csr *x509.CertificateRequest) ([]byte, error) {
	if csr == nil {
		return nil, fmt.Errorf("CSR is nil")
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csr.Raw,
	}), nil
}

// EncodeCSRToDER encodes a Certificate Signing Request to DER format
func EncodeCSRToDER(csr *x509.CertificateRequest) ([]byte, error) {
	if csr == nil {
		return nil, fmt.Errorf("CSR is nil")
	}
	return csr.Raw, nil
}

// EncodeToPKCS12 encodes a certificate and private key to PKCS12 format
func EncodeToPKCS12(
	certificate *x509.Certificate,
	privateKey crypto.PrivateKey,
	password string,
) ([]byte, error) {
	if certificate == nil {
		return nil, fmt.Errorf("certificate is nil")
	}
	if privateKey == nil {
		return nil, fmt.Errorf("private key is nil")
	}

	// Encode to PKCS12
	pfxData, err := pkcs12.Modern.Encode(privateKey, certificate, nil, password)
	if err != nil {
		return nil, fmt.Errorf("failed to encode to PKCS12: %w", err)
	}

	return pfxData, nil
}

// DecodePEM decodes a PEM-encoded block and returns the raw bytes
func DecodePEM(pemData []byte) ([]byte, string, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, "", fmt.Errorf("failed to decode PEM block")
	}

	return block.Bytes, block.Type, nil
}

// DecodeCertificateFromPEM decodes a PEM-encoded certificate
func DecodeCertificateFromPEM(pemData []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("invalid PEM block type: expected CERTIFICATE, got %s", block.Type)
	}

	return x509.ParseCertificate(block.Bytes)
}

// DecodeCertificateFromDER decodes a DER-encoded certificate
func DecodeCertificateFromDER(derData []byte) (*x509.Certificate, error) {
	return x509.ParseCertificate(derData)
}

// DecodePrivateKeyFromPEM decodes a PEM-encoded private key
func DecodePrivateKeyFromPEM(pemData []byte) (crypto.PrivateKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	if block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("invalid PEM block type: expected PRIVATE KEY, got %s", block.Type)
	}

	return x509.ParsePKCS8PrivateKey(block.Bytes)
}

// DecodePrivateKeyFromDER decodes a DER-encoded private key
func DecodePrivateKeyFromDER(derData []byte) (crypto.PrivateKey, error) {
	return x509.ParsePKCS8PrivateKey(derData)
}

// DecodeCSRFromPEM decodes a PEM-encoded Certificate Signing Request
func DecodeCSRFromPEM(pemData []byte) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	if block.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("invalid PEM block type: expected CERTIFICATE REQUEST, got %s", block.Type)
	}

	return x509.ParseCertificateRequest(block.Bytes)
}

// DecodeCSRFromDER decodes a DER-encoded Certificate Signing Request
func DecodeCSRFromDER(derData []byte) (*x509.CertificateRequest, error) {
	return x509.ParseCertificateRequest(derData)
}

// DecodeFromPKCS12 decodes a PKCS12-encoded bundle
func DecodeFromPKCS12(
	pfxData []byte,
	password string,
) (*x509.Certificate, crypto.PrivateKey, error) {
	// Decode PKCS12
	privateKey, certificate, caCerts, err := pkcs12.DecodeChain(pfxData, password)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode PKCS12: %w", err)
	}

	if certificate == nil {
		return nil, nil, fmt.Errorf("no certificate found in PKCS12")
	}

	_ = caCerts // Unused for now, can be used if chain is needed

	return certificate, privateKey, nil
}

// EncodeCertificateChainToPEM encodes a certificate chain to PEM format
func EncodeCertificateChainToPEM(certs ...*x509.Certificate) ([]byte, error) {
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates provided")
	}

	var result []byte
	for _, cert := range certs {
		if cert == nil {
			continue
		}
		certPEM, err := EncodeCertificateToPEM(cert)
		if err != nil {
			return nil, err
		}
		result = append(result, certPEM...)
	}

	return result, nil
}

// DecodeCertificateChainFromPEM decodes a PEM-encoded certificate chain
func DecodeCertificateChainFromPEM(pemData []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate

	remaining := pemData
	for {
		block, rest := pem.Decode(remaining)
		if block == nil {
			break
		}

		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("failed to parse certificate: %w", err)
			}
			certs = append(certs, cert)
		}

		remaining = rest
	}

	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates found in PEM data")
	}

	return certs, nil
}
