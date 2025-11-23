package encoding

import (
	"crypto/x509"
	"testing"

	"github.com/0x524a/certifier/pkg/cert"
)

func TestEncodeCertificateToPEM(t *testing.T) {
	config := &cert.CertificateConfig{
		CommonName: "test.example.com",
		KeyType:    cert.KeyTypeRSA2048,
		Validity:   365,
	}

	certificate, _, err := cert.GenerateSelfSignedCertificate(config)
	if err != nil {
		t.Fatalf("Failed to generate certificate: %v", err)
	}

	pemData, err := EncodeCertificateToPEM(certificate)
	if err != nil {
		t.Fatalf("Failed to encode certificate to PEM: %v", err)
	}

	if len(pemData) == 0 {
		t.Fatal("PEM data is empty")
	}

	// Verify it's valid PEM
	decodedCert, err := DecodeCertificateFromPEM(pemData)
	if err != nil {
		t.Fatalf("Failed to decode PEM: %v", err)
	}

	if decodedCert.SerialNumber.Cmp(certificate.SerialNumber) != 0 {
		t.Error("Decoded certificate serial number does not match")
	}
}

func TestEncodeCertificateToDER(t *testing.T) {
	config := &cert.CertificateConfig{
		CommonName: "test.example.com",
		KeyType:    cert.KeyTypeRSA2048,
		Validity:   365,
	}

	certificate, _, err := cert.GenerateSelfSignedCertificate(config)
	if err != nil {
		t.Fatalf("Failed to generate certificate: %v", err)
	}

	derData, err := EncodeCertificateToDER(certificate)
	if err != nil {
		t.Fatalf("Failed to encode certificate to DER: %v", err)
	}

	if len(derData) == 0 {
		t.Fatal("DER data is empty")
	}

	decodedCert, err := DecodeCertificateFromDER(derData)
	if err != nil {
		t.Fatalf("Failed to decode DER: %v", err)
	}

	if decodedCert.SerialNumber.Cmp(certificate.SerialNumber) != 0 {
		t.Error("Decoded certificate serial number does not match")
	}
}

func TestEncodeDecodePrivateKey(t *testing.T) {
	privateKey, err := cert.GeneratePrivateKey(cert.KeyTypeRSA2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Test PEM encoding/decoding
	pemData, err := EncodePrivateKeyToPEM(privateKey)
	if err != nil {
		t.Fatalf("Failed to encode key to PEM: %v", err)
	}

	if len(pemData) == 0 {
		t.Fatal("PEM data is empty")
	}

	decodedKey, err := DecodePrivateKeyFromPEM(pemData)
	if err != nil {
		t.Fatalf("Failed to decode key from PEM: %v", err)
	}

	if decodedKey == nil {
		t.Fatal("Decoded key is nil")
	}

	// Test DER encoding/decoding
	derData, err := EncodePrivateKeyToDER(privateKey)
	if err != nil {
		t.Fatalf("Failed to encode key to DER: %v", err)
	}

	if len(derData) == 0 {
		t.Fatal("DER data is empty")
	}

	decodedKeyDER, err := DecodePrivateKeyFromDER(derData)
	if err != nil {
		t.Fatalf("Failed to decode key from DER: %v", err)
	}

	if decodedKeyDER == nil {
		t.Fatal("Decoded key is nil")
	}
}

func TestEncodeCSRToPEM(t *testing.T) {
	config := &cert.CSRConfig{
		CommonName: "test.example.com",
		KeyType:    cert.KeyTypeRSA2048,
	}

	csr, _, err := cert.GenerateCSR(config)
	if err != nil {
		t.Fatalf("Failed to generate CSR: %v", err)
	}

	pemData, err := EncodeCSRToPEM(csr)
	if err != nil {
		t.Fatalf("Failed to encode CSR to PEM: %v", err)
	}

	if len(pemData) == 0 {
		t.Fatal("PEM data is empty")
	}

	decodedCSR, err := DecodeCSRFromPEM(pemData)
	if err != nil {
		t.Fatalf("Failed to decode CSR from PEM: %v", err)
	}

	if decodedCSR.Subject.CommonName != "test.example.com" {
		t.Errorf("Expected CN=test.example.com, got %s", decodedCSR.Subject.CommonName)
	}
}

func TestEncodeCertificateChainToPEM(t *testing.T) {
	// Generate CA
	caConfig := &cert.CertificateConfig{
		CommonName: "Test CA",
		KeyType:    cert.KeyTypeRSA2048,
		Validity:   3650,
		IsCA:       true,
	}

	caCert, caKey, err := cert.GenerateSelfSignedCertificate(caConfig)
	if err != nil {
		t.Fatalf("Failed to generate CA: %v", err)
	}

	// Generate certificate
	certConfig := &cert.CertificateConfig{
		CommonName: "example.com",
		KeyType:    cert.KeyTypeRSA2048,
		Validity:   365,
	}

	serverCert, _, err := cert.GenerateCASignedCertificate(certConfig, caConfig, caKey, caCert)
	if err != nil {
		t.Fatalf("Failed to generate certificate: %v", err)
	}

	chainPEM, err := EncodeCertificateChainToPEM(serverCert, caCert)
	if err != nil {
		t.Fatalf("Failed to encode chain to PEM: %v", err)
	}

	if len(chainPEM) == 0 {
		t.Fatal("Chain PEM is empty")
	}

	chainCerts, err := DecodeCertificateChainFromPEM(chainPEM)
	if err != nil {
		t.Fatalf("Failed to decode chain from PEM: %v", err)
	}

	if len(chainCerts) != 2 {
		t.Errorf("Expected 2 certificates in chain, got %d", len(chainCerts))
	}
}

func TestEncodeToPKCS12(t *testing.T) {
	config := &cert.CertificateConfig{
		CommonName: "test.example.com",
		KeyType:    cert.KeyTypeRSA2048,
		Validity:   365,
	}

	certificate, privateKey, err := cert.GenerateSelfSignedCertificate(config)
	if err != nil {
		t.Fatalf("Failed to generate certificate: %v", err)
	}

	password := "test-password-123"
	pfxData, err := EncodeToPKCS12(certificate, privateKey, password)
	if err != nil {
		t.Fatalf("Failed to encode to PKCS12: %v", err)
	}

	if len(pfxData) == 0 {
		t.Fatal("PKCS12 data is empty")
	}

	// Decode and verify
	decodedCert, decodedKey, err := DecodeFromPKCS12(pfxData, password)
	if err != nil {
		t.Fatalf("Failed to decode PKCS12: %v", err)
	}

	if decodedCert == nil || decodedKey == nil {
		t.Fatal("Decoded certificate or key is nil")
	}

	if decodedCert.SerialNumber.Cmp(certificate.SerialNumber) != 0 {
		t.Error("Decoded certificate serial number does not match")
	}
}

// Additional tests for uncovered functions

func TestDecodeCSRFromDER(t *testing.T) {
	config := &cert.CSRConfig{
		CommonName: "test.example.com",
		KeyType:    cert.KeyTypeRSA2048,
	}

	csr, _, err := cert.GenerateCSR(config)
	if err != nil {
		t.Fatalf("Failed to generate CSR: %v", err)
	}

	// Encode to DER
	derData := csr.Raw

	// Decode from DER
	decodedCSR, err := DecodeCSRFromDER(derData)
	if err != nil {
		t.Fatalf("Failed to decode CSR from DER: %v", err)
	}

	if decodedCSR.Subject.CommonName != "test.example.com" {
		t.Errorf("Expected CN=test.example.com, got %s", decodedCSR.Subject.CommonName)
	}
}

func TestDecodeCSRFromDERInvalid(t *testing.T) {
	invalidDER := []byte("invalid DER data")

	decodedCSR, err := DecodeCSRFromDER(invalidDER)
	if err == nil {
		t.Fatal("Expected error for invalid DER data")
	}

	if decodedCSR != nil {
		t.Error("Expected nil CSR for invalid data")
	}
}

func TestDecodePrivateKeyFromPEMVariants(t *testing.T) {
	keyTypes := []cert.KeyType{
		cert.KeyTypeRSA2048,
		cert.KeyTypeRSA4096,
		cert.KeyTypeECDSAP256,
		cert.KeyTypeECDSAP384,
		cert.KeyTypeECDSAP521,
		cert.KeyTypeEd25519,
	}

	for _, kt := range keyTypes {
		t.Run(string(kt), func(t *testing.T) {
			privateKey, err := cert.GeneratePrivateKey(kt)
			if err != nil {
				t.Fatalf("Failed to generate key: %v", err)
			}

			// Encode to PEM
			pemData, err := EncodePrivateKeyToPEM(privateKey)
			if err != nil {
				t.Fatalf("Failed to encode to PEM: %v", err)
			}

			// Decode from PEM
			decodedKey, err := DecodePrivateKeyFromPEM(pemData)
			if err != nil {
				t.Fatalf("Failed to decode from PEM: %v", err)
			}

			if decodedKey == nil {
				t.Fatal("Decoded key is nil")
			}
		})
	}
}

func TestDecodePrivateKeyFromPEMInvalid(t *testing.T) {
	invalidPEM := []byte("-----BEGIN PRIVATE KEY-----\ninvalid\n-----END PRIVATE KEY-----")

	decodedKey, err := DecodePrivateKeyFromPEM(invalidPEM)
	if err == nil {
		t.Fatal("Expected error for invalid PEM data")
	}

	if decodedKey != nil {
		t.Error("Expected nil key for invalid data")
	}
}

func TestDecodeCSRFromPEMInvalid(t *testing.T) {
	invalidPEM := []byte("-----BEGIN CERTIFICATE REQUEST-----\ninvalid\n-----END CERTIFICATE REQUEST-----")

	decodedCSR, err := DecodeCSRFromPEM(invalidPEM)
	if err == nil {
		t.Fatal("Expected error for invalid PEM data")
	}

	if decodedCSR != nil {
		t.Error("Expected nil CSR for invalid data")
	}
}

func TestDecodeFromPKCS12InvalidPassword(t *testing.T) {
	config := &cert.CertificateConfig{
		CommonName: "test.example.com",
		KeyType:    cert.KeyTypeRSA2048,
		Validity:   365,
	}

	certificate, privateKey, err := cert.GenerateSelfSignedCertificate(config)
	if err != nil {
		t.Fatalf("Failed to generate certificate: %v", err)
	}

	password := "correct-password"
	pfxData, err := EncodeToPKCS12(certificate, privateKey, password)
	if err != nil {
		t.Fatalf("Failed to encode to PKCS12: %v", err)
	}

	// Try with wrong password
	_, _, err = DecodeFromPKCS12(pfxData, "wrong-password")
	if err == nil {
		t.Fatal("Expected error with wrong password")
	}
}

func TestDecodeCertificateChainFromPEMSingleCert(t *testing.T) {
	config := &cert.CertificateConfig{
		CommonName: "test.example.com",
		KeyType:    cert.KeyTypeRSA2048,
		Validity:   365,
	}

	certificate, _, err := cert.GenerateSelfSignedCertificate(config)
	if err != nil {
		t.Fatalf("Failed to generate certificate: %v", err)
	}

	pemData, err := EncodeCertificateToPEM(certificate)
	if err != nil {
		t.Fatalf("Failed to encode to PEM: %v", err)
	}

	decodedChain, err := DecodeCertificateChainFromPEM(pemData)
	if err != nil {
		t.Fatalf("Failed to decode chain from PEM: %v", err)
	}

	if len(decodedChain) != 1 {
		t.Errorf("Expected 1 certificate in chain, got %d", len(decodedChain))
	}

	if decodedChain[0].SerialNumber.Cmp(certificate.SerialNumber) != 0 {
		t.Error("Decoded certificate serial number does not match")
	}
}

func TestDecodeCertificateChainFromPEMInvalid(t *testing.T) {
	invalidPEM := []byte("-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----")

	decodedChain, err := DecodeCertificateChainFromPEM(invalidPEM)
	if err == nil {
		t.Fatal("Expected error for invalid PEM data")
	}

	if decodedChain != nil {
		t.Error("Expected nil chain for invalid data")
	}
}

func TestEncodeCertificateToPEMNilCert(t *testing.T) {
	_, err := EncodeCertificateToPEM(nil)
	if err == nil {
		t.Fatal("Expected error for nil certificate")
	}
}

func TestEncodeCertificateToDERNilCert(t *testing.T) {
	_, err := EncodeCertificateToDER(nil)
	if err == nil {
		t.Fatal("Expected error for nil certificate")
	}
}

func TestEncodePrivateKeyToPEMNilKey(t *testing.T) {
	_, err := EncodePrivateKeyToPEM(nil)
	if err == nil {
		t.Fatal("Expected error for nil private key")
	}
}

func TestEncodePrivateKeyToDERNilKey(t *testing.T) {
	_, err := EncodePrivateKeyToDER(nil)
	if err == nil {
		t.Fatal("Expected error for nil private key")
	}
}

func TestEncodeCSRToPEMNilCSR(t *testing.T) {
	_, err := EncodeCSRToPEM(nil)
	if err == nil {
		t.Fatal("Expected error for nil CSR")
	}
}

func TestEncodeCertificateChainToPEMEmptyChain(t *testing.T) {
	config := &cert.CertificateConfig{
		CommonName: "test.example.com",
		KeyType:    cert.KeyTypeRSA2048,
		Validity:   365,
	}

	certificate, _, err := cert.GenerateSelfSignedCertificate(config)
	if err != nil {
		t.Fatalf("Failed to generate certificate: %v", err)
	}

	// Single cert is valid
	chainPEM, err := EncodeCertificateChainToPEM(certificate)
	if err != nil {
		t.Fatalf("Failed to encode chain to PEM: %v", err)
	}

	if len(chainPEM) == 0 {
		t.Fatal("Chain PEM is empty")
	}
}

func TestEncodeToPKCS12NilCertOrKey(t *testing.T) {
	config := &cert.CertificateConfig{
		CommonName: "test.example.com",
		KeyType:    cert.KeyTypeRSA2048,
		Validity:   365,
	}

	certificate, privateKey, err := cert.GenerateSelfSignedCertificate(config)
	if err != nil {
		t.Fatalf("Failed to generate certificate: %v", err)
	}

	tests := []struct {
		name        string
		cert        *x509.Certificate
		key         interface{}
		password    string
		shouldError bool
	}{
		{
			name:        "nil certificate",
			cert:        nil,
			key:         privateKey,
			password:    "test",
			shouldError: true,
		},
		{
			name:        "nil key",
			cert:        certificate,
			key:         nil,
			password:    "test",
			shouldError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := EncodeToPKCS12(tt.cert, tt.key, tt.password)
			if (err != nil) != tt.shouldError {
				t.Errorf("Expected error=%v, got err=%v", tt.shouldError, err)
			}
		})
	}
}
