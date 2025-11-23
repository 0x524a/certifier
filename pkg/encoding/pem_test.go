package encoding

import (
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
