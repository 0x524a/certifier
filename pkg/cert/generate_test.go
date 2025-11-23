package cert

import (
	"testing"
	"time"
)

func TestGenerateSelfSignedCertificate(t *testing.T) {
	config := &CertificateConfig{
		CommonName:   "test.example.com",
		Country:      "US",
		Organization: "Test Org",
		KeyType:      KeyTypeRSA2048,
		Validity:     365,
		IsCA:         false,
	}

	cert, key, err := GenerateSelfSignedCertificate(config)
	if err != nil {
		t.Fatalf("Failed to generate certificate: %v", err)
	}

	if cert == nil {
		t.Fatal("Certificate is nil")
	}

	if key == nil {
		t.Fatal("Private key is nil")
	}

	if cert.Subject.CommonName != "test.example.com" {
		t.Errorf("Expected CN=test.example.com, got %s", cert.Subject.CommonName)
	}

	if !cert.NotBefore.Before(cert.NotAfter) {
		t.Error("NotBefore should be before NotAfter")
	}
}

func TestGenerateCASignedCertificate(t *testing.T) {
	// Generate CA
	caConfig := &CertificateConfig{
		CommonName:    "My CA",
		Country:       "US",
		Organization:  "Test CA",
		KeyType:       KeyTypeRSA2048,
		Validity:      3650,
		IsCA:          true,
		MaxPathLength: -1,
	}

	caCert, caKey, err := GenerateSelfSignedCertificate(caConfig)
	if err != nil {
		t.Fatalf("Failed to generate CA certificate: %v", err)
	}

	// Generate certificate signed by CA
	certConfig := &CertificateConfig{
		CommonName:   "example.com",
		Country:      "US",
		Organization: "Test Org",
		KeyType:      KeyTypeRSA2048,
		Validity:     365,
	}

	cert, key, err := GenerateCASignedCertificate(certConfig, caConfig, caKey, caCert)
	if err != nil {
		t.Fatalf("Failed to generate CA-signed certificate: %v", err)
	}

	if cert == nil {
		t.Fatal("Certificate is nil")
	}

	if key == nil {
		t.Fatal("Private key is nil")
	}

	if cert.Subject.CommonName != "example.com" {
		t.Errorf("Expected CN=example.com, got %s", cert.Subject.CommonName)
	}

	if caCert.Subject.String() != cert.Issuer.String() {
		t.Error("Certificate issuer does not match CA subject")
	}
}

func TestGenerateCSR(t *testing.T) {
	config := &CSRConfig{
		CommonName:   "test.example.com",
		Country:      "US",
		Organization: "Test Org",
		KeyType:      KeyTypeRSA2048,
		DNSNames:     []string{"test.example.com", "www.example.com"},
	}

	csr, key, err := GenerateCSR(config)
	if err != nil {
		t.Fatalf("Failed to generate CSR: %v", err)
	}

	if csr == nil {
		t.Fatal("CSR is nil")
	}

	if key == nil {
		t.Fatal("Private key is nil")
	}

	if csr.Subject.CommonName != "test.example.com" {
		t.Errorf("Expected CN=test.example.com, got %s", csr.Subject.CommonName)
	}

	if len(csr.DNSNames) != 2 {
		t.Errorf("Expected 2 DNS names, got %d", len(csr.DNSNames))
	}
}

func TestGeneratePrivateKey(t *testing.T) {
	tests := []struct {
		name    string
		keyType KeyType
	}{
		{"RSA 2048", KeyTypeRSA2048},
		{"RSA 4096", KeyTypeRSA4096},
		{"ECDSA P-256", KeyTypeECDSAP256},
		{"ECDSA P-384", KeyTypeECDSAP384},
		{"ECDSA P-521", KeyTypeECDSAP521},
		{"Ed25519", KeyTypeEd25519},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := GeneratePrivateKey(tt.keyType)
			if err != nil {
				t.Errorf("Failed to generate key: %v", err)
			}

			if key == nil {
				t.Error("Generated key is nil")
			}

			size := GetKeySize(key)
			if size == 0 {
				t.Error("Key size is 0")
			}
		})
	}
}

func TestCertificateExpiration(t *testing.T) {
	config := &CertificateConfig{
		CommonName: "test.example.com",
		KeyType:    KeyTypeRSA2048,
		Validity:   1, // 1 day
	}

	cert, _, err := GenerateSelfSignedCertificate(config)
	if err != nil {
		t.Fatalf("Failed to generate certificate: %v", err)
	}

	now := time.Now()
	if cert.NotBefore.After(now) {
		t.Error("Certificate NotBefore should not be in the future")
	}

	expectedExpiry := now.Add(24 * time.Hour)
	if !cert.NotAfter.After(expectedExpiry.Add(-10*time.Minute)) ||
		!cert.NotAfter.Before(expectedExpiry.Add(10*time.Minute)) {
		t.Errorf("Certificate expiry is not as expected. Got %v", cert.NotAfter)
	}
}
