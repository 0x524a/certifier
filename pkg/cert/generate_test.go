package cert

import (
	"net"
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

func TestGenerateSelfSignedCertificateWithAllKeyTypes(t *testing.T) {
	keyTypes := []KeyType{
		KeyTypeRSA2048,
		KeyTypeRSA4096,
		KeyTypeECDSAP256,
		KeyTypeECDSAP384,
		KeyTypeECDSAP521,
		KeyTypeEd25519,
	}

	for _, keyType := range keyTypes {
		t.Run(string(keyType), func(t *testing.T) {
			config := &CertificateConfig{
				CommonName:   "test.example.com",
				Country:      "US",
				Organization: "Test Org",
				KeyType:      keyType,
				Validity:     365,
				IsCA:         false,
			}

			cert, key, err := GenerateSelfSignedCertificate(config)
			if err != nil {
				t.Fatalf("Failed to generate certificate with %s: %v", keyType, err)
			}

			if cert == nil {
				t.Fatal("Certificate is nil")
			}

			if key == nil {
				t.Fatal("Private key is nil")
			}

			// Verify public key can be extracted
			pubKey, err := GetPublicKey(key)
			if err != nil {
				t.Fatalf("Failed to get public key: %v", err)
			}

			if pubKey == nil {
				t.Fatal("Public key is nil")
			}
		})
	}
}

func TestGenerateCASignedCertificateWithDNSNames(t *testing.T) {
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

	// Generate certificate with DNS names
	certConfig := &CertificateConfig{
		CommonName:     "example.com",
		Country:        "US",
		Organization:   "Test Org",
		KeyType:        KeyTypeRSA2048,
		Validity:       365,
		DNSNames:       []string{"example.com", "www.example.com", "api.example.com"},
		EmailAddresses: []string{"admin@example.com"},
		IPAddresses:    []net.IP{net.ParseIP("192.168.1.1"), net.ParseIP("10.0.0.1")},
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

	if len(cert.DNSNames) != 3 {
		t.Errorf("Expected 3 DNS names, got %d", len(cert.DNSNames))
	}

	if len(cert.EmailAddresses) != 1 {
		t.Errorf("Expected 1 email address, got %d", len(cert.EmailAddresses))
	}

	if len(cert.IPAddresses) != 2 {
		t.Errorf("Expected 2 IP addresses, got %d", len(cert.IPAddresses))
	}
}

func TestGenerateCASignedCertificateWithECDSA(t *testing.T) {
	// Generate ECDSA CA
	caConfig := &CertificateConfig{
		CommonName:    "ECDSA CA",
		Country:       "US",
		Organization:  "Test CA",
		KeyType:       KeyTypeECDSAP256,
		Validity:      3650,
		IsCA:          true,
		MaxPathLength: -1,
	}

	caCert, caKey, err := GenerateSelfSignedCertificate(caConfig)
	if err != nil {
		t.Fatalf("Failed to generate CA certificate: %v", err)
	}

	// Generate certificate signed by ECDSA CA
	certConfig := &CertificateConfig{
		CommonName:   "example.com",
		Country:      "US",
		Organization: "Test Org",
		KeyType:      KeyTypeECDSAP256,
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
}

func TestGetPublicKey(t *testing.T) {
	keyTypes := []KeyType{
		KeyTypeRSA2048,
		KeyTypeECDSAP256,
		KeyTypeEd25519,
	}

	for _, keyType := range keyTypes {
		t.Run(string(keyType), func(t *testing.T) {
			key, err := GeneratePrivateKey(keyType)
			if err != nil {
				t.Fatalf("Failed to generate key: %v", err)
			}

			pubKey, err := GetPublicKey(key)
			if err != nil {
				t.Errorf("Failed to get public key: %v", err)
			}

			if pubKey == nil {
				t.Error("Public key is nil")
			}
		})
	}
}

func TestGetSignatureAlgorithmForKey(t *testing.T) {
	tests := []struct {
		name    string
		keyType KeyType
	}{
		{"RSA 2048", KeyTypeRSA2048},
		{"ECDSA P-256", KeyTypeECDSAP256},
		{"ECDSA P-384", KeyTypeECDSAP384},
		{"ECDSA P-521", KeyTypeECDSAP521},
		{"Ed25519", KeyTypeEd25519},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := GeneratePrivateKey(tt.keyType)
			if err != nil {
				t.Fatalf("Failed to generate key: %v", err)
			}

			sigAlg, err := GetSignatureAlgorithmForKey(key)
			if err != nil {
				t.Errorf("Failed to get signature algorithm: %v", err)
			}

			if sigAlg == 0 {
				t.Error("Signature algorithm is unknown")
			}
		})
	}
}

func TestGetKeySize(t *testing.T) {
	tests := []struct {
		name    string
		keyType KeyType
		minSize int
		maxSize int
	}{
		{"RSA 2048", KeyTypeRSA2048, 2040, 2056},
		{"RSA 4096", KeyTypeRSA4096, 4080, 4112},
		{"ECDSA P-256", KeyTypeECDSAP256, 250, 270},
		{"ECDSA P-384", KeyTypeECDSAP384, 378, 398},
		{"ECDSA P-521", KeyTypeECDSAP521, 510, 530},
		{"Ed25519", KeyTypeEd25519, 256, 256},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := GeneratePrivateKey(tt.keyType)
			if err != nil {
				t.Fatalf("Failed to generate key: %v", err)
			}

			size := GetKeySize(key)
			if size < tt.minSize || size > tt.maxSize {
				t.Errorf("Key size %d not in expected range [%d, %d]", size, tt.minSize, tt.maxSize)
			}
		})
	}
}
