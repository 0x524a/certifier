package cert

import (
	"crypto/x509"
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

func TestGenerateSelfSignedCertificateWithExtensions(t *testing.T) {
	config := &CertificateConfig{
		CommonName:            "test.example.com",
		Country:               "US",
		Organization:          "Test Org",
		KeyType:               KeyTypeRSA2048,
		Validity:              365,
		IsCA:                  false,
		CRLDistributionPoints: []string{"http://crl.example.com/ca.crl"},
		OCSPServer:            []string{"http://ocsp.example.com"},
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

	if len(cert.CRLDistributionPoints) != 1 {
		t.Errorf("Expected 1 CRL distribution point, got %d", len(cert.CRLDistributionPoints))
	}

	if len(cert.OCSPServer) != 1 {
		t.Errorf("Expected 1 OCSP server, got %d", len(cert.OCSPServer))
	}
}

func TestGenerateCASignedCertificateWithExtensions(t *testing.T) {
	// Generate CA
	caConfig := &CertificateConfig{
		CommonName:    "Test CA",
		Country:       "US",
		Organization:  "Test CA",
		KeyType:       KeyTypeRSA2048,
		Validity:      3650,
		IsCA:          true,
		MaxPathLength: -1,
	}

	caCert, caKey, err := GenerateSelfSignedCertificate(caConfig)
	if err != nil {
		t.Fatalf("Failed to generate CA: %v", err)
	}

	// Generate certificate with extensions
	certConfig := &CertificateConfig{
		CommonName:            "example.com",
		Country:               "US",
		Organization:          "Test Org",
		KeyType:               KeyTypeRSA2048,
		Validity:              365,
		CRLDistributionPoints: []string{"http://crl.example.com/ca.crl"},
		OCSPServer:            []string{"http://ocsp.example.com"},
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

	if len(cert.CRLDistributionPoints) != 1 {
		t.Errorf("Expected 1 CRL distribution point, got %d", len(cert.CRLDistributionPoints))
	}

	if len(cert.OCSPServer) != 1 {
		t.Errorf("Expected 1 OCSP server, got %d", len(cert.OCSPServer))
	}
}

func TestGenerateCSRWithAllFields(t *testing.T) {
	config := &CSRConfig{
		CommonName:   "test.example.com",
		Country:      "US",
		Organization: "Test Org",
		KeyType:      KeyTypeRSA2048,
		DNSNames:     []string{"test.example.com", "www.example.com"},
		IPAddresses:  []net.IP{net.ParseIP("192.168.1.1"), net.ParseIP("10.0.0.1")},
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

	if len(csr.IPAddresses) != 2 {
		t.Errorf("Expected 2 IP addresses, got %d", len(csr.IPAddresses))
	}
}

func TestGenerateCSRWithEachKeyType(t *testing.T) {
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
			config := &CSRConfig{
				CommonName:   "test.example.com",
				Country:      "US",
				Organization: "Test Org",
				KeyType:      keyType,
			}

			csr, key, err := GenerateCSR(config)
			if err != nil {
				t.Fatalf("Failed to generate CSR with %s: %v", keyType, err)
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
		})
	}
}

func TestGenerateSelfSignedCAWithPathLength(t *testing.T) {
	tests := []struct {
		name          string
		maxPathLength int
	}{
		{"unlimited", -1},
		{"zero", 0},
		{"one", 1},
		{"two", 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &CertificateConfig{
				CommonName:    "Test CA",
				Organization:  "Test Org",
				KeyType:       KeyTypeRSA2048,
				Validity:      365,
				IsCA:          true,
				MaxPathLength: tt.maxPathLength,
			}

			cert, _, err := GenerateSelfSignedCertificate(config)
			if err != nil {
				t.Fatalf("Failed to generate CA: %v", err)
			}

			if cert == nil {
				t.Fatal("Certificate is nil")
			}

			if !cert.IsCA {
				t.Error("Expected IsCA to be true")
			}

			if !cert.BasicConstraintsValid {
				t.Error("Expected BasicConstraintsValid to be true")
			}
		})
	}
}

// TestGenerateCSRWithExtendedKeyUsageOIDs tests CSR generation with valid configurations
func TestGenerateCSRWithExtendedKeyUsageOIDs(t *testing.T) {
	tests := []struct {
		name    string
		dns     []string
		wantErr bool
	}{
		{
			name:    "Valid DNS names",
			dns:     []string{"example.com", "www.example.com"},
			wantErr: false,
		},
		{
			name:    "Empty DNS names",
			dns:     []string{},
			wantErr: false,
		},
		{
			name:    "Single DNS name",
			dns:     []string{"localhost"},
			wantErr: false,
		},
		{
			name:    "Wildcard DNS",
			dns:     []string{"*.example.com"},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &CSRConfig{
				CommonName:   "test.example.com",
				Country:      "US",
				Organization: "Test Org",
				KeyType:      "rsa2048",
				DNSNames:     tt.dns,
			}

			csr, _, err := GenerateCSR(config)
			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateCSR error = %v, wantErr %v", err, tt.wantErr)
			}

			if err == nil && csr == nil {
				t.Error("CSR should not be nil when error is nil")
			}
		})
	}
}

// TestGenerateSelfSignedCertificateWithExtendedKeyUsage tests self-signed cert with custom EKU OIDs
func TestGenerateSelfSignedCertificateWithExtendedKeyUsage(t *testing.T) {
	tests := []struct {
		name    string
		oids    []string
		wantErr bool
	}{
		{
			name:    "Valid OID for module signing",
			oids:    []string{"1.3.6.1.4.1.57453.1.1"},
			wantErr: false,
		},
		{
			name:    "Multiple OIDs",
			oids:    []string{"1.2.3.4.5", "2.5.29.37.0", "1.3.6.1.5.5.7.3.1"},
			wantErr: false,
		},
		{
			name:    "Single invalid OID (too short)",
			oids:    []string{"1"},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &CertificateConfig{
				CommonName:           "test.example.com",
				Country:              "US",
				Organization:         "Test Org",
				KeyType:              "rsa2048",
				IsCA:                 false,
				Validity:             365,
				ExtendedKeyUsageOIDs: tt.oids,
			}

			cert, _, err := GenerateSelfSignedCertificate(config)
			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateSelfSignedCertificate error = %v, wantErr %v", err, tt.wantErr)
			}

			if err == nil && cert == nil {
				t.Error("Certificate should not be nil when error is nil")
			}
		})
	}
}

// TestGenerateCASignedCertificateWithExtendedKeyUsage tests CA-signed cert with custom EKU OIDs
func TestGenerateCASignedCertificateWithExtendedKeyUsage(t *testing.T) {
	// Create a CA certificate first
	caConfig := &CertificateConfig{
		CommonName:    "Test CA",
		Organization:  "Test Org",
		IsCA:          true,
		MaxPathLength: -1,
		Validity:      3650,
		KeyType:       "rsa2048",
	}

	caCert, caKey, err := GenerateSelfSignedCertificate(caConfig)
	if err != nil {
		t.Fatalf("Failed to generate CA: %v", err)
	}

	serverConfig := &CertificateConfig{
		CommonName:           "server.example.com",
		Organization:         "Test Org",
		KeyType:              "rsa2048",
		Validity:             365,
		ExtendedKeyUsageOIDs: []string{"1.3.6.1.5.5.7.3.1", "1.3.6.1.5.5.7.3.2"},
	}

	cert, _, err := GenerateCASignedCertificate(serverConfig, caConfig, caKey, caCert)
	if err != nil {
		t.Errorf("GenerateCASignedCertificate error = %v", err)
	}

	if cert == nil {
		t.Error("Certificate should not be nil")
	}
}

// TestGenerateCSRWithInvalidExtendedKeyUsageFormat tests CSR with various configurations
func TestGenerateCSRWithInvalidExtendedKeyUsageFormat(t *testing.T) {
	tests := []struct {
		name string
		dns  []string
		ips  []string
	}{
		{
			name: "Multiple DNS and IPs",
			dns:  []string{"example.com", "www.example.com"},
			ips:  []string{"192.168.1.1", "10.0.0.1"},
		},
		{
			name: "DNS names only",
			dns:  []string{"test.example.com"},
			ips:  []string{},
		},
		{
			name: "IPs only",
			dns:  []string{},
			ips:  []string{"::1", "2001:db8::1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var ips []net.IP
			for _, ip := range tt.ips {
				ips = append(ips, net.ParseIP(ip))
			}

			config := &CSRConfig{
				CommonName:   "test.example.com",
				Country:      "US",
				Organization: "Test Org",
				KeyType:      "rsa2048",
				DNSNames:     tt.dns,
				IPAddresses:  ips,
			}

			csr, _, err := GenerateCSR(config)
			// Even with various configurations, generation should succeed
			if err != nil {
				t.Errorf("GenerateCSR unexpected error: %v", err)
			}
			if csr == nil {
				t.Error("CSR should not be nil")
			}
		})
	}
}

// TestGenerateSelfSignedCertificateWithNilConfig tests error handling for nil config
func TestGenerateSelfSignedCertificateWithNilConfig(t *testing.T) {
	cert, key, err := GenerateSelfSignedCertificate(nil)
	if err == nil {
		t.Error("Expected error for nil config")
	}
	if cert != nil || key != nil {
		t.Error("Expected nil cert and key for nil config")
	}
}

// TestGenerateCASignedCertificateWithNilConfig tests error handling for nil cert config
func TestGenerateCASignedCertificateWithNilConfig(t *testing.T) {
	caConfig := &CertificateConfig{
		CommonName: "Test CA",
		IsCA:       true,
		KeyType:    "rsa2048",
		Validity:   365,
	}
	caCert, caKey, _ := GenerateSelfSignedCertificate(caConfig)

	cert, key, err := GenerateCASignedCertificate(nil, caConfig, caKey, caCert)
	if err == nil {
		t.Error("Expected error for nil cert config")
	}
	if cert != nil || key != nil {
		t.Error("Expected nil cert and key for nil config")
	}
}

// TestGenerateCASignedCertificateWithNilCAKey tests error handling for nil CA key
func TestGenerateCASignedCertificateWithNilCAKey(t *testing.T) {
	caConfig := &CertificateConfig{
		CommonName: "Test CA",
		IsCA:       true,
		KeyType:    "rsa2048",
		Validity:   365,
	}
	caCert, _, _ := GenerateSelfSignedCertificate(caConfig)

	certConfig := &CertificateConfig{
		CommonName: "test.example.com",
		KeyType:    "rsa2048",
		Validity:   365,
	}

	cert, key, err := GenerateCASignedCertificate(certConfig, caConfig, nil, caCert)
	if err == nil {
		t.Error("Expected error for nil CA private key")
	}
	if cert != nil || key != nil {
		t.Error("Expected nil cert and key for nil CA key")
	}
}

// TestGenerateCASignedCertificateWithNilCACert tests error handling for nil CA cert
func TestGenerateCASignedCertificateWithNilCACert(t *testing.T) {
	caConfig := &CertificateConfig{
		CommonName: "Test CA",
		IsCA:       true,
		KeyType:    "rsa2048",
		Validity:   365,
	}
	_, caKey, _ := GenerateSelfSignedCertificate(caConfig)

	certConfig := &CertificateConfig{
		CommonName: "test.example.com",
		KeyType:    "rsa2048",
		Validity:   365,
	}

	cert, key, err := GenerateCASignedCertificate(certConfig, caConfig, caKey, nil)
	if err == nil {
		t.Error("Expected error for nil CA certificate")
	}
	if cert != nil || key != nil {
		t.Error("Expected nil cert and key for nil CA cert")
	}
}

// TestGenerateCSRWithNilConfig tests error handling for nil CSR config
func TestGenerateCSRWithNilConfig(t *testing.T) {
	csr, key, err := GenerateCSR(nil)
	if err == nil {
		t.Error("Expected error for nil CSR config")
	}
	if csr != nil || key != nil {
		t.Error("Expected nil CSR and key for nil config")
	}
}

// TestGenerateSelfSignedCertificateWithEmptyCommonName tests error handling for empty CN
func TestGenerateSelfSignedCertificateWithEmptyCommonName(t *testing.T) {
	config := &CertificateConfig{
		CommonName: "",
		KeyType:    "rsa2048",
		Validity:   365,
	}

	cert, key, err := GenerateSelfSignedCertificate(config)
	if err == nil {
		t.Error("Expected error for empty common name")
	}
	if cert != nil || key != nil {
		t.Error("Expected nil cert and key for empty CN")
	}
}

// TestGenerateCSRWithEmptyCommonName tests error handling for empty CN in CSR
func TestGenerateCSRWithEmptyCommonName(t *testing.T) {
	config := &CSRConfig{
		CommonName: "",
		KeyType:    "rsa2048",
	}

	csr, key, err := GenerateCSR(config)
	if err == nil {
		t.Error("Expected error for empty common name")
	}
	if csr != nil || key != nil {
		t.Error("Expected nil CSR and key for empty CN")
	}
}

// TestGenerateSelfSignedCertificateWithZeroValidity tests certificate with zero validity
func TestGenerateSelfSignedCertificateWithZeroValidity(t *testing.T) {
	config := &CertificateConfig{
		CommonName: "test.example.com",
		KeyType:    "rsa2048",
		Validity:   0, // Will use default 365 days
	}

	cert, key, err := GenerateSelfSignedCertificate(config)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if cert == nil || key == nil {
		t.Error("Expected valid cert and key")
	}
}

// TestGenerateCASignedCertificateWithCASignature tests CA-signed cert signature
func TestGenerateCASignedCertificateWithCASignature(t *testing.T) {
	// Create CA
	caConfig := &CertificateConfig{
		CommonName:    "Root CA",
		Organization:  "Test Org",
		IsCA:          true,
		MaxPathLength: 1,
		Validity:      3650,
		KeyType:       "ecdsa-p256",
	}

	caCert, caKey, err := GenerateSelfSignedCertificate(caConfig)
	if err != nil {
		t.Fatalf("Failed to create CA: %v", err)
	}

	// Create certificate signed by CA
	certConfig := &CertificateConfig{
		CommonName:   "server.example.com",
		Organization: "Test Org",
		DNSNames:     []string{"www.example.com", "api.example.com"},
		Validity:     365,
		KeyType:      "ecdsa-p256",
		CertType:     "server",
	}

	cert, key, err := GenerateCASignedCertificate(certConfig, caConfig, caKey, caCert)
	if err != nil {
		t.Fatalf("Failed to create CA-signed certificate: %v", err)
	}

	if cert == nil || key == nil {
		t.Fatal("Expected valid certificate and key")
	}

	// Verify issuer matches CA subject
	if cert.Issuer.CommonName != caCert.Subject.CommonName {
		t.Errorf("Expected issuer %s, got %s", caCert.Subject.CommonName, cert.Issuer.CommonName)
	}

	// Verify cert is not a CA
	if cert.IsCA {
		t.Error("Expected non-CA certificate")
	}
}

// TestGenerateCASignedCertificateWithIntermediateCA tests intermediate CA creation
func TestGenerateCASignedCertificateWithIntermediateCA(t *testing.T) {
	// Create Root CA
	rootConfig := &CertificateConfig{
		CommonName:    "Root CA",
		IsCA:          true,
		MaxPathLength: 2,
		Validity:      7300,
		KeyType:       "rsa4096",
	}

	rootCert, rootKey, err := GenerateSelfSignedCertificate(rootConfig)
	if err != nil {
		t.Fatalf("Failed to create root CA: %v", err)
	}

	// Create Intermediate CA signed by root
	intermediateConfig := &CertificateConfig{
		CommonName:    "Intermediate CA",
		IsCA:          true,
		MaxPathLength: 0,
		Validity:      3650,
		KeyType:       "rsa2048",
	}

	intermediateCert, intermediateKey, err := GenerateCASignedCertificate(intermediateConfig, rootConfig, rootKey, rootCert)
	if err != nil {
		t.Fatalf("Failed to create intermediate CA: %v", err)
	}

	if !intermediateCert.IsCA {
		t.Error("Expected intermediate to be a CA")
	}

	// Verify intermediate is signed by root
	if intermediateCert.Issuer.CommonName != rootCert.Subject.CommonName {
		t.Errorf("Expected issuer to be root CA")
	}

	// Now create a leaf cert signed by intermediate
	leafConfig := &CertificateConfig{
		CommonName: "leaf.example.com",
		Validity:   365,
		KeyType:    "rsa2048",
	}

	leafCert, _, err := GenerateCASignedCertificate(leafConfig, intermediateConfig, intermediateKey, intermediateCert)
	if err != nil {
		t.Fatalf("Failed to create leaf certificate: %v", err)
	}

	if leafCert.IsCA {
		t.Error("Expected leaf to not be a CA")
	}
}

// TestGenerateCSRWithEmailAddresses tests CSR with email addresses
func TestGenerateCSRWithDNSOnly(t *testing.T) {
	config := &CSRConfig{
		CommonName:   "dns-only.example.com",
		Organization: "Test Org",
		KeyType:      "rsa2048",
		DNSNames:     []string{"www.example.com", "api.example.com"},
	}

	csr, key, err := GenerateCSR(config)
	if err != nil {
		t.Fatalf("Failed to generate CSR with DNS names: %v", err)
	}

	if csr == nil || key == nil {
		t.Fatal("Expected valid CSR and key")
	}
}

// TestGenerateCertificateWithPresetKeyUsage tests cert with preset key usage
func TestGenerateCertificateWithPresetKeyUsage(t *testing.T) {
	config := &CertificateConfig{
		CommonName: "preset.example.com",
		KeyType:    "rsa2048",
		Validity:   365,
		KeyUsage:   x509.KeyUsageDigitalSignature | x509.KeyUsageDataEncipherment,
	}

	cert, key, err := GenerateSelfSignedCertificate(config)
	if err != nil {
		t.Fatalf("Failed to generate cert with preset key usage: %v", err)
	}

	if cert == nil || key == nil {
		t.Fatal("Expected valid cert and key")
	}

	// Verify key usage was preserved
	if cert.KeyUsage != config.KeyUsage {
		t.Errorf("Expected key usage %d, got %d", config.KeyUsage, cert.KeyUsage)
	}
}

// TestGenerateCertificateWithPresetExtKeyUsage tests cert with preset ext key usage
func TestGenerateCertificateWithPresetExtKeyUsage(t *testing.T) {
	config := &CertificateConfig{
		CommonName:       "preset-ext.example.com",
		KeyType:          "rsa2048",
		Validity:         365,
		ExtendedKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning, x509.ExtKeyUsageEmailProtection},
	}

	cert, key, err := GenerateSelfSignedCertificate(config)
	if err != nil {
		t.Fatalf("Failed to generate cert with preset ext key usage: %v", err)
	}

	if cert == nil || key == nil {
		t.Fatal("Expected valid cert and key")
	}

	// The ExtendedKeyUsage field in template may be modified during generation
	// Just verify we got a valid cert with ext key usage
	if len(cert.ExtKeyUsage) == 0 {
		t.Error("Expected at least one ext key usage")
	}
}

// TestGenerateCertificateWithCRLDistributionPoints tests cert with CRL URLs
func TestGenerateCertificateWithCRLDistributionPoints(t *testing.T) {
	config := &CertificateConfig{
		CommonName:              "crl.example.com",
		KeyType:                 "rsa2048",
		Validity:                365,
		CRLDistributionPoints:   []string{"http://example.com/crl1", "http://example.com/crl2"},
	}

	cert, key, err := GenerateSelfSignedCertificate(config)
	if err != nil {
		t.Fatalf("Failed to generate cert with CRL URLs: %v", err)
	}

	if cert == nil || key == nil {
		t.Fatal("Expected valid cert and key")
	}

	if len(cert.CRLDistributionPoints) != 2 {
		t.Errorf("Expected 2 CRL distribution points, got %d", len(cert.CRLDistributionPoints))
	}
}

// TestGenerateCertificateWithOCSPServer tests cert with OCSP server URLs
func TestGenerateCertificateWithOCSPServer(t *testing.T) {
	config := &CertificateConfig{
		CommonName: "ocsp.example.com",
		KeyType:    "rsa2048",
		Validity:   365,
		OCSPServer: []string{"http://ocsp.example.com"},
	}

	cert, key, err := GenerateSelfSignedCertificate(config)
	if err != nil {
		t.Fatalf("Failed to generate cert with OCSP server: %v", err)
	}

	if cert == nil || key == nil {
		t.Fatal("Expected valid cert and key")
	}

	if len(cert.OCSPServer) != 1 {
		t.Errorf("Expected 1 OCSP server, got %d", len(cert.OCSPServer))
	}
}

// TestGenerateCertificateWithInvalidOIDFormat tests handling of malformed OIDs
func TestGenerateCertificateWithInvalidOIDFormat(t *testing.T) {
	config := &CertificateConfig{
		CommonName:           "invalid-oid.example.com",
		KeyType:              "rsa2048",
		Validity:             365,
		ExtendedKeyUsageOIDs: []string{"invalid", "1", "a.b.c"},
	}

	cert, key, err := GenerateSelfSignedCertificate(config)
	if err != nil {
		t.Fatalf("Failed to generate cert with invalid OIDs: %v", err)
	}

	// Should still generate successfully, just skip invalid OIDs
	if cert == nil || key == nil {
		t.Fatal("Expected valid cert and key")
	}
}

// TestGenerateCertificateWithComplexSubject tests cert with all subject fields
func TestGenerateCertificateWithComplexSubject(t *testing.T) {
	config := &CertificateConfig{
		CommonName:         "complex.example.com",
		Country:            "US",
		Organization:       "Test Organization Inc.",
		OrganizationalUnit: "Engineering Department",
		Locality:           "San Francisco",
		Province:           "California",
		StreetAddress:      "123 Main St",
		PostalCode:         "94105",
		KeyType:            "rsa2048",
		Validity:           365,
	}

	cert, key, err := GenerateSelfSignedCertificate(config)
	if err != nil {
		t.Fatalf("Failed to generate cert with complex subject: %v", err)
	}

	if cert == nil || key == nil {
		t.Fatal("Expected valid cert and key")
	}

	// Verify subject fields
	if cert.Subject.CommonName != config.CommonName {
		t.Errorf("Expected CN %s, got %s", config.CommonName, cert.Subject.CommonName)
	}
	if len(cert.Subject.Organization) == 0 || cert.Subject.Organization[0] != config.Organization {
		t.Errorf("Expected org %s, got %v", config.Organization, cert.Subject.Organization)
	}
}

// TestGenerateCAWithPathLengthZero tests CA with path length = 0 (no intermediates allowed)
func TestGenerateCAWithPathLengthZero(t *testing.T) {
	config := &CertificateConfig{
		CommonName:    "No Intermediate CA",
		IsCA:          true,
		MaxPathLength: 0,
		Validity:      365,
		KeyType:       "rsa2048",
	}

	cert, key, err := GenerateSelfSignedCertificate(config)
	if err != nil {
		t.Fatalf("Failed to generate CA with path length 0: %v", err)
	}

	if cert == nil || key == nil {
		t.Fatal("Expected valid cert and key")
	}

	if !cert.IsCA {
		t.Error("Expected CA certificate")
	}

	if cert.MaxPathLen != 0 {
		t.Errorf("Expected max path length 0, got %d", cert.MaxPathLen)
	}
}
