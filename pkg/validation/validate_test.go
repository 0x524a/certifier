package validation

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/0x524a/certifier/pkg/cert"
)

func TestValidateCertificate(t *testing.T) {
	// Create a valid test certificate
	caCfg := &cert.CertificateConfig{
		CommonName:    "Test CA",
		Organization:  "Test Org",
		IsCA:          true,
		MaxPathLength: -1,
		Validity:      365,
		KeyType:       "rsa2048",
	}

	caCert, _, err := cert.GenerateSelfSignedCertificate(caCfg)
	if err != nil {
		t.Fatalf("Failed to generate test CA: %v", err)
	}

	// Create a server certificate
	serverCfg := &cert.CertificateConfig{
		CommonName:   "example.com",
		Organization: "Test Org",
		Validity:     365,
		DNSNames:     []string{"example.com", "www.example.com"},
		KeyType:      "rsa2048",
	}

	serverCert, _, err := cert.GenerateSelfSignedCertificate(serverCfg)
	if err != nil {
		t.Fatalf("Failed to generate test certificate: %v", err)
	}

	tests := []struct {
		name        string
		certificate *x509.Certificate
		config      *cert.ValidationConfig
		checkValid  bool
		checkExpired bool
		checkHostname bool
	}{
		{
			name:        "Valid certificate with no validation",
			certificate: serverCert,
			config: &cert.ValidationConfig{
				CheckExpiration: false,
			},
			checkValid: true,
		},
		{
			name:        "Valid certificate with expiration check",
			certificate: serverCert,
			config: &cert.ValidationConfig{
				CheckExpiration: true,
				AllowExpired:    false,
			},
			checkValid:  true,
			checkExpired: true,
		},
		{
			name:        "Expired certificate",
			certificate: &x509.Certificate{
				SerialNumber: big.NewInt(1),
				Subject:      pkix.Name{CommonName: "expired.com"},
				NotBefore:    time.Now().AddDate(-2, 0, 0),
				NotAfter:     time.Now().AddDate(-1, 0, 0),
				IsCA:         false,
			},
			config: &cert.ValidationConfig{
				CheckExpiration: true,
				AllowExpired:    false,
			},
			checkValid:   false,
			checkExpired: false,
		},
		{
			name:        "Not yet valid certificate",
			certificate: &x509.Certificate{
				SerialNumber: big.NewInt(2),
				Subject:      pkix.Name{CommonName: "future.com"},
				NotBefore:    time.Now().AddDate(1, 0, 0),
				NotAfter:     time.Now().AddDate(2, 0, 0),
				IsCA:         false,
			},
			config: &cert.ValidationConfig{
				CheckExpiration: true,
				AllowExpired:    false,
			},
			checkValid:   false,
			checkExpired: false,
		},
		{
			name:        "Certificate with hostname verification",
			certificate: serverCert,
			config: &cert.ValidationConfig{
				CheckExpiration: true,
				DNSName:         "example.com",
			},
			checkValid:    true,
			checkHostname: true,
		},
		{
			name:        "Certificate with invalid hostname",
			certificate: serverCert,
			config: &cert.ValidationConfig{
				CheckExpiration: true,
				DNSName:         "invalid.com",
			},
			checkValid:    false,
			checkHostname: false,
		},
		{
			name:        "Expired certificate with AllowExpired true",
			certificate: &x509.Certificate{
				SerialNumber: big.NewInt(3),
				Subject:      pkix.Name{CommonName: "expired2.com"},
				NotBefore:    time.Now().AddDate(-2, 0, 0),
				NotAfter:     time.Now().AddDate(-1, 0, 0),
				IsCA:         false,
			},
			config: &cert.ValidationConfig{
				CheckExpiration: true,
				AllowExpired:    true,
			},
			checkValid: true,
		},
		{
			name:        "CA certificate",
			certificate: caCert,
			config: &cert.ValidationConfig{
				CheckExpiration: true,
			},
			checkValid: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ValidateCertificate(tt.certificate, tt.config)

			if result.Valid != tt.checkValid {
				t.Errorf("Expected Valid=%v, got %v", tt.checkValid, result.Valid)
			}

			if tt.checkExpired && !result.NotExpired {
				t.Errorf("Expected NotExpired=true for valid certificate")
			}

			if tt.checkHostname && !result.HostnameValid {
				t.Errorf("Expected HostnameValid=true for matching hostname")
			}
		})
	}
}

func TestValidateCertificateExtensions(t *testing.T) {
	// Create certificate with extensions
	crlURLs := []string{"http://crl.example.com/ca.crl"}
	ocspURLs := []string{"http://ocsp.example.com"}

	cfg := &cert.CertificateConfig{
		CommonName:            "test.com",
		Organization:          "Test Org",
		Validity:              365,
		CRLDistributionPoints: crlURLs,
		OCSPServer:            ocspURLs,
		KeyType:               "rsa2048",
	}

	certificate, _, err := cert.GenerateSelfSignedCertificate(cfg)
	if err != nil {
		t.Fatalf("Failed to generate test certificate: %v", err)
	}

	result := ValidateCertificate(certificate, &cert.ValidationConfig{
		CheckExpiration: false,
	})

	if result.CRLDistributionURL != crlURLs[0] {
		t.Errorf("Expected CRL URL %s, got %s", crlURLs[0], result.CRLDistributionURL)
	}

	if result.OCSPURL != ocspURLs[0] {
		t.Errorf("Expected OCSP URL %s, got %s", ocspURLs[0], result.OCSPURL)
	}
}

func TestValidateChain(t *testing.T) {
	// Create CA
	caCfg := &cert.CertificateConfig{
		CommonName:    "Test CA",
		Organization:  "Test Org",
		IsCA:          true,
		MaxPathLength: -1,
		Validity:      365,
		KeyType:       "rsa2048",
	}

	caCert, caKey, err := cert.GenerateSelfSignedCertificate(caCfg)
	if err != nil {
		t.Fatalf("Failed to generate CA: %v", err)
	}

	// Create leaf cert signed by CA
	leafCfg := &cert.CertificateConfig{
		CommonName:   "leaf.example.com",
		Organization: "Test Org",
		Validity:     365,
		KeyType:      "rsa2048",
	}

	leafCert, _, err := cert.GenerateCASignedCertificate(leafCfg, caCfg, caKey, caCert)
	if err != nil {
		t.Fatalf("Failed to generate leaf certificate: %v", err)
	}

	tests := []struct {
		name            string
		leafCert        *x509.Certificate
		intermediateCerts []*x509.Certificate
		rootCerts       []*x509.Certificate
		shouldFail      bool
	}{
		{
			name:       "Valid chain with root only",
			leafCert:   leafCert,
			rootCerts:  []*x509.Certificate{caCert},
			shouldFail: false,
		},
		{
			name:       "Empty root pool",
			leafCert:   leafCert,
			rootCerts:  []*x509.Certificate{},
			shouldFail: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateChain(tt.leafCert, tt.intermediateCerts, tt.rootCerts)
			if (err != nil) != tt.shouldFail {
				t.Errorf("Expected shouldFail=%v, got error=%v", tt.shouldFail, err)
			}
		})
	}
}

func TestGetKeySize(t *testing.T) {
	tests := []struct {
		name        string
		keyType     cert.KeyType
		expectedMin int
		expectedMax int
	}{
		{name: "RSA 2048", keyType: "rsa2048", expectedMin: 2048, expectedMax: 2048},
		{name: "RSA 4096", keyType: "rsa4096", expectedMin: 4096, expectedMax: 4096},
		{name: "ECDSA P-256", keyType: "ecdsa-p256", expectedMin: 256, expectedMax: 256},
		{name: "ECDSA P-384", keyType: "ecdsa-p384", expectedMin: 384, expectedMax: 384},
		{name: "ECDSA P-521", keyType: "ecdsa-p521", expectedMin: 521, expectedMax: 521},
		{name: "Ed25519", keyType: "ed25519", expectedMin: 256, expectedMax: 256},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &cert.CertificateConfig{
				CommonName: "test.com",
				KeyType:    tt.keyType,
				Validity:   365,
			}

			certificate, _, err := cert.GenerateSelfSignedCertificate(cfg)
			if err != nil {
				t.Fatalf("Failed to generate certificate: %v", err)
			}

			keySize := getKeySize(certificate.PublicKey)
			if keySize < tt.expectedMin || keySize > tt.expectedMax {
				t.Errorf("Expected key size between %d-%d, got %d", tt.expectedMin, tt.expectedMax, keySize)
			}
		})
	}
}

func TestValidateSignatureAlgorithm(t *testing.T) {
	cfg := &cert.CertificateConfig{
		CommonName: "test.com",
		KeyType:    "rsa2048",
		Validity:   365,
	}

	certificate, _, err := cert.GenerateSelfSignedCertificate(cfg)
	if err != nil {
		t.Fatalf("Failed to generate certificate: %v", err)
	}

	result := ValidateCertificate(certificate, &cert.ValidationConfig{
		CheckExpiration: false,
	})

	if len(result.SignatureAlgorithm) == 0 {
		t.Errorf("Expected SignatureAlgorithm to be set")
	}

	if len(result.PublicKeyAlgorithm) == 0 {
		t.Errorf("Expected PublicKeyAlgorithm to be set")
	}
}

func TestValidateCertificateWithCustomTime(t *testing.T) {
	cfg := &cert.CertificateConfig{
		CommonName: "test.com",
		KeyType:    "rsa2048",
		Validity:   10, // 10 days
	}

	certificate, _, err := cert.GenerateSelfSignedCertificate(cfg)
	if err != nil {
		t.Fatalf("Failed to generate certificate: %v", err)
	}

	// Check with current time (should be valid)
	result := ValidateCertificate(certificate, &cert.ValidationConfig{
		CheckExpiration: true,
		AllowExpired:    false,
		CurrentTime:     time.Now(),
	})

	if !result.Valid {
		t.Errorf("Expected certificate to be valid at current time")
	}

	// Check with future time (should be expired)
	futureTime := time.Now().AddDate(1, 0, 0)
	result = ValidateCertificate(certificate, &cert.ValidationConfig{
		CheckExpiration: true,
		AllowExpired:    false,
		CurrentTime:     futureTime,
	})

	if result.Valid {
		t.Errorf("Expected certificate to be invalid at future time")
	}
}

func TestValidateCertificateCAConstraints(t *testing.T) {
	// Create a non-CA certificate with IsCA flag set (invalid)
	nonCACert := &x509.Certificate{
		SerialNumber:   big.NewInt(1),
		Subject:        pkix.Name{CommonName: "test.com"},
		NotBefore:      time.Now(),
		NotAfter:       time.Now().AddDate(1, 0, 0),
		IsCA:           false,
		MaxPathLen:     0, // Invalid: non-CA with path length
		MaxPathLenZero: true,
	}

	result := ValidateCertificate(nonCACert, &cert.ValidationConfig{
		CheckExpiration: false,
	})

	if len(result.Warnings) == 0 {
		t.Errorf("Expected warning about non-CA certificate with path length constraint")
	}
}

func TestValidateCertificatePublicKeyAlgorithm(t *testing.T) {
	tests := []struct {
		name    string
		keyType cert.KeyType
	}{
		{name: "RSA", keyType: "rsa2048"},
		{name: "ECDSA", keyType: "ecdsa-p256"},
		{name: "Ed25519", keyType: "ed25519"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &cert.CertificateConfig{
				CommonName: "test.com",
				KeyType:    tt.keyType,
				Validity:   365,
			}

			certificate, _, err := cert.GenerateSelfSignedCertificate(cfg)
			if err != nil {
				t.Fatalf("Failed to generate certificate: %v", err)
			}

			result := ValidateCertificate(certificate, &cert.ValidationConfig{
				CheckExpiration: false,
			})

			if len(result.PublicKeyAlgorithm) == 0 {
				t.Errorf("Expected PublicKeyAlgorithm to be populated")
			}
		})
	}
}
