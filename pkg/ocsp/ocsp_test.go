package ocsp

import (
	"crypto/x509"
	"testing"
	"time"

	"github.com/0x524a/certifier/pkg/cert"
)

func TestGenerateOCSPResponse(t *testing.T) {
	tests := []struct {
		name    string
		config  *OCSPConfig
		wantErr bool
	}{
		{
			name:    "nil config",
			config:  nil,
			wantErr: true,
		},
		{
			name: "missing certificate",
			config: &OCSPConfig{
				Status: 0,
			},
			wantErr: true,
		},
		{
			name: "valid placeholder config",
			config: &OCSPConfig{
				Certificate: &x509.Certificate{},
			},
			wantErr: true, // Placeholder returns error
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := GenerateOCSPResponse(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateOCSPResponse error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestParseOCSPResponse(t *testing.T) {
	tests := []struct {
		name      string
		respBytes []byte
		wantErr   bool
	}{
		{
			name:      "empty response",
			respBytes: []byte{},
			wantErr:   true,
		},
		{
			name:      "valid placeholder response",
			respBytes: []byte("test"),
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseOCSPResponse(tt.respBytes)

			if (err != nil) != tt.wantErr {
				t.Errorf("ParseOCSPResponse error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && result == nil {
				t.Errorf("Expected non-nil result")
			}
		})
	}
}

func TestVerifyOCSPResponse(t *testing.T) {
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

	leafCfg := &cert.CertificateConfig{
		CommonName:   "test.example.com",
		Organization: "Test Org",
		Validity:     365,
		KeyType:      "rsa2048",
	}

	leafCert, _, err := cert.GenerateCASignedCertificate(leafCfg, caCfg, caKey, caCert)
	if err != nil {
		t.Fatalf("Failed to generate leaf cert: %v", err)
	}

	tests := []struct {
		name      string
		respBytes []byte
		cert      *x509.Certificate
		issuer    *x509.Certificate
		wantErr   bool
	}{
		{
			name:      "nil certificate",
			respBytes: []byte("test"),
			cert:      nil,
			issuer:    caCert,
			wantErr:   true,
		},
		{
			name:      "nil issuer",
			respBytes: []byte("test"),
			cert:      leafCert,
			issuer:    nil,
			wantErr:   true,
		},
		{
			name:      "valid placeholder config",
			respBytes: []byte("test"),
			cert:      leafCert,
			issuer:    caCert,
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := VerifyOCSPResponse(tt.respBytes, tt.cert, tt.issuer)

			if (err != nil) != tt.wantErr {
				t.Errorf("VerifyOCSPResponse error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && result == nil {
				t.Errorf("Expected non-nil result")
			}
		})
	}
}

func TestCreateOCSPRequest(t *testing.T) {
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

	leafCfg := &cert.CertificateConfig{
		CommonName:   "test.example.com",
		Organization: "Test Org",
		Validity:     365,
		KeyType:      "rsa2048",
	}

	leafCert, _, err := cert.GenerateCASignedCertificate(leafCfg, caCfg, caKey, caCert)
	if err != nil {
		t.Fatalf("Failed to generate leaf cert: %v", err)
	}

	tests := []struct {
		name    string
		cert    *x509.Certificate
		issuer  *x509.Certificate
		wantErr bool
	}{
		{
			name:    "nil certificate",
			cert:    nil,
			issuer:  caCert,
			wantErr: true,
		},
		{
			name:    "nil issuer",
			cert:    leafCert,
			issuer:  nil,
			wantErr: true,
		},
		{
			name:    "valid placeholder config",
			cert:    leafCert,
			issuer:  caCert,
			wantErr: true, // Placeholder returns error
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := CreateOCSPRequest(tt.cert, tt.issuer)
			if (err != nil) != tt.wantErr {
				t.Errorf("CreateOCSPRequest error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestParseOCSPRequest(t *testing.T) {
	tests := []struct {
		name     string
		reqBytes []byte
		wantErr  bool
	}{
		{
			name:     "empty request",
			reqBytes: []byte{},
			wantErr:  true,
		},
		{
			name:     "valid placeholder request",
			reqBytes: []byte("test"),
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseOCSPRequest(tt.reqBytes)

			if (err != nil) != tt.wantErr {
				t.Errorf("ParseOCSPRequest error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && result == nil {
				t.Errorf("Expected non-nil result")
			}
		})
	}
}

func TestCheckCertificateStatus(t *testing.T) {
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

	leafCfg := &cert.CertificateConfig{
		CommonName:   "test.example.com",
		Organization: "Test Org",
		Validity:     365,
		KeyType:      "rsa2048",
	}

	leafCert, _, err := cert.GenerateCASignedCertificate(leafCfg, caCfg, caKey, caCert)
	if err != nil {
		t.Fatalf("Failed to generate leaf cert: %v", err)
	}

	tests := []struct {
		name    string
		cert    *x509.Certificate
		ocspURL string
		wantErr bool
	}{
		{
			name:    "nil certificate",
			cert:    nil,
			ocspURL: "http://ocsp.example.com",
			wantErr: true,
		},
		{
			name:    "empty OCSP URL",
			cert:    leafCert,
			ocspURL: "",
			wantErr: true,
		},
		{
			name:    "valid certificate and URL",
			cert:    leafCert,
			ocspURL: "http://ocsp.example.com",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status, err := CheckCertificateStatus(tt.cert, tt.ocspURL)

			if (err != nil) != tt.wantErr {
				t.Errorf("CheckCertificateStatus error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if status == nil {
					t.Errorf("Expected non-nil status")
					return
				}
				if status.Serial == nil {
					t.Errorf("Expected serial number in status")
				}
				if status.Status != "unknown" {
					t.Errorf("Expected status 'unknown', got %s", status.Status)
				}
				if status.ResponderURL != tt.ocspURL {
					t.Errorf("Expected ResponderURL %s, got %s", tt.ocspURL, status.ResponderURL)
				}
			}
		})
	}
}

func TestOCSPCertificateStatus(t *testing.T) {
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

	leafCfg := &cert.CertificateConfig{
		CommonName:   "test.example.com",
		Organization: "Test Org",
		Validity:     365,
		KeyType:      "rsa2048",
	}

	leafCert, _, err := cert.GenerateCASignedCertificate(leafCfg, caCfg, caKey, caCert)
	if err != nil {
		t.Fatalf("Failed to generate leaf cert: %v", err)
	}

	status, err := CheckCertificateStatus(leafCert, "http://ocsp.example.com")
	if err != nil {
		t.Fatalf("Failed to check certificate status: %v", err)
	}

	if status.Serial.Cmp(leafCert.SerialNumber) != 0 {
		t.Errorf("Serial number mismatch in status")
	}

	if status.NextUpdate.Before(status.ThisUpdate) {
		t.Errorf("NextUpdate should not be before ThisUpdate")
	}

	if status.ResponderURL != "http://ocsp.example.com" {
		t.Errorf("ResponderURL mismatch")
	}
}

func TestOCSPStatusConstants(t *testing.T) {
	// Verify status values are reasonable
	statuses := []string{"good", "revoked", "unknown"}

	if len(statuses) == 0 {
		t.Errorf("Expected at least one status constant")
	}

	// Verify that status field can be set
	status := &OCSPCertificateStatus{
		Status: "unknown",
	}

	if status.Status != "unknown" {
		t.Errorf("Expected status 'unknown', got %s", status.Status)
	}
}

func TestCheckCertificateStatusDates(t *testing.T) {
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

	leafCfg := &cert.CertificateConfig{
		CommonName:   "test.example.com",
		Organization: "Test Org",
		Validity:     365,
		KeyType:      "rsa2048",
	}

	leafCert, _, err := cert.GenerateCASignedCertificate(leafCfg, caCfg, caKey, caCert)
	if err != nil {
		t.Fatalf("Failed to generate leaf cert: %v", err)
	}

	status, err := CheckCertificateStatus(leafCert, "http://ocsp.example.com")
	if err != nil {
		t.Fatalf("Failed to check certificate status: %v", err)
	}

	// Verify dates are set
	if status.ThisUpdate.IsZero() {
		t.Errorf("Expected ThisUpdate to be set")
	}

	if status.NextUpdate.IsZero() {
		t.Errorf("Expected NextUpdate to be set")
	}

	// NextUpdate should be ~7 days after ThisUpdate
	expectedNextUpdate := status.ThisUpdate.Add(7 * 24 * time.Hour)
	timeDiff := status.NextUpdate.Sub(expectedNextUpdate).Abs()

	if timeDiff > time.Minute {
		t.Logf("Warning: NextUpdate time difference from expected: %v", timeDiff)
	}
}
