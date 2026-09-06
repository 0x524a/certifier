package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0x524a/certifier/pkg/cert"
	"github.com/0x524a/certifier/pkg/encoding"
)

func TestGenerateCRLCmd(t *testing.T) {
	caCertFile, caKeyFile := createTestCertificate(t)

	tests := []struct {
		name      string
		args      func(tmpDir string) []string
		expectErr bool
	}{
		{
			name: "valid CRL generation",
			args: func(tmpDir string) []string {
				return []string{
					"--ca-cert", caCertFile,
					"--ca-key", caKeyFile,
					"--output", filepath.Join(tmpDir, "test.crl"),
					"--validity", "30",
					"--number", "1",
				}
			},
			expectErr: false,
		},
		{
			name: "valid CRL with revoked certificates",
			args: func(tmpDir string) []string {
				return []string{
					"--ca-cert", caCertFile,
					"--ca-key", caKeyFile,
					"--output", filepath.Join(tmpDir, "revoked.crl"),
					"--revoked", "12345,67890",
					"--reason", "1",
				}
			},
			expectErr: false,
		},
		{
			name: "missing ca-cert",
			args: func(tmpDir string) []string {
				return []string{
					"--ca-key", caKeyFile,
					"--output", filepath.Join(tmpDir, "test.crl"),
				}
			},
			expectErr: true,
		},
		{
			name: "missing ca-key",
			args: func(tmpDir string) []string {
				return []string{
					"--ca-cert", caCertFile,
					"--output", filepath.Join(tmpDir, "test.crl"),
				}
			},
			expectErr: true,
		},
		{
			name: "nonexistent ca-cert file",
			args: func(tmpDir string) []string {
				return []string{
					"--ca-cert", "/nonexistent/ca.crt",
					"--ca-key", caKeyFile,
					"--output", filepath.Join(tmpDir, "test.crl"),
				}
			},
			expectErr: true,
		},
		{
			name: "nonexistent ca-key file",
			args: func(tmpDir string) []string {
				return []string{
					"--ca-cert", caCertFile,
					"--ca-key", "/nonexistent/ca.key",
					"--output", filepath.Join(tmpDir, "test.crl"),
				}
			},
			expectErr: true,
		},
		{
			name: "invalid revoked serial number",
			args: func(tmpDir string) []string {
				return []string{
					"--ca-cert", caCertFile,
					"--ca-key", caKeyFile,
					"--output", filepath.Join(tmpDir, "test.crl"),
					"--revoked", "not-a-number",
				}
			},
			expectErr: true,
		},
		{
			name: "invalid flag",
			args: func(tmpDir string) []string {
				return []string{"--invalid-flag", "value"}
			},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			err := GenerateCRLCmd(tt.args(tmpDir))

			if (err != nil) != tt.expectErr {
				t.Errorf("GenerateCRLCmd() error = %v, expectErr = %v", err, tt.expectErr)
			}
		})
	}
}

func TestGenerateCRL_Wrapper(t *testing.T) {
	caCertFile, caKeyFile := createTestCertificate(t)
	tmpDir := t.TempDir()
	crlFile := filepath.Join(tmpDir, "test.crl")

	output := captureOutput(func() {
		GenerateCRL([]string{
			"--ca-cert", caCertFile,
			"--ca-key", caKeyFile,
			"--output", crlFile,
		})
	})

	if !strings.Contains(output, "CRL generated successfully") {
		t.Errorf("Expected success message, got: %s", output)
	}
}

func TestViewCRLCmd(t *testing.T) {
	caCertFile, caKeyFile := createTestCertificate(t)
	tmpDir := t.TempDir()
	crlFile := filepath.Join(tmpDir, "test.crl")

	if err := GenerateCRLCmd([]string{
		"--ca-cert", caCertFile,
		"--ca-key", caKeyFile,
		"--output", crlFile,
		"--revoked", "111,222",
	}); err != nil {
		t.Fatalf("Failed to generate CRL for test setup: %v", err)
	}

	emptyCRLFile := filepath.Join(tmpDir, "empty.crl")
	if err := GenerateCRLCmd([]string{
		"--ca-cert", caCertFile,
		"--ca-key", caKeyFile,
		"--output", emptyCRLFile,
	}); err != nil {
		t.Fatalf("Failed to generate empty CRL for test setup: %v", err)
	}

	tests := []struct {
		name      string
		args      []string
		expectErr bool
	}{
		{
			name:      "view CRL with revoked certs",
			args:      []string{"--crl", crlFile},
			expectErr: false,
		},
		{
			name:      "view empty CRL",
			args:      []string{"--crl", emptyCRLFile},
			expectErr: false,
		},
		{
			name:      "missing crl flag",
			args:      []string{},
			expectErr: true,
		},
		{
			name:      "nonexistent crl file",
			args:      []string{"--crl", "/nonexistent/test.crl"},
			expectErr: true,
		},
		{
			name:      "invalid crl data",
			args:      []string{"--crl", caCertFile},
			expectErr: true,
		},
		{
			name:      "invalid flag",
			args:      []string{"--invalid-flag", "value"},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ViewCRLCmd(tt.args)
			if (err != nil) != tt.expectErr {
				t.Errorf("ViewCRLCmd() error = %v, expectErr = %v", err, tt.expectErr)
			}
		})
	}
}

func TestViewCRL_Wrapper(t *testing.T) {
	caCertFile, caKeyFile := createTestCertificate(t)
	tmpDir := t.TempDir()
	crlFile := filepath.Join(tmpDir, "test.crl")

	if err := GenerateCRLCmd([]string{
		"--ca-cert", caCertFile,
		"--ca-key", caKeyFile,
		"--output", crlFile,
		"--revoked", "999",
	}); err != nil {
		t.Fatalf("Failed to generate CRL for test setup: %v", err)
	}

	output := captureOutput(func() {
		ViewCRL([]string{"--crl", crlFile})
	})

	if !strings.Contains(output, "CRL Details") {
		t.Errorf("Expected 'CRL Details' in output, got: %s", output)
	}

	if !strings.Contains(output, "999") {
		t.Errorf("Expected revoked serial number 999 in output, got: %s", output)
	}
}

func TestCheckCRLCmd(t *testing.T) {
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

	tmpDir := t.TempDir()
	caCertFile := filepath.Join(tmpDir, "ca.crt")
	caKeyFile := filepath.Join(tmpDir, "ca.key")

	caCertPEM, err := encoding.EncodeCertificateToPEM(caCert)
	if err != nil {
		t.Fatalf("Failed to encode CA certificate: %v", err)
	}
	if err := os.WriteFile(caCertFile, caCertPEM, 0644); err != nil {
		t.Fatalf("Failed to write CA certificate: %v", err)
	}

	caKeyPEM, err := encoding.EncodePrivateKeyToPEM(caKey)
	if err != nil {
		t.Fatalf("Failed to encode CA key: %v", err)
	}
	if err := os.WriteFile(caKeyFile, caKeyPEM, 0644); err != nil {
		t.Fatalf("Failed to write CA key: %v", err)
	}

	// Leaf certificate signed by the CA - this will be revoked
	leafCfg := &cert.CertificateConfig{
		CommonName:   "revoked.example.com",
		Organization: "Test Org",
		Validity:     365,
		KeyType:      "rsa2048",
	}

	leafCert, _, err := cert.GenerateCASignedCertificate(leafCfg, caCfg, caKey, caCert)
	if err != nil {
		t.Fatalf("Failed to generate leaf certificate: %v", err)
	}

	leafCertFile := filepath.Join(tmpDir, "leaf.crt")
	leafCertPEM, err := encoding.EncodeCertificateToPEM(leafCert)
	if err != nil {
		t.Fatalf("Failed to encode leaf certificate: %v", err)
	}
	if err := os.WriteFile(leafCertFile, leafCertPEM, 0644); err != nil {
		t.Fatalf("Failed to write leaf certificate: %v", err)
	}

	// Another leaf certificate - this will NOT be revoked
	notRevokedCfg := &cert.CertificateConfig{
		CommonName:   "clean.example.com",
		Organization: "Test Org",
		Validity:     365,
		KeyType:      "rsa2048",
	}

	notRevokedCert, _, err := cert.GenerateCASignedCertificate(notRevokedCfg, caCfg, caKey, caCert)
	if err != nil {
		t.Fatalf("Failed to generate second leaf certificate: %v", err)
	}

	notRevokedCertFile := filepath.Join(tmpDir, "clean.crt")
	notRevokedCertPEM, err := encoding.EncodeCertificateToPEM(notRevokedCert)
	if err != nil {
		t.Fatalf("Failed to encode second leaf certificate: %v", err)
	}
	if err := os.WriteFile(notRevokedCertFile, notRevokedCertPEM, 0644); err != nil {
		t.Fatalf("Failed to write second leaf certificate: %v", err)
	}

	crlFile := filepath.Join(tmpDir, "test.crl")
	if err := GenerateCRLCmd([]string{
		"--ca-cert", caCertFile,
		"--ca-key", caKeyFile,
		"--output", crlFile,
		"--revoked", leafCert.SerialNumber.String(),
	}); err != nil {
		t.Fatalf("Failed to generate CRL for test setup: %v", err)
	}

	tests := []struct {
		name       string
		args       []string
		expectErr  bool
		wantOutput string
	}{
		{
			name:       "revoked certificate",
			args:       []string{"--crl", crlFile, "--cert", leafCertFile},
			expectErr:  false,
			wantOutput: "REVOKED",
		},
		{
			name:       "non-revoked certificate",
			args:       []string{"--crl", crlFile, "--cert", notRevokedCertFile},
			expectErr:  false,
			wantOutput: "NOT revoked",
		},
		{
			name:      "missing crl flag",
			args:      []string{"--cert", leafCertFile},
			expectErr: true,
		},
		{
			name:      "missing cert flag",
			args:      []string{"--crl", crlFile},
			expectErr: true,
		},
		{
			name:      "nonexistent crl file",
			args:      []string{"--crl", "/nonexistent/test.crl", "--cert", leafCertFile},
			expectErr: true,
		},
		{
			name:      "nonexistent cert file",
			args:      []string{"--crl", crlFile, "--cert", "/nonexistent/cert.crt"},
			expectErr: true,
		},
		{
			name:      "invalid flag",
			args:      []string{"--invalid-flag", "value"},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var output string
			err := func() error {
				var innerErr error
				output = captureOutput(func() {
					innerErr = CheckCRLCmd(tt.args)
				})
				return innerErr
			}()

			if (err != nil) != tt.expectErr {
				t.Errorf("CheckCRLCmd() error = %v, expectErr = %v", err, tt.expectErr)
			}

			if !tt.expectErr && tt.wantOutput != "" && !strings.Contains(output, tt.wantOutput) {
				t.Errorf("Expected output to contain %q, got: %s", tt.wantOutput, output)
			}
		})
	}
}

func TestCheckCRL_Wrapper(t *testing.T) {
	caCertFile, caKeyFile := createTestCertificate(t)
	tmpDir := t.TempDir()
	crlFile := filepath.Join(tmpDir, "test.crl")

	if err := GenerateCRLCmd([]string{
		"--ca-cert", caCertFile,
		"--ca-key", caKeyFile,
		"--output", crlFile,
	}); err != nil {
		t.Fatalf("Failed to generate CRL for test setup: %v", err)
	}

	output := captureOutput(func() {
		CheckCRL([]string{"--crl", crlFile, "--cert", caCertFile})
	})

	if !strings.Contains(output, "NOT revoked") {
		t.Errorf("Expected 'NOT revoked' in output, got: %s", output)
	}
}
