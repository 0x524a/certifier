package cli

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/0x524a/certifier/pkg/cert"
	"github.com/0x524a/certifier/pkg/encoding"
)

// newStaticOCSPResponder starts an httptest.Server that always serves the
// given pre-built DER-encoded OCSP response, regardless of the request body -
// enough to test CheckOCSPStatusCmd's HTTP plumbing against a fixed fixture.
func newStaticOCSPResponder(t *testing.T, respBytes []byte) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/ocsp-response")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(respBytes)
	}))
}

// createTestOCSPFixtures creates a CA and a leaf certificate signed by it, writes
// their PEM-encoded certificates and private keys to temp files, and returns the
// file paths: CA cert, CA key, leaf cert, leaf key.
func createTestOCSPFixtures(t *testing.T) (caCertFile, caKeyFile, certFile, keyFile string) {
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

	leafCert, leafKey, err := cert.GenerateCASignedCertificate(leafCfg, caCfg, caKey, caCert)
	if err != nil {
		t.Fatalf("Failed to generate leaf certificate: %v", err)
	}

	tmpDir := t.TempDir()

	caCertFile = filepath.Join(tmpDir, "ca.crt")
	caKeyFile = filepath.Join(tmpDir, "ca.key")
	certFile = filepath.Join(tmpDir, "leaf.crt")
	keyFile = filepath.Join(tmpDir, "leaf.key")

	writePEMFile := func(path string, data []byte, perm os.FileMode) {
		if err := os.WriteFile(path, data, perm); err != nil {
			t.Fatalf("Failed to write %s: %v", path, err)
		}
	}

	caCertPEM, err := encoding.EncodeCertificateToPEM(caCert)
	if err != nil {
		t.Fatalf("Failed to encode CA certificate: %v", err)
	}
	writePEMFile(caCertFile, caCertPEM, 0644)

	caKeyPEM, err := encoding.EncodePrivateKeyToPEM(caKey)
	if err != nil {
		t.Fatalf("Failed to encode CA key: %v", err)
	}
	writePEMFile(caKeyFile, caKeyPEM, 0600)

	certPEM, err := encoding.EncodeCertificateToPEM(leafCert)
	if err != nil {
		t.Fatalf("Failed to encode leaf certificate: %v", err)
	}
	writePEMFile(certFile, certPEM, 0644)

	keyPEM, err := encoding.EncodePrivateKeyToPEM(leafKey)
	if err != nil {
		t.Fatalf("Failed to encode leaf key: %v", err)
	}
	writePEMFile(keyFile, keyPEM, 0600)

	return caCertFile, caKeyFile, certFile, keyFile
}

func TestGenerateOCSPResponseCmd(t *testing.T) {
	caCertFile, caKeyFile, certFile, _ := createTestOCSPFixtures(t)
	tmpDir := t.TempDir()

	tests := []struct {
		name    string
		args    []string
		wantErr bool
	}{
		{
			name:    "missing cert flag",
			args:    []string{"--ca-cert", caCertFile, "--responder-key", caKeyFile},
			wantErr: true,
		},
		{
			name:    "missing ca-cert flag",
			args:    []string{"--cert", certFile, "--responder-key", caKeyFile},
			wantErr: true,
		},
		{
			name:    "missing responder-key flag",
			args:    []string{"--cert", certFile, "--ca-cert", caCertFile},
			wantErr: true,
		},
		{
			name:    "nonexistent cert file",
			args:    []string{"--cert", "/nonexistent/cert.crt", "--ca-cert", caCertFile, "--responder-key", caKeyFile},
			wantErr: true,
		},
		{
			name:    "invalid status",
			args:    []string{"--cert", certFile, "--ca-cert", caCertFile, "--responder-key", caKeyFile, "--status", "bogus", "--output", filepath.Join(tmpDir, "bad.der")},
			wantErr: true,
		},
		{
			name:    "valid good response",
			args:    []string{"--cert", certFile, "--ca-cert", caCertFile, "--responder-key", caKeyFile, "--status", "good", "--output", filepath.Join(tmpDir, "good.der")},
			wantErr: false,
		},
		{
			name:    "valid revoked response",
			args:    []string{"--cert", certFile, "--ca-cert", caCertFile, "--responder-key", caKeyFile, "--status", "revoked", "--revocation-reason", "1", "--output", filepath.Join(tmpDir, "revoked.der")},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := GenerateOCSPResponseCmd(tt.args)
			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateOCSPResponseCmd() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestGenerateOCSPResponseCmdWithExplicitResponderCert(t *testing.T) {
	caCertFile, caKeyFile, certFile, _ := createTestOCSPFixtures(t)
	tmpDir := t.TempDir()
	output := filepath.Join(tmpDir, "response.der")

	// Use the CA certificate as the explicit responder certificate as well.
	err := GenerateOCSPResponseCmd([]string{
		"--cert", certFile,
		"--ca-cert", caCertFile,
		"--responder-cert", caCertFile,
		"--responder-key", caKeyFile,
		"--output", output,
	})
	if err != nil {
		t.Fatalf("GenerateOCSPResponseCmd failed: %v", err)
	}

	if _, err := os.Stat(output); err != nil {
		t.Errorf("Expected output file to exist: %v", err)
	}
}

func TestGenerateOCSPResponseCmdInvalidArgs(t *testing.T) {
	err := GenerateOCSPResponseCmd([]string{"--unknown-flag"})
	if err == nil {
		t.Errorf("Expected error for invalid flags")
	}
}

func TestGenerateOCSPResponse_Wrapper(t *testing.T) {
	caCertFile, caKeyFile, certFile, _ := createTestOCSPFixtures(t)
	tmpDir := t.TempDir()
	output := filepath.Join(tmpDir, "response.der")

	// Should not exit the process for a valid call.
	GenerateOCSPResponse([]string{
		"--cert", certFile,
		"--ca-cert", caCertFile,
		"--responder-key", caKeyFile,
		"--output", output,
	})

	if _, err := os.Stat(output); err != nil {
		t.Errorf("Expected output file to exist: %v", err)
	}
}

func TestCreateOCSPRequestCmd(t *testing.T) {
	caCertFile, _, certFile, _ := createTestOCSPFixtures(t)
	tmpDir := t.TempDir()

	tests := []struct {
		name    string
		args    []string
		wantErr bool
	}{
		{
			name:    "missing cert flag",
			args:    []string{"--ca-cert", caCertFile},
			wantErr: true,
		},
		{
			name:    "missing ca-cert flag",
			args:    []string{"--cert", certFile},
			wantErr: true,
		},
		{
			name:    "nonexistent cert file",
			args:    []string{"--cert", "/nonexistent/cert.crt", "--ca-cert", caCertFile},
			wantErr: true,
		},
		{
			name:    "valid request",
			args:    []string{"--cert", certFile, "--ca-cert", caCertFile, "--output", filepath.Join(tmpDir, "request.der")},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CreateOCSPRequestCmd(tt.args)
			if (err != nil) != tt.wantErr {
				t.Errorf("CreateOCSPRequestCmd() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestCreateOCSPRequestCmdInvalidArgs(t *testing.T) {
	err := CreateOCSPRequestCmd([]string{"--unknown-flag"})
	if err == nil {
		t.Errorf("Expected error for invalid flags")
	}
}

func TestCreateOCSPRequest_Wrapper(t *testing.T) {
	caCertFile, _, certFile, _ := createTestOCSPFixtures(t)
	tmpDir := t.TempDir()
	output := filepath.Join(tmpDir, "request.der")

	CreateOCSPRequest([]string{
		"--cert", certFile,
		"--ca-cert", caCertFile,
		"--output", output,
	})

	if _, err := os.Stat(output); err != nil {
		t.Errorf("Expected output file to exist: %v", err)
	}
}

func TestVerifyOCSPResponseCmd(t *testing.T) {
	caCertFile, caKeyFile, certFile, _ := createTestOCSPFixtures(t)
	tmpDir := t.TempDir()

	responseFile := filepath.Join(tmpDir, "response.der")
	if err := GenerateOCSPResponseCmd([]string{
		"--cert", certFile,
		"--ca-cert", caCertFile,
		"--responder-key", caKeyFile,
		"--status", "good",
		"--output", responseFile,
	}); err != nil {
		t.Fatalf("Failed to generate response fixture: %v", err)
	}

	revokedResponseFile := filepath.Join(tmpDir, "revoked_response.der")
	if err := GenerateOCSPResponseCmd([]string{
		"--cert", certFile,
		"--ca-cert", caCertFile,
		"--responder-key", caKeyFile,
		"--status", "revoked",
		"--output", revokedResponseFile,
	}); err != nil {
		t.Fatalf("Failed to generate revoked response fixture: %v", err)
	}

	invalidResponseFile := filepath.Join(tmpDir, "invalid_response.der")
	if err := os.WriteFile(invalidResponseFile, []byte("not a valid response"), 0644); err != nil {
		t.Fatalf("Failed to write invalid response fixture: %v", err)
	}

	tests := []struct {
		name    string
		args    []string
		wantErr bool
	}{
		{
			name:    "missing response flag",
			args:    []string{"--cert", certFile, "--ca-cert", caCertFile},
			wantErr: true,
		},
		{
			name:    "missing cert flag",
			args:    []string{"--response", responseFile, "--ca-cert", caCertFile},
			wantErr: true,
		},
		{
			name:    "missing ca-cert flag",
			args:    []string{"--response", responseFile, "--cert", certFile},
			wantErr: true,
		},
		{
			name:    "nonexistent response file",
			args:    []string{"--response", "/nonexistent/response.der", "--cert", certFile, "--ca-cert", caCertFile},
			wantErr: true,
		},
		{
			name:    "invalid response bytes",
			args:    []string{"--response", invalidResponseFile, "--cert", certFile, "--ca-cert", caCertFile},
			wantErr: true,
		},
		{
			name:    "valid good response verifies successfully",
			args:    []string{"--response", responseFile, "--cert", certFile, "--ca-cert", caCertFile},
			wantErr: false,
		},
		{
			name:    "valid revoked response verifies successfully",
			args:    []string{"--response", revokedResponseFile, "--cert", certFile, "--ca-cert", caCertFile},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := VerifyOCSPResponseCmd(tt.args)
			if (err != nil) != tt.wantErr {
				t.Errorf("VerifyOCSPResponseCmd() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestVerifyOCSPResponseCmdInvalidArgs(t *testing.T) {
	err := VerifyOCSPResponseCmd([]string{"--unknown-flag"})
	if err == nil {
		t.Errorf("Expected error for invalid flags")
	}
}

func TestVerifyOCSPResponse_Wrapper(t *testing.T) {
	caCertFile, caKeyFile, certFile, _ := createTestOCSPFixtures(t)
	tmpDir := t.TempDir()
	responseFile := filepath.Join(tmpDir, "response.der")

	if err := GenerateOCSPResponseCmd([]string{
		"--cert", certFile,
		"--ca-cert", caCertFile,
		"--responder-key", caKeyFile,
		"--output", responseFile,
	}); err != nil {
		t.Fatalf("Failed to generate response fixture: %v", err)
	}

	VerifyOCSPResponse([]string{
		"--response", responseFile,
		"--cert", certFile,
		"--ca-cert", caCertFile,
	})
}

func TestCheckOCSPStatusCmd(t *testing.T) {
	caCertFile, caKeyFile, certFile, _ := createTestOCSPFixtures(t)
	tmpDir := t.TempDir()

	goodResponseFile := filepath.Join(tmpDir, "good.der")
	if err := GenerateOCSPResponseCmd([]string{
		"--cert", certFile,
		"--ca-cert", caCertFile,
		"--responder-key", caKeyFile,
		"--status", "good",
		"--output", goodResponseFile,
	}); err != nil {
		t.Fatalf("Failed to generate good response fixture: %v", err)
	}
	goodBytes, err := os.ReadFile(goodResponseFile)
	if err != nil {
		t.Fatalf("Failed to read good response fixture: %v", err)
	}

	revokedResponseFile := filepath.Join(tmpDir, "revoked.der")
	if err := GenerateOCSPResponseCmd([]string{
		"--cert", certFile,
		"--ca-cert", caCertFile,
		"--responder-key", caKeyFile,
		"--status", "revoked",
		"--output", revokedResponseFile,
	}); err != nil {
		t.Fatalf("Failed to generate revoked response fixture: %v", err)
	}
	revokedBytes, err := os.ReadFile(revokedResponseFile)
	if err != nil {
		t.Fatalf("Failed to read revoked response fixture: %v", err)
	}

	goodServer := newStaticOCSPResponder(t, goodBytes)
	defer goodServer.Close()
	revokedServer := newStaticOCSPResponder(t, revokedBytes)
	defer revokedServer.Close()
	badServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer badServer.Close()

	tests := []struct {
		name    string
		args    []string
		wantErr bool
	}{
		{
			name:    "missing cert flag",
			args:    []string{"--ca-cert", caCertFile, "--url", goodServer.URL},
			wantErr: true,
		},
		{
			name:    "missing ca-cert flag",
			args:    []string{"--cert", certFile, "--url", goodServer.URL},
			wantErr: true,
		},
		{
			name:    "nonexistent cert file",
			args:    []string{"--cert", "/nonexistent/cert.crt", "--ca-cert", caCertFile, "--url", goodServer.URL},
			wantErr: true,
		},
		{
			name:    "no url and no AIA entry",
			args:    []string{"--cert", certFile, "--ca-cert", caCertFile},
			wantErr: true,
		},
		{
			name:    "responder returns non-200",
			args:    []string{"--cert", certFile, "--ca-cert", caCertFile, "--url", badServer.URL},
			wantErr: true,
		},
		{
			name:    "good status",
			args:    []string{"--cert", certFile, "--ca-cert", caCertFile, "--url", goodServer.URL},
			wantErr: false,
		},
		{
			name:    "revoked status",
			args:    []string{"--cert", certFile, "--ca-cert", caCertFile, "--url", revokedServer.URL},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CheckOCSPStatusCmd(tt.args)
			if (err != nil) != tt.wantErr {
				t.Errorf("CheckOCSPStatusCmd() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestCheckOCSPStatusCmdInvalidArgs(t *testing.T) {
	err := CheckOCSPStatusCmd([]string{"--unknown-flag"})
	if err == nil {
		t.Errorf("Expected error for invalid flags")
	}
}

func TestCheckOCSPStatus_Wrapper(t *testing.T) {
	caCertFile, caKeyFile, certFile, _ := createTestOCSPFixtures(t)
	tmpDir := t.TempDir()
	responseFile := filepath.Join(tmpDir, "response.der")

	if err := GenerateOCSPResponseCmd([]string{
		"--cert", certFile,
		"--ca-cert", caCertFile,
		"--responder-key", caKeyFile,
		"--output", responseFile,
	}); err != nil {
		t.Fatalf("Failed to generate response fixture: %v", err)
	}
	respBytes, err := os.ReadFile(responseFile)
	if err != nil {
		t.Fatalf("Failed to read response fixture: %v", err)
	}
	server := newStaticOCSPResponder(t, respBytes)
	defer server.Close()

	// Should not exit the process for a valid call.
	CheckOCSPStatus([]string{
		"--cert", certFile,
		"--ca-cert", caCertFile,
		"--url", server.URL,
	})
}
