package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0x524a/certifier/pkg/cert"
	"github.com/0x524a/certifier/pkg/encoding"
)

// createTestCSR creates a temporary CSR PEM file and returns its path
func createTestCSR(t *testing.T) string {
	csrConfig := &cert.CSRConfig{
		CommonName:   "csr.example.com",
		Organization: "Test Org",
		Country:      "US",
		KeyType:      "rsa2048",
		DNSNames:     []string{"csr.example.com", "www.csr.example.com"},
	}

	csr, _, err := cert.GenerateCSR(csrConfig)
	if err != nil {
		t.Fatalf("Failed to generate test CSR: %v", err)
	}

	csrPEM, err := encoding.EncodeCSRToPEM(csr)
	if err != nil {
		t.Fatalf("Failed to encode CSR: %v", err)
	}

	tmpDir := t.TempDir()
	csrFile := filepath.Join(tmpDir, "test.csr")
	if err := os.WriteFile(csrFile, csrPEM, 0644); err != nil {
		t.Fatalf("Failed to write CSR file: %v", err)
	}

	return csrFile
}

// TestSignCertCmd tests signing a CSR with a CA
func TestSignCertCmd(t *testing.T) {
	caCertFile, caKeyFile := createTestCertificate(t)
	csrFile := createTestCSR(t)

	tmpDir := t.TempDir()
	outputFile := filepath.Join(tmpDir, "signed.crt")

	err := SignCertCmd([]string{
		"--csr", csrFile,
		"--ca-cert", caCertFile,
		"--ca-key", caKeyFile,
		"--output", outputFile,
		"--validity", "30",
	})
	if err != nil {
		t.Fatalf("SignCertCmd failed: %v", err)
	}

	certPEM, err := os.ReadFile(outputFile)
	if err != nil {
		t.Fatalf("Failed to read signed certificate: %v", err)
	}

	signedCert, err := encoding.DecodeCertificateFromPEM(certPEM)
	if err != nil {
		t.Fatalf("Failed to decode signed certificate: %v", err)
	}

	if signedCert.Subject.CommonName != "csr.example.com" {
		t.Errorf("Expected CN=csr.example.com, got %s", signedCert.Subject.CommonName)
	}

	if len(signedCert.DNSNames) != 2 {
		t.Errorf("Expected 2 DNS names, got %d", len(signedCert.DNSNames))
	}
}

// TestSignCertCmdMissingFlags tests SignCertCmd error handling for missing required flags
func TestSignCertCmdMissingFlags(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{"missing csr", []string{"--ca-cert", "ca.crt", "--ca-key", "ca.key"}},
		{"missing ca-cert", []string{"--csr", "test.csr", "--ca-key", "ca.key"}},
		{"missing ca-key", []string{"--csr", "test.csr", "--ca-cert", "ca.crt"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := SignCertCmd(tt.args); err == nil {
				t.Errorf("Expected error for %s, got nil", tt.name)
			}
		})
	}
}

// TestSignCertCmdInvalidFiles tests SignCertCmd error handling for unreadable/invalid files
func TestSignCertCmdInvalidFiles(t *testing.T) {
	caCertFile, caKeyFile := createTestCertificate(t)
	csrFile := createTestCSR(t)

	err := SignCertCmd([]string{
		"--csr", "/nonexistent/file.csr",
		"--ca-cert", caCertFile,
		"--ca-key", caKeyFile,
	})
	if err == nil {
		t.Error("Expected error for non-existent CSR file, got nil")
	}

	err = SignCertCmd([]string{
		"--csr", csrFile,
		"--ca-cert", "/nonexistent/ca.crt",
		"--ca-key", caKeyFile,
	})
	if err == nil {
		t.Error("Expected error for non-existent CA cert file, got nil")
	}

	err = SignCertCmd([]string{
		"--csr", csrFile,
		"--ca-cert", caCertFile,
		"--ca-key", "/nonexistent/ca.key",
	})
	if err == nil {
		t.Error("Expected error for non-existent CA key file, got nil")
	}
}

// TestSignCert tests the os.Exit-wrapped SignCert function on the success path
func TestSignCert(t *testing.T) {
	caCertFile, caKeyFile := createTestCertificate(t)
	csrFile := createTestCSR(t)

	tmpDir := t.TempDir()
	outputFile := filepath.Join(tmpDir, "signed.crt")

	output := captureOutput(func() {
		SignCert([]string{
			"--csr", csrFile,
			"--ca-cert", caCertFile,
			"--ca-key", caKeyFile,
			"--output", outputFile,
		})
	})

	if !strings.Contains(output, "Certificate signed successfully") {
		t.Errorf("Expected success message, got: %s", output)
	}
}

// TestValidateCertCmd tests validating a certificate against its actual issuing CA
func TestValidateCertCmd(t *testing.T) {
	caCfg := &cert.CertificateConfig{
		CommonName:    "Validate Test CA",
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

	serverCfg := &cert.CertificateConfig{
		CommonName:   "example.com",
		Organization: "Test Org",
		Validity:     365,
		DNSNames:     []string{"example.com", "www.example.com"},
		KeyType:      "rsa2048",
	}

	serverCert, _, err := cert.GenerateCASignedCertificate(serverCfg, caCfg, caKey, caCert)
	if err != nil {
		t.Fatalf("Failed to generate server certificate: %v", err)
	}

	tmpDir := t.TempDir()
	caCertFile := filepath.Join(tmpDir, "ca.crt")
	serverCertFile := filepath.Join(tmpDir, "server.crt")

	caCertPEM, err := encoding.EncodeCertificateToPEM(caCert)
	if err != nil {
		t.Fatalf("Failed to encode CA certificate: %v", err)
	}
	if err := os.WriteFile(caCertFile, caCertPEM, 0644); err != nil {
		t.Fatalf("Failed to write CA certificate: %v", err)
	}

	serverCertPEM, err := encoding.EncodeCertificateToPEM(serverCert)
	if err != nil {
		t.Fatalf("Failed to encode server certificate: %v", err)
	}
	if err := os.WriteFile(serverCertFile, serverCertPEM, 0644); err != nil {
		t.Fatalf("Failed to write server certificate: %v", err)
	}

	err = ValidateCertCmd([]string{
		"--cert", serverCertFile,
		"--roots", caCertFile,
		"--dns", "example.com",
	})
	if err != nil {
		t.Errorf("ValidateCertCmd failed for a valid certificate: %v", err)
	}
}

// TestValidateCertCmdMissingCert tests ValidateCertCmd without required --cert flag
func TestValidateCertCmdMissingCert(t *testing.T) {
	if err := ValidateCertCmd([]string{}); err == nil {
		t.Error("Expected error for missing --cert flag, got nil")
	}
}

// TestValidateCertCmdInvalidCertFile tests ValidateCertCmd with a non-existent cert file
func TestValidateCertCmdInvalidCertFile(t *testing.T) {
	if err := ValidateCertCmd([]string{"--cert", "/nonexistent/cert.crt"}); err == nil {
		t.Error("Expected error for non-existent certificate file, got nil")
	}
}

// TestValidateCertCmdInvalidRoots tests ValidateCertCmd with an invalid root CA file
func TestValidateCertCmdInvalidRoots(t *testing.T) {
	certFile, _ := createTestCertificate(t)

	if err := ValidateCertCmd([]string{
		"--cert", certFile,
		"--roots", "/nonexistent/root.crt",
	}); err == nil {
		t.Error("Expected error for non-existent root CA file, got nil")
	}
}

// TestValidateCertCmdInvalidIntermediates tests ValidateCertCmd with an invalid intermediate CA file
func TestValidateCertCmdInvalidIntermediates(t *testing.T) {
	certFile, _ := createTestCertificate(t)

	if err := ValidateCertCmd([]string{
		"--cert", certFile,
		"--intermediates", "/nonexistent/intermediate.crt",
	}); err == nil {
		t.Error("Expected error for non-existent intermediate CA file, got nil")
	}
}

// TestValidateCertCmdExpiredNotAllowed tests validation failure via DNS name mismatch,
// which ValidateCertificate reports through result.Valid=false and Errors.
func TestValidateCertCmdHostnameMismatch(t *testing.T) {
	serverCertFile, _, _ := createTestServerCertificate(t)

	err := ValidateCertCmd([]string{
		"--cert", serverCertFile,
		"--dns", "wrong-host.example.org",
	})
	if err == nil {
		t.Error("Expected error for hostname mismatch, got nil")
	}
}

// TestValidateCertCmdAllowExpired tests the --allow-expired and --check-expiration flags parse correctly
func TestValidateCertCmdAllowExpired(t *testing.T) {
	certFile, _ := createTestCertificate(t)

	err := ValidateCertCmd([]string{
		"--cert", certFile,
		"--check-expiration=false",
		"--allow-expired",
	})
	if err != nil {
		t.Errorf("ValidateCertCmd with allow-expired failed: %v", err)
	}
}

// TestValidateCert tests the os.Exit-wrapped ValidateCert function on the success path
func TestValidateCert(t *testing.T) {
	certFile, _ := createTestCertificate(t)

	output := captureOutput(func() {
		ValidateCert([]string{"--cert", certFile})
	})

	if !strings.Contains(output, "Validation Result") {
		t.Errorf("Expected validation output, got: %s", output)
	}
}

// TestViewCSRCmd tests viewing CSR details
func TestViewCSRCmd(t *testing.T) {
	csrFile := createTestCSR(t)

	output := captureOutput(func() {
		if err := ViewCSRCmd([]string{"--csr", csrFile}); err != nil {
			t.Errorf("ViewCSRCmd failed: %v", err)
		}
	})

	if !strings.Contains(output, "CSR Details") {
		t.Error("Output should contain 'CSR Details'")
	}
	if !strings.Contains(output, "csr.example.com") {
		t.Error("Output should contain the CSR common name")
	}
	if !strings.Contains(output, "DNS Names") {
		t.Error("Output should contain DNS Names")
	}
}

// TestViewCSRCmdMissingFlag tests ViewCSRCmd without required --csr flag
func TestViewCSRCmdMissingFlag(t *testing.T) {
	if err := ViewCSRCmd([]string{}); err == nil {
		t.Error("Expected error for missing --csr flag, got nil")
	}
}

// TestViewCSRCmdInvalidFile tests ViewCSRCmd with a non-existent CSR file
func TestViewCSRCmdInvalidFile(t *testing.T) {
	if err := ViewCSRCmd([]string{"--csr", "/nonexistent/file.csr"}); err == nil {
		t.Error("Expected error for non-existent CSR file, got nil")
	}
}

// TestViewCSRCmdInvalidContent tests ViewCSRCmd with invalid CSR content
func TestViewCSRCmdInvalidContent(t *testing.T) {
	tmpDir := t.TempDir()
	invalidFile := filepath.Join(tmpDir, "invalid.csr")
	if err := os.WriteFile(invalidFile, []byte("not a csr"), 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	if err := ViewCSRCmd([]string{"--csr", invalidFile}); err == nil {
		t.Error("Expected error for invalid CSR content, got nil")
	}
}

// TestViewCSR tests the os.Exit-wrapped ViewCSR function on the success path
func TestViewCSR(t *testing.T) {
	csrFile := createTestCSR(t)

	output := captureOutput(func() {
		ViewCSR([]string{"--csr", csrFile})
	})

	if !strings.Contains(output, "CSR Details") {
		t.Errorf("Expected CSR details output, got: %s", output)
	}
}

// TestEncodeCertCmdDER tests encoding a PEM certificate to DER
func TestEncodeCertCmdDER(t *testing.T) {
	certFile, _ := createTestCertificate(t)
	tmpDir := t.TempDir()
	outputFile := filepath.Join(tmpDir, "cert.der")

	err := EncodeCertCmd([]string{
		"--input", certFile,
		"--output", outputFile,
		"--format", "der",
	})
	if err != nil {
		t.Fatalf("EncodeCertCmd (der) failed: %v", err)
	}

	derData, err := os.ReadFile(outputFile)
	if err != nil {
		t.Fatalf("Failed to read DER output: %v", err)
	}

	if _, err := encoding.DecodeCertificateFromDER(derData); err != nil {
		t.Errorf("Output is not valid DER: %v", err)
	}
}

// TestEncodeCertCmdPKCS12 tests encoding a PEM certificate and key to PKCS12
func TestEncodeCertCmdPKCS12(t *testing.T) {
	certFile, keyFile := createTestCertificate(t)
	tmpDir := t.TempDir()
	outputFile := filepath.Join(tmpDir, "cert.p12")

	err := EncodeCertCmd([]string{
		"--input", certFile,
		"--output", outputFile,
		"--format", "pkcs12",
		"--key", keyFile,
		"--password", "test1234",
	})
	if err != nil {
		t.Fatalf("EncodeCertCmd (pkcs12) failed: %v", err)
	}

	pfxData, err := os.ReadFile(outputFile)
	if err != nil {
		t.Fatalf("Failed to read PKCS12 output: %v", err)
	}

	if _, _, err := encoding.DecodeFromPKCS12(pfxData, "test1234"); err != nil {
		t.Errorf("Output is not valid PKCS12: %v", err)
	}
}

// TestEncodeCertCmdPKCS12MissingKey tests EncodeCertCmd (pkcs12) without required --key flag
func TestEncodeCertCmdPKCS12MissingKey(t *testing.T) {
	certFile, _ := createTestCertificate(t)
	tmpDir := t.TempDir()
	outputFile := filepath.Join(tmpDir, "cert.p12")

	err := EncodeCertCmd([]string{
		"--input", certFile,
		"--output", outputFile,
		"--format", "pkcs12",
	})
	if err == nil {
		t.Error("Expected error for missing --key flag with pkcs12 format, got nil")
	}
}

// TestEncodeCertCmdMissingFlags tests EncodeCertCmd error handling for missing required flags
func TestEncodeCertCmdMissingFlags(t *testing.T) {
	if err := EncodeCertCmd([]string{"--output", "out.der"}); err == nil {
		t.Error("Expected error for missing --input flag, got nil")
	}

	certFile, _ := createTestCertificate(t)
	if err := EncodeCertCmd([]string{"--input", certFile}); err == nil {
		t.Error("Expected error for missing --output flag, got nil")
	}
}

// TestEncodeCertCmdUnknownFormat tests EncodeCertCmd with an unsupported format
func TestEncodeCertCmdUnknownFormat(t *testing.T) {
	certFile, _ := createTestCertificate(t)
	tmpDir := t.TempDir()

	err := EncodeCertCmd([]string{
		"--input", certFile,
		"--output", filepath.Join(tmpDir, "out.bin"),
		"--format", "unknown",
	})
	if err == nil {
		t.Error("Expected error for unknown format, got nil")
	}
}

// TestEncodeCertCmdInvalidInput tests EncodeCertCmd with a non-existent input file
func TestEncodeCertCmdInvalidInput(t *testing.T) {
	tmpDir := t.TempDir()

	err := EncodeCertCmd([]string{
		"--input", "/nonexistent/cert.pem",
		"--output", filepath.Join(tmpDir, "out.der"),
	})
	if err == nil {
		t.Error("Expected error for non-existent input file, got nil")
	}
}

// TestEncodeCert tests the os.Exit-wrapped EncodeCert function on the success path
func TestEncodeCert(t *testing.T) {
	certFile, _ := createTestCertificate(t)
	tmpDir := t.TempDir()
	outputFile := filepath.Join(tmpDir, "cert.der")

	output := captureOutput(func() {
		EncodeCert([]string{
			"--input", certFile,
			"--output", outputFile,
			"--format", "der",
		})
	})

	if !strings.Contains(output, "Certificate encoded successfully") {
		t.Errorf("Expected success message, got: %s", output)
	}
}

// TestDecodeCertCmdDER tests decoding a DER certificate back to PEM
func TestDecodeCertCmdDER(t *testing.T) {
	certFile, _ := createTestCertificate(t)
	tmpDir := t.TempDir()
	derFile := filepath.Join(tmpDir, "cert.der")
	pemOutFile := filepath.Join(tmpDir, "cert-out.pem")

	if err := EncodeCertCmd([]string{"--input", certFile, "--output", derFile, "--format", "der"}); err != nil {
		t.Fatalf("Failed to prepare DER fixture: %v", err)
	}

	err := DecodeCertCmd([]string{
		"--input", derFile,
		"--output", pemOutFile,
		"--format", "der",
	})
	if err != nil {
		t.Fatalf("DecodeCertCmd (der) failed: %v", err)
	}

	pemData, err := os.ReadFile(pemOutFile)
	if err != nil {
		t.Fatalf("Failed to read PEM output: %v", err)
	}

	if _, err := encoding.DecodeCertificateFromPEM(pemData); err != nil {
		t.Errorf("Output is not valid PEM: %v", err)
	}
}

// TestDecodeCertCmdPKCS12 tests decoding a PKCS12 bundle back to PEM cert and key
func TestDecodeCertCmdPKCS12(t *testing.T) {
	certFile, keyFile := createTestCertificate(t)
	tmpDir := t.TempDir()
	p12File := filepath.Join(tmpDir, "cert.p12")
	pemOutFile := filepath.Join(tmpDir, "cert-out.pem")
	keyOutFile := filepath.Join(tmpDir, "key-out.pem")

	err := EncodeCertCmd([]string{
		"--input", certFile,
		"--output", p12File,
		"--format", "pkcs12",
		"--key", keyFile,
		"--password", "secret",
	})
	if err != nil {
		t.Fatalf("Failed to prepare PKCS12 fixture: %v", err)
	}

	err = DecodeCertCmd([]string{
		"--input", p12File,
		"--output", pemOutFile,
		"--key-output", keyOutFile,
		"--format", "pkcs12",
		"--password", "secret",
	})
	if err != nil {
		t.Fatalf("DecodeCertCmd (pkcs12) failed: %v", err)
	}

	pemData, err := os.ReadFile(pemOutFile)
	if err != nil {
		t.Fatalf("Failed to read certificate PEM output: %v", err)
	}
	if _, err := encoding.DecodeCertificateFromPEM(pemData); err != nil {
		t.Errorf("Certificate output is not valid PEM: %v", err)
	}

	keyPEM, err := os.ReadFile(keyOutFile)
	if err != nil {
		t.Fatalf("Failed to read private key PEM output: %v", err)
	}
	if _, err := encoding.DecodePrivateKeyFromPEM(keyPEM); err != nil {
		t.Errorf("Key output is not valid PEM: %v", err)
	}
}

// TestDecodeCertCmdPKCS12WithoutKeyOutput tests decoding PKCS12 when --key-output is omitted
func TestDecodeCertCmdPKCS12WithoutKeyOutput(t *testing.T) {
	certFile, keyFile := createTestCertificate(t)
	tmpDir := t.TempDir()
	p12File := filepath.Join(tmpDir, "cert.p12")
	pemOutFile := filepath.Join(tmpDir, "cert-out.pem")

	if err := EncodeCertCmd([]string{
		"--input", certFile,
		"--output", p12File,
		"--format", "pkcs12",
		"--key", keyFile,
	}); err != nil {
		t.Fatalf("Failed to prepare PKCS12 fixture: %v", err)
	}

	err := DecodeCertCmd([]string{
		"--input", p12File,
		"--output", pemOutFile,
		"--format", "pkcs12",
	})
	if err != nil {
		t.Fatalf("DecodeCertCmd (pkcs12, no key-output) failed: %v", err)
	}

	if _, err := os.Stat(pemOutFile); err != nil {
		t.Errorf("Certificate output file not created: %v", err)
	}
}

// TestDecodeCertCmdMissingFlags tests DecodeCertCmd error handling for missing required flags
func TestDecodeCertCmdMissingFlags(t *testing.T) {
	tmpDir := t.TempDir()

	if err := DecodeCertCmd([]string{"--output", filepath.Join(tmpDir, "out.pem")}); err == nil {
		t.Error("Expected error for missing --input flag, got nil")
	}

	if err := DecodeCertCmd([]string{"--input", filepath.Join(tmpDir, "in.der")}); err == nil {
		t.Error("Expected error for missing --output flag, got nil")
	}
}

// TestDecodeCertCmdUnknownFormat tests DecodeCertCmd with an unsupported format
func TestDecodeCertCmdUnknownFormat(t *testing.T) {
	tmpDir := t.TempDir()
	inputFile := filepath.Join(tmpDir, "in.bin")
	if err := os.WriteFile(inputFile, []byte("data"), 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	err := DecodeCertCmd([]string{
		"--input", inputFile,
		"--output", filepath.Join(tmpDir, "out.pem"),
		"--format", "unknown",
	})
	if err == nil {
		t.Error("Expected error for unknown format, got nil")
	}
}

// TestDecodeCertCmdInvalidInput tests DecodeCertCmd with invalid/non-existent input
func TestDecodeCertCmdInvalidInput(t *testing.T) {
	tmpDir := t.TempDir()

	err := DecodeCertCmd([]string{
		"--input", "/nonexistent/cert.der",
		"--output", filepath.Join(tmpDir, "out.pem"),
	})
	if err == nil {
		t.Error("Expected error for non-existent input file, got nil")
	}

	invalidFile := filepath.Join(tmpDir, "invalid.der")
	if err := os.WriteFile(invalidFile, []byte("not der data"), 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	err = DecodeCertCmd([]string{
		"--input", invalidFile,
		"--output", filepath.Join(tmpDir, "out.pem"),
		"--format", "der",
	})
	if err == nil {
		t.Error("Expected error for invalid DER content, got nil")
	}
}

// TestDecodeCert tests the os.Exit-wrapped DecodeCert function on the success path
func TestDecodeCert(t *testing.T) {
	certFile, _ := createTestCertificate(t)
	tmpDir := t.TempDir()
	derFile := filepath.Join(tmpDir, "cert.der")
	pemOutFile := filepath.Join(tmpDir, "cert-out.pem")

	if err := EncodeCertCmd([]string{"--input", certFile, "--output", derFile, "--format", "der"}); err != nil {
		t.Fatalf("Failed to prepare DER fixture: %v", err)
	}

	output := captureOutput(func() {
		DecodeCert([]string{
			"--input", derFile,
			"--output", pemOutFile,
			"--format", "der",
		})
	})

	if !strings.Contains(output, "Certificate decoded successfully") {
		t.Errorf("Expected success message, got: %s", output)
	}
}
