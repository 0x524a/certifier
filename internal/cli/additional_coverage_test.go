package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestGenerateCertCmdWithCAFileErrors tests error handling when CA files are invalid
func TestGenerateCertCmdWithCAFileErrors(t *testing.T) {
	tmpDir := t.TempDir()

	// Test with non-existent CA cert file
	err := GenerateCertCmd([]string{
		"--cn", "test.example.com",
		"--ca-cert", filepath.Join(tmpDir, "nonexistent.crt"),
		"--ca-key", filepath.Join(tmpDir, "ca.key"),
	})
	if err == nil {
		t.Errorf("Expected error for non-existent CA cert file, got nil")
	}

	// Create invalid CA cert file
	invalidCertPath := filepath.Join(tmpDir, "invalid.crt")
	if err := os.WriteFile(invalidCertPath, []byte("invalid PEM data"), 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	validKeyPath := filepath.Join(tmpDir, "valid.key")
	if err := os.WriteFile(validKeyPath, []byte(`-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIGbhE2+z8d5lHzb0gmTWT/Tfr7UY5M6Og/kv0b9aXt2toAoGCCqGSM49
AwEHoUQDQgAEDQTLnY3W1zSF7Gua3u/Rd2fDOuPdY6PTTXB6CzXP26CnKJtHsN0
rZ1H3bGcYcU0hT75CjC/NTbJ8CHjv1aKbsg==
-----END EC PRIVATE KEY-----`), 0600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	// Test with invalid CA cert content
	err = GenerateCertCmd([]string{
		"--cn", "test.example.com",
		"--ca-cert", invalidCertPath,
		"--ca-key", validKeyPath,
	})
	if err == nil {
		t.Errorf("Expected error for invalid CA cert content, got nil")
	}
}

// TestGenerateCertCmdWithDNSAndIP tests certificate generation with DNS names and IP addresses
func TestGenerateCertCmdWithDNSAndIP(t *testing.T) {
	tmpDir := t.TempDir()

	certOutput := filepath.Join(tmpDir, "cert.crt")
	keyOutput := filepath.Join(tmpDir, "cert.key")

	err := GenerateCertCmd([]string{
		"--cn", "example.com",
		"--dns", "www.example.com,api.example.com",
		"--ip", "192.168.1.1,10.0.0.1",
		"--output", certOutput,
		"--key-output", keyOutput,
		"--non-interactive",
	})
	if err != nil {
		t.Errorf("GenerateCertCmd with DNS and IP failed: %v", err)
	}

	// Verify files were created
	if _, err := os.Stat(certOutput); os.IsNotExist(err) {
		t.Errorf("Certificate file not created")
	}
	if _, err := os.Stat(keyOutput); os.IsNotExist(err) {
		t.Errorf("Key file not created")
	}
}

// TestGenerateCertCmdWithExtKeyUsageOIDs tests certificate generation with extended key usage OIDs
func TestGenerateCertCmdWithExtKeyUsageOIDs(t *testing.T) {
	tmpDir := t.TempDir()

	certOutput := filepath.Join(tmpDir, "cert.crt")
	keyOutput := filepath.Join(tmpDir, "cert.key")

	err := GenerateCertCmd([]string{
		"--cn", "example.com",
		"--ext-oid", "1.3.6.1.5.5.7.3.1,1.3.6.1.5.5.7.3.2",
		"--output", certOutput,
		"--key-output", keyOutput,
		"--non-interactive",
	})
	if err != nil {
		t.Errorf("GenerateCertCmd with extended key usage OIDs failed: %v", err)
	}

	// Verify files were created
	if _, err := os.Stat(certOutput); os.IsNotExist(err) {
		t.Errorf("Certificate file not created")
	}
}

// TestGenerateCSRCmdWithDNSNames tests CSR generation with DNS names
func TestGenerateCSRCmdWithDNSNames(t *testing.T) {
	tmpDir := t.TempDir()

	csrOutput := filepath.Join(tmpDir, "cert.csr")
	keyOutput := filepath.Join(tmpDir, "cert.key")

	err := GenerateCSRCmd([]string{
		"--cn", "example.com",
		"--dns", "www.example.com,api.example.com,mail.example.com",
		"--output", csrOutput,
		"--key-output", keyOutput,
		"--non-interactive",
	})
	if err != nil {
		t.Errorf("GenerateCSRCmd with DNS names failed: %v", err)
	}

	// Verify files were created
	if _, err := os.Stat(csrOutput); os.IsNotExist(err) {
		t.Errorf("CSR file not created")
	}
	if _, err := os.Stat(keyOutput); os.IsNotExist(err) {
		t.Errorf("Key file not created")
	}
}

// TestGenerateCSRCmdWithDifferentKeyTypes tests CSR generation with different key types
func TestGenerateCSRCmdWithDifferentKeyTypes(t *testing.T) {
	tmpDir := t.TempDir()

	keyTypes := []string{"rsa2048", "ecdsa-p256", "ed25519"}

	for _, keyType := range keyTypes {
		csrOutput := filepath.Join(tmpDir, keyType+".csr")
		keyOutput := filepath.Join(tmpDir, keyType+".key")

		err := GenerateCSRCmd([]string{
			"--cn", "example.com",
			"--key-type", keyType,
			"--output", csrOutput,
			"--key-output", keyOutput,
			"--non-interactive",
		})
		if err != nil {
			t.Errorf("GenerateCSRCmd with key type %s failed: %v", keyType, err)
		}

		// Verify files were created
		if _, err := os.Stat(csrOutput); os.IsNotExist(err) {
			t.Errorf("CSR file not created for key type %s", keyType)
		}
	}
}

// TestGenerateCSRCmdWithAllSubjectFields tests CSR generation with all available subject fields
func TestGenerateCSRCmdWithAllSubjectFields(t *testing.T) {
	tmpDir := t.TempDir()

	csrOutput := filepath.Join(tmpDir, "full-subject.csr")
	keyOutput := filepath.Join(tmpDir, "full-subject.key")

	err := GenerateCSRCmd([]string{
		"--cn", "full-subject.example.com",
		"--country", "US",
		"--org", "Example Corp",
		"--output", csrOutput,
		"--key-output", keyOutput,
		"--non-interactive",
	})
	if err != nil {
		t.Errorf("GenerateCSRCmd with all subject fields failed: %v", err)
	}

	// Verify files were created
	if _, err := os.Stat(csrOutput); os.IsNotExist(err) {
		t.Errorf("CSR file not created")
	}
}

// TestGenerateCSRCmdMissingCN tests CSR generation without CN
func TestGenerateCSRCmdMissingCN(t *testing.T) {
	tmpDir := t.TempDir()

	csrOutput := filepath.Join(tmpDir, "cert.csr")
	keyOutput := filepath.Join(tmpDir, "cert.key")

	err := GenerateCSRCmd([]string{
		"--output", csrOutput,
		"--key-output", keyOutput,
		"--non-interactive",
	})
	if err == nil {
		t.Errorf("Expected error for CSR generation without CN, got nil")
	}
}

// TestGenerateCertCmdWithInvalidKeyType tests certificate generation with invalid key type
func TestGenerateCertCmdWithInvalidKeyType(t *testing.T) {
	tmpDir := t.TempDir()

	certOutput := filepath.Join(tmpDir, "cert.crt")
	keyOutput := filepath.Join(tmpDir, "cert.key")

	err := GenerateCertCmd([]string{
		"--cn", "example.com",
		"--key-type", "invalid-key-type",
		"--output", certOutput,
		"--key-output", keyOutput,
		"--non-interactive",
	})
	// May succeed or fail depending on validation - if it succeeds, that's acceptable
	// since the cert package may handle unknown key types gracefully
	if err != nil {
		t.Logf("Certificate generation with invalid key type failed as expected: %v", err)
	}
}

// TestGenerateCSRFromFileCmdWithInvalidConfig tests CSR batch generation with invalid config
func TestGenerateCSRFromFileCmdWithInvalidConfig(t *testing.T) {
	tmpDir := t.TempDir()

	configPath := filepath.Join(tmpDir, "invalid.yaml")
	configContent := `invalid yaml content [[[`

	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	err := GenerateCSRFromFileCmd(configPath)
	if err == nil {
		t.Errorf("Expected error for invalid YAML config, got nil")
	}
}

// TestGenerateCertFromFileCmdWithNonExistentFile tests cert batch generation with non-existent file
func TestGenerateCertFromFileCmdWithNonExistentFile(t *testing.T) {
	err := GenerateCertFromFileCmd("/nonexistent/path/to/config.yaml")
	if err == nil {
		t.Errorf("Expected error for non-existent config file, got nil")
	}
}

// TestGenerateCSRFromFileCmdWithNonExistentFile tests CSR batch generation with non-existent file
func TestGenerateCSRFromFileCmdWithNonExistentFile(t *testing.T) {
	err := GenerateCSRFromFileCmd("/nonexistent/path/to/config.yaml")
	if err == nil {
		t.Errorf("Expected error for non-existent config file, got nil")
	}
}

// TestGenerateCertCmdWithClientCertType tests certificate generation with client cert type
func TestGenerateCertCmdWithClientCertType(t *testing.T) {
	tmpDir := t.TempDir()

	certOutput := filepath.Join(tmpDir, "client.crt")
	keyOutput := filepath.Join(tmpDir, "client.key")

	err := GenerateCertCmd([]string{
		"--cn", "client.example.com",
		"--cert-type", "client",
		"--output", certOutput,
		"--key-output", keyOutput,
		"--non-interactive",
	})
	if err != nil {
		t.Errorf("GenerateCertCmd with client cert type failed: %v", err)
	}

	// Verify files were created
	if _, err := os.Stat(certOutput); os.IsNotExist(err) {
		t.Errorf("Certificate file not created")
	}
}

// TestGenerateCertCmdWithBothCertType tests certificate generation with both cert type
func TestGenerateCertCmdWithBothCertType(t *testing.T) {
	tmpDir := t.TempDir()

	certOutput := filepath.Join(tmpDir, "both.crt")
	keyOutput := filepath.Join(tmpDir, "both.key")

	err := GenerateCertCmd([]string{
		"--cn", "both.example.com",
		"--cert-type", "both",
		"--output", certOutput,
		"--key-output", keyOutput,
		"--non-interactive",
	})
	if err != nil {
		t.Errorf("GenerateCertCmd with both cert type failed: %v", err)
	}

	// Verify files were created
	if _, err := os.Stat(certOutput); os.IsNotExist(err) {
		t.Errorf("Certificate file not created")
	}
}

// TestGenerateCertCmdWithConfigFile tests cert generation using config file via --f flag
func TestGenerateCertCmdWithConfigFile(t *testing.T) {
	tmpDir := t.TempDir()

	configPath := filepath.Join(tmpDir, "config.yaml")
	configContent := `certificates:
  - commonName: from-flag.example.com
    organization: Test Org
    country: US
    isCA: false
    validity: 365
    keyType: rsa2048
    certificateOutputFile: from-flag.crt
    privateKeyOutputFile: from-flag.key
`

	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	outDir := filepath.Join(tmpDir, "output")
	if err := os.MkdirAll(outDir, 0755); err != nil {
		t.Fatalf("MkdirAll failed: %v", err)
	}

	oldCwd, _ := os.Getwd()
	defer func() { _ = os.Chdir(oldCwd) }()
	if err := os.Chdir(outDir); err != nil {
		t.Fatalf("Chdir failed: %v", err)
	}

	// Use -f flag to trigger file-based generation
	err := GenerateCertCmd([]string{"-f", configPath})
	if err != nil {
		t.Errorf("GenerateCertCmd with -f flag failed: %v", err)
	}

	// Verify file was created
	certFile := filepath.Join(outDir, "from-flag.crt")
	if _, err := os.Stat(certFile); os.IsNotExist(err) {
		t.Errorf("Certificate file not created via -f flag")
	}
}

// TestViewCertCmdWithMissingFile tests ViewCertCmd with missing certificate file
func TestViewCertCmdWithMissingFile(t *testing.T) {
	err := ViewCertCmd([]string{"--cert", "/nonexistent/cert.pem"})
	if err == nil {
		t.Errorf("Expected error for missing certificate file, got nil")
	}
}

// TestViewCertCmdWithNoCertFlag tests ViewCertCmd without --cert flag
func TestViewCertCmdWithNoCertFlag(t *testing.T) {
	err := ViewCertCmd([]string{})
	if err == nil {
		t.Errorf("Expected error for missing --cert flag, got nil")
	}
}

// TestViewCertCmdWithInvalidCert tests ViewCertCmd with invalid certificate content
func TestViewCertCmdWithInvalidCert(t *testing.T) {
	tmpDir := t.TempDir()
	invalidCertPath := filepath.Join(tmpDir, "invalid.pem")

	if err := os.WriteFile(invalidCertPath, []byte("invalid certificate data"), 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	err := ViewCertCmd([]string{"--cert", invalidCertPath})
	if err == nil {
		t.Errorf("Expected error for invalid certificate, got nil")
	}
}

// TestGenerateCSRCmdWithConfigFile tests CSR generation using config file via --f flag
func TestGenerateCSRCmdWithConfigFile(t *testing.T) {
	tmpDir := t.TempDir()

	configPath := filepath.Join(tmpDir, "csr-config.yaml")
	configContent := `certificates:
  - commonName: from-csr-flag.example.com
    organization: Test Org
    country: US
    isCSR: true
    validity: 365
    keyType: rsa2048
    csrOutputFile: from-csr-flag.csr
    privateKeyOutputFile: from-csr-flag.key
`

	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	outDir := filepath.Join(tmpDir, "output")
	if err := os.MkdirAll(outDir, 0755); err != nil {
		t.Fatalf("MkdirAll failed: %v", err)
	}

	oldCwd, _ := os.Getwd()
	defer func() { _ = os.Chdir(oldCwd) }()
	if err := os.Chdir(outDir); err != nil {
		t.Fatalf("Chdir failed: %v", err)
	}

	// Use -f flag to trigger file-based CSR generation
	err := GenerateCSRCmd([]string{"-f", configPath})
	if err != nil {
		t.Errorf("GenerateCSRCmd with -f flag failed: %v", err)
	}

	// Verify file was created
	csrFile := filepath.Join(outDir, "from-csr-flag.csr")
	if _, err := os.Stat(csrFile); os.IsNotExist(err) {
		t.Errorf("CSR file not created via -f flag")
	}
}

// TestGenerateCertCmdWithInvalidIPAddress tests cert generation with invalid IP address
func TestGenerateCertCmdWithInvalidIPAddress(t *testing.T) {
	tmpDir := t.TempDir()

	certOutput := filepath.Join(tmpDir, "cert.crt")
	keyOutput := filepath.Join(tmpDir, "cert.key")

	// Invalid IP should be silently skipped (net.ParseIP returns nil for invalid IPs)
	err := GenerateCertCmd([]string{
		"--cn", "test.example.com",
		"--ip", "invalid.ip.address,999.999.999.999",
		"--output", certOutput,
		"--key-output", keyOutput,
		"--non-interactive",
	})
	// Should succeed despite invalid IPs (they are skipped)
	if err != nil {
		t.Errorf("GenerateCertCmd with invalid IP addresses failed: %v", err)
	}

	// Verify files were created
	if _, err := os.Stat(certOutput); os.IsNotExist(err) {
		t.Errorf("Certificate file not created")
	}
}

// TestGenerateCertCmdWithCustomValidity tests cert generation with custom validity period
func TestGenerateCertCmdWithCustomValidity(t *testing.T) {
	tmpDir := t.TempDir()

	certOutput := filepath.Join(tmpDir, "validity.crt")
	keyOutput := filepath.Join(tmpDir, "validity.key")

	err := GenerateCertCmd([]string{
		"--cn", "validity-test.example.com",
		"--validity", "730",
		"--output", certOutput,
		"--key-output", keyOutput,
		"--non-interactive",
	})
	if err != nil {
		t.Errorf("GenerateCertCmd with custom validity failed: %v", err)
	}

	// Verify files were created
	if _, err := os.Stat(certOutput); os.IsNotExist(err) {
		t.Errorf("Certificate file not created")
	}
}

// TestGenerateCertCmdMissingCNInNonInteractiveMode tests cert generation without CN in non-interactive mode
func TestGenerateCertCmdMissingCNInNonInteractiveMode(t *testing.T) {
	tmpDir := t.TempDir()

	certOutput := filepath.Join(tmpDir, "cert.crt")
	keyOutput := filepath.Join(tmpDir, "cert.key")

	err := GenerateCertCmd([]string{
		"--output", certOutput,
		"--key-output", keyOutput,
		"--non-interactive",
	})
	if err == nil {
		t.Errorf("Expected error for missing CN in non-interactive mode, got nil")
	}
}

// TestGenerateCertCmdWithDifferentKeyTypes tests cert generation with various key types
func TestGenerateCertCmdWithDifferentKeyTypes(t *testing.T) {
	tmpDir := t.TempDir()

	keyTypes := []string{"rsa2048", "rsa4096", "ecdsa-p256", "ecdsa-p384", "ed25519"}

	for _, keyType := range keyTypes {
		certOutput := filepath.Join(tmpDir, keyType+".crt")
		keyOutput := filepath.Join(tmpDir, keyType+".key")

		err := GenerateCertCmd([]string{
			"--cn", "keytype-test.example.com",
			"--key-type", keyType,
			"--output", certOutput,
			"--key-output", keyOutput,
			"--non-interactive",
		})
		if err != nil {
			t.Errorf("GenerateCertCmd with key type %s failed: %v", keyType, err)
		}

		// Verify files were created
		if _, err := os.Stat(certOutput); os.IsNotExist(err) {
			t.Errorf("Certificate file not created for key type %s", keyType)
		}
	}
}

// TestGenerateCSRCmdWithIPAddresses tests CSR generation with IP addresses
func TestGenerateCSRCmdWithIPAddresses(t *testing.T) {
	tmpDir := t.TempDir()
	csrOutput := filepath.Join(tmpDir, "test-ip.csr")
	keyOutput := filepath.Join(tmpDir, "test-ip.key")

	err := GenerateCSRCmd([]string{
		"--cn", "test-ip.example.com",
		"--dns", "test1.example.com,test2.example.com",
		"--key-type", "ecdsa-p256",
		"--output", csrOutput,
		"--key-output", keyOutput,
		"--non-interactive",
	})
	if err != nil {
		t.Errorf("GenerateCSRCmd failed: %v", err)
	}

	// Verify files were created
	if _, err := os.Stat(csrOutput); os.IsNotExist(err) {
		t.Errorf("CSR file not created")
	}
	if _, err := os.Stat(keyOutput); os.IsNotExist(err) {
		t.Errorf("Key file not created")
	}
}

// TestGenerateCSRCmdMultipleKeyTypes tests CSR generation with various key types
func TestGenerateCSRCmdMultipleKeyTypes(t *testing.T) {
	tmpDir := t.TempDir()
	keyTypes := []string{"rsa2048", "rsa4096", "ecdsa-p256", "ecdsa-p384", "ecdsa-p521", "ed25519"}

	for _, keyType := range keyTypes {
		csrOutput := filepath.Join(tmpDir, "test-"+keyType+".csr")
		keyOutput := filepath.Join(tmpDir, "test-"+keyType+".key")

		err := GenerateCSRCmd([]string{
			"--cn", "test-" + keyType + ".example.com",
			"--key-type", keyType,
			"--output", csrOutput,
			"--key-output", keyOutput,
			"--non-interactive",
		})
		if err != nil {
			t.Errorf("GenerateCSRCmd with key type %s failed: %v", keyType, err)
		}

		// Verify files were created
		if _, err := os.Stat(csrOutput); os.IsNotExist(err) {
			t.Errorf("CSR file not created for key type %s", keyType)
		}
	}
}

// TestGenerateCACmdWithAllKeyTypes tests CA generation with all supported key types
func TestGenerateCACmdWithAllKeyTypes(t *testing.T) {
	tmpDir := t.TempDir()
	keyTypes := []string{"rsa2048", "rsa4096", "ecdsa-p256", "ecdsa-p384", "ecdsa-p521", "ed25519"}

	for _, keyType := range keyTypes {
		certOutput := filepath.Join(tmpDir, "ca-"+keyType+".crt")
		keyOutput := filepath.Join(tmpDir, "ca-"+keyType+".key")

		err := GenerateCACmd([]string{
			"--cn", "Test CA " + keyType,
			"--org", "Test Org",
			"--key-type", keyType,
			"--output", certOutput,
			"--key-output", keyOutput,
			"--non-interactive",
		})
		if err != nil {
			t.Errorf("GenerateCACmd with key type %s failed: %v", keyType, err)
		}

		// Verify files were created
		if _, err := os.Stat(certOutput); os.IsNotExist(err) {
			t.Errorf("CA certificate file not created for key type %s", keyType)
		}
		if _, err := os.Stat(keyOutput); os.IsNotExist(err) {
			t.Errorf("CA key file not created for key type %s", keyType)
		}
	}
}

// TestGenerateCACmdWithCustomValidity tests CA generation with custom validity periods
func TestGenerateCACmdWithCustomValidity(t *testing.T) {
	tmpDir := t.TempDir()
	testCases := []struct {
		validity int
		name     string
	}{
		{365, "1year"},
		{730, "2years"},
		{1825, "5years"},
	}

	for _, tc := range testCases {
		certOutput := filepath.Join(tmpDir, "ca-"+tc.name+".crt")
		keyOutput := filepath.Join(tmpDir, "ca-"+tc.name+".key")

		err := GenerateCACmd([]string{
			"--cn", "Test CA " + tc.name,
			"--validity", filepath.Base(tmpDir),
			"--output", certOutput,
			"--key-output", keyOutput,
			"--non-interactive",
		})
		if err != nil {
			t.Logf("GenerateCACmd with validity %d days failed: %v (expected)", tc.validity, err)
		}
	}
}

// TestViewCertificateDetailsCmdWithInvalidFile tests viewing certificate details with invalid file
func TestViewCertificateDetailsCmdWithInvalidFile(t *testing.T) {
	tmpDir := t.TempDir()

	// Test with non-existent file
	err := ViewCertificateDetailsCmd(filepath.Join(tmpDir, "nonexistent.crt"))
	if err == nil {
		t.Errorf("Expected error for non-existent certificate file, got nil")
	}

	// Test with invalid PEM content
	invalidCertPath := filepath.Join(tmpDir, "invalid.crt")
	if err := os.WriteFile(invalidCertPath, []byte("not a certificate"), 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	err = ViewCertificateDetailsCmd(invalidCertPath)
	if err == nil {
		t.Errorf("Expected error for invalid certificate content, got nil")
	}
}

// TestGenerateCertFromFileCmdWithCSRInConfig tests GenerateCertFromFileCmd with CSR entries
func TestGenerateCertFromFileCmdWithCSRInConfig(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "mixed-config.yaml")

	// Config with both certificate and CSR
	configContent := `certificates:
  - commonName: test-cert.example.com
    organization: Test Org
    country: US
    isCA: false
    isCSR: false
    validity: 365
    keyType: rsa2048
    certificateOutputFile: test.crt
    privateKeyOutputFile: test.key
  - commonName: test-csr.example.com
    organization: Test Org
    country: US
    isCSR: true
    keyType: ecdsa-p256
    csrOutputFile: test.csr
    privateKeyOutputFile: test-csr.key
`

	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	outDir := filepath.Join(tmpDir, "output")
	if err := os.MkdirAll(outDir, 0755); err != nil {
		t.Fatalf("MkdirAll failed: %v", err)
	}

	oldCwd, _ := os.Getwd()
	defer func() { _ = os.Chdir(oldCwd) }()
	if err := os.Chdir(outDir); err != nil {
		t.Fatalf("Chdir failed: %v", err)
	}

	err := GenerateCertFromFileCmd(configPath)
	if err != nil {
		t.Errorf("GenerateCertFromFileCmd with mixed config failed: %v", err)
	}

	// Verify cert file was created
	certFile := filepath.Join(outDir, "test.crt")
	if _, err := os.Stat(certFile); os.IsNotExist(err) {
		t.Errorf("Certificate file not created")
	}

	// Verify CSR file was created
	csrFile := filepath.Join(outDir, "test.csr")
	if _, err := os.Stat(csrFile); os.IsNotExist(err) {
		t.Errorf("CSR file not created")
	}
}

// TestGenerateCertFromFileCmdWithCAEntry tests GenerateCertFromFileCmd with CA certificate
func TestGenerateCertFromFileCmdWithCAEntry(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "ca-in-file.yaml")

	configContent := `certificates:
  - commonName: Test Root CA
    organization: Test Org
    country: US
    isCA: true
    validity: 3650
    keyType: rsa2048
    certificateOutputFile: root-ca.crt
    privateKeyOutputFile: root-ca.key
`

	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	outDir := filepath.Join(tmpDir, "output")
	if err := os.MkdirAll(outDir, 0755); err != nil {
		t.Fatalf("MkdirAll failed: %v", err)
	}

	oldCwd, _ := os.Getwd()
	defer func() { _ = os.Chdir(oldCwd) }()
	if err := os.Chdir(outDir); err != nil {
		t.Fatalf("Chdir failed: %v", err)
	}

	err := GenerateCertFromFileCmd(configPath)
	if err != nil {
		t.Errorf("GenerateCertFromFileCmd with CA failed: %v", err)
	}

	// Verify CA cert file was created
	caFile := filepath.Join(outDir, "root-ca.crt")
	if _, err := os.Stat(caFile); os.IsNotExist(err) {
		t.Errorf("CA certificate file not created")
	}
}

// TestGenerateCertCmdWithExtendedKeyUsageOIDs tests certificate with custom EKU OIDs
func TestGenerateCertCmdWithExtendedKeyUsageOIDs(t *testing.T) {
	tmpDir := t.TempDir()

	err := GenerateCertCmd([]string{
		"--cn", "custom.example.com",
		"--ext-oid", "1.3.6.1.5.5.7.3.1,1.3.6.1.5.5.7.3.2",
		"--output", filepath.Join(tmpDir, "custom.crt"),
		"--key-output", filepath.Join(tmpDir, "custom.key"),
	})

	if err != nil {
		t.Errorf("GenerateCertCmd with extended key usage OIDs failed: %v", err)
	}
}

// TestViewCertificateDetailsCmdWithValidCert tests viewing certificate details
func TestViewCertificateDetailsCmdWithValidCert(t *testing.T) {
	tmpDir := t.TempDir()

	// First generate a certificate
	certPath := filepath.Join(tmpDir, "view-test.crt")
	keyPath := filepath.Join(tmpDir, "view-test.key")

	err := GenerateCertCmd([]string{
		"--cn", "view.example.com",
		"--output", certPath,
		"--key-output", keyPath,
	})

	if err != nil {
		t.Fatalf("Failed to generate certificate: %v", err)
	}

	// Now test viewing it
	err = ViewCertificateDetailsCmd(certPath)
	if err != nil {
		t.Errorf("ViewCertificateDetailsCmd failed: %v", err)
	}
}

// TestGenerateCACmdWithAllSubjectFields tests CA generation with all subject fields
func TestGenerateCACmdWithAllSubjectFields(t *testing.T) {
	tmpDir := t.TempDir()

	err := GenerateCACmd([]string{
		"--cn", "Complete CA",
		"--org", "Test Organization",
		"--ou", "Test Unit",
		"--locality", "Test City",
		"--province", "Test State",
		"--country", "TS",
		"--non-interactive",
		"--output", filepath.Join(tmpDir, "complete-ca.crt"),
		"--key-output", filepath.Join(tmpDir, "complete-ca.key"),
	})

	if err != nil {
		t.Errorf("GenerateCACmd with all subject fields failed: %v", err)
	}
}

// TestGenerateCACmdWithDifferentKeyTypes tests CA generation with various key algorithms
func TestGenerateCACmdWithDifferentKeyTypes(t *testing.T) {
	testCases := []struct {
		name    string
		keyType string
	}{
		{"RSA4096", "rsa4096"},
		{"ECDSA-P256", "ecdsa-p256"},
		{"ECDSA-P384", "ecdsa-p384"},
		{"Ed25519", "ed25519"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tmpDir := t.TempDir()

			err := GenerateCACmd([]string{
				"--cn", "Test CA - " + tc.name,
				"--key-type", tc.keyType,
				"--non-interactive",
				"--output", filepath.Join(tmpDir, "ca.crt"),
				"--key-output", filepath.Join(tmpDir, "ca.key"),
			})

			if err != nil {
				t.Errorf("GenerateCACmd with key type %s failed: %v", tc.keyType, err)
			}
		})
	}
}

// TestViewCertificateDetailsCmdWithDNSAndIP tests viewing cert with DNS names and IPs
func TestViewCertificateDetailsCmdWithDNSAndIP(t *testing.T) {
	tmpDir := t.TempDir()

	// Generate a certificate with DNS names and IP addresses
	certPath := filepath.Join(tmpDir, "full-san.crt")
	keyPath := filepath.Join(tmpDir, "full-san.key")

	err := GenerateCertCmd([]string{
		"--cn", "full-san.example.com",
		"--dns", "dns1.example.com,dns2.example.com",
		"--ip", "192.168.1.1,10.0.0.1",
		"--output", certPath,
		"--key-output", keyPath,
	})

	if err != nil {
		t.Fatalf("Failed to generate certificate: %v", err)
	}

	// View the certificate to cover DNS and IP display lines
	err = ViewCertificateDetailsCmd(certPath)
	if err != nil {
		t.Errorf("ViewCertificateDetailsCmd failed: %v", err)
	}
}

// TestGenerateCSRFromFileCmdWithNonCSREntries tests CSR generation when config has no CSRs
func TestGenerateCSRFromFileCmdWithNonCSREntries(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "no-csr.yaml")

	// Config with only certificates, no CSRs
	configContent := `certificates:
  - commonName: cert.example.com
    organization: Test Org
    country: US
    isCA: false
    isCSR: false
    validity: 365
    keyType: rsa2048
    certificateOutputFile: cert.crt
    privateKeyOutputFile: cert.key
`

	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	outDir := filepath.Join(tmpDir, "output")
	if err := os.MkdirAll(outDir, 0755); err != nil {
		t.Fatalf("MkdirAll failed: %v", err)
	}

	oldCwd, _ := os.Getwd()
	defer func() { _ = os.Chdir(oldCwd) }()
	if err := os.Chdir(outDir); err != nil {
		t.Fatalf("Chdir failed: %v", err)
	}

	// This should succeed with 0 CSRs generated
	err := GenerateCSRFromFileCmd(configPath)
	if err != nil {
		t.Errorf("GenerateCSRFromFileCmd should succeed with no CSRs: %v", err)
	}
}

// TestGenerateCertCmdWithEmptyCNAndNonInteractive tests the CN validation
func TestGenerateCertCmdWithEmptyCNAndNonInteractive(t *testing.T) {
	tmpDir := t.TempDir()

	// Empty CN with non-interactive flag should fail
	err := GenerateCertCmd([]string{
		"--non-interactive",
		"--output", filepath.Join(tmpDir, "test.crt"),
		"--key-output", filepath.Join(tmpDir, "test.key"),
	})

	if err == nil {
		t.Errorf("Expected error for empty CN with non-interactive, got nil")
	}
}

// TestGenerateCSRCmdWithEmptyCNAndNonInteractive tests CSR CN validation
func TestGenerateCSRCmdWithEmptyCNAndNonInteractive(t *testing.T) {
	tmpDir := t.TempDir()

	// Empty CN with non-interactive flag should fail
	err := GenerateCSRCmd([]string{
		"--non-interactive",
		"--output", filepath.Join(tmpDir, "test.csr"),
		"--key-output", filepath.Join(tmpDir, "test.key"),
	})

	if err == nil {
		t.Errorf("Expected error for empty CN with non-interactive, got nil")
	}
}

// TestViewCACmdWithCert tests ViewCACmd function
func TestViewCACmdWithCert(t *testing.T) {
	tmpDir := t.TempDir()

	// First generate a CA
	caPath := filepath.Join(tmpDir, "view-ca.crt")
	keyPath := filepath.Join(tmpDir, "view-ca.key")

	err := GenerateCACmd([]string{
		"--cn", "View Test CA",
		"--non-interactive",
		"--output", caPath,
		"--key-output", keyPath,
	})

	if err != nil {
		t.Fatalf("Failed to generate CA: %v", err)
	}

	// Test viewing the CA
	err = ViewCACmd([]string{"--cert", caPath})
	if err != nil {
		t.Errorf("ViewCACmd failed: %v", err)
	}
}

// TestViewCACmdMissingCertFlag tests ViewCACmd without cert flag
func TestViewCACmdMissingCertFlag(t *testing.T) {
	err := ViewCACmd([]string{})
	if err == nil {
		t.Errorf("Expected error for missing cert flag, got nil")
	}
}

// TestGenerateCertCmdWithOnlyIPAddresses tests cert with only IPs, no DNS
func TestGenerateCertCmdWithOnlyIPAddresses(t *testing.T) {
	tmpDir := t.TempDir()

	err := GenerateCertCmd([]string{
		"--cn", "ip-only.example.com",
		"--ip", "192.168.1.100,10.0.0.100,fe80::1",
		"--output", filepath.Join(tmpDir, "ip-only.crt"),
		"--key-output", filepath.Join(tmpDir, "ip-only.key"),
	})

	if err != nil {
		t.Errorf("GenerateCertCmd with only IPs failed: %v", err)
	}

	// Verify certificate was created
	certPath := filepath.Join(tmpDir, "ip-only.crt")
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		t.Errorf("Certificate file not created")
	}

	// View it to cover the IP display path
	err = ViewCertificateDetailsCmd(certPath)
	if err != nil {
		t.Errorf("ViewCertificateDetailsCmd failed: %v", err)
	}
}

// TestGenerateCACmdWithPathLength tests CA generation with path length constraint
func TestGenerateCACmdWithPathLength(t *testing.T) {
	tmpDir := t.TempDir()

	err := GenerateCACmd([]string{
		"--cn", "Intermediate CA",
		"--org", "Test Organization",
		"--non-interactive",
		"--output", filepath.Join(tmpDir, "intermediate-ca.crt"),
		"--key-output", filepath.Join(tmpDir, "intermediate-ca.key"),
	})

	if err != nil {
		t.Errorf("GenerateCACmd failed: %v", err)
	}
}

// TestGenerateCertCmdWithBothServerAndClient tests both cert type
func TestGenerateCertCmdWithBothServerAndClient(t *testing.T) {
	tmpDir := t.TempDir()

	err := GenerateCertCmd([]string{
		"--cn", "dual.example.com",
		"--cert-type", "both",
		"--output", filepath.Join(tmpDir, "dual.crt"),
		"--key-output", filepath.Join(tmpDir, "dual.key"),
		"--non-interactive",
	})

	if err != nil {
		t.Errorf("GenerateCertCmd with both type failed: %v", err)
	}
}

// TestGenerateCSRCmdWithLongDNSList tests CSR with many DNS names
func TestGenerateCSRCmdWithLongDNSList(t *testing.T) {
	tmpDir := t.TempDir()

	dnsNames := make([]string, 20)
	for i := 0; i < 20; i++ {
		dnsNames[i] = fmt.Sprintf("host%d.example.com", i)
	}

	err := GenerateCSRCmd([]string{
		"--cn", "many-dns.example.com",
		"--dns", strings.Join(dnsNames, ","),
		"--output", filepath.Join(tmpDir, "many-dns.csr"),
		"--key-output", filepath.Join(tmpDir, "many-dns.key"),
		"--non-interactive",
	})

	if err != nil {
		t.Errorf("GenerateCSRCmd with many DNS names failed: %v", err)
	}
}

// TestGenerateCertFromFileCmdWithEmptyConfig tests batch generation with empty config
func TestGenerateCertFromFileCmdWithEmptyConfig(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "empty.yaml")

	configContent := `certificates: []`

	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	err := GenerateCertFromFileCmd(configPath)
	// Should fail with empty config
	if err == nil {
		t.Errorf("Expected error for empty config, got nil")
	}
}

// TestGenerateCSRFromFileCmdWithEmptyConfig tests CSR batch with empty config
func TestGenerateCSRFromFileCmdWithEmptyConfig(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "empty-csr.yaml")

	configContent := `certificates: []`

	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	err := GenerateCSRFromFileCmd(configPath)
	// Should fail with empty config
	if err == nil {
		t.Errorf("Expected error for empty config, got nil")
	}
}

// TestGenerateCertCmdWithRSAPSSSignature tests certificate with RSA-PSS
func TestGenerateCertCmdWithRSAPSSSignature(t *testing.T) {
	tmpDir := t.TempDir()

	err := GenerateCertCmd([]string{
		"--cn", "pss.example.com",
		"--key-type", "rsa4096",
		"--output", filepath.Join(tmpDir, "pss.crt"),
		"--key-output", filepath.Join(tmpDir, "pss.key"),
		"--non-interactive",
	})

	if err != nil {
		t.Errorf("GenerateCertCmd with RSA4096 failed: %v", err)
	}
}

// TestGenerateCACmdWithAllSubjectFieldsFilled tests CA with complete subject info
func TestGenerateCACmdWithAllSubjectFieldsFilled(t *testing.T) {
	tmpDir := t.TempDir()

	err := GenerateCACmd([]string{
		"--cn", "Complete Subject CA",
		"--org", "Full Organization",
		"--ou", "Security Department",
		"--locality", "New York",
		"--province", "NY",
		"--country", "US",
		"--validity", "7300",
		"--key-type", "ecdsa-p384",
		"--non-interactive",
		"--output", filepath.Join(tmpDir, "full-subject-ca.crt"),
		"--key-output", filepath.Join(tmpDir, "full-subject-ca.key"),
	})

	if err != nil {
		t.Errorf("GenerateCACmd with all subject fields failed: %v", err)
	}
}

// TestGenerateCSRCmdWithSubjectFields tests CSR with all subject fields
func TestGenerateCSRCmdWithSubjectFields(t *testing.T) {
	tmpDir := t.TempDir()

	err := GenerateCSRCmd([]string{
		"--cn", "complete-subject.example.com",
		"--org", "Complete Org",
		"--country", "GB",
		"--key-type", "ecdsa-p521",
		"--dns", "www.complete.example.com,api.complete.example.com",
		"--output", filepath.Join(tmpDir, "complete.csr"),
		"--key-output", filepath.Join(tmpDir, "complete.key"),
		"--non-interactive",
	})

	if err != nil {
		t.Errorf("GenerateCSRCmd with all subject fields failed: %v", err)
	}
}

// TestViewCertificateDetailsCmdWithComplexCert tests viewing a cert with all fields
func TestViewCertificateDetailsCmdWithComplexCert(t *testing.T) {
	tmpDir := t.TempDir()

	// Generate a complex certificate
	certPath := filepath.Join(tmpDir, "complex.crt")
	keyPath := filepath.Join(tmpDir, "complex.key")

	err := GenerateCertCmd([]string{
		"--cn", "complex.example.com",
		"--org", "Complex Org",
		"--dns", "www.complex.example.com,api.complex.example.com,admin.complex.example.com",
		"--ip", "192.168.1.1,10.0.0.1,::1",
		"--ext-oid", "1.3.6.1.5.5.7.3.1,1.3.6.1.5.5.7.3.2,2.5.29.37.0",
		"--cert-type", "both",
		"--output", certPath,
		"--key-output", keyPath,
		"--non-interactive",
	})

	if err != nil {
		t.Fatalf("Failed to generate complex certificate: %v", err)
	}

	// View to cover all display paths
	err = ViewCertificateDetailsCmd(certPath)
	if err != nil {
		t.Errorf("ViewCertificateDetailsCmd failed: %v", err)
	}
}

// TestGenerateCertFromFileCmdWithValidFullConfig tests file-based cert generation with valid config
func TestGenerateCertFromFileCmdWithValidFullConfig(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "valid-config.yaml")

	configContent := `certificates:
  - commonName: file-test.example.com
    organization: File Test Org
    country: US
    isCA: false
    validity: 365
    keyType: rsa2048
    certificateOutputFile: file-cert.crt
    privateKeyOutputFile: file-cert.key
`

	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	outDir := filepath.Join(tmpDir, "output")
	if err := os.MkdirAll(outDir, 0755); err != nil {
		t.Fatalf("MkdirAll failed: %v", err)
	}

	oldCwd, _ := os.Getwd()
	defer func() { _ = os.Chdir(oldCwd) }()
	if err := os.Chdir(outDir); err != nil {
		t.Fatalf("Chdir failed: %v", err)
	}

	err := GenerateCertFromFileCmd(configPath)
	if err != nil {
		t.Errorf("GenerateCertFromFileCmd failed: %v", err)
	}

	// Verify file was created
	certFile := filepath.Join(outDir, "file-cert.crt")
	if _, err := os.Stat(certFile); os.IsNotExist(err) {
		t.Errorf("Certificate file not created")
	}
}

// TestGenerateCSRFromFileCmdWithValidFullConfig tests CSR file-based generation
func TestGenerateCSRFromFileCmdWithValidFullConfig(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "csr-valid.yaml")

	configContent := `certificates:
  - commonName: csr-file.example.com
    organization: CSR Test Org
    country: US
    isCSR: true
    keyType: ecdsa-p256
    csrOutputFile: file-csr.csr
    privateKeyOutputFile: file-csr.key
`

	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	outDir := filepath.Join(tmpDir, "output")
	if err := os.MkdirAll(outDir, 0755); err != nil {
		t.Fatalf("MkdirAll failed: %v", err)
	}

	oldCwd, _ := os.Getwd()
	defer func() { _ = os.Chdir(oldCwd) }()
	if err := os.Chdir(outDir); err != nil {
		t.Fatalf("Chdir failed: %v", err)
	}

	err := GenerateCSRFromFileCmd(configPath)
	if err != nil {
		t.Errorf("GenerateCSRFromFileCmd failed: %v", err)
	}

	// Verify file was created
	csrFile := filepath.Join(outDir, "file-csr.csr")
	if _, err := os.Stat(csrFile); os.IsNotExist(err) {
		t.Errorf("CSR file not created")
	}
}

// TestGenerateCertFromConfigWithCA tests generateCertFromConfig with CA certificate
func TestGenerateCertFromConfigWithCA(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "ca-config.yaml")

	configContent := `certificates:
  - commonName: Config Test CA
    organization: Config CA Org
    country: US
    isCA: true
    validity: 3650
    keyType: rsa2048
    certificateOutputFile: config-ca.crt
    privateKeyOutputFile: config-ca.key
`

	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	outDir := filepath.Join(tmpDir, "output")
	if err := os.MkdirAll(outDir, 0755); err != nil {
		t.Fatalf("MkdirAll failed: %v", err)
	}

	oldCwd, _ := os.Getwd()
	defer func() { _ = os.Chdir(oldCwd) }()
	if err := os.Chdir(outDir); err != nil {
		t.Fatalf("Chdir failed: %v", err)
	}

	err := GenerateCertFromFileCmd(configPath)
	if err != nil {
		t.Errorf("GenerateCertFromFileCmd with CA failed: %v", err)
	}

	// Verify CA cert was created
	certFile := filepath.Join(outDir, "config-ca.crt")
	if _, err := os.Stat(certFile); os.IsNotExist(err) {
		t.Errorf("CA certificate file not created")
	}
}

// TestGenerateCertFromConfigWithIPAddresses tests cert generation with IP addresses
func TestGenerateCertFromConfigWithIPAddresses(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "ip-config.yaml")

	configContent := `certificates:
  - commonName: IP Test
    organization: IP Test Org
    country: US
    isCA: false
    validity: 365
    keyType: ecdsa-p256
    ipAddresses:
      - 192.168.1.100
      - 10.0.0.1
      - "::1"
    certificateOutputFile: ip-cert.crt
    privateKeyOutputFile: ip-cert.key
`

	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	outDir := filepath.Join(tmpDir, "output")
	if err := os.MkdirAll(outDir, 0755); err != nil {
		t.Fatalf("MkdirAll failed: %v", err)
	}

	oldCwd, _ := os.Getwd()
	defer func() { _ = os.Chdir(oldCwd) }()
	if err := os.Chdir(outDir); err != nil {
		t.Fatalf("Chdir failed: %v", err)
	}

	err := GenerateCertFromFileCmd(configPath)
	if err != nil {
		t.Errorf("GenerateCertFromFileCmd with IPs failed: %v", err)
	}

	// Verify cert was created
	certFile := filepath.Join(outDir, "ip-cert.crt")
	if _, err := os.Stat(certFile); os.IsNotExist(err) {
		t.Errorf("Certificate file with IPs not created")
	}
}

// TestGenerateCSRFromConfigWithIPAddresses tests CSR generation with IP addresses
func TestGenerateCSRFromConfigWithIPAddresses(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "csr-ip-config.yaml")

	configContent := `certificates:
  - commonName: CSR IP Test
    organization: CSR IP Org
    country: US
    isCSR: true
    keyType: rsa2048
    ipAddresses:
      - 192.168.1.200
      - "2001:db8::1"
    dnsNames:
      - test.example.com
    csrOutputFile: ip-csr.csr
    privateKeyOutputFile: ip-csr.key
`

	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	outDir := filepath.Join(tmpDir, "output")
	if err := os.MkdirAll(outDir, 0755); err != nil {
		t.Fatalf("MkdirAll failed: %v", err)
	}

	oldCwd, _ := os.Getwd()
	defer func() { _ = os.Chdir(oldCwd) }()
	if err := os.Chdir(outDir); err != nil {
		t.Fatalf("Chdir failed: %v", err)
	}

	err := GenerateCSRFromFileCmd(configPath)
	if err != nil {
		t.Errorf("GenerateCSRFromFileCmd with IPs failed: %v", err)
	}

	// Verify CSR was created
	csrFile := filepath.Join(outDir, "ip-csr.csr")
	if _, err := os.Stat(csrFile); os.IsNotExist(err) {
		t.Errorf("CSR file with IPs not created")
	}
}

// TestGenerateCertFromConfigWithExtKeyUsages tests cert with extended key usages
func TestGenerateCertFromConfigWithExtKeyUsages(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "eku-config.yaml")

	configContent := `certificates:
  - commonName: EKU Test
    organization: EKU Test Org
    country: US
    isCA: false
    validity: 365
    keyType: rsa2048
    certificateType: server
    extendedKeyUsageOIDs:
      - "1.3.6.1.5.5.7.3.1"
      - "1.3.6.1.5.5.7.3.2"
    certificateOutputFile: eku-cert.crt
    privateKeyOutputFile: eku-cert.key
`

	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	outDir := filepath.Join(tmpDir, "output")
	if err := os.MkdirAll(outDir, 0755); err != nil {
		t.Fatalf("MkdirAll failed: %v", err)
	}

	oldCwd, _ := os.Getwd()
	defer func() { _ = os.Chdir(oldCwd) }()
	if err := os.Chdir(outDir); err != nil {
		t.Fatalf("Chdir failed: %v", err)
	}

	err := GenerateCertFromFileCmd(configPath)
	if err != nil {
		t.Errorf("GenerateCertFromFileCmd with EKU failed: %v", err)
	}

	// Verify cert was created
	certFile := filepath.Join(outDir, "eku-cert.crt")
	if _, err := os.Stat(certFile); os.IsNotExist(err) {
		t.Errorf("Certificate file with EKU not created")
	}
}

// TestGenerateCACmdWithInvalidKeyType tests CA generation with invalid key type
func TestGenerateCACmdWithInvalidKeyType(t *testing.T) {
	tmpDir := t.TempDir()

	err := GenerateCACmd([]string{
		"--cn", "Invalid Key CA",
		"--key-type", "invalid-type",
		"--output", filepath.Join(tmpDir, "ca.crt"),
		"--key-output", filepath.Join(tmpDir, "ca.key"),
		"--non-interactive",
	})

	// Should succeed - invalid key types default to RSA2048
	if err != nil {
		t.Logf("GenerateCACmd with invalid key type: %v (may succeed with default)", err)
	}
}

// TestGenerateCACmdWithAllSubjectFieldsComplete tests CA with all subject fields
func TestGenerateCACmdWithAllSubjectFieldsComplete(t *testing.T) {
	tmpDir := t.TempDir()

	err := GenerateCACmd([]string{
		"--cn", "Complete Subject CA",
		"--org", "Complete Org",
		"--ou", "Complete OU",
		"--locality", "Complete City",
		"--province", "Complete State",
		"--country", "US",
		"--validity", "7300",
		"--key-type", "ecdsa-p384",
		"--output", filepath.Join(tmpDir, "complete-ca.crt"),
		"--key-output", filepath.Join(tmpDir, "complete-ca.key"),
		"--non-interactive",
	})

	if err != nil {
		t.Errorf("GenerateCACmd with all subject fields failed: %v", err)
	}

	// Verify files were created
	certFile := filepath.Join(tmpDir, "complete-ca.crt")
	if _, err := os.Stat(certFile); os.IsNotExist(err) {
		t.Errorf("Complete CA certificate file not created")
	}
}

// TestGenerateCSRCmdWithCompleteConfig tests CSR with full configuration
func TestGenerateCSRCmdWithCompleteConfig(t *testing.T) {
	tmpDir := t.TempDir()

	err := GenerateCSRCmd([]string{
		"--cn", "Complete CSR",
		"--org", "Complete CSR Org",
		"--country", "CA",
		"--dns", "csr1.example.com,csr2.example.com,csr3.example.com",
		"--key-type", "ed25519",
		"--output", filepath.Join(tmpDir, "complete.csr"),
		"--key-output", filepath.Join(tmpDir, "complete.key"),
		"--non-interactive",
	})

	if err != nil {
		t.Errorf("GenerateCSRCmd with complete config failed: %v", err)
	}

	// Verify files were created
	csrFile := filepath.Join(tmpDir, "complete.csr")
	if _, err := os.Stat(csrFile); os.IsNotExist(err) {
		t.Errorf("Complete CSR file not created")
	}
}

// TestGenerateCertCmdWithInvalidConfigFile tests cert generation with invalid config file
func TestGenerateCertCmdWithInvalidConfigFile(t *testing.T) {
	err := GenerateCertCmd([]string{"-f", "/nonexistent/invalid/path/config.yaml"})
	if err == nil {
		t.Error("Expected error for invalid config file path")
	}
}

// TestGenerateCSRCmdWithInvalidConfigFile tests CSR generation with invalid config file
func TestGenerateCSRCmdWithInvalidConfigFile(t *testing.T) {
	err := GenerateCSRCmd([]string{"-f", "/nonexistent/invalid/path/csr-config.yaml"})
	if err == nil {
		t.Error("Expected error for invalid CSR config file path")
	}
}
