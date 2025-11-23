package config

import (
	"os"
	"path/filepath"
	"testing"
)

// TestLoadConfigFromFile_ValidYAML tests loading a valid YAML configuration file
func TestLoadConfigFromFile_ValidYAML(t *testing.T) {
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "config.yaml")

	yamlContent := `certificates:
  - commonName: "Test Server"
    organization: "Test Org"
    country: "US"
    validity: 365
    keyType: "rsa2048"
    certificateOutputFile: "server.crt"
    privateKeyOutputFile: "server.key"
`

	err := os.WriteFile(configFile, []byte(yamlContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create test config file: %v", err)
	}

	configs, err := LoadConfigFromFile(configFile)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	if len(configs) != 1 {
		t.Errorf("Expected 1 certificate config, got %d", len(configs))
	}

	if configs[0].CommonName != "Test Server" {
		t.Errorf("Expected CN=Test Server, got %s", configs[0].CommonName)
	}

	if configs[0].Organization != "Test Org" {
		t.Errorf("Expected Org=Test Org, got %s", configs[0].Organization)
	}

	if configs[0].Validity != 365 {
		t.Errorf("Expected validity=365, got %d", configs[0].Validity)
	}
}

// TestLoadConfigFromFile_MultipleCertificates tests loading multiple certificates from YAML
func TestLoadConfigFromFile_MultipleCertificates(t *testing.T) {
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "multi-config.yaml")

	yamlContent := `certificates:
  - commonName: "Server 1"
    organization: "Test Org"
    country: "US"
    validity: 365
    keyType: "rsa2048"
    certificateOutputFile: "server1.crt"
    privateKeyOutputFile: "server1.key"
  - commonName: "Server 2"
    organization: "Test Org"
    country: "US"
    validity: 730
    keyType: "rsa4096"
    certificateOutputFile: "server2.crt"
    privateKeyOutputFile: "server2.key"
  - commonName: "CA"
    organization: "Test Org"
    country: "US"
    validity: 3650
    keyType: "rsa4096"
    isCA: true
    maxPathLength: 0
    certificateOutputFile: "ca.crt"
    privateKeyOutputFile: "ca.key"
`

	err := os.WriteFile(configFile, []byte(yamlContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create test config file: %v", err)
	}

	configs, err := LoadConfigFromFile(configFile)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	if len(configs) != 3 {
		t.Errorf("Expected 3 certificate configs, got %d", len(configs))
	}

	if !configs[2].IsCA {
		t.Error("Expected third cert to be CA")
	}

	if configs[2].MaxPathLength != 0 {
		t.Errorf("Expected maxPathLength=0 for CA, got %d", configs[2].MaxPathLength)
	}
}

// TestLoadConfigFromFile_MissingCommonName tests that missing CommonName is rejected
func TestLoadConfigFromFile_MissingCommonName(t *testing.T) {
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "invalid-config.yaml")

	yamlContent := `certificates:
  - organization: "Test Org"
    country: "US"
    certificateOutputFile: "server.crt"
    privateKeyOutputFile: "server.key"
`

	err := os.WriteFile(configFile, []byte(yamlContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create test config file: %v", err)
	}

	_, err = LoadConfigFromFile(configFile)
	if err == nil {
		t.Error("Expected error for missing commonName")
	}
}

// TestLoadConfigFromFile_MissingCertificateOutputFile tests validation of certificate output
func TestLoadConfigFromFile_MissingCertificateOutputFile(t *testing.T) {
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "no-cert-output.yaml")

	yamlContent := `certificates:
  - commonName: "Test Server"
    organization: "Test Org"
    country: "US"
    privateKeyOutputFile: "server.key"
`

	err := os.WriteFile(configFile, []byte(yamlContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create test config file: %v", err)
	}

	_, err = LoadConfigFromFile(configFile)
	if err == nil {
		t.Error("Expected error for missing certificateOutputFile")
	}
}

// TestLoadConfigFromFile_MissingPrivateKeyOutputFile tests validation of key output
func TestLoadConfigFromFile_MissingPrivateKeyOutputFile(t *testing.T) {
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "no-key-output.yaml")

	yamlContent := `certificates:
  - commonName: "Test Server"
    organization: "Test Org"
    country: "US"
    certificateOutputFile: "server.crt"
`

	err := os.WriteFile(configFile, []byte(yamlContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create test config file: %v", err)
	}

	_, err = LoadConfigFromFile(configFile)
	if err == nil {
		t.Error("Expected error for missing privateKeyOutputFile")
	}
}

// TestLoadConfigFromFile_NonexistentFile tests handling of nonexistent file
func TestLoadConfigFromFile_NonexistentFile(t *testing.T) {
	_, err := LoadConfigFromFile("/nonexistent/path/config.yaml")
	if err == nil {
		t.Error("Expected error for nonexistent file")
	}
}

// TestLoadConfigFromFile_EmptyPath tests handling of empty path
func TestLoadConfigFromFile_EmptyPath(t *testing.T) {
	_, err := LoadConfigFromFile("")
	if err == nil {
		t.Error("Expected error for empty path")
	}
}

// TestLoadConfigFromFile_NoCertificates tests handling of config with no certificates
func TestLoadConfigFromFile_NoCertificates(t *testing.T) {
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "empty-config.yaml")

	yamlContent := `certificates: []
`

	err := os.WriteFile(configFile, []byte(yamlContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create test config file: %v", err)
	}

	_, err = LoadConfigFromFile(configFile)
	if err == nil {
		t.Error("Expected error for empty certificates list")
	}
}

// TestToCertificateConfig_Defaults tests that defaults are properly set
func TestToCertificateConfig_Defaults(t *testing.T) {
	ccf := &CertificateConfigFile{
		CommonName: "example.com",
	}

	config, err := ccf.ToCertificateConfig()
	if err != nil {
		t.Fatalf("Failed to convert config: %v", err)
	}

	if config.KeyType != "rsa2048" {
		t.Errorf("Expected default KeyType=rsa2048, got %s", config.KeyType)
	}

	if config.CertType != "server" {
		t.Errorf("Expected default CertType=server, got %s", config.CertType)
	}

	if config.Validity != 365 {
		t.Errorf("Expected default Validity=365, got %d", config.Validity)
	}

	if config.MaxPathLength != -1 {
		t.Errorf("Expected default MaxPathLength=-1 for non-CA, got %d", config.MaxPathLength)
	}
}

// TestToCertificateConfig_PreservesValues tests that provided values are preserved
func TestToCertificateConfig_PreservesValues(t *testing.T) {
	ccf := &CertificateConfigFile{
		CommonName:         "test.com",
		Organization:       "Test Corp",
		OrganizationalUnit: "Security",
		Country:            "US",
		Locality:           "San Francisco",
		Province:           "CA",
		StreetAddress:      "123 Main St",
		PostalCode:         "94105",
		KeyType:            "rsa4096",
		CertificateType:    "client",
		Validity:           730,
		IsCA:               false,
		MaxPathLength:      5,
	}

	config, err := ccf.ToCertificateConfig()
	if err != nil {
		t.Fatalf("Failed to convert config: %v", err)
	}

	if config.CommonName != "test.com" {
		t.Errorf("Expected CommonName=test.com, got %s", config.CommonName)
	}

	if config.Organization != "Test Corp" {
		t.Errorf("Expected Organization=Test Corp, got %s", config.Organization)
	}

	if config.KeyType != "rsa4096" {
		t.Errorf("Expected KeyType=rsa4096, got %s", config.KeyType)
	}

	if config.CertType != "client" {
		t.Errorf("Expected CertType=client, got %s", config.CertType)
	}

	if config.Validity != 730 {
		t.Errorf("Expected Validity=730, got %d", config.Validity)
	}
}

// TestLoadConfigFromFile_WithDNSNames tests loading config with DNS names
func TestLoadConfigFromFile_WithDNSNames(t *testing.T) {
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "dns-config.yaml")

	yamlContent := `certificates:
  - commonName: "example.com"
    organization: "Test Org"
    country: "US"
    dnsNames:
      - "example.com"
      - "www.example.com"
      - "api.example.com"
    certificateOutputFile: "server.crt"
    privateKeyOutputFile: "server.key"
`

	err := os.WriteFile(configFile, []byte(yamlContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create test config file: %v", err)
	}

	configs, err := LoadConfigFromFile(configFile)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	if len(configs[0].DNSNames) != 3 {
		t.Errorf("Expected 3 DNS names, got %d", len(configs[0].DNSNames))
	}
}

// TestLoadConfigFromFile_WithIPAddresses tests loading config with IP addresses
func TestLoadConfigFromFile_WithIPAddresses(t *testing.T) {
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "ip-config.yaml")

	yamlContent := `certificates:
  - commonName: "example.com"
    organization: "Test Org"
    country: "US"
    ipAddresses:
      - "192.168.1.1"
      - "127.0.0.1"
    certificateOutputFile: "server.crt"
    privateKeyOutputFile: "server.key"
`

	err := os.WriteFile(configFile, []byte(yamlContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create test config file: %v", err)
	}

	configs, err := LoadConfigFromFile(configFile)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	if len(configs[0].IPAddresses) != 2 {
		t.Errorf("Expected 2 IP addresses, got %d", len(configs[0].IPAddresses))
	}
}

// TestLoadConfigFromFile_WithEmailAddresses tests loading config with email addresses
func TestLoadConfigFromFile_WithEmailAddresses(t *testing.T) {
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "email-config.yaml")

	yamlContent := `certificates:
  - commonName: "user@example.com"
    organization: "Test Org"
    country: "US"
    emailAddresses:
      - "user@example.com"
      - "admin@example.com"
    certificateOutputFile: "client.crt"
    privateKeyOutputFile: "client.key"
`

	err := os.WriteFile(configFile, []byte(yamlContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create test config file: %v", err)
	}

	configs, err := LoadConfigFromFile(configFile)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	if len(configs[0].EmailAddresses) != 2 {
		t.Errorf("Expected 2 email addresses, got %d", len(configs[0].EmailAddresses))
	}
}

// TestLoadConfigFromFile_WithExtendedKeyUsageOIDs tests loading config with EKU OIDs
func TestLoadConfigFromFile_WithExtendedKeyUsageOIDs(t *testing.T) {
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "eku-config.yaml")

	yamlContent := `certificates:
  - commonName: "signer"
    organization: "Test Org"
    country: "US"
    extendedKeyUsageOIDs:
      - "1.3.6.1.4.1.2312.16.1.2"
      - "1.3.6.1.5.5.7.3.1"
    certificateOutputFile: "signer.crt"
    privateKeyOutputFile: "signer.key"
`

	err := os.WriteFile(configFile, []byte(yamlContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create test config file: %v", err)
	}

	configs, err := LoadConfigFromFile(configFile)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	if len(configs[0].ExtendedKeyUsageOIDs) != 2 {
		t.Errorf("Expected 2 EKU OIDs, got %d", len(configs[0].ExtendedKeyUsageOIDs))
	}
}

// TestLoadConfigFromFile_CSRConfiguration tests loading CSR configuration
func TestLoadConfigFromFile_CSRConfiguration(t *testing.T) {
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "csr-config.yaml")

	yamlContent := `certificates:
  - commonName: "example.com"
    organization: "Test Org"
    country: "US"
    dnsNames:
      - "example.com"
    isCSR: true
    csrOutputFile: "example.csr"
    privateKeyOutputFile: "example.key"
`

	err := os.WriteFile(configFile, []byte(yamlContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create test config file: %v", err)
	}

	configs, err := LoadConfigFromFile(configFile)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	if !configs[0].IsCSR {
		t.Error("Expected IsCSR to be true")
	}

	if configs[0].CSROutputFile != "example.csr" {
		t.Errorf("Expected CSROutputFile=example.csr, got %s", configs[0].CSROutputFile)
	}
}

// TestLoadConfigFromFile_CSRMissingCSROutputFile tests CSR validation
func TestLoadConfigFromFile_CSRMissingCSROutputFile(t *testing.T) {
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "invalid-csr.yaml")

	yamlContent := `certificates:
  - commonName: "example.com"
    organization: "Test Org"
    country: "US"
    isCSR: true
    privateKeyOutputFile: "example.key"
`

	err := os.WriteFile(configFile, []byte(yamlContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create test config file: %v", err)
	}

	_, err = LoadConfigFromFile(configFile)
	if err == nil {
		t.Error("Expected error for missing csrOutputFile in CSR config")
	}
}

// TestLoadConfigFromFile_CAConfiguration tests loading CA configuration
func TestLoadConfigFromFile_CAConfiguration(t *testing.T) {
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "ca-config.yaml")

	yamlContent := `certificates:
  - commonName: "Root CA"
    organization: "Test Org"
    country: "US"
    validity: 3650
    keyType: "rsa4096"
    isCA: true
    maxPathLength: 2
    crlDistributionPoints:
      - "http://example.com/crl.pem"
    ocspServer:
      - "http://ocsp.example.com"
    certificateOutputFile: "ca.crt"
    privateKeyOutputFile: "ca.key"
`

	err := os.WriteFile(configFile, []byte(yamlContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create test config file: %v", err)
	}

	configs, err := LoadConfigFromFile(configFile)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	if !configs[0].IsCA {
		t.Error("Expected IsCA to be true")
	}

	if configs[0].MaxPathLength != 2 {
		t.Errorf("Expected MaxPathLength=2, got %d", configs[0].MaxPathLength)
	}

	if len(configs[0].CRLDistributionPoints) != 1 {
		t.Errorf("Expected 1 CRL DP, got %d", len(configs[0].CRLDistributionPoints))
	}

	if len(configs[0].OCSPServer) != 1 {
		t.Errorf("Expected 1 OCSP server, got %d", len(configs[0].OCSPServer))
	}
}

// TestToCertificateConfig_CAWithMaxPathLength tests CA configuration with path length
func TestToCertificateConfig_CAWithMaxPathLength(t *testing.T) {
	ccf := &CertificateConfigFile{
		CommonName:    "CA",
		IsCA:          true,
		MaxPathLength: 1,
	}

	config, err := ccf.ToCertificateConfig()
	if err != nil {
		t.Fatalf("Failed to convert config: %v", err)
	}

	if !config.IsCA {
		t.Error("Expected IsCA to be true")
	}

	if config.MaxPathLength != 1 {
		t.Errorf("Expected MaxPathLength=1, got %d", config.MaxPathLength)
	}
}

// TestLoadConfigFromFile_MixedCertificateAndCSR tests loading mixed cert and CSR configs
func TestLoadConfigFromFile_MixedCertificateAndCSR(t *testing.T) {
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "mixed-config.yaml")

	yamlContent := `certificates:
  - commonName: "server.example.com"
    organization: "Test Org"
    country: "US"
    certificateOutputFile: "server.crt"
    privateKeyOutputFile: "server.key"
  - commonName: "client.example.com"
    organization: "Test Org"
    country: "US"
    isCSR: true
    csrOutputFile: "client.csr"
    privateKeyOutputFile: "client.key"
`

	err := os.WriteFile(configFile, []byte(yamlContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create test config file: %v", err)
	}

	configs, err := LoadConfigFromFile(configFile)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	if len(configs) != 2 {
		t.Errorf("Expected 2 configs, got %d", len(configs))
	}

	if configs[0].IsCSR {
		t.Error("Expected first config to not be CSR")
	}

	if !configs[1].IsCSR {
		t.Error("Expected second config to be CSR")
	}
}
