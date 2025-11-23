package config

import (
	"fmt"
	"os"

	"github.com/0x524a/certifier/pkg/cert"
	"gopkg.in/yaml.v3"
)

// CertificateConfigFile represents a certificate configuration that can be loaded from file
type CertificateConfigFile struct {
	CommonName              string   `yaml:"commonName" json:"commonName"`
	Country                 string   `yaml:"country" json:"country"`
	Organization            string   `yaml:"organization" json:"organization"`
	OrganizationalUnit      string   `yaml:"organizationalUnit" json:"organizationalUnit"`
	Locality                string   `yaml:"locality" json:"locality"`
	Province                string   `yaml:"province" json:"province"`
	StreetAddress           string   `yaml:"streetAddress" json:"streetAddress"`
	PostalCode              string   `yaml:"postalCode" json:"postalCode"`
	KeyType                 string   `yaml:"keyType" json:"keyType"`
	CertificateType         string   `yaml:"certificateType" json:"certificateType"`
	Validity                int      `yaml:"validity" json:"validity"`
	DNSNames                []string `yaml:"dnsNames" json:"dnsNames"`
	IPAddresses             []string `yaml:"ipAddresses" json:"ipAddresses"`
	EmailAddresses          []string `yaml:"emailAddresses" json:"emailAddresses"`
	ExtendedKeyUsageOIDs    []string `yaml:"extendedKeyUsageOIDs" json:"extendedKeyUsageOIDs"`
	CertificateOutputFile   string   `yaml:"certificateOutputFile" json:"certificateOutputFile"`
	PrivateKeyOutputFile    string   `yaml:"privateKeyOutputFile" json:"privateKeyOutputFile"`
	IsCA                    bool     `yaml:"isCA" json:"isCA"`
	MaxPathLength           int      `yaml:"maxPathLength" json:"maxPathLength"`
	CRLDistributionPoints   []string `yaml:"crlDistributionPoints" json:"crlDistributionPoints"`
	OCSPServer              []string `yaml:"ocspServer" json:"ocspServer"`
	IssuingCertificateURL   []string `yaml:"issuingCertificateURL" json:"issuingCertificateURL"`
	AuthorityInfoAccessOCSP []string `yaml:"authorityInfoAccessOCSP" json:"authorityInfoAccessOCSP"`
	// CSR generation flag
	IsCSR         bool   `yaml:"isCSR" json:"isCSR"`
	CSROutputFile string `yaml:"csrOutputFile" json:"csrOutputFile"`
}

// ConfigurationFile represents the top-level configuration file structure
type ConfigurationFile struct {
	Certificates []CertificateConfigFile `yaml:"certificates" json:"certificates"`
}

// LoadConfigFromFile loads certificate configurations from a YAML file
func LoadConfigFromFile(filePath string) ([]CertificateConfigFile, error) {
	if filePath == "" {
		return nil, fmt.Errorf("config file path is required")
	}

	// Read file
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	// Parse YAML
	var configs ConfigurationFile
	if err := yaml.Unmarshal(content, &configs); err != nil {
		return nil, fmt.Errorf("failed to parse YAML config: %w", err)
	}

	// Validate configurations
	if len(configs.Certificates) == 0 {
		return nil, fmt.Errorf("no certificates found in config file")
	}

	for i, certCfg := range configs.Certificates {
		if certCfg.CommonName == "" {
			return nil, fmt.Errorf("certificate %d: commonName is required", i+1)
		}
		// Output files are required for cert generation only
		if !certCfg.IsCSR {
			if certCfg.CertificateOutputFile == "" {
				return nil, fmt.Errorf("certificate %d: certificateOutputFile is required for cert generation", i+1)
			}
			if certCfg.PrivateKeyOutputFile == "" {
				return nil, fmt.Errorf("certificate %d: privateKeyOutputFile is required for cert generation", i+1)
			}
		} else {
			// CSR requires CSR output
			if certCfg.CSROutputFile == "" {
				return nil, fmt.Errorf("certificate %d: csrOutputFile is required for CSR generation", i+1)
			}
			if certCfg.PrivateKeyOutputFile == "" {
				return nil, fmt.Errorf("certificate %d: privateKeyOutputFile is required for CSR generation", i+1)
			}
		}
	}

	return configs.Certificates, nil
}

// ToCertificateConfig converts a CertificateConfigFile to a CertificateConfig
func (ccf *CertificateConfigFile) ToCertificateConfig() (*cert.CertificateConfig, error) {
	// Set defaults
	if ccf.KeyType == "" {
		ccf.KeyType = "rsa2048"
	}
	if ccf.CertificateType == "" {
		ccf.CertificateType = "server"
	}
	if ccf.Validity == 0 {
		ccf.Validity = 365
	}
	if ccf.MaxPathLength == 0 && !ccf.IsCA {
		ccf.MaxPathLength = -1
	}

	config := &cert.CertificateConfig{
		CommonName:              ccf.CommonName,
		Country:                 ccf.Country,
		Organization:            ccf.Organization,
		OrganizationalUnit:      ccf.OrganizationalUnit,
		Locality:                ccf.Locality,
		Province:                ccf.Province,
		StreetAddress:           ccf.StreetAddress,
		PostalCode:              ccf.PostalCode,
		KeyType:                 cert.KeyType(ccf.KeyType),
		CertType:                cert.CertificateType(ccf.CertificateType),
		Validity:                ccf.Validity,
		DNSNames:                ccf.DNSNames,
		EmailAddresses:          ccf.EmailAddresses,
		ExtendedKeyUsageOIDs:    ccf.ExtendedKeyUsageOIDs,
		IsCA:                    ccf.IsCA,
		MaxPathLength:           ccf.MaxPathLength,
		CRLDistributionPoints:   ccf.CRLDistributionPoints,
		OCSPServer:              ccf.OCSPServer,
		IssuingCertificateURL:   ccf.IssuingCertificateURL,
		AuthorityInfoAccessOCSP: ccf.AuthorityInfoAccessOCSP,
	}

	return config, nil
}
