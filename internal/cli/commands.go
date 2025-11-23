package cli

import (
	"crypto/x509"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/0x524a/certifier/pkg/cert"
	"github.com/0x524a/certifier/pkg/config"
	"github.com/0x524a/certifier/pkg/encoding"
)

// GenerateCACmd generates a CA certificate and returns an error instead of exiting
func GenerateCACmd(args []string) error {
	cmd := flag.NewFlagSet("ca generate", flag.ContinueOnError)
	cn := cmd.String("cn", "", "Common Name (required)")
	country := cmd.String("country", "US", "Country")
	org := cmd.String("org", "", "Organization")
	orgUnit := cmd.String("ou", "", "Organizational Unit")
	locality := cmd.String("locality", "", "Locality")
	province := cmd.String("province", "", "Province/State")
	validityDays := cmd.Int("validity", 365*10, "Validity in days")
	keyType := cmd.String("key-type", "rsa2048", "Key type (rsa2048, rsa4096, ecdsa-p256, ecdsa-p384, ecdsa-p521, ed25519)")
	certOutput := cmd.String("output", "ca.crt", "Output certificate file")
	keyOutput := cmd.String("key-output", "ca.key", "Output private key file")
	nonInteractive := cmd.Bool("non-interactive", false, "Enable non-interactive mode (requires --cn)")

	if err := cmd.Parse(args); err != nil {
		return fmt.Errorf("error parsing flags: %w", err)
	}

	// Use interactive mode by default if no CN provided and not explicitly non-interactive
	useInteractive := !*nonInteractive && *cn == ""

	if useInteractive {
		// Interactive mode
		im := NewInteractiveMode()
		fmt.Println("\n╔════════════════════════════════════════════════════════════╗")
		fmt.Println("║            CA GENERATION - INTERACTIVE MODE                ║")
		fmt.Println("╚════════════════════════════════════════════════════════════╝")

		// Get subject information
		subject := im.PromptSubjectInfo()
		if subject["commonName"] == "" {
			return fmt.Errorf("common Name is required")
		}

		// Get key type
		keyTypeStr := im.PromptKeyType()

		// Get validity (default to 10 years for CA)
		validity := im.PromptValidity()

		// Get output files
		certOut := im.PromptFileOutput("ca.crt")
		keyOut := im.PromptFileOutput("ca.key")

		// Create config
		certConfig := &cert.CertificateConfig{
			CommonName:         subject["commonName"],
			Country:            subject["country"],
			Organization:       subject["organization"],
			OrganizationalUnit: subject["organizationalUnit"],
			Locality:           subject["locality"],
			Province:           subject["province"],
			KeyType:            cert.KeyType(keyTypeStr),
			Validity:           validity,
			IsCA:               true,
			MaxPathLength:      -1,
		}

		// Display summary
		summary := map[string]interface{}{
			"Common Name":      certConfig.CommonName,
			"Organization":     certConfig.Organization,
			"Key Type":         string(certConfig.KeyType),
			"Validity":         fmt.Sprintf("%d days", certConfig.Validity),
			"Certificate Type": "CA",
		}
		SummaryTable(summary)

		if !im.ConfirmGeneration() {
			fmt.Println("CA generation cancelled.")
			return nil
		}

		certificate, privateKey, err := cert.GenerateSelfSignedCertificate(certConfig)
		if err != nil {
			return fmt.Errorf("error generating CA certificate: %w", err)
		}

		certPEM, err := encoding.EncodeCertificateToPEM(certificate)
		if err != nil {
			return fmt.Errorf("error encoding certificate: %w", err)
		}

		keyPEM, err := encoding.EncodePrivateKeyToPEM(privateKey)
		if err != nil {
			return fmt.Errorf("error encoding private key: %w", err)
		}

		if err := os.WriteFile(certOut, certPEM, 0644); err != nil {
			return fmt.Errorf("error writing certificate file: %w", err)
		}

		if err := os.WriteFile(keyOut, keyPEM, 0600); err != nil {
			return fmt.Errorf("error writing key file: %w", err)
		}

		fmt.Printf("CA Certificate generated successfully!\n")
		fmt.Printf("Certificate: %s\n", certOut)
		fmt.Printf("Private Key: %s\n", keyOut)
		fmt.Printf("Serial Number: %s\n", certificate.SerialNumber)
		fmt.Printf("Valid From: %s\n", certificate.NotBefore)
		fmt.Printf("Valid Until: %s\n", certificate.NotAfter)
		return nil
	}

	if *cn == "" {
		return fmt.Errorf("common Name (--cn) is required for non-interactive mode")
	}

	certConfig := &cert.CertificateConfig{
		CommonName:         *cn,
		Country:            *country,
		Organization:       *org,
		OrganizationalUnit: *orgUnit,
		Locality:           *locality,
		Province:           *province,
		KeyType:            cert.KeyType(*keyType),
		Validity:           *validityDays,
		IsCA:               true,
		MaxPathLength:      -1,
	}

	certificate, privateKey, err := cert.GenerateSelfSignedCertificate(certConfig)
	if err != nil {
		return fmt.Errorf("error generating CA certificate: %w", err)
	}

	certPEM, err := encoding.EncodeCertificateToPEM(certificate)
	if err != nil {
		return fmt.Errorf("error encoding certificate: %w", err)
	}

	keyPEM, err := encoding.EncodePrivateKeyToPEM(privateKey)
	if err != nil {
		return fmt.Errorf("error encoding private key: %w", err)
	}

	if err := os.WriteFile(*certOutput, certPEM, 0644); err != nil {
		return fmt.Errorf("error writing certificate file: %w", err)
	}

	if err := os.WriteFile(*keyOutput, keyPEM, 0600); err != nil {
		return fmt.Errorf("error writing key file: %w", err)
	}

	fmt.Printf("CA Certificate generated successfully!\n")
	fmt.Printf("Certificate: %s\n", *certOutput)
	fmt.Printf("Private Key: %s\n", *keyOutput)
	fmt.Printf("Serial Number: %s\n", certificate.SerialNumber)
	fmt.Printf("Valid From: %s\n", certificate.NotBefore)
	fmt.Printf("Valid Until: %s\n", certificate.NotAfter)
	return nil
}

// GenerateCA generates a CA certificate (wrapper that calls GenerateCACmd and handles exit)
func GenerateCA(args []string) {
	if err := GenerateCACmd(args); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// GenerateCertCmd generates a certificate and returns an error instead of exiting
func GenerateCertCmd(args []string) error {
	cmd := flag.NewFlagSet("cert generate", flag.ContinueOnError)
	cn := cmd.String("cn", "", "Common Name (required)")
	country := cmd.String("country", "US", "Country")
	org := cmd.String("org", "", "Organization")
	orgUnit := cmd.String("ou", "", "Organizational Unit")
	locality := cmd.String("locality", "", "Locality")
	province := cmd.String("province", "", "Province/State")
	validityDays := cmd.Int("validity", 365, "Validity in days")
	keyType := cmd.String("key-type", "rsa2048", "Key type")
	certType := cmd.String("cert-type", "server", "Certificate type (client, server, or both)")
	dnsNames := cmd.String("dns", "", "DNS names (comma-separated)")
	ipAddrs := cmd.String("ip", "", "IP addresses (comma-separated)")
	extKeyUsageOIDs := cmd.String("ext-oid", "", "Extended key usage OIDs (comma-separated)")
	caCertFile := cmd.String("ca-cert", "", "CA certificate file (for signing)")
	caKeyFile := cmd.String("ca-key", "", "CA private key file (for signing)")
	certOutput := cmd.String("output", "cert.crt", "Output certificate file")
	keyOutput := cmd.String("key-output", "cert.key", "Output private key file")
	configFile := cmd.String("f", "", "Configuration file (YAML) for batch generation")
	nonInteractive := cmd.Bool("non-interactive", false, "Enable non-interactive mode (requires --cn)")

	if err := cmd.Parse(args); err != nil {
		return fmt.Errorf("error parsing flags: %w", err)
	}

	// Handle file-based configuration
	if *configFile != "" {
		return GenerateCertFromFileCmd(*configFile)
	}

	if *cn == "" && (*nonInteractive || *cn != "") {
		return fmt.Errorf("common Name (--cn) is required for non-interactive mode")
	}

	var dnsNamesList []string
	if *dnsNames != "" {
		dnsNamesList = strings.Split(*dnsNames, ",")
		for i, name := range dnsNamesList {
			dnsNamesList[i] = strings.TrimSpace(name)
		}
	}

	var ipAddrsList []net.IP
	if *ipAddrs != "" {
		for _, addr := range strings.Split(*ipAddrs, ",") {
			ip := net.ParseIP(strings.TrimSpace(addr))
			if ip != nil {
				ipAddrsList = append(ipAddrsList, ip)
			}
		}
	}

	var extOIDsList []string
	if *extKeyUsageOIDs != "" {
		extOIDsList = strings.Split(*extKeyUsageOIDs, ",")
		for i, oid := range extOIDsList {
			extOIDsList[i] = strings.TrimSpace(oid)
		}
	}

	var caCert *x509.Certificate
	var caPrivateKey interface{}

	if *caCertFile != "" && *caKeyFile != "" {
		caCertPEM, err := os.ReadFile(*caCertFile)
		if err != nil {
			return fmt.Errorf("error reading CA certificate: %w", err)
		}

		caKeyPEM, err := os.ReadFile(*caKeyFile)
		if err != nil {
			return fmt.Errorf("error reading CA key: %w", err)
		}

		caCert, err = encoding.DecodeCertificateFromPEM(caCertPEM)
		if err != nil {
			return fmt.Errorf("error parsing CA certificate: %w", err)
		}

		caPrivateKey, err = encoding.DecodePrivateKeyFromPEM(caKeyPEM)
		if err != nil {
			return fmt.Errorf("error parsing CA key: %w", err)
		}
	}

	config := &cert.CertificateConfig{
		CommonName:           *cn,
		Country:              *country,
		Organization:         *org,
		OrganizationalUnit:   *orgUnit,
		Locality:             *locality,
		Province:             *province,
		KeyType:              cert.KeyType(*keyType),
		CertType:             cert.CertificateType(*certType),
		Validity:             *validityDays,
		DNSNames:             dnsNamesList,
		IPAddresses:          ipAddrsList,
		ExtendedKeyUsageOIDs: extOIDsList,
	}

	var certificate *x509.Certificate
	var privateKey interface{}
	var err error

	if caCert != nil && caPrivateKey != nil {
		certificate, privateKey, err = cert.GenerateCASignedCertificate(config, config, caPrivateKey, caCert)
	} else {
		certificate, privateKey, err = cert.GenerateSelfSignedCertificate(config)
	}

	if err != nil {
		return fmt.Errorf("error generating certificate: %w", err)
	}

	certPEM, err := encoding.EncodeCertificateToPEM(certificate)
	if err != nil {
		return fmt.Errorf("error encoding certificate: %w", err)
	}

	keyPEM, err := encoding.EncodePrivateKeyToPEM(privateKey)
	if err != nil {
		return fmt.Errorf("error encoding private key: %w", err)
	}

	if err := os.WriteFile(*certOutput, certPEM, 0644); err != nil {
		return fmt.Errorf("error writing certificate file: %w", err)
	}

	if err := os.WriteFile(*keyOutput, keyPEM, 0600); err != nil {
		return fmt.Errorf("error writing key file: %w", err)
	}

	fmt.Printf("Certificate generated successfully!\n")
	fmt.Printf("Certificate: %s\n", *certOutput)
	fmt.Printf("Private Key: %s\n", *keyOutput)
	if caCert != nil {
		fmt.Printf("Signed by CA\n")
	}
	fmt.Printf("Serial Number: %s\n", certificate.SerialNumber)
	fmt.Printf("Valid From: %s\n", certificate.NotBefore)
	fmt.Printf("Valid Until: %s\n", certificate.NotAfter)
	fmt.Printf("DNS Names: %s\n", strings.Join(config.DNSNames, ", "))

	return nil
}

// GenerateCertFromFileCmd generates certificates from a config file and returns an error
func GenerateCertFromFileCmd(configPath string) error {
	// Load configuration from file
	certConfigs, err := config.LoadConfigFromFile(configPath)
	if err != nil {
		return fmt.Errorf("error loading configuration: %w", err)
	}

	successCount := 0
	failureCount := 0

	fmt.Printf("Generating from configuration file...\n\n")

	for i, certCfg := range certConfigs {
		fmt.Printf("═══════════════════════════════════════════════════════════\n")

		if certCfg.IsCSR {
			fmt.Printf("CSR %d: %s\n", i+1, certCfg.CommonName)
		} else {
			if certCfg.IsCA {
				fmt.Printf("CA Certificate %d: %s\n", i+1, certCfg.CommonName)
			} else {
				fmt.Printf("Certificate %d: %s\n", i+1, certCfg.CommonName)
			}
		}
		fmt.Printf("═══════════════════════════════════════════════════════════\n")

		if certCfg.IsCSR {
			// Generate CSR
			if err := generateCSRFromConfig(&certCfg); err != nil {
				fmt.Fprintf(os.Stderr, "Error generating CSR: %v\n", err)
				failureCount++
				continue
			}
		} else {
			// Generate certificate
			if err := generateCertFromConfig(&certCfg); err != nil {
				fmt.Fprintf(os.Stderr, "Error generating certificate: %v\n", err)
				failureCount++
				continue
			}
		}

		successCount++
	}

	fmt.Printf("\n═══════════════════════════════════════════════════════════\n")
	fmt.Printf("Summary: %d successful, %d failed\n", successCount, failureCount)

	if failureCount > 0 {
		return fmt.Errorf("failed to generate %d certificates/CSRs", failureCount)
	}

	return nil
}

// GenerateCert generates a certificate (wrapper that calls GenerateCertCmd and handles exit)
func GenerateCert(args []string) {
	if err := GenerateCertCmd(args); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// ViewCert views certificate details
// ViewCertCmd views certificate details and returns an error instead of exiting
func ViewCertCmd(args []string) error {
	cmd := flag.NewFlagSet("cert view", flag.ContinueOnError)
	certFile := cmd.String("cert", "", "Certificate file (required)")

	if err := cmd.Parse(args); err != nil {
		return fmt.Errorf("error parsing flags: %w", err)
	}

	if *certFile == "" {
		return fmt.Errorf("certificate file (--cert) is required")
	}

	return ViewCertificateDetailsCmd(*certFile)
}

// ViewCert views certificate details (wrapper that calls ViewCertCmd and handles exit)
func ViewCert(args []string) {
	if err := ViewCertCmd(args); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// GenerateCSRCmd generates a Certificate Signing Request and returns an error instead of exiting
func GenerateCSRCmd(args []string) error {
	cmd := flag.NewFlagSet("csr generate", flag.ContinueOnError)
	cn := cmd.String("cn", "", "Common Name (required)")
	country := cmd.String("country", "US", "Country")
	org := cmd.String("org", "", "Organization")
	dnsNames := cmd.String("dns", "", "DNS names (comma-separated)")
	keyType := cmd.String("key-type", "rsa2048", "Key type")
	csrOutput := cmd.String("output", "cert.csr", "Output CSR file")
	keyOutput := cmd.String("key-output", "cert.key", "Output private key file")
	configFile := cmd.String("f", "", "Configuration file (YAML) for batch CSR generation")
	nonInteractive := cmd.Bool("non-interactive", false, "Enable non-interactive mode (requires --cn)")

	if err := cmd.Parse(args); err != nil {
		return fmt.Errorf("error parsing flags: %w", err)
	}

	// Handle file-based configuration
	if *configFile != "" {
		return GenerateCSRFromFileCmd(*configFile)
	}

	if *cn == "" && (*nonInteractive || *cn != "") {
		return fmt.Errorf("common Name (--cn) is required for non-interactive mode")
	}

	var dnsNamesList []string
	if *dnsNames != "" {
		dnsNamesList = strings.Split(*dnsNames, ",")
		for i, name := range dnsNamesList {
			dnsNamesList[i] = strings.TrimSpace(name)
		}
	}

	config := &cert.CSRConfig{
		CommonName:   *cn,
		Country:      *country,
		Organization: *org,
		KeyType:      cert.KeyType(*keyType),
		DNSNames:     dnsNamesList,
	}

	csr, privateKey, err := cert.GenerateCSR(config)
	if err != nil {
		return fmt.Errorf("error generating CSR: %w", err)
	}

	csrPEM, err := encoding.EncodeCSRToPEM(csr)
	if err != nil {
		return fmt.Errorf("error encoding CSR: %w", err)
	}

	keyPEM, err := encoding.EncodePrivateKeyToPEM(privateKey)
	if err != nil {
		return fmt.Errorf("error encoding key: %w", err)
	}

	if err := os.WriteFile(*csrOutput, csrPEM, 0644); err != nil {
		return fmt.Errorf("error writing CSR file: %w", err)
	}

	if err := os.WriteFile(*keyOutput, keyPEM, 0600); err != nil {
		return fmt.Errorf("error writing key file: %w", err)
	}

	fmt.Printf("CSR generated successfully!\n")
	fmt.Printf("CSR: %s\n", *csrOutput)
	fmt.Printf("Private Key: %s\n", *keyOutput)

	return nil
}

// GenerateCSRFromFileCmd generates CSRs from a config file and returns an error
func GenerateCSRFromFileCmd(configPath string) error {
	// Load configuration from file
	certConfigs, err := config.LoadConfigFromFile(configPath)
	if err != nil {
		return fmt.Errorf("error loading configuration: %w", err)
	}

	successCount := 0
	failureCount := 0

	fmt.Printf("Generating from configuration file...\n\n")

	for i, certCfg := range certConfigs {
		if certCfg.IsCSR {
			fmt.Printf("═══════════════════════════════════════════════════════════\n")
			fmt.Printf("CSR %d: %s\n", i+1, certCfg.CommonName)
			fmt.Printf("═══════════════════════════════════════════════════════════\n")

			if err := generateCSRFromConfig(&certCfg); err != nil {
				fmt.Fprintf(os.Stderr, "Error generating CSR: %v\n", err)
				failureCount++
				continue
			}
			successCount++
		}
	}

	fmt.Printf("\n═══════════════════════════════════════════════════════════\n")
	fmt.Printf("Summary: %d successful, %d failed\n", successCount, failureCount)

	if failureCount > 0 {
		return fmt.Errorf("failed to generate %d CSRs", failureCount)
	}

	return nil
}

// GenerateCSR generates a Certificate Signing Request (wrapper that calls GenerateCSRCmd and handles exit)
func GenerateCSR(args []string) {
	if err := GenerateCSRCmd(args); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// ViewCertificateDetailsCmd displays certificate information and returns an error instead of exiting
func ViewCertificateDetailsCmd(certFile string) error {
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return fmt.Errorf("error reading certificate file: %w", err)
	}

	certificate, err := encoding.DecodeCertificateFromPEM(certPEM)
	if err != nil {
		return fmt.Errorf("error parsing certificate: %w", err)
	}

	fmt.Println("Certificate Details:")
	fmt.Println("====================")
	fmt.Printf("Serial Number: %s\n", certificate.SerialNumber)
	fmt.Printf("Subject: %s\n", certificate.Subject)
	fmt.Printf("Issuer: %s\n", certificate.Issuer)
	fmt.Printf("Valid From: %s\n", certificate.NotBefore)
	fmt.Printf("Valid Until: %s\n", certificate.NotAfter)
	fmt.Printf("Is CA: %v\n", certificate.IsCA)
	fmt.Printf("Public Key Algorithm: %s\n", certificate.PublicKeyAlgorithm)
	fmt.Printf("Signature Algorithm: %s\n", certificate.SignatureAlgorithm)

	if len(certificate.DNSNames) > 0 {
		fmt.Printf("DNS Names: %v\n", certificate.DNSNames)
	}

	if len(certificate.IPAddresses) > 0 {
		fmt.Printf("IP Addresses: %v\n", certificate.IPAddresses)
	}

	return nil
}

// ViewCertificateDetails displays certificate information (wrapper that calls ViewCertificateDetailsCmd and handles exit)
func ViewCertificateDetails(certFile string) {
	if err := ViewCertificateDetailsCmd(certFile); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// ViewCA views CA certificate details
// ViewCACmd views CA details and returns an error instead of exiting
func ViewCACmd(args []string) error {
	cmd := flag.NewFlagSet("ca view", flag.ContinueOnError)
	certFile := cmd.String("cert", "", "CA certificate file (required)")

	if err := cmd.Parse(args); err != nil {
		return fmt.Errorf("error parsing flags: %w", err)
	}

	if *certFile == "" {
		return fmt.Errorf("CA certificate file (--cert) is required")
	}

	return ViewCertificateDetailsCmd(*certFile)
}

// ViewCA views CA details (wrapper that calls ViewCACmd and handles exit)
func ViewCA(args []string) {
	if err := ViewCACmd(args); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// GenerateCertFromFile generates certificates and CSRs from a configuration file
func GenerateCertFromFile(configPath string) {
	// Load configuration from file
	certConfigs, err := config.LoadConfigFromFile(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading configuration: %v\n", err)
		os.Exit(1)
	}

	successCount := 0
	failureCount := 0

	fmt.Printf("Generating from configuration file...\n\n")

	for i, certCfg := range certConfigs {
		fmt.Printf("═══════════════════════════════════════════════════════════\n")

		if certCfg.IsCSR {
			fmt.Printf("CSR %d: %s\n", i+1, certCfg.CommonName)
		} else {
			if certCfg.IsCA {
				fmt.Printf("CA Certificate %d: %s\n", i+1, certCfg.CommonName)
			} else {
				fmt.Printf("Certificate %d: %s\n", i+1, certCfg.CommonName)
			}
		}
		fmt.Printf("═══════════════════════════════════════════════════════════\n")

		if certCfg.IsCSR {
			// Generate CSR
			if err := generateCSRFromConfig(&certCfg); err != nil {
				fmt.Fprintf(os.Stderr, "Error generating CSR: %v\n", err)
				failureCount++
				continue
			}
		} else {
			// Generate certificate
			if err := generateCertFromConfig(&certCfg); err != nil {
				fmt.Fprintf(os.Stderr, "Error generating certificate: %v\n", err)
				failureCount++
				continue
			}
		}

		successCount++
	}

	fmt.Printf("═══════════════════════════════════════════════════════════\n")
	fmt.Printf("Summary: %d succeeded, %d failed\n", successCount, failureCount)
	if failureCount > 0 {
		os.Exit(1)
	}
}

// generateCertFromConfig generates a certificate from config
func generateCertFromConfig(certCfg *config.CertificateConfigFile) error {
	// Convert file config to certificate config
	certConfig, err := certCfg.ToCertificateConfig()
	if err != nil {
		return fmt.Errorf("error converting configuration: %v", err)
	}

	// Parse IP addresses
	for _, ipStr := range certCfg.IPAddresses {
		ip := net.ParseIP(strings.TrimSpace(ipStr))
		if ip != nil {
			certConfig.IPAddresses = append(certConfig.IPAddresses, ip)
		}
	}

	// Generate certificate
	var certificate *x509.Certificate
	var privateKey interface{}

	if certCfg.IsCA {
		// Generate CA certificate
		var err error
		certificate, privateKey, err = cert.GenerateSelfSignedCertificate(certConfig)
		if err != nil {
			return fmt.Errorf("error generating CA certificate: %v", err)
		}
	} else {
		// Generate regular certificate
		var err error
		certificate, privateKey, err = cert.GenerateSelfSignedCertificate(certConfig)
		if err != nil {
			return fmt.Errorf("error generating certificate: %v", err)
		}
	}

	// Encode certificate and key
	certPEM, err := encoding.EncodeCertificateToPEM(certificate)
	if err != nil {
		return fmt.Errorf("error encoding certificate: %v", err)
	}

	keyPEM, err := encoding.EncodePrivateKeyToPEM(privateKey)
	if err != nil {
		return fmt.Errorf("error encoding private key: %v", err)
	}

	// Write files
	if err := os.WriteFile(certCfg.CertificateOutputFile, certPEM, 0644); err != nil {
		return fmt.Errorf("error writing certificate file: %v", err)
	}

	if err := os.WriteFile(certCfg.PrivateKeyOutputFile, keyPEM, 0600); err != nil {
		return fmt.Errorf("error writing private key file: %v", err)
	}

	fmt.Printf("✓ %s generated successfully!\n", map[bool]string{true: "CA Certificate", false: "Certificate"}[certCfg.IsCA])
	fmt.Printf("  Certificate: %s\n", certCfg.CertificateOutputFile)
	fmt.Printf("  Private Key: %s\n", certCfg.PrivateKeyOutputFile)
	fmt.Printf("  Serial Number: %s\n", certificate.SerialNumber)
	fmt.Printf("  Valid From: %s\n", certificate.NotBefore)
	fmt.Printf("  Valid Until: %s\n", certificate.NotAfter)
	if len(certificate.ExtKeyUsage) > 0 {
		fmt.Printf("  Extended Key Usages: %v\n", certificate.ExtKeyUsage)
	}
	fmt.Println()

	return nil
}

// generateCSRFromConfig generates a CSR from config
func generateCSRFromConfig(csrCfg *config.CertificateConfigFile) error {
	// Create CSR config
	csrConfig := &cert.CSRConfig{
		CommonName:   csrCfg.CommonName,
		Country:      csrCfg.Country,
		Organization: csrCfg.Organization,
		KeyType:      cert.KeyType(csrCfg.KeyType),
		DNSNames:     csrCfg.DNSNames,
	}

	// Parse IP addresses
	for _, ipStr := range csrCfg.IPAddresses {
		ip := net.ParseIP(strings.TrimSpace(ipStr))
		if ip != nil {
			csrConfig.IPAddresses = append(csrConfig.IPAddresses, ip)
		}
	}

	// Generate CSR
	csr, privateKey, err := cert.GenerateCSR(csrConfig)
	if err != nil {
		return fmt.Errorf("error generating CSR: %v", err)
	}

	// Encode CSR and key
	csrPEM, err := encoding.EncodeCSRToPEM(csr)
	if err != nil {
		return fmt.Errorf("error encoding CSR: %v", err)
	}

	keyPEM, err := encoding.EncodePrivateKeyToPEM(privateKey)
	if err != nil {
		return fmt.Errorf("error encoding private key: %v", err)
	}

	// Write files
	if err := os.WriteFile(csrCfg.CSROutputFile, csrPEM, 0644); err != nil {
		return fmt.Errorf("error writing CSR file: %v", err)
	}

	if err := os.WriteFile(csrCfg.PrivateKeyOutputFile, keyPEM, 0600); err != nil {
		return fmt.Errorf("error writing private key file: %v", err)
	}

	fmt.Printf("✓ CSR generated successfully!\n")
	fmt.Printf("  CSR: %s\n", csrCfg.CSROutputFile)
	fmt.Printf("  Private Key: %s\n", csrCfg.PrivateKeyOutputFile)
	fmt.Printf("  Common Name: %s\n", csr.Subject.CommonName)
	if len(csr.DNSNames) > 0 {
		fmt.Printf("  DNS Names: %v\n", csr.DNSNames)
	}
	fmt.Println()

	return nil
}

// GenerateCSRFromFile generates CSRs from a configuration file
func GenerateCSRFromFile(configPath string) {
	// Load configuration
	configs, err := config.LoadConfigFromFile(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading config file: %v\n", err)
		os.Exit(1)
	}

	// Filter to CSR configurations only
	var csrConfigs []*config.CertificateConfigFile
	for i := range configs {
		if configs[i].IsCSR {
			csrConfigs = append(csrConfigs, &configs[i])
		}
	}

	if len(csrConfigs) == 0 {
		fmt.Fprintf(os.Stderr, "No CSR configurations found in config file (isCSR must be true)\n")
		os.Exit(1)
	}

	fmt.Println("Generating from configuration file...")

	successCount := 0
	failureCount := 0

	for i, csrCfg := range csrConfigs {
		fmt.Printf("\n%s═══════════════════════════════════════════════════════════\n", "")
		fmt.Printf("CSR %d: %s\n", i+1, csrCfg.CommonName)
		fmt.Printf("%s═══════════════════════════════════════════════════════════\n", "")

		if err := generateCSRFromConfig(csrCfg); err != nil {
			fmt.Fprintf(os.Stderr, "✗ Error: %v\n\n", err)
			failureCount++
		} else {
			successCount++
		}
	}

	fmt.Printf("%s═══════════════════════════════════════════════════════════\n", "")
	fmt.Printf("Summary: %d succeeded, %d failed\n", successCount, failureCount)

	if failureCount > 0 {
		os.Exit(1)
	}
}
