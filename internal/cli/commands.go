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

// GenerateCA generates a CA certificate
func GenerateCA(args []string) {
	cmd := flag.NewFlagSet("ca generate", flag.ExitOnError)
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
		fmt.Fprintf(os.Stderr, "Error parsing flags: %v\n", err)
		os.Exit(1)
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
			fmt.Fprintf(os.Stderr, "Error: Common Name is required\n")
			os.Exit(1)
		}

		// Get key type
		keyTypeStr := im.PromptKeyType()

		// Get validity (default to 10 years for CA)
		validity := im.PromptValidity()

		// Get output files
		certOut := im.PromptFileOutput("ca.crt")
		keyOut := im.PromptFileOutput("ca.key")

		// Create config
		config := &cert.CertificateConfig{
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
			"Common Name":      config.CommonName,
			"Organization":     config.Organization,
			"Key Type":         string(config.KeyType),
			"Validity":         fmt.Sprintf("%d days", config.Validity),
			"Certificate Type": "CA",
		}
		SummaryTable(summary)

		if !im.ConfirmGeneration() {
			fmt.Println("CA generation cancelled.")
			os.Exit(0)
		}

		certificate, privateKey, err := cert.GenerateSelfSignedCertificate(config)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error generating CA certificate: %v\n", err)
			os.Exit(1)
		}

		certPEM, err := encoding.EncodeCertificateToPEM(certificate)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error encoding certificate: %v\n", err)
			os.Exit(1)
		}

		keyPEM, err := encoding.EncodePrivateKeyToPEM(privateKey)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error encoding private key: %v\n", err)
			os.Exit(1)
		}

		if err := os.WriteFile(certOut, certPEM, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing certificate file: %v\n", err)
			os.Exit(1)
		}

		if err := os.WriteFile(keyOut, keyPEM, 0600); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing key file: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("CA Certificate generated successfully!\n")
		fmt.Printf("Certificate: %s\n", certOut)
		fmt.Printf("Private Key: %s\n", keyOut)
		fmt.Printf("Serial Number: %s\n", certificate.SerialNumber)
		fmt.Printf("Valid From: %s\n", certificate.NotBefore)
		fmt.Printf("Valid Until: %s\n", certificate.NotAfter)
		return
	}

	if *cn == "" {
		fmt.Fprintf(os.Stderr, "Error: Common Name (--cn) is required for non-interactive mode\n")
		os.Exit(1)
	}

	config := &cert.CertificateConfig{
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

	certificate, privateKey, err := cert.GenerateSelfSignedCertificate(config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating CA certificate: %v\n", err)
		os.Exit(1)
	}

	certPEM, err := encoding.EncodeCertificateToPEM(certificate)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error encoding certificate: %v\n", err)
		os.Exit(1)
	}

	keyPEM, err := encoding.EncodePrivateKeyToPEM(privateKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error encoding private key: %v\n", err)
		os.Exit(1)
	}

	if err := os.WriteFile(*certOutput, certPEM, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing certificate file: %v\n", err)
		os.Exit(1)
	}

	if err := os.WriteFile(*keyOutput, keyPEM, 0600); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing key file: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("CA Certificate generated successfully!\n")
	fmt.Printf("Certificate: %s\n", *certOutput)
	fmt.Printf("Private Key: %s\n", *keyOutput)
	fmt.Printf("Serial Number: %s\n", certificate.SerialNumber)
	fmt.Printf("Valid From: %s\n", certificate.NotBefore)
	fmt.Printf("Valid Until: %s\n", certificate.NotAfter)
}

// GenerateCert generates a certificate
func GenerateCert(args []string) {
	cmd := flag.NewFlagSet("cert generate", flag.ExitOnError)
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
		fmt.Fprintf(os.Stderr, "Error parsing flags: %v\n", err)
		os.Exit(1)
	}

	// Handle file-based configuration
	if *configFile != "" {
		GenerateCertFromFile(*configFile)
		return
	}

	var config *cert.CertificateConfig
	var certOut string
	var keyOut string
	var caCert *x509.Certificate
	var caPrivateKey interface{}

	// Use interactive mode by default if no CN provided and not explicitly non-interactive
	useInteractive := !*nonInteractive && *cn == ""

	if useInteractive {
		// Interactive mode
		im := NewInteractiveMode()
		fmt.Println("\n╔════════════════════════════════════════════════════════════╗")
		fmt.Println("║         CERTIFICATE GENERATION - INTERACTIVE MODE           ║")
		fmt.Println("╚════════════════════════════════════════════════════════════╝")

		// Get subject information
		subject := im.PromptSubjectInfo()
		if subject["commonName"] == "" {
			fmt.Fprintf(os.Stderr, "Error: Common Name is required\n")
			os.Exit(1)
		}

		// Get key type
		keyTypeStr := im.PromptKeyType()

		// Get certificate type
		certTypeStr := im.PromptCertificateType()

		// Get validity
		validity := im.PromptValidity()

		// Get DNS names (SANs)
		dnsNamesList := im.PromptDNSNames()

		// Get IP addresses (SANs)
		ipAddressList := im.PromptIPAddresses()

		// Get custom Extended Key Usage OIDs
		extOIDsList := im.PromptExtendedKeyUsageOIDs()

		// Ask about CA signing
		wantCA := im.PromptYesNo("Sign with existing CA?", false)

		if wantCA {
			caCertPath := im.PromptString("CA certificate file", "ca.crt")
			caKeyPath := im.PromptString("CA private key file", "ca.key")

			caCertPEM, err := os.ReadFile(caCertPath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error reading CA certificate: %v\n", err)
				os.Exit(1)
			}

			caKeyPEM, err := os.ReadFile(caKeyPath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error reading CA key: %v\n", err)
				os.Exit(1)
			}

			caCert, err = encoding.DecodeCertificateFromPEM(caCertPEM)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error parsing CA certificate: %v\n", err)
				os.Exit(1)
			}

			caPrivateKey, err = encoding.DecodePrivateKeyFromPEM(caKeyPEM)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error parsing CA key: %v\n", err)
				os.Exit(1)
			}
		}

		// Get output files
		certOut = im.PromptFileOutput("cert.crt")
		keyOut = im.PromptFileOutput("cert.key")

		// Create config
		config = &cert.CertificateConfig{
			CommonName:           subject["commonName"],
			Country:              subject["country"],
			Organization:         subject["organization"],
			OrganizationalUnit:   subject["organizationalUnit"],
			Locality:             subject["locality"],
			Province:             subject["province"],
			KeyType:              cert.KeyType(keyTypeStr),
			CertType:             cert.CertificateType(certTypeStr),
			Validity:             validity,
			DNSNames:             dnsNamesList,
			IPAddresses:          ipAddressList,
			ExtendedKeyUsageOIDs: extOIDsList,
		}

		// Display summary
		summary := map[string]interface{}{
			"Common Name":      config.CommonName,
			"Organization":     config.Organization,
			"Key Type":         string(config.KeyType),
			"Certificate Type": string(config.CertType),
			"Validity":         fmt.Sprintf("%d days", config.Validity),
			"DNS Names":        strings.Join(dnsNamesList, ", "),
		}
		if len(extOIDsList) > 0 {
			summary["EKU OIDs"] = strings.Join(extOIDsList, ", ")
		}
		if len(ipAddressList) > 0 {
			ipStrings := make([]string, len(ipAddressList))
			for i, ip := range ipAddressList {
				ipStrings[i] = ip.String()
			}
			summary["IP Addresses"] = strings.Join(ipStrings, ", ")
		}
		SummaryTable(summary)

		if !im.ConfirmGeneration() {
			fmt.Println("Certificate generation cancelled.")
			os.Exit(0)
		}
	} else {
		// Non-interactive mode (original behavior)
		if *cn == "" {
			fmt.Fprintf(os.Stderr, "Error: Common Name (--cn) is required\n")
			os.Exit(1)
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

		config = &cert.CertificateConfig{
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

		if *caCertFile != "" && *caKeyFile != "" {
			caCertPEM, err := os.ReadFile(*caCertFile)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error reading CA certificate: %v\n", err)
				os.Exit(1)
			}

			caKeyPEM, err := os.ReadFile(*caKeyFile)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error reading CA key: %v\n", err)
				os.Exit(1)
			}

			caCert, err = encoding.DecodeCertificateFromPEM(caCertPEM)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error parsing CA certificate: %v\n", err)
				os.Exit(1)
			}

			caPrivateKey, err = encoding.DecodePrivateKeyFromPEM(caKeyPEM)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error parsing CA key: %v\n", err)
				os.Exit(1)
			}
		}

		certOut = *certOutput
		keyOut = *keyOutput
	}

	var certificate *x509.Certificate
	var privateKey interface{}
	var err error

	if caCert != nil && caPrivateKey != nil {
		caConfig := &cert.CertificateConfig{CommonName: caCert.Subject.CommonName}
		certificate, privateKey, err = cert.GenerateCASignedCertificate(config, caConfig, caPrivateKey, caCert)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error generating certificate: %v\n", err)
			os.Exit(1)
		}
	} else {
		certificate, privateKey, err = cert.GenerateSelfSignedCertificate(config)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error generating certificate: %v\n", err)
			os.Exit(1)
		}
	}

	certPEM, err := encoding.EncodeCertificateToPEM(certificate)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error encoding certificate: %v\n", err)
		os.Exit(1)
	}

	keyPEM, err := encoding.EncodePrivateKeyToPEM(privateKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error encoding private key: %v\n", err)
		os.Exit(1)
	}

	if err := os.WriteFile(certOut, certPEM, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing certificate file: %v\n", err)
		os.Exit(1)
	}

	if err := os.WriteFile(keyOut, keyPEM, 0600); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing key file: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Certificate generated successfully!\n")
	fmt.Printf("Certificate: %s\n", certOut)
	fmt.Printf("Private Key: %s\n", keyOut)
	fmt.Printf("Serial Number: %s\n", certificate.SerialNumber)
	fmt.Printf("Valid From: %s\n", certificate.NotBefore)
	fmt.Printf("Valid Until: %s\n", certificate.NotAfter)
	if len(certificate.DNSNames) > 0 {
		fmt.Printf("DNS Names: %s\n", strings.Join(certificate.DNSNames, ", "))
	}
}

// ViewCert views certificate details
func ViewCert(args []string) {
	cmd := flag.NewFlagSet("cert view", flag.ExitOnError)
	certFile := cmd.String("cert", "", "Certificate file (required)")

	if err := cmd.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing flags: %v\n", err)
		os.Exit(1)
	}

	if *certFile == "" {
		fmt.Fprintf(os.Stderr, "Error: Certificate file (--cert) is required\n")
		os.Exit(1)
	}

	ViewCertificateDetails(*certFile)
}

// GenerateCSR generates a Certificate Signing Request
func GenerateCSR(args []string) {
	cmd := flag.NewFlagSet("csr generate", flag.ExitOnError)
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
		fmt.Fprintf(os.Stderr, "Error parsing flags: %v\n", err)
		os.Exit(1)
	}

	// Handle file-based configuration
	if *configFile != "" {
		GenerateCSRFromFile(*configFile)
		return
	}

	// Use interactive mode by default if no CN provided and not explicitly non-interactive
	useInteractive := !*nonInteractive && *cn == ""

	if useInteractive {
		// Interactive mode
		im := NewInteractiveMode()
		fmt.Println("\n╔════════════════════════════════════════════════════════════╗")
		fmt.Println("║        CSR GENERATION - INTERACTIVE MODE                   ║")
		fmt.Println("╚════════════════════════════════════════════════════════════╝")

		// Get subject information
		subject := im.PromptSubjectInfo()
		if subject["commonName"] == "" {
			fmt.Fprintf(os.Stderr, "Error: Common Name is required\n")
			os.Exit(1)
		}

		// Get key type
		keyTypeStr := im.PromptKeyType()

		// Get DNS names (SANs)
		dnsNamesList := im.PromptDNSNames()

		// Get output files
		csrOut := im.PromptFileOutput("cert.csr")
		keyOut := im.PromptFileOutput("cert.key")

		// Create config
		config := &cert.CSRConfig{
			CommonName:   subject["commonName"],
			Country:      subject["country"],
			Organization: subject["organization"],
			KeyType:      cert.KeyType(keyTypeStr),
			DNSNames:     dnsNamesList,
		}

		// Display summary
		summary := map[string]interface{}{
			"Common Name":  config.CommonName,
			"Organization": config.Organization,
			"Key Type":     string(config.KeyType),
			"DNS Names":    strings.Join(dnsNamesList, ", "),
		}
		SummaryTable(summary)

		if !im.ConfirmGeneration() {
			fmt.Println("CSR generation cancelled.")
			os.Exit(0)
		}

		csr, privateKey, err := cert.GenerateCSR(config)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error generating CSR: %v\n", err)
			os.Exit(1)
		}

		csrPEM, err := encoding.EncodeCSRToPEM(csr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error encoding CSR: %v\n", err)
			os.Exit(1)
		}

		keyPEM, err := encoding.EncodePrivateKeyToPEM(privateKey)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error encoding key: %v\n", err)
			os.Exit(1)
		}

		if err := os.WriteFile(csrOut, csrPEM, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing CSR file: %v\n", err)
			os.Exit(1)
		}

		if err := os.WriteFile(keyOut, keyPEM, 0600); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing key file: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("CSR generated successfully!\n")
		fmt.Printf("CSR: %s\n", csrOut)
		fmt.Printf("Private Key: %s\n", keyOut)
		return
	}

	if *cn == "" {
		fmt.Fprintf(os.Stderr, "Error: Common Name (--cn) is required for non-interactive mode\n")
		os.Exit(1)
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
		fmt.Fprintf(os.Stderr, "Error generating CSR: %v\n", err)
		os.Exit(1)
	}

	csrPEM, err := encoding.EncodeCSRToPEM(csr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error encoding CSR: %v\n", err)
		os.Exit(1)
	}

	keyPEM, err := encoding.EncodePrivateKeyToPEM(privateKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error encoding key: %v\n", err)
		os.Exit(1)
	}

	if err := os.WriteFile(*csrOutput, csrPEM, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing CSR file: %v\n", err)
		os.Exit(1)
	}

	if err := os.WriteFile(*keyOutput, keyPEM, 0600); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing key file: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("CSR generated successfully!\n")
	fmt.Printf("CSR: %s\n", *csrOutput)
	fmt.Printf("Private Key: %s\n", *keyOutput)
}

// ViewCertificateDetails displays certificate information
func ViewCertificateDetails(certFile string) {
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading certificate file: %v\n", err)
		os.Exit(1)
	}

	certificate, err := encoding.DecodeCertificateFromPEM(certPEM)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing certificate: %v\n", err)
		os.Exit(1)
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
}

// ViewCA views CA certificate details
func ViewCA(args []string) {
	cmd := flag.NewFlagSet("ca view", flag.ExitOnError)
	certFile := cmd.String("cert", "", "CA certificate file (required)")

	if err := cmd.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing flags: %v\n", err)
		os.Exit(1)
	}

	if *certFile == "" {
		fmt.Fprintf(os.Stderr, "Error: CA certificate file (--cert) is required\n")
		os.Exit(1)
	}

	ViewCertificateDetails(*certFile)
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
