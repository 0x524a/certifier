package cli

import (
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"strings"

	"github.com/0x524a/certifier/pkg/cert"
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

	if err := cmd.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing flags: %v\n", err)
		os.Exit(1)
	}

	if *cn == "" {
		fmt.Fprintf(os.Stderr, "Error: Common Name (--cn) is required\n")
		os.Exit(1)
	}

	config := &cert.CertificateConfig{
		CommonName:    *cn,
		Country:       *country,
		Organization:  *org,
		OrganizationalUnit: *orgUnit,
		Locality:      *locality,
		Province:      *province,
		KeyType:       cert.KeyType(*keyType),
		Validity:      *validityDays,
		IsCA:          true,
		MaxPathLength: -1,
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

	if err := ioutil.WriteFile(*certOutput, certPEM, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing certificate file: %v\n", err)
		os.Exit(1)
	}

	if err := ioutil.WriteFile(*keyOutput, keyPEM, 0600); err != nil {
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
	dnsNames := cmd.String("dns", "", "DNS names (comma-separated)")
	ipAddrs := cmd.String("ip", "", "IP addresses (comma-separated)")
	caCertFile := cmd.String("ca-cert", "", "CA certificate file (for signing)")
	caKeyFile := cmd.String("ca-key", "", "CA private key file (for signing)")
	certOutput := cmd.String("output", "cert.crt", "Output certificate file")
	keyOutput := cmd.String("key-output", "cert.key", "Output private key file")

	if err := cmd.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing flags: %v\n", err)
		os.Exit(1)
	}

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

	config := &cert.CertificateConfig{
		CommonName:    *cn,
		Country:       *country,
		Organization:  *org,
		OrganizationalUnit: *orgUnit,
		Locality:      *locality,
		Province:      *province,
		KeyType:       cert.KeyType(*keyType),
		Validity:      *validityDays,
		DNSNames:      dnsNamesList,
		IPAddresses:   ipAddrsList,
	}

	var certificate *x509.Certificate
	var privateKey interface{}
	var err error

	if *caCertFile != "" && *caKeyFile != "" {
		caCertPEM, err := ioutil.ReadFile(*caCertFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading CA certificate: %v\n", err)
			os.Exit(1)
		}

		caKeyPEM, err := ioutil.ReadFile(*caKeyFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading CA key: %v\n", err)
			os.Exit(1)
		}

		caCert, err := encoding.DecodeCertificateFromPEM(caCertPEM)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing CA certificate: %v\n", err)
			os.Exit(1)
		}

		caPrivateKey, err := encoding.DecodePrivateKeyFromPEM(caKeyPEM)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing CA key: %v\n", err)
			os.Exit(1)
		}

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

	if err := ioutil.WriteFile(*certOutput, certPEM, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing certificate file: %v\n", err)
		os.Exit(1)
	}

	if err := ioutil.WriteFile(*keyOutput, keyPEM, 0600); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing key file: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Certificate generated successfully!\n")
	fmt.Printf("Certificate: %s\n", *certOutput)
	fmt.Printf("Private Key: %s\n", *keyOutput)
	fmt.Printf("Serial Number: %s\n", certificate.SerialNumber)
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

	if err := cmd.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing flags: %v\n", err)
		os.Exit(1)
	}

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

	if err := ioutil.WriteFile(*csrOutput, csrPEM, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing CSR file: %v\n", err)
		os.Exit(1)
	}

	if err := ioutil.WriteFile(*keyOutput, keyPEM, 0600); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing key file: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("CSR generated successfully!\n")
	fmt.Printf("CSR: %s\n", *csrOutput)
	fmt.Printf("Private Key: %s\n", *keyOutput)
}

// ViewCertificateDetails displays certificate information
func ViewCertificateDetails(certFile string) {
	certPEM, err := ioutil.ReadFile(certFile)
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
