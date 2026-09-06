package cli

import (
	"crypto/x509"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/0x524a/certifier/pkg/cert"
	"github.com/0x524a/certifier/pkg/encoding"
	"github.com/0x524a/certifier/pkg/validation"
)

// SignCertCmd signs a CSR with a CA to produce a certificate and returns an error instead of exiting
func SignCertCmd(args []string) error {
	cmd := flag.NewFlagSet("sign", flag.ContinueOnError)
	csrFile := cmd.String("csr", "", "CSR PEM file (required)")
	caCertFile := cmd.String("ca-cert", "", "CA certificate file (required)")
	caKeyFile := cmd.String("ca-key", "", "CA private key file (required)")
	output := cmd.String("output", "signed.crt", "Output certificate file")
	validityDays := cmd.Int("validity", 365, "Validity in days")

	if err := cmd.Parse(args); err != nil {
		return fmt.Errorf("error parsing flags: %w", err)
	}

	if *csrFile == "" {
		return fmt.Errorf("CSR file (--csr) is required")
	}
	if *caCertFile == "" {
		return fmt.Errorf("CA certificate file (--ca-cert) is required")
	}
	if *caKeyFile == "" {
		return fmt.Errorf("CA private key file (--ca-key) is required")
	}

	csrPEM, err := os.ReadFile(*csrFile)
	if err != nil {
		return fmt.Errorf("error reading CSR file: %w", err)
	}

	csr, err := encoding.DecodeCSRFromPEM(csrPEM)
	if err != nil {
		return fmt.Errorf("error decoding CSR: %w", err)
	}

	caCertPEM, err := os.ReadFile(*caCertFile)
	if err != nil {
		return fmt.Errorf("error reading CA certificate file: %w", err)
	}

	caCert, err := encoding.DecodeCertificateFromPEM(caCertPEM)
	if err != nil {
		return fmt.Errorf("error decoding CA certificate: %w", err)
	}

	caKeyPEM, err := os.ReadFile(*caKeyFile)
	if err != nil {
		return fmt.Errorf("error reading CA private key file: %w", err)
	}

	caKey, err := encoding.DecodePrivateKeyFromPEM(caKeyPEM)
	if err != nil {
		return fmt.Errorf("error decoding CA private key: %w", err)
	}

	signedCert, err := cert.SignCSR(csr, caKey, caCert, *validityDays)
	if err != nil {
		return fmt.Errorf("error signing CSR: %w", err)
	}

	signedPEM, err := encoding.EncodeCertificateToPEM(signedCert)
	if err != nil {
		return fmt.Errorf("error encoding signed certificate: %w", err)
	}

	if err := os.WriteFile(*output, signedPEM, 0644); err != nil {
		return fmt.Errorf("error writing certificate file: %w", err)
	}

	fmt.Printf("Certificate signed successfully!\n")
	fmt.Printf("Serial Number: %s\n", signedCert.SerialNumber)
	fmt.Printf("Subject: %s\n", signedCert.Subject)
	fmt.Printf("Output: %s\n", *output)

	return nil
}

// SignCert signs a CSR with a CA (wrapper that calls SignCertCmd and handles exit)
func SignCert(args []string) {
	if err := SignCertCmd(args); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// ValidateCertCmd validates a certificate and returns an error instead of exiting
func ValidateCertCmd(args []string) error {
	cmd := flag.NewFlagSet("validate", flag.ContinueOnError)
	certFile := cmd.String("cert", "", "Certificate file (required)")
	roots := cmd.String("roots", "", "Root CA certificate files (comma-separated)")
	intermediates := cmd.String("intermediates", "", "Intermediate CA certificate files (comma-separated)")
	dnsName := cmd.String("dns", "", "Hostname to verify")
	checkExpiration := cmd.Bool("check-expiration", true, "Check certificate expiration")
	allowExpired := cmd.Bool("allow-expired", false, "Allow expired certificates")

	if err := cmd.Parse(args); err != nil {
		return fmt.Errorf("error parsing flags: %w", err)
	}

	if *certFile == "" {
		return fmt.Errorf("certificate file (--cert) is required")
	}

	certPEM, err := os.ReadFile(*certFile)
	if err != nil {
		return fmt.Errorf("error reading certificate file: %w", err)
	}

	certificate, err := encoding.DecodeCertificateFromPEM(certPEM)
	if err != nil {
		return fmt.Errorf("error decoding certificate: %w", err)
	}

	rootCerts, err := loadCertificateFiles(*roots)
	if err != nil {
		return fmt.Errorf("error loading root CA certificates: %w", err)
	}

	intermediateCerts, err := loadCertificateFiles(*intermediates)
	if err != nil {
		return fmt.Errorf("error loading intermediate CA certificates: %w", err)
	}

	config := &cert.ValidationConfig{
		RootCAs:         rootCerts,
		IntermediateCAs: intermediateCerts,
		CheckExpiration: *checkExpiration,
		DNSName:         *dnsName,
		AllowExpired:    *allowExpired,
	}

	result := validation.ValidateCertificate(certificate, config)

	fmt.Println("Validation Result:")
	fmt.Println("===================")
	fmt.Printf("Valid: %v\n", result.Valid)
	if len(result.Errors) > 0 {
		fmt.Printf("Errors: %s\n", strings.Join(result.Errors, "; "))
	}
	if len(result.Warnings) > 0 {
		fmt.Printf("Warnings: %s\n", strings.Join(result.Warnings, "; "))
	}
	fmt.Printf("Valid From: %s\n", result.ValidFrom)
	fmt.Printf("Valid Until: %s\n", result.ValidUntil)
	fmt.Printf("Expires In: %s\n", result.ExpiresIn)
	fmt.Printf("Signature Algorithm: %s\n", result.SignatureAlgorithm)
	fmt.Printf("Public Key Algorithm: %s\n", result.PublicKeyAlgorithm)
	fmt.Printf("Key Size: %d\n", result.KeySize)

	if !result.Valid {
		return fmt.Errorf("certificate validation failed: %s", strings.Join(result.Errors, "; "))
	}

	return nil
}

// ValidateCert validates a certificate (wrapper that calls ValidateCertCmd and handles exit)
func ValidateCert(args []string) {
	if err := ValidateCertCmd(args); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// ViewCSRCmd displays CSR details and returns an error instead of exiting
func ViewCSRCmd(args []string) error {
	cmd := flag.NewFlagSet("csr view", flag.ContinueOnError)
	csrFile := cmd.String("csr", "", "CSR file (required)")

	if err := cmd.Parse(args); err != nil {
		return fmt.Errorf("error parsing flags: %w", err)
	}

	if *csrFile == "" {
		return fmt.Errorf("CSR file (--csr) is required")
	}

	csrPEM, err := os.ReadFile(*csrFile)
	if err != nil {
		return fmt.Errorf("error reading CSR file: %w", err)
	}

	csr, err := encoding.DecodeCSRFromPEM(csrPEM)
	if err != nil {
		return fmt.Errorf("error decoding CSR: %w", err)
	}

	fmt.Println("CSR Details:")
	fmt.Println("============")
	fmt.Printf("Subject: %s\n", csr.Subject)

	if len(csr.DNSNames) > 0 {
		fmt.Printf("DNS Names: %v\n", csr.DNSNames)
	}

	if len(csr.EmailAddresses) > 0 {
		fmt.Printf("Email Addresses: %v\n", csr.EmailAddresses)
	}

	if len(csr.IPAddresses) > 0 {
		fmt.Printf("IP Addresses: %v\n", csr.IPAddresses)
	}

	fmt.Printf("Signature Algorithm: %s\n", csr.SignatureAlgorithm)
	fmt.Printf("Public Key Algorithm: %s\n", csr.PublicKeyAlgorithm)

	return nil
}

// ViewCSR displays CSR details (wrapper that calls ViewCSRCmd and handles exit)
func ViewCSR(args []string) {
	if err := ViewCSRCmd(args); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// EncodeCertCmd converts a PEM certificate to DER or PKCS12 and returns an error instead of exiting
func EncodeCertCmd(args []string) error {
	cmd := flag.NewFlagSet("encode", flag.ContinueOnError)
	input := cmd.String("input", "", "Input PEM certificate file (required)")
	output := cmd.String("output", "", "Output file (required)")
	format := cmd.String("format", "der", "Output format (der or pkcs12)")
	keyFile := cmd.String("key", "", "Private key PEM file (required for pkcs12)")
	password := cmd.String("password", "", "Password (for pkcs12)")

	if err := cmd.Parse(args); err != nil {
		return fmt.Errorf("error parsing flags: %w", err)
	}

	if *input == "" {
		return fmt.Errorf("input file (--input) is required")
	}
	if *output == "" {
		return fmt.Errorf("output file (--output) is required")
	}

	certPEM, err := os.ReadFile(*input)
	if err != nil {
		return fmt.Errorf("error reading certificate file: %w", err)
	}

	certificate, err := encoding.DecodeCertificateFromPEM(certPEM)
	if err != nil {
		return fmt.Errorf("error decoding certificate: %w", err)
	}

	switch *format {
	case "der":
		derBytes, err := encoding.EncodeCertificateToDER(certificate)
		if err != nil {
			return fmt.Errorf("error encoding certificate to DER: %w", err)
		}

		if err := os.WriteFile(*output, derBytes, 0644); err != nil {
			return fmt.Errorf("error writing output file: %w", err)
		}
	case "pkcs12":
		if *keyFile == "" {
			return fmt.Errorf("private key file (--key) is required for pkcs12 format")
		}

		keyPEM, err := os.ReadFile(*keyFile)
		if err != nil {
			return fmt.Errorf("error reading private key file: %w", err)
		}

		privateKey, err := encoding.DecodePrivateKeyFromPEM(keyPEM)
		if err != nil {
			return fmt.Errorf("error decoding private key: %w", err)
		}

		pfxData, err := encoding.EncodeToPKCS12(certificate, privateKey, *password)
		if err != nil {
			return fmt.Errorf("error encoding to PKCS12: %w", err)
		}

		if err := os.WriteFile(*output, pfxData, 0644); err != nil {
			return fmt.Errorf("error writing output file: %w", err)
		}
	default:
		return fmt.Errorf("unknown format: %s (expected der or pkcs12)", *format)
	}

	fmt.Printf("Certificate encoded successfully!\n")
	fmt.Printf("Format: %s\n", *format)
	fmt.Printf("Output: %s\n", *output)

	return nil
}

// EncodeCert converts a PEM certificate to DER or PKCS12 (wrapper that calls EncodeCertCmd and handles exit)
func EncodeCert(args []string) {
	if err := EncodeCertCmd(args); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// DecodeCertCmd converts a DER or PKCS12 certificate back to PEM and returns an error instead of exiting
func DecodeCertCmd(args []string) error {
	cmd := flag.NewFlagSet("decode", flag.ContinueOnError)
	input := cmd.String("input", "", "Input file (required)")
	output := cmd.String("output", "", "Output certificate PEM file (required)")
	keyOutput := cmd.String("key-output", "", "Output private key PEM file (pkcs12 only)")
	format := cmd.String("format", "der", "Input format (der or pkcs12)")
	password := cmd.String("password", "", "Password (for pkcs12)")

	if err := cmd.Parse(args); err != nil {
		return fmt.Errorf("error parsing flags: %w", err)
	}

	if *input == "" {
		return fmt.Errorf("input file (--input) is required")
	}
	if *output == "" {
		return fmt.Errorf("output certificate file (--output) is required")
	}

	data, err := os.ReadFile(*input)
	if err != nil {
		return fmt.Errorf("error reading input file: %w", err)
	}

	switch *format {
	case "der":
		certificate, err := encoding.DecodeCertificateFromDER(data)
		if err != nil {
			return fmt.Errorf("error decoding certificate from DER: %w", err)
		}

		certPEM, err := encoding.EncodeCertificateToPEM(certificate)
		if err != nil {
			return fmt.Errorf("error encoding certificate to PEM: %w", err)
		}

		if err := os.WriteFile(*output, certPEM, 0644); err != nil {
			return fmt.Errorf("error writing certificate file: %w", err)
		}
	case "pkcs12":
		certificate, privateKey, err := encoding.DecodeFromPKCS12(data, *password)
		if err != nil {
			return fmt.Errorf("error decoding PKCS12: %w", err)
		}

		certPEM, err := encoding.EncodeCertificateToPEM(certificate)
		if err != nil {
			return fmt.Errorf("error encoding certificate to PEM: %w", err)
		}

		if err := os.WriteFile(*output, certPEM, 0644); err != nil {
			return fmt.Errorf("error writing certificate file: %w", err)
		}

		if *keyOutput != "" {
			keyPEM, err := encoding.EncodePrivateKeyToPEM(privateKey)
			if err != nil {
				return fmt.Errorf("error encoding private key to PEM: %w", err)
			}

			if err := os.WriteFile(*keyOutput, keyPEM, 0600); err != nil {
				return fmt.Errorf("error writing private key file: %w", err)
			}
		}
	default:
		return fmt.Errorf("unknown format: %s (expected der or pkcs12)", *format)
	}

	fmt.Printf("Certificate decoded successfully!\n")
	fmt.Printf("Format: %s\n", *format)
	fmt.Printf("Output: %s\n", *output)

	return nil
}

// DecodeCert converts a DER or PKCS12 certificate back to PEM (wrapper that calls DecodeCertCmd and handles exit)
func DecodeCert(args []string) {
	if err := DecodeCertCmd(args); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// loadCertificateFiles loads and decodes a comma-separated list of PEM certificate files
func loadCertificateFiles(csv string) ([]*x509.Certificate, error) {
	if csv == "" {
		return nil, nil
	}

	var certs []*x509.Certificate
	for _, file := range strings.Split(csv, ",") {
		file = strings.TrimSpace(file)
		if file == "" {
			continue
		}

		pemData, err := os.ReadFile(file)
		if err != nil {
			return nil, fmt.Errorf("error reading certificate file %s: %w", file, err)
		}

		certificate, err := encoding.DecodeCertificateFromPEM(pemData)
		if err != nil {
			return nil, fmt.Errorf("error decoding certificate %s: %w", file, err)
		}

		certs = append(certs, certificate)
	}

	return certs, nil
}
