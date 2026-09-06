package cli

import (
	"flag"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/0x524a/certifier/pkg/crl"
	"github.com/0x524a/certifier/pkg/encoding"
)

// GenerateCRLCmd generates a Certificate Revocation List and returns an error instead of exiting
func GenerateCRLCmd(args []string) error {
	cmd := flag.NewFlagSet("crl generate", flag.ContinueOnError)
	caCertFile := cmd.String("ca-cert", "", "CA certificate file (required)")
	caKeyFile := cmd.String("ca-key", "", "CA private key file (required)")
	output := cmd.String("output", "crl.der", "Output CRL file")
	validityDays := cmd.Int("validity", 30, "Validity in days")
	number := cmd.Int64("number", 1, "CRL sequence number")
	revoked := cmd.String("revoked", "", "Comma-separated list of revoked serial numbers (decimal)")
	reason := cmd.Int("reason", crl.ReasonUnspecified, "Revocation reason code applied to all entries in --revoked")
	distributionURL := cmd.String("distribution-url", "", "URL for CRL distribution")

	if err := cmd.Parse(args); err != nil {
		return fmt.Errorf("error parsing flags: %w", err)
	}

	if *caCertFile == "" {
		return fmt.Errorf("CA certificate file (--ca-cert) is required")
	}

	if *caKeyFile == "" {
		return fmt.Errorf("CA private key file (--ca-key) is required")
	}

	caCertPEM, err := os.ReadFile(*caCertFile)
	if err != nil {
		return fmt.Errorf("error reading CA certificate: %w", err)
	}

	caCert, err := encoding.DecodeCertificateFromPEM(caCertPEM)
	if err != nil {
		return fmt.Errorf("error parsing CA certificate: %w", err)
	}

	caKeyPEM, err := os.ReadFile(*caKeyFile)
	if err != nil {
		return fmt.Errorf("error reading CA key: %w", err)
	}

	caPrivateKey, err := encoding.DecodePrivateKeyFromPEM(caKeyPEM)
	if err != nil {
		return fmt.Errorf("error parsing CA key: %w", err)
	}

	var revokedList []*crl.RevokedCertificate
	if *revoked != "" {
		now := time.Now()
		for _, serialStr := range strings.Split(*revoked, ",") {
			serialStr = strings.TrimSpace(serialStr)
			serial, ok := new(big.Int).SetString(serialStr, 10)
			if !ok {
				return fmt.Errorf("invalid serial number: %s", serialStr)
			}

			revokedList = append(revokedList, &crl.RevokedCertificate{
				SerialNumber:     serial,
				RevocationTime:   now,
				RevocationReason: *reason,
			})
		}
	}

	config := &crl.CRLConfig{
		CAKeyPair:       crl.NewKeyPair(caPrivateKey),
		CACertificate:   caCert,
		RevokedCerts:    revokedList,
		ValidityDays:    *validityDays,
		Number:          *number,
		DistributionURL: *distributionURL,
	}

	crlBytes, err := crl.GenerateCRL(config)
	if err != nil {
		return fmt.Errorf("error generating CRL: %w", err)
	}

	if err := os.WriteFile(*output, crlBytes, 0644); err != nil {
		return fmt.Errorf("error writing CRL file: %w", err)
	}

	fmt.Printf("CRL generated successfully!\n")
	fmt.Printf("CRL Number: %d\n", *number)
	fmt.Printf("Output: %s\n", *output)

	return nil
}

// GenerateCRL generates a Certificate Revocation List (wrapper that calls GenerateCRLCmd and handles exit)
func GenerateCRL(args []string) {
	if err := GenerateCRLCmd(args); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// ViewCRLCmd displays CRL details and returns an error instead of exiting
func ViewCRLCmd(args []string) error {
	cmd := flag.NewFlagSet("crl view", flag.ContinueOnError)
	crlFile := cmd.String("crl", "", "CRL file (required, DER-encoded)")

	if err := cmd.Parse(args); err != nil {
		return fmt.Errorf("error parsing flags: %w", err)
	}

	if *crlFile == "" {
		return fmt.Errorf("CRL file (--crl) is required")
	}

	crlData, err := os.ReadFile(*crlFile)
	if err != nil {
		return fmt.Errorf("error reading CRL file: %w", err)
	}

	revocationList, err := crl.ParseCRL(crlData)
	if err != nil {
		return fmt.Errorf("error parsing CRL: %w", err)
	}

	fmt.Println("CRL Details:")
	fmt.Println("============")
	fmt.Printf("Issuer: %s\n", revocationList.Issuer)
	fmt.Printf("Number: %s\n", revocationList.Number)
	fmt.Printf("This Update: %s\n", revocationList.ThisUpdate)
	fmt.Printf("Next Update: %s\n", revocationList.NextUpdate)

	if len(revocationList.RevokedCertificateEntries) == 0 {
		fmt.Println("No revoked certificates.")
		return nil
	}

	fmt.Printf("Revoked Certificates: %d\n", len(revocationList.RevokedCertificateEntries))
	for _, entry := range revocationList.RevokedCertificateEntries {
		fmt.Println("---")
		fmt.Printf("Serial Number: %s\n", entry.SerialNumber)
		fmt.Printf("Revocation Time: %s\n", entry.RevocationTime)
		fmt.Printf("Reason Code: %d\n", entry.ReasonCode)
	}

	return nil
}

// ViewCRL displays CRL details (wrapper that calls ViewCRLCmd and handles exit)
func ViewCRL(args []string) {
	if err := ViewCRLCmd(args); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// CheckCRLCmd checks whether a certificate is revoked according to a CRL and returns an error instead of exiting
func CheckCRLCmd(args []string) error {
	cmd := flag.NewFlagSet("crl check", flag.ContinueOnError)
	crlFile := cmd.String("crl", "", "CRL file (required, DER-encoded)")
	certFile := cmd.String("cert", "", "Certificate file to check (required, PEM)")

	if err := cmd.Parse(args); err != nil {
		return fmt.Errorf("error parsing flags: %w", err)
	}

	if *crlFile == "" {
		return fmt.Errorf("CRL file (--crl) is required")
	}

	if *certFile == "" {
		return fmt.Errorf("certificate file (--cert) is required")
	}

	crlData, err := os.ReadFile(*crlFile)
	if err != nil {
		return fmt.Errorf("error reading CRL file: %w", err)
	}

	revocationList, err := crl.ParseCRL(crlData)
	if err != nil {
		return fmt.Errorf("error parsing CRL: %w", err)
	}

	certPEM, err := os.ReadFile(*certFile)
	if err != nil {
		return fmt.Errorf("error reading certificate file: %w", err)
	}

	certificate, err := encoding.DecodeCertificateFromPEM(certPEM)
	if err != nil {
		return fmt.Errorf("error parsing certificate: %w", err)
	}

	fmt.Printf("Serial Number: %s\n", certificate.SerialNumber)

	if crl.CheckRevocation(certificate, revocationList) {
		fmt.Println("Certificate is REVOKED")
	} else {
		fmt.Println("Certificate is NOT revoked")
	}

	return nil
}

// CheckCRL checks whether a certificate is revoked according to a CRL (wrapper that calls CheckCRLCmd and handles exit)
func CheckCRL(args []string) {
	if err := CheckCRLCmd(args); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
