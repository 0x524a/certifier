package cli

import (
	"flag"
	"fmt"
	"os"

	"github.com/0x524a/certifier/pkg/encoding"
	"github.com/0x524a/certifier/pkg/ocsp"
)

// GenerateOCSPResponseCmd generates an OCSP response and returns an error instead of exiting
func GenerateOCSPResponseCmd(args []string) error {
	cmd := flag.NewFlagSet("ocsp generate", flag.ContinueOnError)
	certFile := cmd.String("cert", "", "Certificate file to create response for (required)")
	caCertFile := cmd.String("ca-cert", "", "CA certificate file (issuer) (required)")
	responderCertFile := cmd.String("responder-cert", "", "OCSP responder certificate file (defaults to --ca-cert)")
	responderKeyFile := cmd.String("responder-key", "", "OCSP responder private key file (required)")
	statusStr := cmd.String("status", "good", "Certificate status: good, revoked, or unknown")
	revocationReason := cmd.Int("revocation-reason", 0, "Revocation reason code (used when --status=revoked)")
	output := cmd.String("output", "response.der", "Output OCSP response file")

	if err := cmd.Parse(args); err != nil {
		return fmt.Errorf("error parsing flags: %w", err)
	}

	if *certFile == "" {
		return fmt.Errorf("certificate file (--cert) is required")
	}
	if *caCertFile == "" {
		return fmt.Errorf("CA certificate file (--ca-cert) is required")
	}
	if *responderKeyFile == "" {
		return fmt.Errorf("responder private key file (--responder-key) is required")
	}

	certPEM, err := os.ReadFile(*certFile)
	if err != nil {
		return fmt.Errorf("error reading certificate file: %w", err)
	}
	certificate, err := encoding.DecodeCertificateFromPEM(certPEM)
	if err != nil {
		return fmt.Errorf("error parsing certificate: %w", err)
	}

	caCertPEM, err := os.ReadFile(*caCertFile)
	if err != nil {
		return fmt.Errorf("error reading CA certificate: %w", err)
	}
	caCert, err := encoding.DecodeCertificateFromPEM(caCertPEM)
	if err != nil {
		return fmt.Errorf("error parsing CA certificate: %w", err)
	}

	responderCertificate := caCert
	if *responderCertFile != "" {
		responderCertPEM, err := os.ReadFile(*responderCertFile)
		if err != nil {
			return fmt.Errorf("error reading responder certificate: %w", err)
		}
		responderCertificate, err = encoding.DecodeCertificateFromPEM(responderCertPEM)
		if err != nil {
			return fmt.Errorf("error parsing responder certificate: %w", err)
		}
	}

	responderKeyPEM, err := os.ReadFile(*responderKeyFile)
	if err != nil {
		return fmt.Errorf("error reading responder private key: %w", err)
	}
	responderKey, err := encoding.DecodePrivateKeyFromPEM(responderKeyPEM)
	if err != nil {
		return fmt.Errorf("error parsing responder private key: %w", err)
	}

	status, err := parseOCSPStatus(*statusStr)
	if err != nil {
		return err
	}

	config := &ocsp.OCSPConfig{
		ResponderCertificate: responderCertificate,
		ResponderPrivateKey:  responderKey,
		CACertificate:        caCert,
		Certificate:          certificate,
		Status:               status,
		RevocationReason:     *revocationReason,
	}

	respBytes, err := ocsp.GenerateOCSPResponse(config)
	if err != nil {
		return fmt.Errorf("error generating OCSP response: %w", err)
	}

	if err := os.WriteFile(*output, respBytes, 0644); err != nil {
		return fmt.Errorf("error writing OCSP response file: %w", err)
	}

	fmt.Printf("OCSP response generated successfully!\n")
	fmt.Printf("Status: %s\n", *statusStr)
	fmt.Printf("Output: %s\n", *output)

	return nil
}

// GenerateOCSPResponse generates an OCSP response (wrapper that calls GenerateOCSPResponseCmd and handles exit)
func GenerateOCSPResponse(args []string) {
	if err := GenerateOCSPResponseCmd(args); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// CreateOCSPRequestCmd creates an OCSP request and returns an error instead of exiting
func CreateOCSPRequestCmd(args []string) error {
	cmd := flag.NewFlagSet("ocsp request", flag.ContinueOnError)
	certFile := cmd.String("cert", "", "Certificate file to request status for (required)")
	caCertFile := cmd.String("ca-cert", "", "CA certificate file (issuer) (required)")
	output := cmd.String("output", "request.der", "Output OCSP request file")

	if err := cmd.Parse(args); err != nil {
		return fmt.Errorf("error parsing flags: %w", err)
	}

	if *certFile == "" {
		return fmt.Errorf("certificate file (--cert) is required")
	}
	if *caCertFile == "" {
		return fmt.Errorf("CA certificate file (--ca-cert) is required")
	}

	certPEM, err := os.ReadFile(*certFile)
	if err != nil {
		return fmt.Errorf("error reading certificate file: %w", err)
	}
	certificate, err := encoding.DecodeCertificateFromPEM(certPEM)
	if err != nil {
		return fmt.Errorf("error parsing certificate: %w", err)
	}

	caCertPEM, err := os.ReadFile(*caCertFile)
	if err != nil {
		return fmt.Errorf("error reading CA certificate: %w", err)
	}
	caCert, err := encoding.DecodeCertificateFromPEM(caCertPEM)
	if err != nil {
		return fmt.Errorf("error parsing CA certificate: %w", err)
	}

	reqBytes, err := ocsp.CreateOCSPRequest(certificate, caCert)
	if err != nil {
		return fmt.Errorf("error creating OCSP request: %w", err)
	}

	if err := os.WriteFile(*output, reqBytes, 0644); err != nil {
		return fmt.Errorf("error writing OCSP request file: %w", err)
	}

	fmt.Printf("OCSP request created successfully!\n")
	fmt.Printf("Output: %s\n", *output)

	return nil
}

// CreateOCSPRequest creates an OCSP request (wrapper that calls CreateOCSPRequestCmd and handles exit)
func CreateOCSPRequest(args []string) {
	if err := CreateOCSPRequestCmd(args); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// VerifyOCSPResponseCmd verifies an OCSP response and returns an error instead of exiting
func VerifyOCSPResponseCmd(args []string) error {
	cmd := flag.NewFlagSet("ocsp verify", flag.ContinueOnError)
	responseFile := cmd.String("response", "", "OCSP response file (DER-encoded) (required)")
	certFile := cmd.String("cert", "", "Certificate to check status for (required)")
	caCertFile := cmd.String("ca-cert", "", "CA certificate file (issuer) (required)")

	if err := cmd.Parse(args); err != nil {
		return fmt.Errorf("error parsing flags: %w", err)
	}

	if *responseFile == "" {
		return fmt.Errorf("OCSP response file (--response) is required")
	}
	if *certFile == "" {
		return fmt.Errorf("certificate file (--cert) is required")
	}
	if *caCertFile == "" {
		return fmt.Errorf("CA certificate file (--ca-cert) is required")
	}

	respBytes, err := os.ReadFile(*responseFile)
	if err != nil {
		return fmt.Errorf("error reading OCSP response file: %w", err)
	}

	certPEM, err := os.ReadFile(*certFile)
	if err != nil {
		return fmt.Errorf("error reading certificate file: %w", err)
	}
	certificate, err := encoding.DecodeCertificateFromPEM(certPEM)
	if err != nil {
		return fmt.Errorf("error parsing certificate: %w", err)
	}

	caCertPEM, err := os.ReadFile(*caCertFile)
	if err != nil {
		return fmt.Errorf("error reading CA certificate: %w", err)
	}
	caCert, err := encoding.DecodeCertificateFromPEM(caCertPEM)
	if err != nil {
		return fmt.Errorf("error parsing CA certificate: %w", err)
	}

	result, err := ocsp.VerifyOCSPResponse(respBytes, certificate, caCert)
	if err != nil {
		fmt.Printf("OCSP Response Verification: FAILED\n")
		return fmt.Errorf("error verifying OCSP response: %w", err)
	}

	fmt.Println("OCSP Response Verification:")
	fmt.Println("============================")
	fmt.Printf("Verified: %v\n", result["verified"])
	fmt.Printf("Status: %v\n", result["status"])
	fmt.Printf("Serial Number: %v\n", result["serialNumber"])
	fmt.Printf("This Update: %v\n", result["thisUpdate"])
	fmt.Printf("Next Update: %v\n", result["nextUpdate"])
	fmt.Printf("Produced At: %v\n", result["producedAt"])

	if revokedAt, ok := result["revokedAt"]; ok {
		fmt.Printf("Revoked At: %v\n", revokedAt)
		fmt.Printf("Revocation Reason: %v\n", result["revocationReason"])
	}

	return nil
}

// VerifyOCSPResponse verifies an OCSP response (wrapper that calls VerifyOCSPResponseCmd and handles exit)
func VerifyOCSPResponse(args []string) {
	if err := VerifyOCSPResponseCmd(args); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// parseOCSPStatus converts a status flag string to the OCSPConfig.Status int value.
func parseOCSPStatus(statusStr string) (int, error) {
	switch statusStr {
	case "good":
		return 0, nil
	case "revoked":
		return 1, nil
	case "unknown":
		return 2, nil
	default:
		return 0, fmt.Errorf("invalid status %q: must be good, revoked, or unknown", statusStr)
	}
}
