package cli

import (
	"context"
	"crypto/x509"
	"fmt"
	"os"

	"github.com/0x524a/certifier/pkg/encoding"
	"github.com/0x524a/certifier/pkg/ocsp"
	cliv3 "github.com/urfave/cli/v3"
)

// loadCertAndIssuer reads and decodes the PEM certificate at certFile and the
// PEM issuer certificate at caCertFile, in that order.
func loadCertAndIssuer(certFile, caCertFile string) (certificate, issuer *x509.Certificate, err error) {
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return nil, nil, fmt.Errorf("error reading certificate file: %w", err)
	}
	certificate, err = encoding.DecodeCertificateFromPEM(certPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("error parsing certificate: %w", err)
	}

	caCertPEM, err := os.ReadFile(caCertFile)
	if err != nil {
		return nil, nil, fmt.Errorf("error reading CA certificate: %w", err)
	}
	issuer, err = encoding.DecodeCertificateFromPEM(caCertPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("error parsing CA certificate: %w", err)
	}

	return certificate, issuer, nil
}

func ocspResponseCommand() *cliv3.Command {
	var certFile, caCertFile, responderCertFile, responderKeyFile, statusStr, output string
	var revocationReason int

	return &cliv3.Command{
		Name:  "response",
		Usage: "Generate an OCSP response",
		Flags: []cliv3.Flag{
			&cliv3.StringFlag{Name: "cert", Usage: "Certificate file to create response for (required)", Destination: &certFile},
			&cliv3.StringFlag{Name: "ca-cert", Usage: "CA certificate file (issuer) (required)", Destination: &caCertFile},
			&cliv3.StringFlag{Name: "responder-cert", Usage: "OCSP responder certificate file (defaults to --ca-cert)", Destination: &responderCertFile},
			&cliv3.StringFlag{Name: "responder-key", Usage: "OCSP responder private key file (required)", Destination: &responderKeyFile},
			&cliv3.StringFlag{Name: "status", Value: "good", Usage: "Certificate status: good, revoked, or unknown", Destination: &statusStr},
			&cliv3.IntFlag{Name: "revocation-reason", Usage: "Revocation reason code (used when --status=revoked)", Destination: &revocationReason},
			&cliv3.StringFlag{Name: "output", Value: "response.der", Usage: "Output OCSP response file", Destination: &output},
		},
		Action: func(ctx context.Context, cmd *cliv3.Command) error {
			if certFile == "" {
				return fmt.Errorf("certificate file (--cert) is required")
			}
			if caCertFile == "" {
				return fmt.Errorf("CA certificate file (--ca-cert) is required")
			}
			if responderKeyFile == "" {
				return fmt.Errorf("responder private key file (--responder-key) is required")
			}

			certificate, caCert, err := loadCertAndIssuer(certFile, caCertFile)
			if err != nil {
				return err
			}

			responderCertificate := caCert
			if responderCertFile != "" {
				responderCertPEM, err := os.ReadFile(responderCertFile)
				if err != nil {
					return fmt.Errorf("error reading responder certificate: %w", err)
				}
				responderCertificate, err = encoding.DecodeCertificateFromPEM(responderCertPEM)
				if err != nil {
					return fmt.Errorf("error parsing responder certificate: %w", err)
				}
			}

			responderKeyPEM, err := os.ReadFile(responderKeyFile)
			if err != nil {
				return fmt.Errorf("error reading responder private key: %w", err)
			}
			responderKey, err := encoding.DecodePrivateKeyFromPEM(responderKeyPEM)
			if err != nil {
				return fmt.Errorf("error parsing responder private key: %w", err)
			}

			status, err := parseOCSPStatus(statusStr)
			if err != nil {
				return err
			}

			config := &ocsp.OCSPConfig{
				ResponderCertificate: responderCertificate,
				ResponderPrivateKey:  responderKey,
				CACertificate:        caCert,
				Certificate:          certificate,
				Status:               status,
				RevocationReason:     revocationReason,
			}

			respBytes, err := ocsp.GenerateOCSPResponse(config)
			if err != nil {
				return fmt.Errorf("error generating OCSP response: %w", err)
			}

			if err := os.WriteFile(output, respBytes, 0644); err != nil {
				return fmt.Errorf("error writing OCSP response file: %w", err)
			}

			fmt.Printf("OCSP response generated successfully!\n")
			fmt.Printf("Status: %s\n", statusStr)
			fmt.Printf("Output: %s\n", output)

			return nil
		},
	}
}

// GenerateOCSPResponseCmd generates an OCSP response and returns an error instead of exiting
func GenerateOCSPResponseCmd(args []string) error {
	return runLeafCommand(ocspResponseCommand(), args)
}

// GenerateOCSPResponse generates an OCSP response (wrapper that calls GenerateOCSPResponseCmd and handles exit)
func GenerateOCSPResponse(args []string) {
	if err := GenerateOCSPResponseCmd(args); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func ocspRequestCommand() *cliv3.Command {
	var certFile, caCertFile, output string

	return &cliv3.Command{
		Name:  "request",
		Usage: "Create an OCSP request",
		Flags: []cliv3.Flag{
			&cliv3.StringFlag{Name: "cert", Usage: "Certificate file to request status for (required)", Destination: &certFile},
			&cliv3.StringFlag{Name: "ca-cert", Usage: "CA certificate file (issuer) (required)", Destination: &caCertFile},
			&cliv3.StringFlag{Name: "output", Value: "request.der", Usage: "Output OCSP request file", Destination: &output},
		},
		Action: func(ctx context.Context, cmd *cliv3.Command) error {
			if certFile == "" {
				return fmt.Errorf("certificate file (--cert) is required")
			}
			if caCertFile == "" {
				return fmt.Errorf("CA certificate file (--ca-cert) is required")
			}

			certificate, caCert, err := loadCertAndIssuer(certFile, caCertFile)
			if err != nil {
				return err
			}

			reqBytes, err := ocsp.CreateOCSPRequest(certificate, caCert)
			if err != nil {
				return fmt.Errorf("error creating OCSP request: %w", err)
			}

			if err := os.WriteFile(output, reqBytes, 0644); err != nil {
				return fmt.Errorf("error writing OCSP request file: %w", err)
			}

			fmt.Printf("OCSP request created successfully!\n")
			fmt.Printf("Output: %s\n", output)

			return nil
		},
	}
}

// CreateOCSPRequestCmd creates an OCSP request and returns an error instead of exiting
func CreateOCSPRequestCmd(args []string) error {
	return runLeafCommand(ocspRequestCommand(), args)
}

// CreateOCSPRequest creates an OCSP request (wrapper that calls CreateOCSPRequestCmd and handles exit)
func CreateOCSPRequest(args []string) {
	if err := CreateOCSPRequestCmd(args); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func ocspVerifyCommand() *cliv3.Command {
	var responseFile, certFile, caCertFile string

	return &cliv3.Command{
		Name:  "verify",
		Usage: "Verify an OCSP response",
		Flags: []cliv3.Flag{
			&cliv3.StringFlag{Name: "response", Usage: "OCSP response file (DER-encoded) (required)", Destination: &responseFile},
			&cliv3.StringFlag{Name: "cert", Usage: "Certificate to check status for (required)", Destination: &certFile},
			&cliv3.StringFlag{Name: "ca-cert", Usage: "CA certificate file (issuer) (required)", Destination: &caCertFile},
		},
		Action: func(ctx context.Context, cmd *cliv3.Command) error {
			if responseFile == "" {
				return fmt.Errorf("OCSP response file (--response) is required")
			}
			if certFile == "" {
				return fmt.Errorf("certificate file (--cert) is required")
			}
			if caCertFile == "" {
				return fmt.Errorf("CA certificate file (--ca-cert) is required")
			}

			respBytes, err := os.ReadFile(responseFile)
			if err != nil {
				return fmt.Errorf("error reading OCSP response file: %w", err)
			}

			certificate, caCert, err := loadCertAndIssuer(certFile, caCertFile)
			if err != nil {
				return err
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
		},
	}
}

// VerifyOCSPResponseCmd verifies an OCSP response and returns an error instead of exiting
func VerifyOCSPResponseCmd(args []string) error {
	return runLeafCommand(ocspVerifyCommand(), args)
}

// VerifyOCSPResponse verifies an OCSP response (wrapper that calls VerifyOCSPResponseCmd and handles exit)
func VerifyOCSPResponse(args []string) {
	if err := VerifyOCSPResponseCmd(args); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func ocspCheckCommand() *cliv3.Command {
	var certFile, caCertFile, url string

	return &cliv3.Command{
		Name:  "check",
		Usage: "Check certificate status against a live OCSP responder",
		Flags: []cliv3.Flag{
			&cliv3.StringFlag{Name: "cert", Usage: "Certificate file to check (required)", Destination: &certFile},
			&cliv3.StringFlag{Name: "ca-cert", Usage: "CA certificate file (issuer) (required)", Destination: &caCertFile},
			&cliv3.StringFlag{Name: "url", Usage: "OCSP responder URL (defaults to the certificate's AIA OCSP URL)", Destination: &url},
		},
		Action: func(ctx context.Context, cmd *cliv3.Command) error {
			if certFile == "" {
				return fmt.Errorf("certificate file (--cert) is required")
			}
			if caCertFile == "" {
				return fmt.Errorf("CA certificate file (--ca-cert) is required")
			}

			certificate, caCert, err := loadCertAndIssuer(certFile, caCertFile)
			if err != nil {
				return err
			}

			status, err := ocsp.CheckCertificateStatus(certificate, caCert, url)
			if err != nil {
				return fmt.Errorf("error checking OCSP status: %w", err)
			}

			fmt.Println("OCSP Certificate Status:")
			fmt.Println("========================")
			fmt.Printf("Status: %s\n", status.Status)
			fmt.Printf("Serial Number: %s\n", status.Serial)
			fmt.Printf("Responder URL: %s\n", status.ResponderURL)
			fmt.Printf("This Update: %s\n", status.ThisUpdate)
			fmt.Printf("Next Update: %s\n", status.NextUpdate)
			fmt.Printf("Produced At: %s\n", status.ProducedAt)

			if status.Status == "revoked" {
				fmt.Printf("Revocation Time: %s\n", status.RevocationTime)
				fmt.Printf("Revocation Reason: %s\n", status.RevocationReason)
			}

			return nil
		},
	}
}

// CheckOCSPStatusCmd checks a certificate's revocation status against a live OCSP
// responder and returns an error instead of exiting.
func CheckOCSPStatusCmd(args []string) error {
	return runLeafCommand(ocspCheckCommand(), args)
}

// CheckOCSPStatus checks a certificate's revocation status against a live OCSP
// responder (wrapper that calls CheckOCSPStatusCmd and handles exit).
func CheckOCSPStatus(args []string) {
	if err := CheckOCSPStatusCmd(args); err != nil {
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

func ocspCommand() *cliv3.Command {
	return &cliv3.Command{
		Name: "ocsp",
		Commands: []*cliv3.Command{
			ocspResponseCommand(),
			ocspRequestCommand(),
			ocspVerifyCommand(),
			ocspCheckCommand(),
		},
		SkipFlagParsing: true,
		Action: func(ctx context.Context, cmd *cliv3.Command) error {
			args := cmd.Args().Slice()
			if len(args) == 0 {
				fmt.Fprintf(os.Stderr, "Usage: certifier ocsp <response|request|verify|check> [options]\n")
				return ErrSilent
			}

			switch args[0] {
			case "-h", "--help":
				fmt.Println("Usage: certifier ocsp <response|request|verify|check> [options]")
				return nil
			default:
				fmt.Fprintf(os.Stderr, "Unknown ocsp subcommand: %s\n", args[0])
				return ErrSilent
			}
		},
	}
}
