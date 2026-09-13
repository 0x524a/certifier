package cli

import (
	"context"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/0x524a/certifier/pkg/crl"
	"github.com/0x524a/certifier/pkg/encoding"
	cliv3 "github.com/urfave/cli/v3"
)

func crlGenerateCommand() *cliv3.Command {
	var caCertFile, caKeyFile, output, revoked, distributionURL string
	var validityDays, reason int
	var number int64

	return &cliv3.Command{
		Name:  "generate",
		Usage: "Generate a Certificate Revocation List",
		Flags: []cliv3.Flag{
			&cliv3.StringFlag{Name: "ca-cert", Usage: "CA certificate file (required)", Destination: &caCertFile},
			&cliv3.StringFlag{Name: "ca-key", Usage: "CA private key file (required)", Destination: &caKeyFile},
			&cliv3.StringFlag{Name: "output", Value: "crl.der", Usage: "Output CRL file", Destination: &output},
			&cliv3.IntFlag{Name: "validity", Value: 30, Usage: "Validity in days", Destination: &validityDays},
			&cliv3.Int64Flag{Name: "number", Value: 1, Usage: "CRL sequence number", Destination: &number},
			&cliv3.StringFlag{Name: "revoked", Usage: "Comma-separated list of revoked serial numbers (decimal)", Destination: &revoked},
			&cliv3.IntFlag{Name: "reason", Value: crl.ReasonUnspecified, Usage: "Revocation reason code applied to all entries in --revoked", Destination: &reason},
			&cliv3.StringFlag{Name: "distribution-url", Usage: "URL for CRL distribution", Destination: &distributionURL},
		},
		Action: func(ctx context.Context, cmd *cliv3.Command) error {
			if caCertFile == "" {
				return fmt.Errorf("CA certificate file (--ca-cert) is required")
			}

			if caKeyFile == "" {
				return fmt.Errorf("CA private key file (--ca-key) is required")
			}

			caCertPEM, err := os.ReadFile(caCertFile)
			if err != nil {
				return fmt.Errorf("error reading CA certificate: %w", err)
			}

			caCert, err := encoding.DecodeCertificateFromPEM(caCertPEM)
			if err != nil {
				return fmt.Errorf("error parsing CA certificate: %w", err)
			}

			caKeyPEM, err := os.ReadFile(caKeyFile)
			if err != nil {
				return fmt.Errorf("error reading CA key: %w", err)
			}

			caPrivateKey, err := encoding.DecodePrivateKeyFromPEM(caKeyPEM)
			if err != nil {
				return fmt.Errorf("error parsing CA key: %w", err)
			}

			var revokedList []*crl.RevokedCertificate
			if revoked != "" {
				now := time.Now()
				for _, serialStr := range strings.Split(revoked, ",") {
					serialStr = strings.TrimSpace(serialStr)
					serial, ok := new(big.Int).SetString(serialStr, 10)
					if !ok {
						return fmt.Errorf("invalid serial number: %s", serialStr)
					}

					revokedList = append(revokedList, &crl.RevokedCertificate{
						SerialNumber:     serial,
						RevocationTime:   now,
						RevocationReason: reason,
					})
				}
			}

			config := &crl.CRLConfig{
				CAKeyPair:       crl.NewKeyPair(caPrivateKey),
				CACertificate:   caCert,
				RevokedCerts:    revokedList,
				ValidityDays:    validityDays,
				Number:          number,
				DistributionURL: distributionURL,
			}

			crlBytes, err := crl.GenerateCRL(config)
			if err != nil {
				return fmt.Errorf("error generating CRL: %w", err)
			}

			if err := os.WriteFile(output, crlBytes, 0644); err != nil {
				return fmt.Errorf("error writing CRL file: %w", err)
			}

			fmt.Printf("CRL generated successfully!\n")
			fmt.Printf("CRL Number: %d\n", number)
			fmt.Printf("Output: %s\n", output)

			return nil
		},
	}
}

// GenerateCRLCmd generates a Certificate Revocation List and returns an error instead of exiting
func GenerateCRLCmd(args []string) error {
	return runLeafCommand(crlGenerateCommand(), args)
}

// GenerateCRL generates a Certificate Revocation List (wrapper that calls GenerateCRLCmd and handles exit)
func GenerateCRL(args []string) {
	if err := GenerateCRLCmd(args); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func crlViewCommand() *cliv3.Command {
	var crlFile string
	return &cliv3.Command{
		Name:  "view",
		Usage: "View CRL details",
		Flags: []cliv3.Flag{
			&cliv3.StringFlag{Name: "crl", Usage: "CRL file (required, DER-encoded)", Destination: &crlFile},
		},
		Action: func(ctx context.Context, cmd *cliv3.Command) error {
			if crlFile == "" {
				return fmt.Errorf("CRL file (--crl) is required")
			}

			crlData, err := os.ReadFile(crlFile)
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
		},
	}
}

// ViewCRLCmd displays CRL details and returns an error instead of exiting
func ViewCRLCmd(args []string) error {
	return runLeafCommand(crlViewCommand(), args)
}

// ViewCRL displays CRL details (wrapper that calls ViewCRLCmd and handles exit)
func ViewCRL(args []string) {
	if err := ViewCRLCmd(args); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func crlCheckCommand() *cliv3.Command {
	var crlFile, certFile string
	return &cliv3.Command{
		Name:  "check",
		Usage: "Check certificate revocation status against a CRL",
		Flags: []cliv3.Flag{
			&cliv3.StringFlag{Name: "crl", Usage: "CRL file (required, DER-encoded)", Destination: &crlFile},
			&cliv3.StringFlag{Name: "cert", Usage: "Certificate file to check (required, PEM)", Destination: &certFile},
		},
		Action: func(ctx context.Context, cmd *cliv3.Command) error {
			if crlFile == "" {
				return fmt.Errorf("CRL file (--crl) is required")
			}

			if certFile == "" {
				return fmt.Errorf("certificate file (--cert) is required")
			}

			crlData, err := os.ReadFile(crlFile)
			if err != nil {
				return fmt.Errorf("error reading CRL file: %w", err)
			}

			revocationList, err := crl.ParseCRL(crlData)
			if err != nil {
				return fmt.Errorf("error parsing CRL: %w", err)
			}

			certPEM, err := os.ReadFile(certFile)
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
		},
	}
}

// CheckCRLCmd checks whether a certificate is revoked according to a CRL and returns an error instead of exiting
func CheckCRLCmd(args []string) error {
	return runLeafCommand(crlCheckCommand(), args)
}

// CheckCRL checks whether a certificate is revoked according to a CRL (wrapper that calls CheckCRLCmd and handles exit)
func CheckCRL(args []string) {
	if err := CheckCRLCmd(args); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func crlCommand() *cliv3.Command {
	return &cliv3.Command{
		Name: "crl",
		Commands: []*cliv3.Command{
			wrapParseErrors(crlGenerateCommand()),
			wrapParseErrors(crlViewCommand()),
			wrapParseErrors(crlCheckCommand()),
		},
		SkipFlagParsing: true,
		Action: func(ctx context.Context, cmd *cliv3.Command) error {
			args := cmd.Args().Slice()
			if len(args) == 0 {
				fmt.Fprintf(os.Stderr, "Usage: certifier crl <generate|view|check> [options]\n")
				return ErrSilent
			}

			switch args[0] {
			case "-h", "--help":
				fmt.Println("Usage: certifier crl <generate|view|check> [options]")
				return nil
			default:
				fmt.Fprintf(os.Stderr, "Unknown crl subcommand: %s\n", args[0])
				return ErrSilent
			}
		},
	}
}
