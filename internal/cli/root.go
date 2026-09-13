package cli

import (
	"context"
	"fmt"
	"os"

	cliv3 "github.com/urfave/cli/v3"
)

// RootCommand builds the full certifier command tree.
func RootCommand() *cliv3.Command {
	return &cliv3.Command{
		Name: "certifier",
		Commands: []*cliv3.Command{
			caCommand(),
			certCommand(),
			csrCommand(),
			certValidateCommand(),
			certViewCommand(),
			encodeCommand(),
			decodeCommand(),
			crlCommand(),
			ocspCommand(),
		},
		HideHelpCommand: true,
		SkipFlagParsing: true,
		Action: func(ctx context.Context, cmd *cliv3.Command) error {
			args := cmd.Args().Slice()
			if len(args) == 0 {
				menu := NewMenuMode()
				menu.DisplayMainMenu()
				return nil
			}

			switch args[0] {
			case "help", "-h", "--help":
				printUsage()
				return nil
			case "version", "-v", "--version":
				fmt.Println("certifier version 1.0.0")
				return nil
			default:
				fmt.Fprintf(os.Stderr, "Unknown command: %s\n", args[0])
				printUsage()
				return ErrSilent
			}
		},
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `certifier - X.509 Certificate Management Tool

Usage:
  certifier <command> [options]

Commands:
  ca       - Certificate Authority operations
             certifier ca generate - Generate a CA certificate
             certifier ca view - View a CA certificate

  cert     - Certificate operations
             certifier cert generate - Generate a certificate
             certifier cert sign - Sign a certificate with CA
             certifier cert view - View certificate details
             certifier cert validate - Validate a certificate

  csr      - Certificate Signing Request operations
             certifier csr generate - Generate a CSR
             certifier csr view - View a CSR

  validate - Validate certificates and chains
  view     - View certificate details
  encode   - Encode certificates/keys to different formats
  decode   - Decode certificates/keys from different formats
  crl      - Certificate Revocation List operations
  ocsp     - OCSP operations

Options:
  -h, --help     Show this help message
  -v, --version  Show version

Examples:
  # Generate a CA certificate
  certifier ca generate --cn "My CA" --output ca.crt --key-output ca.key

  # Generate a server certificate
  certifier cert generate --cn "example.com" --output server.crt --key-output server.key

  # Validate a certificate
  certifier cert validate --cert server.crt --ca-cert ca.crt

  # View certificate details
  certifier cert view --cert server.crt

For more help on a specific command, use:
  certifier <command> -h
`)
}
