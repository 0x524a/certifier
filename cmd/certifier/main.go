package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/0x524a/certifier/internal/cli"
)

// isFlag checks if a string is a command-line flag
func isFlag(s string) bool {
	return strings.HasPrefix(s, "-")
}

func main() {
	if len(os.Args) < 2 {
		// No arguments - start interactive menu mode
		menu := cli.NewMenuMode()
		menu.DisplayMainMenu()
		return
	}

	subcommand := os.Args[1]

	switch subcommand {
	case "ca":
		handleCACommand()
	case "cert":
		handleCertCommand()
	case "csr":
		handleCSRCommand()
	case "validate":
		handleValidateCommand()
	case "view":
		handleViewCommand()
	case "encode":
		handleEncodeCommand()
	case "decode":
		handleDecodeCommand()
	case "crl":
		handleCRLCommand()
	case "ocsp":
		handleOCSPCommand()
	case "help", "-h", "--help":
		printUsage()
		os.Exit(0)
	case "version", "-v", "--version":
		fmt.Println("certifier version 1.0.0")
		os.Exit(0)
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", subcommand)
		printUsage()
		os.Exit(1)
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

func handleCACommand() {
	// If no subcommand provided, or if first arg is a flag, default to generate with interactive mode
	if len(os.Args) < 3 || isFlag(os.Args[2]) {
		generateCA(nil, os.Args[2:])
		return
	}

	caCmd := flag.NewFlagSet("ca", flag.ExitOnError)

	subcommand := os.Args[2]

	switch subcommand {
	case "generate":
		generateCA(caCmd, os.Args[3:])
	case "view":
		viewCA(caCmd, os.Args[3:])
	default:
		fmt.Fprintf(os.Stderr, "Unknown ca subcommand: %s\n", subcommand)
		os.Exit(1)
	}
}

func handleCertCommand() {
	// If no subcommand provided, or if first arg is a flag, default to generate with interactive mode
	if len(os.Args) < 3 || isFlag(os.Args[2]) {
		generateCert(os.Args[2:])
		return
	}

	subcommand := os.Args[2]

	switch subcommand {
	case "generate":
		generateCert(os.Args[3:])
	case "sign":
		signCert(os.Args[3:])
	case "view":
		viewCert(os.Args[3:])
	case "validate":
		validateCert(os.Args[3:])
	default:
		fmt.Fprintf(os.Stderr, "Unknown cert subcommand: %s\n", subcommand)
		os.Exit(1)
	}
}

func handleCSRCommand() {
	// If no subcommand provided, or if first arg is a flag, default to generate with interactive mode
	if len(os.Args) < 3 || isFlag(os.Args[2]) {
		generateCSR(os.Args[2:])
		return
	}

	subcommand := os.Args[2]

	switch subcommand {
	case "generate":
		generateCSR(os.Args[3:])
	case "view":
		viewCSR(os.Args[3:])
	default:
		fmt.Fprintf(os.Stderr, "Unknown csr subcommand: %s\n", subcommand)
		os.Exit(1)
	}
}

func handleValidateCommand() {
	validateCert(os.Args[2:])
}

func handleViewCommand() {
	viewCert(os.Args[2:])
}

func handleEncodeCommand() {
	encodeCert(os.Args[2:])
}

func handleDecodeCommand() {
	decodeCert(os.Args[2:])
}

func handleCRLCommand() {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "Usage: certifier crl <generate|view|check> [options]\n")
		os.Exit(1)
	}

	subcommand := os.Args[2]

	switch subcommand {
	case "generate":
		generateCRL(os.Args[3:])
	case "view":
		viewCRL(os.Args[3:])
	case "check":
		checkCRL(os.Args[3:])
	default:
		fmt.Fprintf(os.Stderr, "Unknown crl subcommand: %s\n", subcommand)
		os.Exit(1)
	}
}

func handleOCSPCommand() {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "Usage: certifier ocsp <response|request|verify> [options]\n")
		os.Exit(1)
	}

	subcommand := os.Args[2]

	switch subcommand {
	case "response":
		generateOCSPResponse(os.Args[3:])
	case "request":
		createOCSPRequest(os.Args[3:])
	case "verify":
		verifyOCSPResponse(os.Args[3:])
	default:
		fmt.Fprintf(os.Stderr, "Unknown ocsp subcommand: %s\n", subcommand)
		os.Exit(1)
	}
}

// Placeholder functions - to be implemented in separate files
func generateCA(caCmd *flag.FlagSet, args []string) {
	cli.GenerateCA(args)
}

func viewCA(caCmd *flag.FlagSet, args []string) {
	cli.ViewCA(args)
}

func generateCert(args []string) {
	cli.GenerateCert(args)
}

func signCert(args []string) {
	fmt.Println("Sign certificate command - not yet implemented")
}

func viewCert(args []string) {
	cli.ViewCert(args)
}

func validateCert(args []string) {
	fmt.Println("Validate certificate command - not yet implemented")
}

func generateCSR(args []string) {
	cli.GenerateCSR(args)
}

func viewCSR(args []string) {
	fmt.Println("View CSR command - not yet implemented")
}

func encodeCert(args []string) {
	fmt.Println("Encode command - not yet implemented")
}

func decodeCert(args []string) {
	fmt.Println("Decode command - not yet implemented")
}

func generateCRL(args []string) {
	fmt.Println("Generate CRL command - not yet implemented")
}

func viewCRL(args []string) {
	fmt.Println("View CRL command - not yet implemented")
}

func checkCRL(args []string) {
	fmt.Println("Check CRL command - not yet implemented")
}

func generateOCSPResponse(args []string) {
	fmt.Println("Generate OCSP response command - not yet implemented")
}

func createOCSPRequest(args []string) {
	fmt.Println("Create OCSP request command - not yet implemented")
}

func verifyOCSPResponse(args []string) {
	fmt.Println("Verify OCSP response command - not yet implemented")
}
