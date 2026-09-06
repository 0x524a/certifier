package cli

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// MenuMode handles the main interactive menu interface
type MenuMode struct {
	reader *bufio.Reader
}

// NewMenuMode creates a new menu mode handler
func NewMenuMode() *MenuMode {
	return &MenuMode{
		reader: bufio.NewReader(os.Stdin),
	}
}

// DisplayMainMenu shows the main menu and handles command routing
func (m *MenuMode) DisplayMainMenu() {
	for {
		m.displayMainMenuScreen()
		choice := m.promptMainMenu()

		switch choice {
		case "1":
			m.handleCAMenu()
		case "2":
			m.handleCertMenu()
		case "3":
			m.handleCSRMenu()
		case "4":
			m.handleQuickOptions()
		case "5":
			m.handleCRLMenu()
		case "6":
			m.handleOCSPMenu()
		case "q", "Q":
			fmt.Println("\nExiting certifier. Goodbye!")
			os.Exit(0)
		default:
			fmt.Println("Invalid choice. Please try again.")
		}
	}
}

func (m *MenuMode) displayMainMenuScreen() {
	fmt.Println("\n╔════════════════════════════════════════════════════════════╗")
	fmt.Println("║              CERTIFIER - INTERACTIVE MODE                 ║")
	fmt.Println("╚════════════════════════════════════════════════════════════╝")
	fmt.Println()
	fmt.Println("What would you like to do?")
	fmt.Println()
	fmt.Println("  1. Certificate Authority (CA) Operations")
	fmt.Println("  2. Certificate Operations")
	fmt.Println("  3. Certificate Signing Request (CSR) Operations")
	fmt.Println("  4. Quick Options (View, Validate, Encode/Decode)")
	fmt.Println("  5. Certificate Revocation List (CRL) Operations")
	fmt.Println("  6. OCSP Operations")
	fmt.Println()
	fmt.Println("  q. Quit")
	fmt.Println()
}

func (m *MenuMode) promptMainMenu() string {
	fmt.Print("Select an option [1-6, q]: ")
	input, err := m.reader.ReadString('\n')
	choice := strings.TrimSpace(input)
	if choice == "" && err != nil {
		// stdin closed/EOF with no data - treat as quit to avoid spinning forever
		return "q"
	}
	return choice
}

func (m *MenuMode) handleCAMenu() {
	for {
		fmt.Println("\n╔════════════════════════════════════════════════════════════╗")
		fmt.Println("║           CERTIFICATE AUTHORITY (CA) OPERATIONS            ║")
		fmt.Println("╚════════════════════════════════════════════════════════════╝")
		fmt.Println()
		fmt.Println("  1. Generate a new CA certificate")
		fmt.Println("  2. View a CA certificate")
		fmt.Println("  3. Back to main menu")
		fmt.Println()

		fmt.Print("Select an option [1-3]: ")
		input, err := m.reader.ReadString('\n')
		choice := strings.TrimSpace(input)

		if choice == "" && err != nil {
			return
		}

		switch choice {
		case "1":
			GenerateCA([]string{})
			return
		case "2":
			m.promptAndViewCAFile()
			return
		case "3":
			return
		default:
			fmt.Println("Invalid choice. Please try again.")
		}
	}
}

func (m *MenuMode) handleCertMenu() {
	for {
		fmt.Println("\n╔════════════════════════════════════════════════════════════╗")
		fmt.Println("║            CERTIFICATE OPERATIONS                          ║")
		fmt.Println("╚════════════════════════════════════════════════════════════╝")
		fmt.Println()
		fmt.Println("  1. Generate a new certificate")
		fmt.Println("  2. View a certificate")
		fmt.Println("  3. Validate a certificate")
		fmt.Println("  4. Back to main menu")
		fmt.Println()

		fmt.Print("Select an option [1-4]: ")
		input, err := m.reader.ReadString('\n')
		choice := strings.TrimSpace(input)

		if choice == "" && err != nil {
			return
		}

		switch choice {
		case "1":
			GenerateCert([]string{})
			return
		case "2":
			m.promptAndViewCertFile()
			return
		case "3":
			m.promptAndValidateCertFile()
			return
		case "4":
			return
		default:
			fmt.Println("Invalid choice. Please try again.")
		}
	}
}

func (m *MenuMode) handleCSRMenu() {
	for {
		fmt.Println("\n╔════════════════════════════════════════════════════════════╗")
		fmt.Println("║     CERTIFICATE SIGNING REQUEST (CSR) OPERATIONS           ║")
		fmt.Println("╚════════════════════════════════════════════════════════════╝")
		fmt.Println()
		fmt.Println("  1. Generate a new CSR")
		fmt.Println("  2. View a CSR")
		fmt.Println("  3. Back to main menu")
		fmt.Println()

		fmt.Print("Select an option [1-3]: ")
		input, err := m.reader.ReadString('\n')
		choice := strings.TrimSpace(input)

		if choice == "" && err != nil {
			return
		}

		switch choice {
		case "1":
			GenerateCSR([]string{})
			return
		case "2":
			m.promptAndViewCSRFile()
			return
		case "3":
			return
		default:
			fmt.Println("Invalid choice. Please try again.")
		}
	}
}

func (m *MenuMode) handleQuickOptions() {
	for {
		fmt.Println("\n╔════════════════════════════════════════════════════════════╗")
		fmt.Println("║              QUICK OPTIONS                                 ║")
		fmt.Println("╚════════════════════════════════════════════════════════════╝")
		fmt.Println()
		fmt.Println("  1. View certificate details")
		fmt.Println("  2. Validate a certificate")
		fmt.Println("  3. Encode/Decode certificates")
		fmt.Println("  4. Back to main menu")
		fmt.Println()

		fmt.Print("Select an option [1-4]: ")
		input, err := m.reader.ReadString('\n')
		choice := strings.TrimSpace(input)

		if choice == "" && err != nil {
			return
		}

		switch choice {
		case "1":
			m.promptAndViewCertFile()
			return
		case "2":
			m.promptAndValidateCertFile()
			return
		case "3":
			m.handleEncodeDecodeMenu()
			return
		case "4":
			return
		default:
			fmt.Println("Invalid choice. Please try again.")
		}
	}
}

func (m *MenuMode) promptAndViewCertFile() {
	fmt.Print("Enter certificate file path: ")
	filePath, _ := m.reader.ReadString('\n')
	filePath = strings.TrimSpace(filePath)

	if filePath == "" {
		fmt.Println("No file path provided.")
		return
	}

	ViewCertificateDetails(filePath)
}

func (m *MenuMode) promptAndViewCAFile() {
	fmt.Print("Enter CA certificate file path: ")
	filePath, _ := m.reader.ReadString('\n')
	filePath = strings.TrimSpace(filePath)

	if filePath == "" {
		fmt.Println("No file path provided.")
		return
	}

	ViewCertificateDetails(filePath)
}

// promptLine prints prompt and returns the next line of input, trimmed.
func (m *MenuMode) promptLine(prompt string) string {
	fmt.Print(prompt)
	input, _ := m.reader.ReadString('\n')
	return strings.TrimSpace(input)
}

// promptChoice prints prompt and returns the next line of input, trimmed,
// along with whether stdin is closed/EOF with no data - used by menu loops
// to stop looping instead of spinning forever once input is exhausted.
func (m *MenuMode) promptChoice(prompt string) (choice string, eof bool) {
	fmt.Print(prompt)
	input, err := m.reader.ReadString('\n')
	choice = strings.TrimSpace(input)
	return choice, choice == "" && err != nil
}

// runCmd runs a *Cmd function that returns an error instead of exiting, and
// prints any error rather than terminating the interactive session.
func runCmd(cmdErr error) {
	if cmdErr != nil {
		fmt.Printf("Error: %v\n", cmdErr)
	}
}

func (m *MenuMode) promptAndValidateCertFile() {
	certFile := m.promptLine("Enter certificate file path: ")
	if certFile == "" {
		fmt.Println("No file path provided.")
		return
	}

	roots := m.promptLine("Enter root CA certificate file(s), comma-separated (optional): ")
	dnsName := m.promptLine("Enter hostname to verify (optional): ")

	args := []string{"--cert", certFile}
	if roots != "" {
		args = append(args, "--roots", roots)
	}
	if dnsName != "" {
		args = append(args, "--dns", dnsName)
	}

	runCmd(ValidateCertCmd(args))
}

func (m *MenuMode) promptAndViewCSRFile() {
	csrFile := m.promptLine("Enter CSR file path: ")
	if csrFile == "" {
		fmt.Println("No file path provided.")
		return
	}

	runCmd(ViewCSRCmd([]string{"--csr", csrFile}))
}

func (m *MenuMode) handleEncodeDecodeMenu() {
	for {
		fmt.Println("\n╔════════════════════════════════════════════════════════════╗")
		fmt.Println("║           ENCODE / DECODE CERTIFICATES                     ║")
		fmt.Println("╚════════════════════════════════════════════════════════════╝")
		fmt.Println()
		fmt.Println("  1. Encode a PEM certificate to DER or PKCS12")
		fmt.Println("  2. Decode a DER or PKCS12 certificate to PEM")
		fmt.Println("  3. Back")
		fmt.Println()

		choice, eof := m.promptChoice("Select an option [1-3]: ")
		if eof {
			return
		}

		switch choice {
		case "1":
			m.promptAndEncodeCert()
			return
		case "2":
			m.promptAndDecodeCert()
			return
		case "3":
			return
		default:
			fmt.Println("Invalid choice. Please try again.")
		}
	}
}

func (m *MenuMode) promptAndEncodeCert() {
	input := m.promptLine("Enter input PEM certificate file path: ")
	if input == "" {
		fmt.Println("No file path provided.")
		return
	}
	output := m.promptLine("Enter output file path: ")
	if output == "" {
		fmt.Println("No output path provided.")
		return
	}
	format := m.promptLine("Format [der/pkcs12] (default der): ")
	if format == "" {
		format = "der"
	}

	args := []string{"--input", input, "--output", output, "--format", format}
	if format == "pkcs12" {
		keyFile := m.promptLine("Enter private key PEM file path: ")
		password := m.promptLine("Enter PKCS12 password (optional): ")
		args = append(args, "--key", keyFile, "--password", password)
	}

	runCmd(EncodeCertCmd(args))
}

func (m *MenuMode) promptAndDecodeCert() {
	input := m.promptLine("Enter input file path: ")
	if input == "" {
		fmt.Println("No file path provided.")
		return
	}
	output := m.promptLine("Enter output PEM certificate file path: ")
	if output == "" {
		fmt.Println("No output path provided.")
		return
	}
	format := m.promptLine("Format [der/pkcs12] (default der): ")
	if format == "" {
		format = "der"
	}

	args := []string{"--input", input, "--output", output, "--format", format}
	if format == "pkcs12" {
		keyOutput := m.promptLine("Enter output private key PEM file path (optional): ")
		password := m.promptLine("Enter PKCS12 password (optional): ")
		if keyOutput != "" {
			args = append(args, "--key-output", keyOutput)
		}
		args = append(args, "--password", password)
	}

	runCmd(DecodeCertCmd(args))
}

func (m *MenuMode) handleCRLMenu() {
	for {
		fmt.Println("\n╔════════════════════════════════════════════════════════════╗")
		fmt.Println("║     CERTIFICATE REVOCATION LIST (CRL) OPERATIONS            ║")
		fmt.Println("╚════════════════════════════════════════════════════════════╝")
		fmt.Println()
		fmt.Println("  1. Generate a CRL")
		fmt.Println("  2. View a CRL")
		fmt.Println("  3. Check whether a certificate is revoked")
		fmt.Println("  4. Back to main menu")
		fmt.Println()

		choice, eof := m.promptChoice("Select an option [1-4]: ")
		if eof {
			return
		}

		switch choice {
		case "1":
			m.promptAndGenerateCRL()
			return
		case "2":
			m.promptAndViewCRL()
			return
		case "3":
			m.promptAndCheckCRL()
			return
		case "4":
			return
		default:
			fmt.Println("Invalid choice. Please try again.")
		}
	}
}

func (m *MenuMode) promptAndGenerateCRL() {
	caCert := m.promptLine("Enter CA certificate file path: ")
	caKey := m.promptLine("Enter CA private key file path: ")
	if caCert == "" || caKey == "" {
		fmt.Println("CA certificate and CA private key are required.")
		return
	}
	output := m.promptLine("Output CRL file path (default crl.der): ")
	if output == "" {
		output = "crl.der"
	}
	revoked := m.promptLine("Revoked serial numbers, comma-separated (optional): ")

	args := []string{"--ca-cert", caCert, "--ca-key", caKey, "--output", output}
	if revoked != "" {
		args = append(args, "--revoked", revoked)
	}

	runCmd(GenerateCRLCmd(args))
}

func (m *MenuMode) promptAndViewCRL() {
	crlFile := m.promptLine("Enter CRL file path: ")
	if crlFile == "" {
		fmt.Println("No file path provided.")
		return
	}

	runCmd(ViewCRLCmd([]string{"--crl", crlFile}))
}

func (m *MenuMode) promptAndCheckCRL() {
	crlFile := m.promptLine("Enter CRL file path: ")
	certFile := m.promptLine("Enter certificate file path to check: ")
	if crlFile == "" || certFile == "" {
		fmt.Println("CRL file and certificate file are required.")
		return
	}

	runCmd(CheckCRLCmd([]string{"--crl", crlFile, "--cert", certFile}))
}

func (m *MenuMode) handleOCSPMenu() {
	for {
		fmt.Println("\n╔════════════════════════════════════════════════════════════╗")
		fmt.Println("║                    OCSP OPERATIONS                          ║")
		fmt.Println("╚════════════════════════════════════════════════════════════╝")
		fmt.Println()
		fmt.Println("  1. Create an OCSP request")
		fmt.Println("  2. Generate an OCSP response")
		fmt.Println("  3. Verify an OCSP response")
		fmt.Println("  4. Back to main menu")
		fmt.Println()

		choice, eof := m.promptChoice("Select an option [1-4]: ")
		if eof {
			return
		}

		switch choice {
		case "1":
			m.promptAndCreateOCSPRequest()
			return
		case "2":
			m.promptAndGenerateOCSPResponse()
			return
		case "3":
			m.promptAndVerifyOCSPResponse()
			return
		case "4":
			return
		default:
			fmt.Println("Invalid choice. Please try again.")
		}
	}
}

func (m *MenuMode) promptAndCreateOCSPRequest() {
	certFile := m.promptLine("Enter certificate file path: ")
	caCertFile := m.promptLine("Enter CA certificate file path: ")
	if certFile == "" || caCertFile == "" {
		fmt.Println("Certificate and CA certificate are required.")
		return
	}
	output := m.promptLine("Output request file path (default request.der): ")
	if output == "" {
		output = "request.der"
	}

	runCmd(CreateOCSPRequestCmd([]string{"--cert", certFile, "--ca-cert", caCertFile, "--output", output}))
}

func (m *MenuMode) promptAndGenerateOCSPResponse() {
	certFile := m.promptLine("Enter certificate file path: ")
	caCertFile := m.promptLine("Enter CA certificate file path: ")
	responderKey := m.promptLine("Enter OCSP responder private key file path: ")
	if certFile == "" || caCertFile == "" || responderKey == "" {
		fmt.Println("Certificate, CA certificate, and responder private key are required.")
		return
	}
	status := m.promptLine("Certificate status [good/revoked/unknown] (default good): ")
	if status == "" {
		status = "good"
	}
	output := m.promptLine("Output response file path (default response.der): ")
	if output == "" {
		output = "response.der"
	}

	args := []string{
		"--cert", certFile,
		"--ca-cert", caCertFile,
		"--responder-key", responderKey,
		"--status", status,
		"--output", output,
	}

	runCmd(GenerateOCSPResponseCmd(args))
}

func (m *MenuMode) promptAndVerifyOCSPResponse() {
	responseFile := m.promptLine("Enter OCSP response file path: ")
	certFile := m.promptLine("Enter certificate file path: ")
	caCertFile := m.promptLine("Enter CA certificate file path: ")
	if responseFile == "" || certFile == "" || caCertFile == "" {
		fmt.Println("Response file, certificate, and CA certificate are required.")
		return
	}

	runCmd(VerifyOCSPResponseCmd([]string{"--response", responseFile, "--cert", certFile, "--ca-cert", caCertFile}))
}
