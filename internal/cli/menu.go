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
	fmt.Println()
	fmt.Println("  q. Quit")
	fmt.Println()
}

func (m *MenuMode) promptMainMenu() string {
	fmt.Print("Select an option [1-4, q]: ")
	input, _ := m.reader.ReadString('\n')
	return strings.TrimSpace(input)
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
		input, _ := m.reader.ReadString('\n')
		choice := strings.TrimSpace(input)

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
		input, _ := m.reader.ReadString('\n')
		choice := strings.TrimSpace(input)

		switch choice {
		case "1":
			GenerateCert([]string{})
			return
		case "2":
			m.promptAndViewCertFile()
			return
		case "3":
			fmt.Println("Certificate validation - not yet implemented")
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
		input, _ := m.reader.ReadString('\n')
		choice := strings.TrimSpace(input)

		switch choice {
		case "1":
			GenerateCSR([]string{})
			return
		case "2":
			fmt.Println("View CSR - not yet implemented")
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
		input, _ := m.reader.ReadString('\n')
		choice := strings.TrimSpace(input)

		switch choice {
		case "1":
			m.promptAndViewCertFile()
			return
		case "2":
			fmt.Println("Certificate validation - not yet implemented")
			return
		case "3":
			fmt.Println("Encode/Decode - not yet implemented")
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
