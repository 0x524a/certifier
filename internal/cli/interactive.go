package cli

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
)

// InteractiveMode enables interactive prompting for certificate generation
type InteractiveMode struct {
	reader *bufio.Reader
}

// NewInteractiveMode creates a new interactive mode instance
func NewInteractiveMode() *InteractiveMode {
	return &InteractiveMode{
		reader: bufio.NewReader(os.Stdin),
	}
}

// PromptString prompts for a string value with optional default
func (im *InteractiveMode) PromptString(prompt, defaultValue string) string {
	if defaultValue != "" {
		fmt.Printf("%s [%s]: ", prompt, defaultValue)
	} else {
		fmt.Printf("%s: ", prompt)
	}

	input, _ := im.reader.ReadString('\n')
	input = strings.TrimSpace(input)

	if input == "" && defaultValue != "" {
		return defaultValue
	}
	return input
}

// PromptInt prompts for an integer value with optional default
func (im *InteractiveMode) PromptInt(prompt string, defaultValue int) int {
	if defaultValue > 0 {
		fmt.Printf("%s [%d]: ", prompt, defaultValue)
	} else {
		fmt.Printf("%s: ", prompt)
	}

	input, _ := im.reader.ReadString('\n')
	input = strings.TrimSpace(input)

	if input == "" && defaultValue > 0 {
		return defaultValue
	}

	var value int
	_, err := fmt.Sscanf(input, "%d", &value)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid integer value\n")
		return defaultValue
	}
	return value
}

// PromptYesNo prompts for yes/no confirmation
func (im *InteractiveMode) PromptYesNo(prompt string, defaultYes bool) bool {
	default_str := "y/N"
	if defaultYes {
		default_str = "Y/n"
	}
	fmt.Printf("%s [%s]: ", prompt, default_str)

	input, _ := im.reader.ReadString('\n')
	input = strings.TrimSpace(strings.ToLower(input))

	if input == "" {
		return defaultYes
	}

	return input == "y" || input == "yes"
}

// PromptStringSlice prompts for multiple string values (one per line, empty to finish)
func (im *InteractiveMode) PromptStringSlice(prompt string) []string {
	fmt.Printf("\n%s (enter each value on a new line, empty line to finish):\n", prompt)

	var values []string
	for {
		input, _ := im.reader.ReadString('\n')
		input = strings.TrimSpace(input)

		if input == "" {
			break
		}
		values = append(values, input)
		fmt.Printf("Added: %s\n", input)
	}

	return values
}

// PromptDNSNames prompts for DNS names (SANs)
func (im *InteractiveMode) PromptDNSNames() []string {
	fmt.Println("\n--- DNS Names (SANs) ---")
	fmt.Println("Enter DNS names for the certificate (one per line).")
	fmt.Println("This is important for server certificates.")
	fmt.Println("Examples: example.com, www.example.com, *.example.com")
	fmt.Println("(Enter empty line to finish)")

	return im.PromptStringSlice("DNS Names")
}

// PromptIPAddresses prompts for IP addresses (SANs)
func (im *InteractiveMode) PromptIPAddresses() []net.IP {
	fmt.Println("\n--- IP Addresses (SANs) ---")
	fmt.Println("Enter IP addresses for the certificate (one per line).")
	fmt.Println("Examples: 192.168.1.1, 127.0.0.1, ::1")
	fmt.Println("(Enter empty line to finish)")

	var ips []net.IP
	for {
		input, _ := im.reader.ReadString('\n')
		input = strings.TrimSpace(input)

		if input == "" {
			break
		}

		ip := net.ParseIP(input)
		if ip == nil {
			fmt.Fprintf(os.Stderr, "Invalid IP address: %s\n", input)
			continue
		}
		ips = append(ips, ip)
		fmt.Printf("Added: %s\n", input)
	}

	return ips
}

// PromptEmailAddresses prompts for email addresses
func (im *InteractiveMode) PromptEmailAddresses() []string {
	fmt.Println("\n--- Email Addresses ---")
	fmt.Println("Enter email addresses for the certificate (one per line).")
	fmt.Println("(Enter empty line to finish)")

	return im.PromptStringSlice("Email Addresses")
}

// PromptSubjectInfo prompts for subject information
func (im *InteractiveMode) PromptSubjectInfo() map[string]string {
	subject := make(map[string]string)

	fmt.Println("\n--- Subject Information ---")
	fmt.Println("Press Enter to skip optional fields.")

	subject["commonName"] = im.PromptString("Common Name (CN)", "")
	subject["country"] = im.PromptString("Country (C)", "US")
	subject["organization"] = im.PromptString("Organization (O)", "")
	subject["organizationalUnit"] = im.PromptString("Organizational Unit (OU)", "")
	subject["locality"] = im.PromptString("Locality/City (L)", "")
	subject["province"] = im.PromptString("Province/State (ST)", "")

	return subject
}

// PromptCertificateType prompts for certificate type (client, server, or both)
func (im *InteractiveMode) PromptCertificateType() string {
	fmt.Println("\n--- Certificate Type ---")
	fmt.Println("What type of certificate do you need?")
	fmt.Println("  1. Server (web servers, APIs)")
	fmt.Println("  2. Client (client authentication, mutual TLS)")
	fmt.Println("  3. Both (server and client authentication)")

	choice := im.PromptString("Select certificate type", "1")

	switch choice {
	case "1":
		return "server"
	case "2":
		return "client"
	case "3":
		return "both"
	default:
		return "server"
	}
}

// PromptFileOutput prompts for output file paths
func (im *InteractiveMode) PromptFileOutput(defaultName string) string {
	return im.PromptString("Output file path", defaultName)
}
func (im *InteractiveMode) PromptKeyType() string {
	fmt.Println("\n--- Key Type Selection ---")
	fmt.Println("1. RSA 2048-bit (default, widely compatible)")
	fmt.Println("2. RSA 4096-bit (stronger, slower)")
	fmt.Println("3. ECDSA P-256 (fast, modern)")
	fmt.Println("4. ECDSA P-384 (stronger ECDSA)")
	fmt.Println("5. ECDSA P-521 (strongest ECDSA)")
	fmt.Println("6. Ed25519 (fastest, post-quantum ready)")

	choice := im.PromptString("Select key type", "1")

	switch choice {
	case "1":
		return "rsa2048"
	case "2":
		return "rsa4096"
	case "3":
		return "ecdsa-p256"
	case "4":
		return "ecdsa-p384"
	case "5":
		return "ecdsa-p521"
	case "6":
		return "ed25519"
	default:
		return "rsa2048"
	}
}

// PromptValidity prompts for certificate validity period
func (im *InteractiveMode) PromptValidity() int {
	fmt.Println("\n--- Certificate Validity ---")
	fmt.Println("Common durations:")
	fmt.Println("  30 days (development/testing)")
	fmt.Println("  90 days (standard short-lived)")
	fmt.Println("  365 days (1 year, standard)")
	fmt.Println("  1825 days (5 years)")
	fmt.Println("  3650 days (10 years, CA certificates)")

	return im.PromptInt("Validity in days", 365)
}

// PromptExtendedKeyUsageOIDs prompts for custom Extended Key Usage OIDs
func (im *InteractiveMode) PromptExtendedKeyUsageOIDs() []string {
	fmt.Println("\n--- Extended Key Usage (EKU) OIDs ---")
	fmt.Println("Add custom Extended Key Usage OIDs for specialized uses:")
	fmt.Println("  2.5.29.37.0     - Kernel Module Signing")
	fmt.Println("  1.3.6.1.4.1.57453.1.1 - Custom Code Signing")
	fmt.Println("  1.3.6.1.4.1.57453.1.2 - Custom Firmware Signing")
	fmt.Println("(Enter empty line to skip)")

	return im.PromptStringSlice("Extended Key Usage OIDs")
}

// SummaryTable displays a summary of certificate details before generation
func SummaryTable(details map[string]interface{}) {
	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("CERTIFICATE SUMMARY")
	fmt.Println(strings.Repeat("=", 60))

	for key, value := range details {
		switch v := value.(type) {
		case string:
			fmt.Printf("%-25s: %s\n", key, v)
		case int:
			fmt.Printf("%-25s: %d\n", key, v)
		case bool:
			fmt.Printf("%-25s: %v\n", key, v)
		case []string:
			if len(v) > 0 {
				fmt.Printf("%-25s: %s\n", key, strings.Join(v, ", "))
			}
		}
	}

	fmt.Println(strings.Repeat("=", 60))
}

// ConfirmGeneration asks for confirmation before generating certificate
func (im *InteractiveMode) ConfirmGeneration() bool {
	return im.PromptYesNo("Proceed with certificate generation?", true)
}
