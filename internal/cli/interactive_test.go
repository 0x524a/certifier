package cli

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"os"
	"strings"
	"testing"
)

// TestNewInteractiveMode tests the creation of a new interactive mode
func TestNewInteractiveMode(t *testing.T) {
	im := NewInteractiveMode()
	if im.reader == nil {
		t.Errorf("InteractiveMode reader is nil")
	}
}

// TestPromptString tests string prompting
func TestPromptString(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		defaultValue string
		expected     string
	}{
		{
			name:         "Input provided",
			input:        "test value\n",
			defaultValue: "default",
			expected:     "test value",
		},
		{
			name:         "Empty input with default",
			input:        "\n",
			defaultValue: "default",
			expected:     "default",
		},
		{
			name:         "Empty input no default",
			input:        "\n",
			defaultValue: "",
			expected:     "",
		},
		{
			name:         "Whitespace trimming",
			input:        "  spaced input  \n",
			defaultValue: "",
			expected:     "spaced input",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			im := &InteractiveMode{
				reader: bufio.NewReader(strings.NewReader(tt.input)),
			}

			result := im.PromptString(tt.name, tt.defaultValue)
			if result != tt.expected {
				t.Errorf("PromptString(%q, %q) = %q, expected %q",
					tt.name, tt.defaultValue, result, tt.expected)
			}
		})
	}
}

// TestPromptInt tests integer prompting
func TestPromptInt(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		defaultValue int
		expected     int
	}{
		{
			name:         "Valid integer",
			input:        "42\n",
			defaultValue: 10,
			expected:     42,
		},
		{
			name:         "Empty input with default",
			input:        "\n",
			defaultValue: 365,
			expected:     365,
		},
		{
			name:         "Invalid integer with default",
			input:        "not a number\n",
			defaultValue: 100,
			expected:     100,
		},
		{
			name:         "Zero input",
			input:        "0\n",
			defaultValue: 365,
			expected:     0,
		},
		{
			name:         "Negative integer",
			input:        "-50\n",
			defaultValue: 10,
			expected:     -50,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			im := &InteractiveMode{
				reader: bufio.NewReader(strings.NewReader(tt.input)),
			}

			result := im.PromptInt(tt.name, tt.defaultValue)
			if result != tt.expected {
				t.Errorf("PromptInt(%q, %d) = %d, expected %d",
					tt.name, tt.defaultValue, result, tt.expected)
			}
		})
	}
}

// TestPromptYesNo tests yes/no prompting
func TestPromptYesNo(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		defaultYes bool
		expected   bool
	}{
		{
			name:       "Yes input",
			input:      "y\n",
			defaultYes: false,
			expected:   true,
		},
		{
			name:       "YES input uppercase",
			input:      "YES\n",
			defaultYes: false,
			expected:   true,
		},
		{
			name:       "Yes full word",
			input:      "yes\n",
			defaultYes: false,
			expected:   true,
		},
		{
			name:       "No input",
			input:      "n\n",
			defaultYes: true,
			expected:   false,
		},
		{
			name:       "Empty input with default true",
			input:      "\n",
			defaultYes: true,
			expected:   true,
		},
		{
			name:       "Empty input with default false",
			input:      "\n",
			defaultYes: false,
			expected:   false,
		},
		{
			name:       "Invalid input with default",
			input:      "maybe\n",
			defaultYes: true,
			expected:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			im := &InteractiveMode{
				reader: bufio.NewReader(strings.NewReader(tt.input)),
			}

			result := im.PromptYesNo(tt.name, tt.defaultYes)
			if result != tt.expected {
				t.Errorf("PromptYesNo(%q, %v) = %v, expected %v",
					tt.name, tt.defaultYes, result, tt.expected)
			}
		})
	}
}

// TestPromptStringSlice tests prompting for multiple string values
func TestPromptStringSlice(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "Single value",
			input:    "value1\n\n",
			expected: []string{"value1"},
		},
		{
			name:     "Multiple values",
			input:    "value1\nvalue2\nvalue3\n\n",
			expected: []string{"value1", "value2", "value3"},
		},
		{
			name:     "No values",
			input:    "\n",
			expected: []string{},
		},
		{
			name:     "Values with whitespace",
			input:    "  value1  \n  value2  \n\n",
			expected: []string{"value1", "value2"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			im := &InteractiveMode{
				reader: bufio.NewReader(strings.NewReader(tt.input)),
			}

			// Capture stdout to avoid cluttering test output
			old := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		result := im.PromptStringSlice("Test prompt")

		_ = w.Close()
		os.Stdout = old
		_, _ = io.ReadAll(r)

		if len(result) != len(tt.expected) {
			t.Errorf("PromptStringSlice length = %d, expected %d", len(result), len(tt.expected))
				return
			}

			for i, v := range result {
				if v != tt.expected[i] {
					t.Errorf("PromptStringSlice[%d] = %q, expected %q", i, v, tt.expected[i])
				}
			}
		})
	}
}

// TestPromptDNSNames tests DNS name prompting
func TestPromptDNSNames(t *testing.T) {
	input := "example.com\nwww.example.com\n*.example.com\n\n"
	expected := []string{"example.com", "www.example.com", "*.example.com"}

	im := &InteractiveMode{
		reader: bufio.NewReader(strings.NewReader(input)),
	}

	// Capture stdout
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	result := im.PromptDNSNames()

	_ = w.Close()
	os.Stdout = old
	_, _ = io.ReadAll(r)

	if len(result) != len(expected) {
		t.Errorf("PromptDNSNames length = %d, expected %d", len(result), len(expected))
		return
	}

	for i, dns := range result {
		if dns != expected[i] {
			t.Errorf("PromptDNSNames[%d] = %q, expected %q", i, dns, expected[i])
		}
	}
}

// TestPromptIPAddresses tests IP address prompting
func TestPromptIPAddresses(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []net.IP
	}{
		{
			name:     "Valid IPv4 addresses",
			input:    "192.168.1.1\n127.0.0.1\n\n",
			expected: []net.IP{net.ParseIP("192.168.1.1"), net.ParseIP("127.0.0.1")},
		},
		{
			name:     "Valid IPv6 addresses",
			input:    "::1\n2001:db8::1\n\n",
			expected: []net.IP{net.ParseIP("::1"), net.ParseIP("2001:db8::1")},
		},
		{
			name:     "Mixed IPv4 and IPv6",
			input:    "192.168.1.1\n::1\n\n",
			expected: []net.IP{net.ParseIP("192.168.1.1"), net.ParseIP("::1")},
		},
		{
			name:     "No addresses",
			input:    "\n",
			expected: []net.IP{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			im := &InteractiveMode{
				reader: bufio.NewReader(strings.NewReader(tt.input)),
			}

			// Capture stdout
			old := os.Stdout
			r, w, _ := os.Pipe()
			os.Stdout = w

		result := im.PromptIPAddresses()

		_ = w.Close()
		os.Stdout = old
		_, _ = io.ReadAll(r)

		if len(result) != len(tt.expected) {
			t.Errorf("PromptIPAddresses length = %d, expected %d", len(result), len(tt.expected))
				return
			}

			for i, ip := range result {
				if !ip.Equal(tt.expected[i]) {
					t.Errorf("PromptIPAddresses[%d] = %v, expected %v", i, ip, tt.expected[i])
				}
			}
		})
	}
}

// TestPromptIPAddressesInvalid tests invalid IP address handling
func TestPromptIPAddressesInvalid(t *testing.T) {
	input := "not-an-ip\n192.168.1.1\n\n"

	im := &InteractiveMode{
		reader: bufio.NewReader(strings.NewReader(input)),
	}

	// Capture stdout and stderr
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	result := im.PromptIPAddresses()

	_ = w.Close()
	os.Stdout = old
	_, _ = io.ReadAll(r)

	// Should only have the valid IP
	if len(result) != 1 {
		t.Errorf("PromptIPAddresses length = %d, expected 1", len(result))
		return
	}

	if !result[0].Equal(net.ParseIP("192.168.1.1")) {
		t.Errorf("PromptIPAddresses[0] = %v, expected 192.168.1.1", result[0])
	}
}

// TestPromptEmailAddresses tests email address prompting
func TestPromptEmailAddresses(t *testing.T) {
	input := "user@example.com\nadmin@example.com\n\n"
	expected := []string{"user@example.com", "admin@example.com"}

	im := &InteractiveMode{
		reader: bufio.NewReader(strings.NewReader(input)),
	}

	// Capture stdout
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	result := im.PromptEmailAddresses()

	_ = w.Close()
	os.Stdout = old
	_, _ = io.ReadAll(r)

	if len(result) != len(expected) {
		t.Errorf("PromptEmailAddresses length = %d, expected %d", len(result), len(expected))
		return
	}

	for i, email := range result {
		if email != expected[i] {
			t.Errorf("PromptEmailAddresses[%d] = %q, expected %q", i, email, expected[i])
		}
	}
}

// TestPromptSubjectInfo tests subject information prompting
func TestPromptSubjectInfo(t *testing.T) {
	input := "example.com\nUS\nTest Organization\nIT\nSan Francisco\nCA\n"

	im := &InteractiveMode{
		reader: bufio.NewReader(strings.NewReader(input)),
	}

	// Capture stdout
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	result := im.PromptSubjectInfo()

	_ = w.Close()
	os.Stdout = old
	_, _ = io.ReadAll(r)

	if result["commonName"] != "example.com" {
		t.Errorf("commonName = %q, expected 'example.com'", result["commonName"])
	}
	if result["country"] != "US" {
		t.Errorf("country = %q, expected 'US'", result["country"])
	}
	if result["organization"] != "Test Organization" {
		t.Errorf("organization = %q, expected 'Test Organization'", result["organization"])
	}
	if result["organizationalUnit"] != "IT" {
		t.Errorf("organizationalUnit = %q, expected 'IT'", result["organizationalUnit"])
	}
	if result["locality"] != "San Francisco" {
		t.Errorf("locality = %q, expected 'San Francisco'", result["locality"])
	}
	if result["province"] != "CA" {
		t.Errorf("province = %q, expected 'CA'", result["province"])
	}
}

// TestPromptCertificateType tests certificate type prompting
func TestPromptCertificateType(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Server type",
			input:    "1\n",
			expected: "server",
		},
		{
			name:     "Client type",
			input:    "2\n",
			expected: "client",
		},
		{
			name:     "Both type",
			input:    "3\n",
			expected: "both",
		},
		{
			name:     "Invalid defaults to server",
			input:    "invalid\n",
			expected: "server",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			im := &InteractiveMode{
				reader: bufio.NewReader(strings.NewReader(tt.input)),
			}

			// Capture stdout
			old := os.Stdout
			r, w, _ := os.Pipe()
			os.Stdout = w

			result := im.PromptCertificateType()

			_ = w.Close()
			os.Stdout = old
			_, _ = io.ReadAll(r)

			if result != tt.expected {
				t.Errorf("PromptCertificateType() = %q, expected %q", result, tt.expected)
			}
		})
	}
}

// TestPromptKeyType tests key type prompting
func TestPromptKeyType(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "RSA 2048",
			input:    "1\n",
			expected: "rsa2048",
		},
		{
			name:     "RSA 4096",
			input:    "2\n",
			expected: "rsa4096",
		},
		{
			name:     "ECDSA P-256",
			input:    "3\n",
			expected: "ecdsa-p256",
		},
		{
			name:     "ECDSA P-384",
			input:    "4\n",
			expected: "ecdsa-p384",
		},
		{
			name:     "ECDSA P-521",
			input:    "5\n",
			expected: "ecdsa-p521",
		},
		{
			name:     "Ed25519",
			input:    "6\n",
			expected: "ed25519",
		},
		{
			name:     "Invalid defaults to RSA 2048",
			input:    "invalid\n",
			expected: "rsa2048",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			im := &InteractiveMode{
				reader: bufio.NewReader(strings.NewReader(tt.input)),
			}

			// Capture stdout
			old := os.Stdout
			r, w, _ := os.Pipe()
			os.Stdout = w

			result := im.PromptKeyType()

			_ = w.Close()
			os.Stdout = old
			_, _ = io.ReadAll(r)

			if result != tt.expected {
				t.Errorf("PromptKeyType() = %q, expected %q", result, tt.expected)
			}
		})
	}
}

// TestPromptValidity tests validity period prompting
func TestPromptValidity(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected int
	}{
		{
			name:     "Valid day count",
			input:    "30\n",
			expected: 30,
		},
		{
			name:     "Standard validity",
			input:    "365\n",
			expected: 365,
		},
		{
			name:     "Long validity",
			input:    "3650\n",
			expected: 3650,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			im := &InteractiveMode{
				reader: bufio.NewReader(strings.NewReader(tt.input)),
			}

			// Capture stdout
			old := os.Stdout
			r, w, _ := os.Pipe()
			os.Stdout = w

			result := im.PromptValidity()

			_ = w.Close()
			os.Stdout = old
			_, _ = io.ReadAll(r)

			if result != tt.expected {
				t.Errorf("PromptValidity() = %d, expected %d", result, tt.expected)
			}
		})
	}
}

// TestPromptExtendedKeyUsageOIDs tests EKU OID prompting
func TestPromptExtendedKeyUsageOIDs(t *testing.T) {
	input := "2.5.29.37.0\n1.3.6.1.4.1.57453.1.1\n\n"
	expected := []string{"2.5.29.37.0", "1.3.6.1.4.1.57453.1.1"}

	im := &InteractiveMode{
		reader: bufio.NewReader(strings.NewReader(input)),
	}

	// Capture stdout
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	result := im.PromptExtendedKeyUsageOIDs()

	_ = w.Close()
	os.Stdout = old
	_, _ = io.ReadAll(r)

	if len(result) != len(expected) {
		t.Errorf("PromptExtendedKeyUsageOIDs length = %d, expected %d", len(result), len(expected))
		return
	}

	for i, oid := range result {
		if oid != expected[i] {
			t.Errorf("PromptExtendedKeyUsageOIDs[%d] = %q, expected %q", i, oid, expected[i])
		}
	}
}

// TestPromptFileOutput tests file output prompting
func TestPromptFileOutput(t *testing.T) {
	input := "custom-path.crt\n"
	expected := "custom-path.crt"

	im := &InteractiveMode{
		reader: bufio.NewReader(strings.NewReader(input)),
	}

	// Capture stdout
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	result := im.PromptFileOutput("default.crt")

	_ = w.Close()
	os.Stdout = old
	_, _ = io.ReadAll(r)

	if result != expected {
		t.Errorf("PromptFileOutput() = %q, expected %q", result, expected)
	}
}

// TestConfirmGeneration tests generation confirmation
func TestConfirmGeneration(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{
			name:     "Confirm yes",
			input:    "y\n",
			expected: true,
		},
		{
			name:     "Confirm no",
			input:    "n\n",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			im := &InteractiveMode{
				reader: bufio.NewReader(strings.NewReader(tt.input)),
			}

			// Capture stdout
			old := os.Stdout
			r, w, _ := os.Pipe()
			os.Stdout = w

			result := im.ConfirmGeneration()

			_ = w.Close()
			os.Stdout = old
			_, _ = io.ReadAll(r)

			if result != tt.expected {
				t.Errorf("ConfirmGeneration() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

// TestSummaryTable tests the summary table display
func TestSummaryTable(t *testing.T) {
	details := map[string]interface{}{
		"Common Name": "example.com",
		"Key Type":    "rsa2048",
		"Validity":    365,
		"IsCA":        true,
		"DNS Names":   []string{"example.com", "www.example.com"},
	}

	// Capture stdout
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	SummaryTable(details)

	_ = w.Close()
	os.Stdout = old

	output := new(bytes.Buffer)
	_, _ = io.Copy(output, r)
	result := output.String()

	// Check that output contains expected content
	if !strings.Contains(result, "CERTIFICATE SUMMARY") {
		t.Errorf("Summary table missing header")
	}

	if !strings.Contains(result, "Common Name") {
		t.Errorf("Summary table missing 'Common Name'")
	}

	if !strings.Contains(result, "example.com") {
		t.Errorf("Summary table missing 'example.com'")
	}
}
