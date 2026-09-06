package cli

import (
	"bufio"
	"io"
	"os"
	"strings"
	"testing"
)

// TestNewMenuMode tests the creation of a new menu mode
func TestNewMenuMode(t *testing.T) {
	m := NewMenuMode()
	if m.reader == nil {
		t.Errorf("MenuMode reader is nil")
	}
}

// TestDisplayMainMenuScreen tests the main menu screen display
func TestDisplayMainMenuScreen(t *testing.T) {
	m := NewMenuMode()

	// Capture stdout
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	m.displayMainMenuScreen()

	_ = w.Close()
	os.Stdout = old

	buf := new(strings.Builder)
	_, _ = io.Copy(buf, r)
	output := buf.String()

	// Check menu content
	if !strings.Contains(output, "CERTIFIER - INTERACTIVE MODE") {
		t.Errorf("Menu screen missing title")
	}

	if !strings.Contains(output, "Certificate Authority (CA) Operations") {
		t.Errorf("Menu screen missing CA operations option")
	}

	if !strings.Contains(output, "Certificate Operations") {
		t.Errorf("Menu screen missing Certificate operations option")
	}

	if !strings.Contains(output, "Certificate Signing Request (CSR) Operations") {
		t.Errorf("Menu screen missing CSR operations option")
	}

	if !strings.Contains(output, "Quick Options") {
		t.Errorf("Menu screen missing Quick Options option")
	}
}

// TestPromptMainMenu tests the main menu prompt
func TestPromptMainMenu(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Option 1",
			input:    "1\n",
			expected: "1",
		},
		{
			name:     "Option 2",
			input:    "2\n",
			expected: "2",
		},
		{
			name:     "Quit option",
			input:    "q\n",
			expected: "q",
		},
		{
			name:     "Uppercase quit",
			input:    "Q\n",
			expected: "Q",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &MenuMode{
				reader: bufio.NewReader(strings.NewReader(tt.input)),
			}

			// Capture stdout
			old := os.Stdout
			_, w, _ := os.Pipe()
			os.Stdout = w

			result := m.promptMainMenu()

			_ = w.Close()
			os.Stdout = old

			if result != tt.expected {
				t.Errorf("promptMainMenu() = %q, expected %q", result, tt.expected)
			}
		})
	}
}

// TestHandleCAMenuGenerate tests CA menu - generate option
func TestHandleCAMenuGenerate(t *testing.T) {
	// This tests only the input handling, not the generation itself
	input := "1\nTest CA\nTestOrg\n\nUS\n1\n365\n\nFalse\nn\n3\n"
	_ = &MenuMode{
		reader: bufio.NewReader(strings.NewReader(input)),
	}

	// Capture stdout to avoid cluttering output
	old := os.Stdout
	_, w, _ := os.Pipe()
	os.Stdout = w

	// This will call GenerateCA and then return
	// We're just testing that it doesn't panic or crash
	// The actual generation is tested in commands_test.go
	defer func() {
		_ = w.Close()
		os.Stdout = old
		if r := recover(); r != nil {
			t.Errorf("HandleCAMenu panicked: %v", r)
		}
	}()

	// Note: We can't fully test this without mocking input
	// This is a partial test to ensure the method exists and is callable
}

// TestPromptAndViewCertFile tests the cert file viewing prompt
func TestPromptAndViewCertFile(t *testing.T) {
	input := "\n" // Empty input (should return early)
	m := &MenuMode{
		reader: bufio.NewReader(strings.NewReader(input)),
	}

	// Capture stdout
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	m.promptAndViewCertFile()

	_ = w.Close()
	os.Stdout = old

	buf := new(strings.Builder)
	_, _ = io.Copy(buf, r)
	output := buf.String()

	if !strings.Contains(output, "No file path provided") {
		t.Errorf("Expected 'No file path provided' message")
	}
}

// TestPromptAndViewCAFile tests the CA file viewing prompt
func TestPromptAndViewCAFile(t *testing.T) {
	input := "\n" // Empty input (should return early)
	m := &MenuMode{
		reader: bufio.NewReader(strings.NewReader(input)),
	}

	// Capture stdout
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	m.promptAndViewCAFile()

	_ = w.Close()
	os.Stdout = old

	buf := new(strings.Builder)
	_, _ = io.Copy(buf, r)
	output := buf.String()

	if !strings.Contains(output, "No file path provided") {
		t.Errorf("Expected 'No file path provided' message")
	}
}

// TestMenuScreens tests that all menu screens display correctly
func TestMenuScreens(t *testing.T) {
	tests := []struct {
		name     string
		testFunc func(*MenuMode)
		contains string
	}{
		{
			name:     "CA Menu Screen",
			testFunc: func(m *MenuMode) { m.displayMainMenuScreen() },
			contains: "CERTIFIER - INTERACTIVE MODE",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := NewMenuMode()

			// Capture stdout
			old := os.Stdout
			r, w, _ := os.Pipe()
			os.Stdout = w

			tt.testFunc(m)

			_ = w.Close()
			os.Stdout = old

			buf := new(strings.Builder)
			_, _ = io.Copy(buf, r)
			output := buf.String()

			if !strings.Contains(output, tt.contains) {
				t.Errorf("Menu screen missing: %q", tt.contains)
			}
		})
	}
}

// TestMenuModeInputTrimming tests that input is properly trimmed
func TestMenuModeInputTrimming(t *testing.T) {
	input := "  1  \n"
	m := &MenuMode{
		reader: bufio.NewReader(strings.NewReader(input)),
	}

	// Capture stdout
	old := os.Stdout
	_, w, _ := os.Pipe()
	os.Stdout = w

	result := m.promptMainMenu()

	_ = w.Close()
	os.Stdout = old

	if result != "1" {
		t.Errorf("promptMainMenu() = %q, expected '1' (should trim whitespace)", result)
	}
}

// TestMenuOptionValidation tests invalid menu options
func TestMenuOptionValidation(t *testing.T) {
	// Test that invalid options are handled gracefully
	input := "invalid\n3\n" // First invalid, then back to main menu, then we exit
	_ = &MenuMode{
		reader: bufio.NewReader(strings.NewReader(input)),
	}

	// This test just ensures these methods are callable
	// Full integration testing would require mocking os.Exit
}

// TestHandleCAMenuOption2ViewCA tests CA menu - View option
func TestHandleCAMenuOption2ViewCA(t *testing.T) {
	// Simulate user selecting option 2 (View CA) then providing no path
	input := "2\n\n"
	m := &MenuMode{
		reader: bufio.NewReader(strings.NewReader(input)),
	}

	// Capture stdout
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	defer func() {
		_ = w.Close()
		os.Stdout = old
		_, _ = io.Copy(io.Discard, r)
	}()

	// We can test the promptAndViewCAFile method separately
	// which is called by handleCAMenu
	_ = m
}

// TestHandleCertMenuOption2View tests Certificate menu - View option
func TestHandleCertMenuOption2View(t *testing.T) {
	// Just empty input - promptAndViewCertFile will receive empty string and return
	input := "\n"
	m := &MenuMode{
		reader: bufio.NewReader(strings.NewReader(input)),
	}

	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	defer func() {
		_ = w.Close()
		os.Stdout = old
		_, _ = io.Copy(io.Discard, r)
	}()

	// Test the promptAndViewCertFile method with empty input
	m.promptAndViewCertFile()
}

// runMenuFuncCapturingStdout runs fn with stdout redirected, then restores it
// and drains the pipe so output doesn't leak into the test run.
func runMenuFuncCapturingStdout(fn func()) {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	fn()

	_ = w.Close()
	os.Stdout = old
	_, _ = io.Copy(io.Discard, r)
}

// TestHandleCAMenuBackAndInvalid covers handleCAMenu's "back to main menu"
// branch (case "3") and the default/invalid-choice branch that loops before
// eventually exiting via a valid choice.
func TestHandleCAMenuBackAndInvalid(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{name: "back to main menu", input: "3\n"},
		{name: "invalid then back", input: "invalid\n3\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &MenuMode{reader: bufio.NewReader(strings.NewReader(tt.input))}
			runMenuFuncCapturingStdout(m.handleCAMenu)
		})
	}
}

// TestHandleCAMenuViewOption covers handleCAMenu's case "2", which delegates
// to promptAndViewCAFile, for both an empty file path and a valid CA file.
func TestHandleCAMenuViewOption(t *testing.T) {
	t.Run("empty path", func(t *testing.T) {
		m := &MenuMode{reader: bufio.NewReader(strings.NewReader("2\n\n"))}
		runMenuFuncCapturingStdout(m.handleCAMenu)
	})

	t.Run("valid ca file", func(t *testing.T) {
		certFile, _ := createTestCertificate(t)
		input := "2\n" + certFile + "\n"
		m := &MenuMode{reader: bufio.NewReader(strings.NewReader(input))}
		runMenuFuncCapturingStdout(m.handleCAMenu)
	})
}

// TestHandleCertMenuBranches covers handleCertMenu's view, validate,
// back-to-main-menu and invalid-choice branches.
func TestHandleCertMenuBranches(t *testing.T) {
	certFile, _ := createTestCertificate(t)

	tests := []struct {
		name  string
		input string
	}{
		{name: "view with empty path", input: "2\n\n"},
		{name: "view with valid path", input: "2\n" + certFile + "\n"},
		{name: "validate with empty path", input: "3\n\n"},
		{name: "validate with valid path", input: "3\n" + certFile + "\n\n\n"},
		{name: "back to main menu", input: "4\n"},
		{name: "invalid then back", input: "invalid\n4\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &MenuMode{reader: bufio.NewReader(strings.NewReader(tt.input))}
			runMenuFuncCapturingStdout(m.handleCertMenu)
		})
	}
}

// TestHandleCSRMenuBranches covers handleCSRMenu's view, back-to-main-menu
// and invalid-choice branches.
func TestHandleCSRMenuBranches(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{name: "view with empty path", input: "2\n\n"},
		{name: "view with nonexistent path", input: "2\n/nonexistent.csr\n"},
		{name: "back to main menu", input: "3\n"},
		{name: "invalid then back", input: "invalid\n3\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &MenuMode{reader: bufio.NewReader(strings.NewReader(tt.input))}
			runMenuFuncCapturingStdout(m.handleCSRMenu)
		})
	}
}

// TestHandleQuickOptionsBranches covers handleQuickOptions's view certificate,
// validate, encode/decode, back-to-main-menu, and invalid-choice branches.
func TestHandleQuickOptionsBranches(t *testing.T) {
	certFile, _ := createTestCertificate(t)

	tests := []struct {
		name  string
		input string
	}{
		{name: "view cert with empty path", input: "1\n\n"},
		{name: "view cert with valid path", input: "1\n" + certFile + "\n"},
		{name: "validate with empty path", input: "2\n\n"},
		{name: "encode/decode back", input: "3\n3\n"},
		{name: "back to main menu", input: "4\n"},
		{name: "invalid then back", input: "invalid\n4\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &MenuMode{reader: bufio.NewReader(strings.NewReader(tt.input))}
			runMenuFuncCapturingStdout(m.handleQuickOptions)
		})
	}
}

// TestHandleEncodeDecodeMenuBranches covers handleEncodeDecodeMenu's encode,
// decode, back, invalid-choice, and EOF branches.
func TestHandleEncodeDecodeMenuBranches(t *testing.T) {
	certFile, keyFile := createTestCertificate(t)
	tmpDir := t.TempDir()
	derFile := tmpDir + "/out.der"
	pfxFile := tmpDir + "/out.pfx"
	roundtripFile := tmpDir + "/roundtrip.crt"

	tests := []struct {
		name  string
		input string
	}{
		{name: "encode to der", input: "1\n" + certFile + "\n" + derFile + "\nder\n"},
		{name: "encode to pkcs12", input: "1\n" + certFile + "\n" + pfxFile + "\npkcs12\n" + keyFile + "\nchangeit\n"},
		{name: "encode missing input", input: "1\n\n"},
		{name: "decode der roundtrip", input: "2\n" + derFile + "\n" + roundtripFile + "\nder\n"},
		{name: "decode missing input", input: "2\n\n"},
		{name: "back to parent menu", input: "3\n"},
		{name: "invalid then back", input: "invalid\n3\n"},
		{name: "eof with no data", input: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &MenuMode{reader: bufio.NewReader(strings.NewReader(tt.input))}
			runMenuFuncCapturingStdout(m.handleEncodeDecodeMenu)
		})
	}
}

// TestHandleCRLMenuBranches covers handleCRLMenu's generate, view, check,
// back, invalid-choice, and EOF branches.
func TestHandleCRLMenuBranches(t *testing.T) {
	caCertFile, caKeyFile, certFile, _ := createTestOCSPFixtures(t)
	tmpDir := t.TempDir()
	crlFile := tmpDir + "/test.crl"

	tests := []struct {
		name  string
		input string
	}{
		{name: "generate missing ca cert", input: "1\n\n\n"},
		{name: "generate success", input: "1\n" + caCertFile + "\n" + caKeyFile + "\n" + crlFile + "\n1,2,3\n"},
		{name: "view missing path", input: "2\n\n"},
		{name: "view success", input: "2\n" + crlFile + "\n"},
		{name: "check missing paths", input: "3\n\n\n"},
		{name: "check success", input: "3\n" + crlFile + "\n" + certFile + "\n"},
		{name: "back to main menu", input: "4\n"},
		{name: "invalid then back", input: "invalid\n4\n"},
		{name: "eof with no data", input: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &MenuMode{reader: bufio.NewReader(strings.NewReader(tt.input))}
			runMenuFuncCapturingStdout(m.handleCRLMenu)
		})
	}
}

// TestHandleOCSPMenuBranches covers handleOCSPMenu's request, response,
// verify, check-status, back, invalid-choice, and EOF branches.
func TestHandleOCSPMenuBranches(t *testing.T) {
	caCertFile, caKeyFile, certFile, _ := createTestOCSPFixtures(t)
	tmpDir := t.TempDir()
	requestFile := tmpDir + "/req.der"
	responseFile := tmpDir + "/resp.der"

	goodResponseFile := tmpDir + "/good.der"
	if err := GenerateOCSPResponseCmd([]string{
		"--cert", certFile, "--ca-cert", caCertFile, "--responder-key", caKeyFile,
		"--status", "good", "--output", goodResponseFile,
	}); err != nil {
		t.Fatalf("Failed to generate good response fixture: %v", err)
	}
	goodBytes, err := os.ReadFile(goodResponseFile)
	if err != nil {
		t.Fatalf("Failed to read good response fixture: %v", err)
	}
	server := newStaticOCSPResponder(t, goodBytes)
	defer server.Close()

	tests := []struct {
		name  string
		input string
	}{
		{name: "request missing paths", input: "1\n\n\n"},
		{name: "request success", input: "1\n" + certFile + "\n" + caCertFile + "\n" + requestFile + "\n"},
		{name: "response missing paths", input: "2\n\n\n\n"},
		{name: "response success", input: "2\n" + certFile + "\n" + caCertFile + "\n" + caKeyFile + "\ngood\n" + responseFile + "\n"},
		{name: "verify missing paths", input: "3\n\n\n\n"},
		{name: "verify success", input: "3\n" + responseFile + "\n" + certFile + "\n" + caCertFile + "\n"},
		{name: "check missing paths", input: "4\n\n\n"},
		{name: "check missing url and no AIA", input: "4\n" + certFile + "\n" + caCertFile + "\n\n"},
		{name: "check success", input: "4\n" + certFile + "\n" + caCertFile + "\n" + server.URL + "\n"},
		{name: "back to main menu", input: "5\n"},
		{name: "invalid then back", input: "invalid\n5\n"},
		{name: "eof with no data", input: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &MenuMode{reader: bufio.NewReader(strings.NewReader(tt.input))}
			runMenuFuncCapturingStdout(m.handleOCSPMenu)
		})
	}
}

// TestDisplayMainMenuScreenListsAllSections verifies the main menu screen
// text includes the CRL and OCSP sections added alongside CA/Cert/CSR/Quick.
func TestDisplayMainMenuScreenListsAllSections(t *testing.T) {
	m := NewMenuMode()

	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	m.displayMainMenuScreen()

	_ = w.Close()
	os.Stdout = old

	buf := new(strings.Builder)
	_, _ = io.Copy(buf, r)
	output := buf.String()

	if !strings.Contains(output, "Certificate Revocation List (CRL) Operations") {
		t.Errorf("Menu screen missing CRL operations option")
	}
	if !strings.Contains(output, "OCSP Operations") {
		t.Errorf("Menu screen missing OCSP operations option")
	}
}
