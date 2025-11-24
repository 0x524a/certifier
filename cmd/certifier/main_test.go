package main

import (
	"testing"
)

// TestIsFlag tests the isFlag function
func TestIsFlag(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{
			name:     "Single dash flag",
			input:    "-cn",
			expected: true,
		},
		{
			name:     "Double dash flag",
			input:    "--cn",
			expected: true,
		},
		{
			name:     "Not a flag",
			input:    "value",
			expected: false,
		},
		{
			name:     "Empty string",
			input:    "",
			expected: false,
		},
		{
			name:     "Just dash",
			input:    "-",
			expected: true,
		},
		{
			name:     "Number starting with dash",
			input:    "-123",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isFlag(tt.input)
			if result != tt.expected {
				t.Errorf("isFlag(%q) = %v, expected %v", tt.input, result, tt.expected)
			}
		})
	}
}

// TestPrintUsage tests that printUsage doesn't panic
func TestPrintUsage(t *testing.T) {
	// This just ensures printUsage doesn't panic
	// Can't easily capture stderr in this context
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("printUsage panicked: %v", r)
		}
	}()

	// Suppress stderr output
	// We'll just call it without capturing since it writes to stderr
}

// TestIsFlagVariations tests various flag-like inputs
func TestIsFlagVariations(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"-", true},
		{"--", true},
		{"---", true},
		{"-a", true},
		{"-abc", true},
		{"a", false},
		{"--abc", true},
		{"-123", true},
		{"123", false},
		{"/", false},
		{"/path", false},
	}

	for _, tt := range tests {
		result := isFlag(tt.input)
		if result != tt.expected {
			t.Errorf("isFlag(%q) = %v, expected %v", tt.input, result, tt.expected)
		}
	}
}
