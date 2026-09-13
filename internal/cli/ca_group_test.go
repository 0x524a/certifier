package cli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCACommandUnknownSubcommand(t *testing.T) {
	err := caCommand().Run(context.Background(), []string{"ca", "bogus-subcommand"})
	if !errors.Is(err, ErrSilent) {
		t.Errorf("err = %v, want ErrSilent", err)
	}
}

func TestCACommandFlagFirstArgDefaultsToGenerate(t *testing.T) {
	dir := t.TempDir()
	certOut := filepath.Join(dir, "ca.crt")
	keyOut := filepath.Join(dir, "ca.key")

	err := caCommand().Run(context.Background(), []string{
		"ca", "--cn", "Test CA", "--non-interactive",
		"--output", certOut, "--key-output", keyOut,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, statErr := os.Stat(certOut); statErr != nil {
		t.Errorf("expected cert file to exist: %v", statErr)
	}
}

func TestCACommandGenerateSubcommand(t *testing.T) {
	dir := t.TempDir()
	certOut := filepath.Join(dir, "ca.crt")
	keyOut := filepath.Join(dir, "ca.key")

	err := caCommand().Run(context.Background(), []string{
		"ca", "generate", "--cn", "Test CA", "--non-interactive",
		"--output", certOut, "--key-output", keyOut,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, statErr := os.Stat(certOut); statErr != nil {
		t.Errorf("expected cert file to exist: %v", statErr)
	}
}

func TestCACommandViewSubcommand(t *testing.T) {
	dir := t.TempDir()
	certOut := filepath.Join(dir, "ca.crt")
	keyOut := filepath.Join(dir, "ca.key")
	if err := caCommand().Run(context.Background(), []string{
		"ca", "generate", "--cn", "Test CA", "--non-interactive",
		"--output", certOut, "--key-output", keyOut,
	}); err != nil {
		t.Fatalf("setup: unexpected error: %v", err)
	}

	if err := caCommand().Run(context.Background(), []string{"ca", "view", "--cert", certOut}); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestCACommandBadFlagThroughTree(t *testing.T) {
	err := caCommand().Run(context.Background(), []string{"ca", "generate", "--bogus", "x"})
	if err == nil || !strings.HasPrefix(err.Error(), "error parsing flags: ") {
		t.Errorf("err = %v, want prefix %q", err, "error parsing flags: ")
	}
}
