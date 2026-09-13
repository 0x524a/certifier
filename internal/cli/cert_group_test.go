package cli

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestCertCommandUnknownSubcommand(t *testing.T) {
	err := certCommand().Run(context.Background(), []string{"cert", "bogus-subcommand"})
	if !errors.Is(err, ErrSilent) {
		t.Errorf("err = %v, want ErrSilent", err)
	}
}

func TestCertCommandFlagFirstArgDefaultsToGenerate(t *testing.T) {
	err := certCommand().Run(context.Background(), []string{"cert", "--non-interactive"})
	if err == nil || err.Error() != "common Name (--cn) is required for non-interactive mode" {
		t.Errorf("err = %v, want the missing-CN business error", err)
	}
}

func TestCertCommandBadFlagThroughTree(t *testing.T) {
	err := certCommand().Run(context.Background(), []string{"cert", "sign", "--bogus", "x"})
	if err == nil || !strings.HasPrefix(err.Error(), "error parsing flags: ") {
		t.Errorf("err = %v, want prefix %q", err, "error parsing flags: ")
	}
}
