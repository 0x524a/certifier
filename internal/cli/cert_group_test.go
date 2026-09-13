package cli

import (
	"context"
	"errors"
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
