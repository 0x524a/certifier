package cli

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestOCSPCommandNoSubcommand(t *testing.T) {
	err := ocspCommand().Run(context.Background(), []string{"ocsp"})
	if !errors.Is(err, ErrSilent) {
		t.Errorf("err = %v, want ErrSilent", err)
	}
}

func TestOCSPCommandUnknownSubcommand(t *testing.T) {
	err := ocspCommand().Run(context.Background(), []string{"ocsp", "bogus"})
	if !errors.Is(err, ErrSilent) {
		t.Errorf("err = %v, want ErrSilent", err)
	}
}

func TestOCSPCommandHelpFlagDoesNotError(t *testing.T) {
	err := ocspCommand().Run(context.Background(), []string{"ocsp", "-h"})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestOCSPCommandBadFlagThroughTree(t *testing.T) {
	err := ocspCommand().Run(context.Background(), []string{"ocsp", "check", "--bogus", "x"})
	if err == nil || !strings.HasPrefix(err.Error(), "error parsing flags: ") {
		t.Errorf("err = %v, want prefix %q", err, "error parsing flags: ")
	}
}
