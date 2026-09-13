package cli

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestCRLCommandNoSubcommand(t *testing.T) {
	err := crlCommand().Run(context.Background(), []string{"crl"})
	if !errors.Is(err, ErrSilent) {
		t.Errorf("err = %v, want ErrSilent", err)
	}
}

func TestCRLCommandUnknownSubcommand(t *testing.T) {
	err := crlCommand().Run(context.Background(), []string{"crl", "bogus"})
	if !errors.Is(err, ErrSilent) {
		t.Errorf("err = %v, want ErrSilent", err)
	}
}

func TestCRLCommandHelpFlagDoesNotError(t *testing.T) {
	err := crlCommand().Run(context.Background(), []string{"crl", "-h"})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestCRLCommandBadFlagThroughTree(t *testing.T) {
	err := crlCommand().Run(context.Background(), []string{"crl", "view", "--bogus", "x"})
	if err == nil || !strings.HasPrefix(err.Error(), "error parsing flags: ") {
		t.Errorf("err = %v, want prefix %q", err, "error parsing flags: ")
	}
}
