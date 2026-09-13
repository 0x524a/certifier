package cli

import (
	"context"
	"errors"
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
