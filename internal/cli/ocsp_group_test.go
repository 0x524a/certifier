package cli

import (
	"context"
	"errors"
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
