package cli

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestCSRCommandUnknownSubcommand(t *testing.T) {
	err := csrCommand().Run(context.Background(), []string{"csr", "bogus-subcommand"})
	if !errors.Is(err, ErrSilent) {
		t.Errorf("err = %v, want ErrSilent", err)
	}
}

func TestCSRCommandBadFlagThroughTree(t *testing.T) {
	err := csrCommand().Run(context.Background(), []string{"csr", "view", "--bogus", "x"})
	if err == nil || !strings.HasPrefix(err.Error(), "error parsing flags: ") {
		t.Errorf("err = %v, want prefix %q", err, "error parsing flags: ")
	}
}
