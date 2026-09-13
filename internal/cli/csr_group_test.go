package cli

import (
	"context"
	"errors"
	"testing"
)

func TestCSRCommandUnknownSubcommand(t *testing.T) {
	err := csrCommand().Run(context.Background(), []string{"csr", "bogus-subcommand"})
	if !errors.Is(err, ErrSilent) {
		t.Errorf("err = %v, want ErrSilent", err)
	}
}
