package cli

import (
	"context"
	"errors"
	"testing"
)

func TestRootCommandUnknownCommand(t *testing.T) {
	err := RootCommand().Run(context.Background(), []string{"certifier", "bogus-command"})
	if !errors.Is(err, ErrSilent) {
		t.Errorf("err = %v, want ErrSilent", err)
	}
}

func TestRootCommandHelpDoesNotError(t *testing.T) {
	for _, args := range [][]string{
		{"certifier", "help"},
		{"certifier", "-h"},
		{"certifier", "--help"},
		{"certifier", "version"},
		{"certifier", "-v"},
		{"certifier", "--version"},
	} {
		if err := RootCommand().Run(context.Background(), args); err != nil {
			t.Errorf("Run(%v) error = %v, want nil", args, err)
		}
	}
}

func TestRootCommandRoutesToCAGroup(t *testing.T) {
	err := RootCommand().Run(context.Background(), []string{"certifier", "ca", "bogus-subcommand"})
	if !errors.Is(err, ErrSilent) {
		t.Errorf("err = %v, want ErrSilent (routed through to the ca group's own dispatch)", err)
	}
}
