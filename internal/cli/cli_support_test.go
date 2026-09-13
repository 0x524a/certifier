package cli

import (
	"context"
	"errors"
	"strings"
	"testing"

	cliv3 "github.com/urfave/cli/v3"
)

func TestRunLeafCommandWrapsFlagParseErrors(t *testing.T) {
	cmd := &cliv3.Command{
		Name:  "test",
		Flags: []cliv3.Flag{&cliv3.StringFlag{Name: "cn"}},
		Action: func(ctx context.Context, c *cliv3.Command) error {
			return nil
		},
	}

	err := runLeafCommand(cmd, []string{"--bogus", "x"})
	if err == nil {
		t.Fatal("expected an error for an undefined flag")
	}
	if !strings.HasPrefix(err.Error(), "error parsing flags: ") {
		t.Errorf("error = %q, want prefix %q", err.Error(), "error parsing flags: ")
	}
}

func TestRunLeafCommandPassesThroughActionErrors(t *testing.T) {
	wantErr := errors.New("common Name (--cn) is required for non-interactive mode")
	cmd := &cliv3.Command{
		Name:  "test",
		Flags: []cliv3.Flag{&cliv3.StringFlag{Name: "cn"}},
		Action: func(ctx context.Context, c *cliv3.Command) error {
			return wantErr
		},
	}

	err := runLeafCommand(cmd, nil)
	if !errors.Is(err, wantErr) {
		t.Errorf("error = %v, want %v", err, wantErr)
	}
}

func TestRunLeafCommandSuccessBindsDestination(t *testing.T) {
	var gotCN string
	cmd := &cliv3.Command{
		Name:  "test",
		Flags: []cliv3.Flag{&cliv3.StringFlag{Name: "cn", Destination: &gotCN}},
		Action: func(ctx context.Context, c *cliv3.Command) error {
			return nil
		},
	}

	if err := runLeafCommand(cmd, []string{"--cn", "hello"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotCN != "hello" {
		t.Errorf("cn = %q, want %q", gotCN, "hello")
	}
}
