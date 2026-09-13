package cli

import (
	"context"
	"errors"
	"fmt"
	"strings"

	cliv3 "github.com/urfave/cli/v3"
)

// ErrSilent signals that the error's message has already been printed to
// stderr by the code that produced it (e.g. an "Unknown X subcommand"
// line), so the top-level caller in cmd/certifier/main.go should set a
// non-zero exit code without printing anything further.
var ErrSilent = errors.New("silent")

// isFlag reports whether s looks like a command-line flag.
func isFlag(s string) bool {
	return strings.HasPrefix(s, "-")
}

// runLeafCommand runs cmd against args, translating urfave/cli's own
// flag-parsing errors into the "error parsing flags: %w" shape the
// existing *Cmd functions and their tests expect, while passing through
// any error returned by cmd's own Action unwrapped (so business-logic
// error messages like "CA certificate is required" reach callers exactly
// as before).
func runLeafCommand(cmd *cliv3.Command, args []string) error {
	ranAction := false
	action := cmd.Action
	cmd.Action = func(ctx context.Context, c *cliv3.Command) error {
		ranAction = true
		return action(ctx, c)
	}
	cmd.OnUsageError = func(ctx context.Context, c *cliv3.Command, err error, isSubcommand bool) error {
		return err
	}

	err := cmd.Run(context.Background(), append([]string{cmd.Name}, args...))
	if err != nil && !ranAction {
		return fmt.Errorf("error parsing flags: %w", err)
	}
	return err
}

// wrapParseErrors installs the same flag-parsing error translation
// runLeafCommand applies, directly onto cmd, so a leaf command reached
// through the real command tree (not just through its XxxCmd wrapper)
// also reports a flag-parsing failure as "error parsing flags: %w"
// instead of urfave/cli's own "Incorrect Usage: ..." banner.
func wrapParseErrors(cmd *cliv3.Command) *cliv3.Command {
	cmd.OnUsageError = func(ctx context.Context, c *cliv3.Command, err error, isSubcommand bool) error {
		return fmt.Errorf("error parsing flags: %w", err)
	}
	return cmd
}
