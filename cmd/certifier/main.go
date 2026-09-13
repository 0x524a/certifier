package main

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/0x524a/certifier/internal/cli"
)

func main() {
	cmd := cli.RootCommand()
	err := cmd.Run(context.Background(), os.Args)
	if err == nil {
		return
	}
	if !errors.Is(err, cli.ErrSilent) {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
	}
	os.Exit(1)
}
