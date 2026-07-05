package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/eitanity/kanonarion/internal/cli"
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
)

func main() {
	if err := cli.Run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(exitCodeForError(err))
	}
}

func exitCodeForError(err error) int {
	if err == nil {
		return cli.ExitOK
	}
	// Honour an explicit exit-code carrier on the error chain so commands can
	// signal categories like ExitNotFound without colliding with the
	// generic ExitConfig fallback.
	if code, ok := cli.ExitCodeFromError(err); ok {
		return code
	}
	if errors.Is(err, walkports.ErrWalkIntegrity) {
		return cli.ExitIntegrity
	}
	return cli.ExitConfig
}
