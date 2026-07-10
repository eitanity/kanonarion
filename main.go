// Copyright 2026 Eitanity Systems VCC / Ейтанити Системи ДПК
//
// SPDX-License-Identifier: Apache-2.0

// Command kanonarion is the root entry point for the CLI.
//
// It exists so `go install github.com/eitanity/kanonarion@latest` resolves a
// main package at the module root: `go install <module>@latest` only builds a
// package whose import path equals the module path. The canonical build target
// remains ./cmd/kanonarion (used by the Makefile, release workflow, and the
// --package examples); this file is a thin duplicate of that entry point so the
// bare module coordinate installs the same binary.
package main

import (
	"fmt"
	"os"

	"github.com/eitanity/kanonarion/internal/cli"
)

func main() {
	if err := cli.Run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(cli.ExitCodeForError(err))
	}
}
