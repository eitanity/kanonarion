// Copyright 2026 Eitanity Systems VCC / Ейтанити Системи ДПК
//
// SPDX-License-Identifier: Apache-2.0

// Command kanonarion is the root entry point for the CLI.
//
// It exists so `go install code.eitanity.com/kanonarion@latest` resolves a
// main package at the module root: `go install <module>@latest` only builds a
// package whose import path equals the module path. The canonical build target
// remains ./cmd/kanonarion (used by the Makefile, release workflow, and the
// --package examples); this file is a thin duplicate of that entry point so the
// bare module coordinate installs the same binary.
package main

import (
	"os"

	"code.eitanity.com/kanonarion/internal/cli"
	"code.eitanity.com/kanonarion/internal/composition/storage"
	sqlitestorage "code.eitanity.com/kanonarion/internal/composition/storage/sqlite"
)

func main() {
	if code := cli.ExitStatus(storage.Register(sqlitestorage.Backend()), os.Stderr); code != cli.ExitOK {
		os.Exit(code)
	}
	if code := cli.ExitStatus(cli.Run(os.Args[1:], os.Stdout, os.Stderr), os.Stderr); code != cli.ExitOK {
		os.Exit(code)
	}
}
