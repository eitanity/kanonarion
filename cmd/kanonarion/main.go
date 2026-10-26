// Copyright 2026 Eitanity Systems VCC / Ейтанити Системи ДПК
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"

	"code.eitanity.com/kanonarion/internal/cli"
	"code.eitanity.com/kanonarion/internal/composition/storage"
	sqlitestorage "code.eitanity.com/kanonarion/internal/composition/storage/sqlite"
)

func main() {
	// Backends are registered here, never from init, so a binary's storage
	// choices are the ones its own main names.
	if err := storage.Register(sqlitestorage.Backend()); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(cli.ExitCodeForError(err))
	}
	if err := cli.Run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(cli.ExitCodeForError(err))
	}
}
