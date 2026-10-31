// Copyright 2026 Eitanity Systems VCC / Ейтанити Системи ДПК
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"

	"code.eitanity.com/kanonarion/internal/cli"
	"code.eitanity.com/kanonarion/internal/composition/storage"
	sqlitestorage "code.eitanity.com/kanonarion/internal/composition/storage/sqlite"
)

func main() {
	// Backends are registered here, never from init, so a binary's storage
	// choices are the ones its own main names.
	if code := cli.ExitStatus(storage.Register(sqlitestorage.Backend()), os.Stderr); code != cli.ExitOK {
		os.Exit(code)
	}
	if code := cli.ExitStatus(cli.Run(os.Args[1:], os.Stdout, os.Stderr), os.Stderr); code != cli.ExitOK {
		os.Exit(code)
	}
}
