// Copyright 2026 Eitanity Systems VCC / Ейтанити Системи ДПК
//
// SPDX-License-Identifier: Apache-2.0

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
