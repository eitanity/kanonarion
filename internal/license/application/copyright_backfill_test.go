package application

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"

	"github.com/eitanity/kanonarion/internal/adapters/ziparchive"

	domain2 "github.com/eitanity/kanonarion/internal/license/domain"
)

func buildArchive(t *testing.T, files map[string]string) *ziparchive.Archive {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("zip create %s: %v", name, err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatalf("zip write %s: %v", name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	a, err := ziparchive.New(buf.Bytes())
	if err != nil {
		t.Fatalf("ziparchive.New: %v", err)
	}
	return a
}

func rootEntry() []domain2.LicenseFileEntry {
	return []domain2.LicenseFileEntry{{Path: "LICENSE", SPDX: "AGPL-3.0"}}
}

func collected(entries []domain2.LicenseFileEntry) []domain2.CopyrightStatement {
	return entries[0].CopyrightStatements
}

// The regression: a module whose .go files all live under subdirectories
// reported "copyright: none found" because the backfill only walked root-level
// files. documize/community is the real-world case — 227 nested .go files, each
// carrying a copyright header, none at the module root.
func TestBackfillCopyrightScansNestedSourceFiles(t *testing.T) {
	const header = "// Copyright 2016 Documize Inc. <legal@documize.com>. All rights reserved.\n"
	archive := buildArchive(t, map[string]string{
		"example.com/mod@v1.0.0/LICENSE":              "AGPL text",
		"example.com/mod@v1.0.0/edition/community.go": header + "package main\n",
		"example.com/mod@v1.0.0/core/env/runtime.go":  header + "package env\n",
	})
	entries := rootEntry()

	uc := &ExtractLicenseUseCase{}
	uc.backfillCopyrightFromSource(context.Background(),
		coordinate.ModuleCoordinate{Path: "example.com/mod", Version: "v1.0.0"},
		archive, entries)

	stmts := collected(entries)
	if len(stmts) != 1 {
		t.Fatalf("got %d statements, want 1 (deduplicated): %+v", len(stmts), stmts)
	}
	if !strings.Contains(stmts[0].Verbatim, "Documize Inc.") {
		t.Errorf("Verbatim = %q, want it to name the holder", stmts[0].Verbatim)
	}
	if stmts[0].Source != "<source-headers>" {
		t.Errorf("Source = %q, want <source-headers>", stmts[0].Source)
	}
}

// Vendored code carries the copyright of the vendored dependency, not of the
// module under analysis, so it must not be attributed to this module.
func TestBackfillCopyrightSkipsVendoredSources(t *testing.T) {
	archive := buildArchive(t, map[string]string{
		"example.com/mod@v1.0.0/vendor/other.com/dep/dep.go": "// Copyright 2011 Someone Else\npackage dep\n",
		"example.com/mod@v1.0.0/internal/a/a.go":             "// Copyright 2020 Real Holder Ltd\npackage a\n",
	})
	entries := rootEntry()

	uc := &ExtractLicenseUseCase{}
	uc.backfillCopyrightFromSource(context.Background(),
		coordinate.ModuleCoordinate{Path: "example.com/mod", Version: "v1.0.0"},
		archive, entries)

	for _, s := range collected(entries) {
		if strings.Contains(s.Verbatim, "Someone Else") {
			t.Errorf("vendored copyright leaked into module attribution: %q", s.Verbatim)
		}
	}
	if len(collected(entries)) != 1 {
		t.Fatalf("got %d statements, want 1", len(collected(entries)))
	}
}

// Which files fall inside copyrightMaxFiles must not depend on archive
// ordering, or the reported holders drift between runs of the same input.
func TestBackfillCopyrightIsDeterministicAtTheFileCap(t *testing.T) {
	files := map[string]string{}
	// More files than the cap, each with a distinct holder, so the set that
	// survives truncation is observable.
	for i := range copyrightMaxFiles + 50 {
		files[fmt.Sprintf("example.com/mod@v1.0.0/pkg%04d/f.go", i)] =
			fmt.Sprintf("// Copyright 2020 Holder %04d\npackage p\n", i)
	}
	archive := buildArchive(t, files)

	var first []domain2.CopyrightStatement
	for range 3 {
		entries := rootEntry()
		uc := &ExtractLicenseUseCase{}
		uc.backfillCopyrightFromSource(context.Background(),
			coordinate.ModuleCoordinate{Path: "example.com/mod", Version: "v1.0.0"},
			archive, entries)
		got := collected(entries)
		if len(got) != copyrightMaxFiles {
			t.Fatalf("got %d statements, want %d (the cap)", len(got), copyrightMaxFiles)
		}
		if first == nil {
			first = got
			continue
		}
		for i := range got {
			if got[i].Verbatim != first[i].Verbatim {
				t.Fatalf("run differed at %d: %q vs %q", i, got[i].Verbatim, first[i].Verbatim)
			}
		}
	}
}
