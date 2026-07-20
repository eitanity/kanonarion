package domain

import (
	"errors"
	"strings"
	"testing"
)

const wellFormed = `package p

// SPDX-SnippetBegin
// SPDX-SnippetCopyrightText: Copyright 2023 Google LLC
// SPDX-License-Identifier: BSD-3-Clause
// SPDX-SnippetName: Capslock classification data
// SPDX-SnippetComment: Transcribed from github.com/google/capslock@v0.3.2, interesting/interesting.cm
var x = 1
// SPDX-SnippetEnd
`

func TestParseSnippets_WellFormedBlock(t *testing.T) {
	atts, err := ParseSnippets("p/f.go", []byte(wellFormed))
	if err != nil {
		t.Fatalf("well-formed block should parse, got: %v", err)
	}
	if len(atts) != 1 {
		t.Fatalf("want 1 attribution, got %d", len(atts))
	}
	a := atts[0]
	if a.SPDX != "BSD-3-Clause" {
		t.Errorf("SPDX = %q, want BSD-3-Clause", a.SPDX)
	}
	if a.Copyright != "Copyright 2023 Google LLC" {
		t.Errorf("Copyright = %q", a.Copyright)
	}
	if a.Coordinate.String() != "github.com/google/capslock@v0.3.2" {
		t.Errorf("Coordinate = %q, want github.com/google/capslock@v0.3.2", a.Coordinate)
	}
	if a.Name != "Capslock classification data" {
		t.Errorf("Name = %q", a.Name)
	}
	if a.SourcePath != "p/f.go" {
		t.Errorf("SourcePath = %q", a.SourcePath)
	}
}

// A file with no snippet tags is the common case and must be silent.
func TestParseSnippets_NoTags(t *testing.T) {
	atts, err := ParseSnippets("p/f.go", []byte("package p\n\nvar x = 1\n"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(atts) != 0 {
		t.Fatalf("want 0 attributions, got %d", len(atts))
	}
}

// The SPDX-SnippetName tag is optional; absent, the coordinate is the name.
func TestParseSnippets_NameDefaultsToCoordinate(t *testing.T) {
	src := strings.Replace(wellFormed, "// SPDX-SnippetName: Capslock classification data\n", "", 1)
	atts, err := ParseSnippets("p/f.go", []byte(src))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if atts[0].Name != "github.com/google/capslock@v0.3.2" {
		t.Errorf("Name = %q, want the origin coordinate", atts[0].Name)
	}
}

// Every defect in an opted-in block is a hard error: a partially tagged block
// must never yield a partial attribution record.
func TestParseSnippets_MalformedBlocks(t *testing.T) {
	tests := []struct {
		name    string
		src     string
		wantErr string
	}{
		{
			name:    "missing licence identifier",
			src:     strings.Replace(wellFormed, "// SPDX-License-Identifier: BSD-3-Clause\n", "", 1),
			wantErr: "missing required SPDX-License-Identifier:",
		},
		{
			name:    "missing copyright text",
			src:     strings.Replace(wellFormed, "// SPDX-SnippetCopyrightText: Copyright 2023 Google LLC\n", "", 1),
			wantErr: "missing required SPDX-SnippetCopyrightText:",
		},
		{
			name:    "missing comment",
			src:     strings.Replace(wellFormed, "// SPDX-SnippetComment: Transcribed from github.com/google/capslock@v0.3.2, interesting/interesting.cm\n", "", 1),
			wantErr: "missing required SPDX-SnippetComment:",
		},
		{
			name:    "comment without origin coordinate",
			src:     strings.Replace(wellFormed, "Transcribed from github.com/google/capslock@v0.3.2, interesting/interesting.cm", "Transcribed from capslock", 1),
			wantErr: "no module@version origin coordinate",
		},
		{
			name:    "compound expression",
			src:     strings.Replace(wellFormed, "BSD-3-Clause", "MIT OR Apache-2.0", 1),
			wantErr: "compound licence expression",
		},
		{
			name:    "unterminated block",
			src:     strings.Replace(wellFormed, "// SPDX-SnippetEnd\n", "", 1),
			wantErr: "unterminated block",
		},
		{
			name:    "nested begin",
			src:     strings.Replace(wellFormed, "var x = 1", "// SPDX-SnippetBegin", 1),
			wantErr: "nested SPDX-SnippetBegin",
		},
		{
			name:    "invalid origin version",
			src:     strings.Replace(wellFormed, "@v0.3.2", "@v0.3.2.4.5", 1),
			wantErr: "invalid origin coordinate",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseSnippets("p/f.go", []byte(tt.src))
			if err == nil {
				t.Fatalf("want an error, got none")
			}
			if !errors.Is(err, ErrMalformedSnippet) {
				t.Errorf("error should wrap ErrMalformedSnippet, got: %v", err)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want it to contain %q", err.Error(), tt.wantErr)
			}
			if !strings.Contains(err.Error(), "p/f.go:3") {
				t.Errorf("error should locate the block, got: %q", err.Error())
			}
		})
	}
}

func TestDedupeSnippets_CollapsesDuplicateCoordinateAndLicence(t *testing.T) {
	atts, err := ParseSnippets("a.go", []byte(wellFormed))
	if err != nil {
		t.Fatal(err)
	}
	second, err := ParseSnippets("b.go", []byte(wellFormed))
	if err != nil {
		t.Fatal(err)
	}
	got, err := DedupeSnippets(append(atts, second...))
	if err != nil {
		t.Fatalf("duplicates should collapse, not error: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 deduped attribution, got %d", len(got))
	}
}

// Two snippets citing one origin under different licences cannot both be
// rendered and cannot be silently reconciled.
func TestDedupeSnippets_ConflictingLicencesError(t *testing.T) {
	a, err := ParseSnippets("a.go", []byte(wellFormed))
	if err != nil {
		t.Fatal(err)
	}
	b, err := ParseSnippets("b.go", []byte(strings.Replace(wellFormed, "BSD-3-Clause", "MIT", 1)))
	if err != nil {
		t.Fatal(err)
	}
	_, err = DedupeSnippets(append(a, b...))
	if err == nil {
		t.Fatal("want a conflicting-licence error, got none")
	}
	if !errors.Is(err, ErrMalformedSnippet) {
		t.Errorf("error should wrap ErrMalformedSnippet, got: %v", err)
	}
	if !strings.Contains(err.Error(), "conflicting licences") {
		t.Errorf("error = %q", err.Error())
	}
}

func TestNoticeEntriesFromSnippets_BuildsEntry(t *testing.T) {
	atts, err := ParseSnippets("internal/capability/domain/sinks.go", []byte(wellFormed))
	if err != nil {
		t.Fatal(err)
	}
	entries, err := NoticeEntriesFromSnippets(atts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("want 1 entry, got %d", len(entries))
	}
	e := entries[0]
	if e.EffectiveSource() != NoticeSourceCopied {
		t.Errorf("Source = %q, want copied-source", e.Source)
	}
	if len(e.LicenseTexts) != 1 || !strings.Contains(e.LicenseTexts[0].Content, "Redistribution and use") {
		t.Errorf("entry should carry the verbatim BSD-3-Clause text, got: %+v", e.LicenseTexts)
	}
	if len(e.Copyrights) != 1 || e.Copyrights[0] != "Copyright 2023 Google LLC" {
		t.Errorf("Copyrights = %v", e.Copyrights)
	}
	if len(e.SourcePaths) != 1 || e.SourcePaths[0] != "internal/capability/domain/sinks.go" {
		t.Errorf("SourcePaths = %v", e.SourcePaths)
	}
}

// An SPDX identifier the embedded table does not cover must fail loudly. A
// record without its licence text is a partial attribution that looks complete.
func TestNoticeEntriesFromSnippets_UnknownSPDXIDError(t *testing.T) {
	atts, err := ParseSnippets("a.go", []byte(strings.Replace(wellFormed, "BSD-3-Clause", "NotALicence-9.9", 1)))
	if err != nil {
		t.Fatal(err)
	}
	_, err = NoticeEntriesFromSnippets(atts)
	if err == nil {
		t.Fatal("want an unknown-identifier error, got none")
	}
	if !errors.Is(err, ErrUnknownSPDXText) {
		t.Errorf("error should wrap ErrUnknownSPDXText, got: %v", err)
	}
}

// One origin cited from several files collapses to a single entry that lists
// every contributing path, so the attribution is traceable.
func TestNoticeEntriesFromSnippets_MergesSourcePaths(t *testing.T) {
	a, err := ParseSnippets("b.go", []byte(wellFormed))
	if err != nil {
		t.Fatal(err)
	}
	b, err := ParseSnippets("a.go", []byte(wellFormed))
	if err != nil {
		t.Fatal(err)
	}
	entries, err := NoticeEntriesFromSnippets(append(a, b...))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("want 1 entry, got %d", len(entries))
	}
	got := strings.Join(entries[0].SourcePaths, ",")
	if got != "a.go,b.go" {
		t.Errorf("SourcePaths = %q, want sorted a.go,b.go", got)
	}
}
