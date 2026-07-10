package domain_test

import (
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/license/domain"
)

func TestCopyrightStatusString(t *testing.T) {
	cases := []struct {
		status domain.CopyrightStatus
		want   string
	}{
		{domain.CopyrightStatusNotAnalysed, "not_analysed"},
		{domain.CopyrightStatusFound, "found"},
		{domain.CopyrightStatusNoneFound, "none_found"},
		{domain.CopyrightStatusExtractionFailed, "extraction_failed"},
		{domain.CopyrightStatus(99), "not_analysed"}, // unknown falls through to default
	}
	for _, tc := range cases {
		if got := tc.status.String(); got != tc.want {
			t.Errorf("CopyrightStatus(%d).String() = %q; want %q", int(tc.status), got, tc.want)
		}
	}
}

// TestExtractCopyright_NoNotice verifies that an empty result (not nil check, but
// functionally empty) is returned when no copyright lines are present, satisfying
// the requirement that NoneFound is determined by the caller checking
// the returned slice, not by treating absence as an error.
func TestExtractCopyright_NoNotice(t *testing.T) {
	content := []byte("Permission is hereby granted, free of charge, to any person obtaining a copy.\n")
	got := domain.ExtractCopyright("LICENSE", content)
	if len(got) != 0 {
		t.Errorf("expected no statements, got %d: %+v", len(got), got)
	}
}

func TestExtractCopyright_MIT(t *testing.T) {
	content := []byte("MIT License\n\nCopyright (c) 2020 Alice Smith\n\nPermission is hereby granted...\n")
	got := domain.ExtractCopyright("LICENSE", content)
	if len(got) != 1 {
		t.Fatalf("expected 1 statement, got %d: %+v", len(got), got)
	}
	stmt := got[0]
	if stmt.Verbatim != "Copyright (c) 2020 Alice Smith" {
		t.Errorf("Verbatim = %q; want %q", stmt.Verbatim, "Copyright (c) 2020 Alice Smith")
	}
	if stmt.Years != "2020" {
		t.Errorf("Years = %q; want %q", stmt.Years, "2020")
	}
	if len(stmt.Holders) != 1 || stmt.Holders[0] != "Alice Smith" {
		t.Errorf("Holders = %v; want [Alice Smith]", stmt.Holders)
	}
	if stmt.Source != "LICENSE" {
		t.Errorf("Source = %q; want %q", stmt.Source, "LICENSE")
	}
}

func TestExtractCopyright_BSDMultiHolder(t *testing.T) {
	content := []byte("Copyright (c) 2015-2019 The BSD Authors\nCopyright (c) 2020 Contributor B\n")
	got := domain.ExtractCopyright("LICENSE", content)
	if len(got) != 2 {
		t.Fatalf("expected 2 statements, got %d: %+v", len(got), got)
	}
	// Sorted lexically by Verbatim: "Copyright (c) 2015-2019..." < "Copyright (c) 2020..."
	if got[0].Verbatim != "Copyright (c) 2015-2019 The BSD Authors" {
		t.Errorf("got[0].Verbatim = %q", got[0].Verbatim)
	}
	if got[0].Years != "2015-2019" {
		t.Errorf("got[0].Years = %q; want 2015-2019", got[0].Years)
	}
	if len(got[0].Holders) != 1 || got[0].Holders[0] != "The BSD Authors" {
		t.Errorf("got[0].Holders = %v; want [The BSD Authors]", got[0].Holders)
	}
	if got[1].Verbatim != "Copyright (c) 2020 Contributor B" {
		t.Errorf("got[1].Verbatim = %q", got[1].Verbatim)
	}
}

func TestExtractCopyright_CopyrightGlyph(t *testing.T) {
	content := []byte("© 2021 Glyph Corp\n")
	got := domain.ExtractCopyright("NOTICE", content)
	if len(got) != 1 {
		t.Fatalf("expected 1 statement, got %d: %+v", len(got), got)
	}
	stmt := got[0]
	if stmt.Verbatim != "© 2021 Glyph Corp" {
		t.Errorf("Verbatim = %q; want %q", stmt.Verbatim, "© 2021 Glyph Corp")
	}
	if stmt.Years != "2021" {
		t.Errorf("Years = %q; want 2021", stmt.Years)
	}
	if len(stmt.Holders) != 1 || stmt.Holders[0] != "Glyph Corp" {
		t.Errorf("Holders = %v; want [Glyph Corp]", stmt.Holders)
	}
}

func TestExtractCopyright_CopyrightUnicode(t *testing.T) {
	// Copyright © with Unicode en-dash year range.
	content := []byte("Copyright © 2018–2022 Unicode Corp\n")
	got := domain.ExtractCopyright("LICENSE", content)
	if len(got) != 1 {
		t.Fatalf("expected 1 statement, got %d", len(got))
	}
	if got[0].Years != "2018-2022" {
		t.Errorf("Years = %q; want 2018-2022 (normalised)", got[0].Years)
	}
}

func TestExtractCopyright_ApacheNOTICEBlock(t *testing.T) {
	// Simulate an Apache NOTICE file with multiple copyright lines.
	content := []byte(`Apache Software
Copyright 2014 The Apache Software Foundation

This product includes software developed at
The Apache Software Foundation (http://www.apache.org/).

Copyright 2019 Contributors
`)
	got := domain.ExtractCopyright("NOTICE", content)
	if len(got) != 2 {
		t.Fatalf("expected 2 statements, got %d: %+v", len(got), got)
	}
	// Sorted: "Copyright 2014..." < "Copyright 2019..."
	if got[0].Verbatim != "Copyright 2014 The Apache Software Foundation" {
		t.Errorf("got[0].Verbatim = %q", got[0].Verbatim)
	}
	if got[1].Verbatim != "Copyright 2019 Contributors" {
		t.Errorf("got[1].Verbatim = %q", got[1].Verbatim)
	}
}

func TestExtractCopyright_VerbatimPreservedWhenParsingFails(t *testing.T) {
	// A declaration that starts with "Copyright" but has no parseable year.
	// Verbatim must still be captured exactly; Holders/Years may be empty.
	content := []byte("Copyright Foo Inc.\n")
	got := domain.ExtractCopyright("COPYING", content)
	if len(got) != 1 {
		t.Fatalf("expected 1 statement, got %d", len(got))
	}
	if got[0].Verbatim != "Copyright Foo Inc." {
		t.Errorf("Verbatim = %q; want %q", got[0].Verbatim, "Copyright Foo Inc.")
	}
	if got[0].Years != "" {
		t.Errorf("Years = %q; want empty for line with no year", got[0].Years)
	}
}

// TestExtractCopyright_BSDBoilerplateNotMatched is a regression test for.
// BSD-3-Clause boilerplate lines that reference "copyright" mid-sentence or use
// "copyright notice/holder" as noun phrases must NOT be captured as declarations.
func TestExtractCopyright_BSDBoilerplateNotMatched(t *testing.T) {
	content := []byte(`Copyright 2009 The Go Authors.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

   * Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.
   * Redistributions in binary form must reproduce the above copyright
notice, this list of conditions and the following disclaimer in the
documentation and/or other materials provided with the distribution.
   * Neither the name of Google Inc. nor the names of its
contributors may be used to endorse or promote products derived from
this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
`)
	got := domain.ExtractCopyright("LICENSE", content)
	if len(got) != 1 {
		verbatims := make([]string, len(got))
		for i, s := range got {
			verbatims[i] = s.Verbatim
		}
		t.Fatalf("expected exactly 1 statement (the declaration), got %d: %v", len(got), verbatims)
	}
	if got[0].Verbatim != "Copyright 2009 The Go Authors." {
		t.Errorf("Verbatim = %q; want the actual declaration", got[0].Verbatim)
	}
	if got[0].Years != "2009" {
		t.Errorf("Years = %q; want 2009", got[0].Years)
	}
	if len(got[0].Holders) != 1 || got[0].Holders[0] != "The Go Authors" {
		t.Errorf("Holders = %v; want [The Go Authors]", got[0].Holders)
	}
}

func TestExtractCopyright_SortedLexically(t *testing.T) {
	content := []byte("Copyright (c) 2022 Zeta Inc\nCopyright (c) 2020 Alpha Corp\nCopyright (c) 2021 Beta LLC\n")
	got := domain.ExtractCopyright("LICENSE", content)
	if len(got) != 3 {
		t.Fatalf("expected 3 statements, got %d", len(got))
	}
	want := []string{
		"Copyright (c) 2020 Alpha Corp",
		"Copyright (c) 2021 Beta LLC",
		"Copyright (c) 2022 Zeta Inc",
	}
	for i, w := range want {
		if got[i].Verbatim != w {
			t.Errorf("got[%d].Verbatim = %q; want %q", i, got[i].Verbatim, w)
		}
	}
}

func TestExtractCopyright_SourcePathPropagated(t *testing.T) {
	content := []byte("Copyright 2023 Someone\n")
	got := domain.ExtractCopyright("vendor/dep/NOTICE", content)
	if len(got) != 1 {
		t.Fatalf("expected 1 statement, got %d", len(got))
	}
	if got[0].Source != "vendor/dep/NOTICE" {
		t.Errorf("Source = %q; want %q", got[0].Source, "vendor/dep/NOTICE")
	}
}

// TestExtractCopyright_VerbatimVsParsed verifies the verbatim-first discipline:
// the verbatim field holds the statement with comment markers stripped;
// Holders is a parsed secondary field.
func TestExtractCopyright_VerbatimVsParsed(t *testing.T) {
	raw := "  Copyright (c) 2018, 2019 The Go Authors.  "
	content := []byte(raw + "\n")
	got := domain.ExtractCopyright("LICENSE", content)
	if len(got) != 1 {
		t.Fatalf("expected 1 statement, got %d", len(got))
	}
	stmt := got[0]
	// Verbatim is trimmed and comment-prefix-stripped, otherwise unchanged.
	if stmt.Verbatim != "Copyright (c) 2018, 2019 The Go Authors." {
		t.Errorf("Verbatim = %q; expected trimmed but verbatim line", stmt.Verbatim)
	}
	// Holders is a best-effort extraction — may not perfectly handle comma-
	// separated years, but must not be the same string as Verbatim.
	if len(stmt.Holders) > 0 && stmt.Holders[0] == stmt.Verbatim {
		t.Errorf("Holders[0] == Verbatim; parsed secondary field must differ from verbatim text")
	}
}

// TestExtractCopyright_TrailingConjunctionStripped is a regression test for the
// musl libc math attribution pattern where consecutive copyright lines are joined
// by trailing " or" / " and" conjunctions. These must be stripped from Verbatim.
func TestExtractCopyright_TrailingConjunctionStripped(t *testing.T) {
	content := []byte("Copyright © 1993,2004 Sun Microsystems or\nCopyright © 2003-2011 David Schultz or\nCopyright © 2017-2018 Arm Limited\n")
	got := domain.ExtractCopyright("LICENSE-3RD-PARTY.md", content)
	if len(got) != 3 {
		t.Fatalf("expected 3 statements, got %d: %+v", len(got), got)
	}
	for _, stmt := range got {
		if strings.HasSuffix(stmt.Verbatim, " or") || strings.HasSuffix(stmt.Verbatim, " and") {
			t.Errorf("Verbatim has trailing conjunction: %q", stmt.Verbatim)
		}
		if len(stmt.Holders) > 0 && (strings.HasSuffix(stmt.Holders[0], " or") || strings.HasSuffix(stmt.Holders[0], " and")) {
			t.Errorf("Holders[0] has trailing conjunction: %q", stmt.Holders[0])
		}
	}
	// Verify specific holders are clean.
	found := map[string]bool{}
	for _, s := range got {
		if len(s.Holders) > 0 {
			found[s.Holders[0]] = true
		}
	}
	if !found["Sun Microsystems"] {
		t.Errorf("expected Holders to contain 'Sun Microsystems', got %v", found)
	}
}

// TestExtractCopyright_CommentPrefixStripped verifies that Go source-style comment
// markers are stripped from Verbatim so they don't appear in NOTICE output.
func TestExtractCopyright_CommentPrefixStripped(t *testing.T) {
	content := []byte("// Copyright 2013-2023 The Cobra Authors\n")
	got := domain.ExtractCopyright("root.go", content)
	if len(got) != 1 {
		t.Fatalf("expected 1 statement, got %d", len(got))
	}
	if got[0].Verbatim != "Copyright 2013-2023 The Cobra Authors" {
		t.Errorf("Verbatim = %q; want comment prefix stripped", got[0].Verbatim)
	}
	if got[0].Years != "2013-2023" {
		t.Errorf("Years = %q; want 2013-2023", got[0].Years)
	}
	if len(got[0].Holders) != 1 || got[0].Holders[0] != "The Cobra Authors" {
		t.Errorf("Holders = %v; want [The Cobra Authors]", got[0].Holders)
	}
}

// TestExtractCopyright_LowercaseCopyrightNotMatched is a regression test for
// lowercase "copyright" prose references that should not be captured as
// declarations. Covers the yaml.v3 LICENSE pattern.
func TestExtractCopyright_LowercaseCopyrightNotMatched(t *testing.T) {
	content := []byte(`The following files were ported to Go from C files of libyaml, and thus
are still covered by their original MIT license, with the additional
copyright staring in 2011 when the project was ported over:

Copyright (c) 2006-2011 Kirill Simonov
`)
	got := domain.ExtractCopyright("LICENSE", content)
	if len(got) != 1 {
		verbatims := make([]string, len(got))
		for i, s := range got {
			verbatims[i] = s.Verbatim
		}
		t.Fatalf("expected 1 statement (the real declaration), got %d: %v", len(got), verbatims)
	}
	if got[0].Verbatim != "Copyright (c) 2006-2011 Kirill Simonov" {
		t.Errorf("Verbatim = %q; want the actual declaration", got[0].Verbatim)
	}
}

// TestExtractCopyright_TemplatePlaceholderDropped is a regression test for the
// GPL/AGPL "How to Apply These Terms" appendix scaffold. Lines carrying unfilled
// angle-bracket placeholders like "<year>" / "<name of author>" are template
// text, not a real holder, and must not be captured.
func TestExtractCopyright_TemplatePlaceholderDropped(t *testing.T) {
	content := []byte("Copyright (C) <year>  <name of author>\n")
	got := domain.ExtractCopyright("LICENSE", content)
	if len(got) != 0 {
		t.Fatalf("expected 0 statements for template placeholder, got %d: %+v", len(got), got)
	}
}

// TestExtractCopyright_GenuineCopyrightStillExtractedAlongsideTemplate pairs with
// the template-drop case: a real "Copyright 2020 Acme" line in the same content
// must still extract even though a template placeholder line is dropped.
func TestExtractCopyright_GenuineCopyrightStillExtractedAlongsideTemplate(t *testing.T) {
	content := []byte("Copyright (C) <year>  <name of author>\nCopyright 2020 Acme\n")
	got := domain.ExtractCopyright("LICENSE", content)
	if len(got) != 1 {
		verbatims := make([]string, len(got))
		for i, s := range got {
			verbatims[i] = s.Verbatim
		}
		t.Fatalf("expected 1 statement (the genuine declaration), got %d: %v", len(got), verbatims)
	}
	if got[0].Verbatim != "Copyright 2020 Acme" {
		t.Errorf("Verbatim = %q; want %q", got[0].Verbatim, "Copyright 2020 Acme")
	}
	if got[0].Years != "2020" {
		t.Errorf("Years = %q; want 2020", got[0].Years)
	}
	if len(got[0].Holders) != 1 || got[0].Holders[0] != "Acme" {
		t.Errorf("Holders = %v; want [Acme]", got[0].Holders)
	}
}

// TestExtractCopyright_SquareBracketTemplatesDropped covers the Apache-2.0
// appendix and the MIT/ISC/BSD "how to apply" templates, all of which use
// SQUARE-bracket placeholders. Each must be dropped rather than emitted as a
// bogus copyright (the oklog/ulid defect: "Copyright [yyyy] [name of copyright
// owner]" leaking into the SBOM).
func TestExtractCopyright_SquareBracketTemplatesDropped(t *testing.T) {
	lines := []string{
		"Copyright [yyyy] [name of copyright owner]", // Apache-2.0 appendix
		"Copyright (c) [year] [fullname]",            // MIT / ISC / BSD template
		"Copyright (C) [year] [name of author]",
	}
	for _, line := range lines {
		t.Run(line, func(t *testing.T) {
			got := domain.ExtractCopyright("LICENSE", []byte(line+"\n"))
			if len(got) != 0 {
				t.Fatalf("expected 0 statements for square-bracket template, got %d: %+v", len(got), got)
			}
		})
	}
}

// TestExtractCopyright_CurlyBraceTemplateDropped covers curly-brace placeholder
// variants some templates ship.
func TestExtractCopyright_CurlyBraceTemplateDropped(t *testing.T) {
	content := []byte("Copyright {yyyy} {name of copyright owner}\n")
	got := domain.ExtractCopyright("LICENSE", content)
	if len(got) != 0 {
		t.Fatalf("expected 0 statements for curly-brace template, got %d: %+v", len(got), got)
	}
}

// TestExtractCopyright_OklogUlidApacheCorpus reproduces the exact module that
// surfaced this defect: oklog/ulid ships a stock Apache-2.0 LICENSE whose only
// column-0 "Copyright" line is the appendix template. Extraction must yield
// zero statements rather than the placeholder.
func TestExtractCopyright_OklogUlidApacheCorpus(t *testing.T) {
	content := []byte(`   APPENDIX: How to apply the Apache License to your work.

      To apply the Apache License to your work, attach the following
      boilerplate notice, with the fields enclosed by brackets "[]"
      replaced with your own identifying information. (Don't include
      the brackets!)  The text should be enclosed in the appropriate
      comment syntax for the file format. We also recommend that a
      file or class name and description of purpose be included on the
      same "printed page" as the copyright notice for easier
      identification within third-party archives.

   Copyright [yyyy] [name of copyright owner]

   Licensed under the Apache License, Version 2.0 (the "License");
`)
	got := domain.ExtractCopyright("LICENSE", content)
	if len(got) != 0 {
		verbatims := make([]string, len(got))
		for i, s := range got {
			verbatims[i] = s.Verbatim
		}
		t.Fatalf("expected 0 statements (only the appendix template present), got %d: %v", len(got), verbatims)
	}
}

// TestExtractCopyright_GenuineExtractedAlongsideSquareTemplate verifies a real
// holder is still captured when a square-bracket template line sits alongside
// it, mirroring the angle-bracket pairing test.
func TestExtractCopyright_GenuineExtractedAlongsideSquareTemplate(t *testing.T) {
	content := []byte("Copyright [yyyy] [name of copyright owner]\nCopyright 2020 Acme\n")
	got := domain.ExtractCopyright("LICENSE", content)
	if len(got) != 1 {
		verbatims := make([]string, len(got))
		for i, s := range got {
			verbatims[i] = s.Verbatim
		}
		t.Fatalf("expected 1 statement (the genuine declaration), got %d: %v", len(got), verbatims)
	}
	if got[0].Verbatim != "Copyright 2020 Acme" {
		t.Errorf("Verbatim = %q; want %q", got[0].Verbatim, "Copyright 2020 Acme")
	}
}

// TestExtractCopyright_URLInSquareBracketsNotTemplate guards the sparing logic
// for square brackets: a real holder that lists a bracketed URL or email must
// still extract, just as the angle-bracket case does.
func TestExtractCopyright_URLInSquareBracketsNotTemplate(t *testing.T) {
	content := []byte("Copyright 2020 Acme Corp [https://acme.example/]\n")
	got := domain.ExtractCopyright("LICENSE", content)
	if len(got) != 1 {
		t.Fatalf("expected 1 statement, got %d: %+v", len(got), got)
	}
	if got[0].Verbatim != "Copyright 2020 Acme Corp [https://acme.example/]" {
		t.Errorf("Verbatim = %q; want the URL-bearing declaration preserved", got[0].Verbatim)
	}
}

// TestExtractCopyright_URLInAngleBracketsNotTemplate verifies the placeholder
// filter is narrow: a holder that carries a URL or email in angle brackets is a
// real declaration, not a template scaffold, and must still extract.
func TestExtractCopyright_URLInAngleBracketsNotTemplate(t *testing.T) {
	content := []byte("Copyright 2020 Acme Corp <https://acme.example/>\n")
	got := domain.ExtractCopyright("LICENSE", content)
	if len(got) != 1 {
		t.Fatalf("expected 1 statement, got %d: %+v", len(got), got)
	}
	if got[0].Verbatim != "Copyright 2020 Acme Corp <https://acme.example/>" {
		t.Errorf("Verbatim = %q; want the URL-bearing declaration preserved", got[0].Verbatim)
	}
}

// TestExtractCopyright_FSFLicenseSelfCopyrightDropped is a regression test for the
// GPL/AGPL/LGPL license document carrying the Free Software Foundation's copyright
// on the license *text*. That is boilerplate about the licence, not a fact about
// the licensed work, and must not be captured as the module's copyright.
func TestExtractCopyright_FSFLicenseSelfCopyrightDropped(t *testing.T) {
	content := []byte("Copyright (C) 2007 Free Software Foundation, Inc. <https://fsf.org/>\n")
	got := domain.ExtractCopyright("LICENSE", content)
	if len(got) != 0 {
		t.Fatalf("expected 0 statements for FSF license self-copyright, got %d: %+v", len(got), got)
	}
}

// TestExtractCopyright_VelociraptorAGPLCorpus reproduces the exact corpus module
// that surfaced this defect: a truncated AGPL-3.0 LICENSE whose only two
// "Copyright" lines are the FSF license self-copyright and the appendix template.
// Neither is velociraptor's copyright, so extraction must yield zero statements.
func TestExtractCopyright_VelociraptorAGPLCorpus(t *testing.T) {
	content := []byte(`                    GNU AFFERO GENERAL PUBLIC LICENSE
                       Version 3, 19 November 2007

 Copyright (C) 2007 Free Software Foundation, Inc. <https://fsf.org/>
 Everyone is permitted to copy and distribute verbatim copies
 of this license document, but changing it is not allowed.

  How to Apply These Terms to Your New Programs

    Copyright (C) <year>  <name of author>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.
`)
	got := domain.ExtractCopyright("LICENSE", content)
	if len(got) != 0 {
		verbatims := make([]string, len(got))
		for i, s := range got {
			verbatims[i] = s.Verbatim
		}
		t.Fatalf("expected 0 statements (no real copyright in AGPL text), got %d: %v", len(got), verbatims)
	}
}

func TestMatchesCopyrightHolder(t *testing.T) {
	entries := []domain.LicenseFileEntry{
		{
			Path: "LICENSE",
			CopyrightStatements: []domain.CopyrightStatement{
				{Verbatim: "Copyright 2024 Acme Corp", Holders: []string{"Acme Corp"}, Years: "2024"},
				{Verbatim: "Copyright 2020 Alice Smith", Holders: []string{"Alice Smith"}, Years: "2020"},
			},
		},
	}

	cases := []struct {
		pattern string
		want    bool
	}{
		{"Acme Corp", true},
		{"acme corp", true}, // case-insensitive
		{"ACME", true},      // substring
		{"Alice", true},
		{"smith", true},
		{"Unknown Org", false},
		{"", false}, // empty pattern never matches
	}
	for _, c := range cases {
		t.Run(c.pattern, func(t *testing.T) {
			if got := domain.MatchesCopyrightHolder(entries, c.pattern); got != c.want {
				t.Errorf("MatchesCopyrightHolder(%q) = %v, want %v", c.pattern, got, c.want)
			}
		})
	}
}

func TestMatchesCopyrightHolder_EmptyEntries(t *testing.T) {
	if domain.MatchesCopyrightHolder(nil, "Acme") {
		t.Error("expected false for nil entries")
	}
}
