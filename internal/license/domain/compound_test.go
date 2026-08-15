package domain_test

import (
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/license/domain"
)

// The fixtures below are cut down from the licence files actually measured in
// the store, keeping the sentence that decides each reading. The point of a
// fixture here is that the deciding sentence, and nothing else, is what moves
// the answer.

// electionText is the gio/go-text shape: the file declares a disjunctive SPDX
// expression and says outright that either licence may be used.
const electionText = `This project is provided under the terms of the UNLICENSE or
the MIT license denoted by the following SPDX identifier:

SPDX-License-Identifier: Unlicense OR MIT

You may use the project under the terms of either license.

Both licenses are reproduced below.

----
The MIT License (MIT)

Copyright (c) 2019 The Gio authors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction.
---

---
The UNLICENSE

This is free and unencumbered software released into the public domain.
---
`

// splitText is the yaml.v3 shape: two licences, each covering named files, and
// no choice offered anywhere in the document.
const splitText = `
This project is covered by two different licenses: MIT and Apache.

#### MIT License ####

The following files were ported to Go from C files of libyaml, and thus
are still covered by their original MIT license:

    apic.go emitterc.go parserc.go readerc.go scannerc.go

Copyright (c) 2006-2010 Kirill Simonov

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction.

### Apache License ###

All the remaining project files are covered by the Apache license:

Copyright (c) 2011-2019 Canonical Ltd

   TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION

Licensed under the Apache License, Version 2.0 (the "License").
`

// bundledText is the OpenTelemetry shape: the module's own Apache-2.0 grant,
// a separator, and then a grant belonging to code the module carries, standing
// behind its own copyright holder.
const bundledText = `                                 Apache License
                           Version 2.0, January 2004

   TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION

   1. Definitions.

   END OF TERMS AND CONDITIONS

   APPENDIX: How to apply the Apache License to your work.

   Copyright [yyyy] [name of copyright owner]

   Licensed under the Apache License, Version 2.0 (the "License");

--------------------------------------------------------------------------------

Copyright 2009 The Go Authors.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:
`

// bundledFirstIsSmallerText is the sean-/seed shape, and the reason the
// module's own licence cannot be taken to be the most-covered match: a short
// MIT grant for the module's own code, then a full BSD-3-Clause for a routine
// cribbed from the Go standard library. The BSD text is longer, so the
// detector reports it as the primary; it is still not this module's licence.
const bundledFirstIsSmallerText = `MIT License

Copyright (c) 2017 Sean Chittenden

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction.

=====

Bits of Go-lang's ` + "`once.Do()`" + ` were cribbed and reused here, too.

Copyright (c) 2009 The Go Authors. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:
`

// omnibusText is the klauspost/compress shape: the module's own grant first,
// then further grants each scoped by a "Files:" stanza to a bundled
// sub-directory.
const omnibusText = `Copyright (c) 2012 The Go Authors. All rights reserved.
Copyright (c) 2019 Klaus Post. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

------------------

Files: gzhttp/*

                                 Apache License
                           Version 2.0, January 2004

   TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION

   END OF TERMS AND CONDITIONS

   Copyright 2016-2017 The New York Times Company

------------------

Files: s2/cmd/internal/readahead/*

The MIT License (MIT)

Copyright (c) 2015 Klaus Post

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction.
`

// ambiguousText carries two full grants and says nothing about how they
// relate: no choice, no scope, and no second copyright holder to show that
// either grant belongs to somebody else's code.
const ambiguousText = `Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met.
`

// apacheOnlyText is the control for the phrase list: Apache-2.0 section 9
// contains "you may choose to offer", and it must not be read as an election.
// Every Apache-2.0 licence file in the corpus contains this sentence.
const apacheOnlyText = `                                 Apache License
                           Version 2.0, January 2004

   TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION

   9. Accepting Warranty or Additional Liability. While redistributing
      the Work or Derivative Works thereof, You may choose to offer,
      and charge a fee for, acceptance of support, warranty, indemnity,
      or other liability obligations.

   END OF TERMS AND CONDITIONS

Redistribution and use in source and binary forms is also permitted.
`

func TestReadCompoundFile_Election(t *testing.T) {
	got := domain.ReadCompoundFile(electionText, []string{"Unlicense", "MIT"})
	if got.Shape != domain.ShapeElection {
		t.Fatalf("shape = %v, want election (evidence %q)", got.Shape, got.Evidence)
	}
	if len(got.Own) != 2 || got.Own[0] != "MIT" || got.Own[1] != "Unlicense" {
		t.Errorf("own = %v, want both arms", got.Own)
	}
	if len(got.Bundled) != 0 {
		t.Errorf("bundled = %v, want none", got.Bundled)
	}
}

func TestReadCompoundFile_Split(t *testing.T) {
	got := domain.ReadCompoundFile(splitText, []string{"MIT", "Apache-2.0"})
	if got.Shape != domain.ShapeSplit {
		t.Fatalf("shape = %v, want split (evidence %q)", got.Shape, got.Evidence)
	}
	if len(got.Own) != 2 {
		t.Errorf("own = %v, want both grants — a split elects nothing away", got.Own)
	}
}

func TestReadCompoundFile_BundledGrant(t *testing.T) {
	got := domain.ReadCompoundFile(bundledText, []string{"Apache-2.0", "BSD-3-Clause"})
	if got.Shape != domain.ShapeBundledGrant {
		t.Fatalf("shape = %v, want bundled-grant (evidence %q)", got.Shape, got.Evidence)
	}
	if len(got.Own) != 1 || got.Own[0] != "Apache-2.0" {
		t.Errorf("own = %v, want [Apache-2.0]", got.Own)
	}
	if len(got.Bundled) != 1 || got.Bundled[0] != "BSD-3-Clause" {
		t.Errorf("bundled = %v, want [BSD-3-Clause]", got.Bundled)
	}
	if !strings.Contains(got.Evidence, "go authors") {
		t.Errorf("evidence = %q, want the copyright notice that introduced the grant", got.Evidence)
	}
}

// TestReadCompoundFile_BundledGrantOutrunsOwn pins the case that defeats every
// confidence-based reading: the bundled grant covers more of the file than the
// module's own does.
func TestReadCompoundFile_BundledGrantOutrunsOwn(t *testing.T) {
	got := domain.ReadCompoundFile(bundledFirstIsSmallerText, []string{"BSD-3-Clause", "MIT"})
	if got.Shape != domain.ShapeBundledGrant {
		t.Fatalf("shape = %v, want bundled-grant (evidence %q)", got.Shape, got.Evidence)
	}
	if len(got.Own) != 1 || got.Own[0] != "MIT" {
		t.Errorf("own = %v, want [MIT] — the grant the module itself makes", got.Own)
	}
}

func TestReadCompoundFile_Unstated(t *testing.T) {
	got := domain.ReadCompoundFile(ambiguousText, []string{"MIT", "BSD-3-Clause"})
	if got.Shape != domain.ShapeUnstated {
		t.Fatalf("shape = %v, want unstated (evidence %q)", got.Shape, got.Evidence)
	}
	if got.Evidence == "" {
		t.Error("evidence is empty; an unstated reading must still say why")
	}
}

// TestReadCompoundFile_ApacheSectionNineIsNotAnElection is the control on the
// phrase list. "You may choose to offer" is Apache-2.0's own boilerplate, so a
// phrase list containing "may choose" would read every Apache-2.0 file as an
// election.
func TestReadCompoundFile_ApacheSectionNineIsNotAnElection(t *testing.T) {
	if !strings.Contains(apacheOnlyText, "You may choose to offer") {
		t.Fatal("fixture no longer carries the Apache-2.0 section 9 sentence")
	}
	got := domain.ReadCompoundFile(apacheOnlyText, []string{"Apache-2.0", "BSD-3-Clause"})
	if got.Shape == domain.ShapeElection {
		t.Errorf("Apache-2.0 section 9 read as an election (evidence %q)", got.Evidence)
	}
}

// TestDeriveExpressionResult_Shapes runs the four shapes through the
// expression, which is where the reading becomes a legal claim.
func TestDeriveExpressionResult_Shapes(t *testing.T) {
	cases := []struct {
		name       string
		primary    string
		alt        string
		text       string
		wantExpr   string
		wantBasis  string
		wantBundle string
	}{
		{
			name: "election stays an election", primary: "Unlicense", alt: "MIT",
			text: electionText, wantExpr: "MIT OR Unlicense", wantBasis: "election:",
		},
		{
			name: "per-file split is a conjunction", primary: "MIT", alt: "Apache-2.0",
			text: splitText, wantExpr: "Apache-2.0 AND MIT", wantBasis: "split:",
		},
		{
			name: "bundled grant leaves the expression", primary: "Apache-2.0", alt: "BSD-3-Clause",
			text: bundledText, wantExpr: "Apache-2.0", wantBasis: "bundled-grant:", wantBundle: "BSD-3-Clause",
		},
		{
			name: "unstated is conservative", primary: "MIT", alt: "BSD-3-Clause",
			text: ambiguousText, wantExpr: "BSD-3-Clause AND MIT", wantBasis: "conservative:",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			entries := []domain.LicenseFileEntry{{
				Path:       "LICENSE",
				SPDX:       tc.primary,
				Confidence: 0.99,
				AltMatches: []domain.AltMatch{{SPDX: tc.alt, Confidence: 0.99}},
			}}
			res := domain.DeriveExpressionResult(entries, map[string]string{"LICENSE": tc.text})
			if res.Expression != tc.wantExpr {
				t.Errorf("expression = %q, want %q", res.Expression, tc.wantExpr)
			}
			if !strings.HasPrefix(res.Basis, tc.wantBasis) {
				t.Errorf("basis = %q, want it to begin %q", res.Basis, tc.wantBasis)
			}
			if tc.wantBundle == "" {
				if len(res.BundledSPDXs) != 0 {
					t.Errorf("bundled = %v, want none", res.BundledSPDXs)
				}
			} else if len(res.BundledSPDXs) != 1 || res.BundledSPDXs[0] != tc.wantBundle {
				t.Errorf("bundled = %v, want [%s]", res.BundledSPDXs, tc.wantBundle)
			}
		})
	}
}

// TestDeriveExpressionResult_BundledGrantIsNeverAnArm states the acceptance
// for the OpenTelemetry shape in the terms a consumer cares about: whatever
// the expression says, it must not offer BSD-3-Clause as a licence anybody may
// elect for OpenTelemetry's own code.
func TestDeriveExpressionResult_BundledGrantIsNeverAnArm(t *testing.T) {
	entries := []domain.LicenseFileEntry{{
		Path:       "LICENSE",
		SPDX:       "Apache-2.0",
		Confidence: 1.0,
		AltMatches: []domain.AltMatch{{SPDX: "BSD-3-Clause", Confidence: 1.0}},
	}}
	res := domain.DeriveExpressionResult(entries, map[string]string{"LICENSE": bundledText})
	if arms := domain.DisjunctionArms(res.Expression); len(arms) != 0 {
		t.Errorf("expression %q offers an election over %v", res.Expression, arms)
	}
	if strings.Contains(res.Expression, "BSD-3-Clause") {
		t.Errorf("expression %q names the bundled grant as a licence of the module", res.Expression)
	}
}
