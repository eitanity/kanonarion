package domain

import (
	"sort"
	"strings"
)

// CompoundShape names what one licence file's own prose says about the several
// licence grants it carries. A detector reports which texts are present; only
// the prose says how they relate, and those are different questions. A file
// carrying two full licence texts at equal coverage is equally consistent with
// an election, a split, and a bundled third-party grant, so the count of texts
// can never decide between them.
type CompoundShape int

const (
	// ShapeUnstated means the file carries several grants and says nothing
	// about how they relate. It is the residual reading, not a failure.
	ShapeUnstated CompoundShape = iota
	// ShapeElection means the file offers the consumer a choice: it declares a
	// disjunctive SPDX expression, or says the work may be used under the
	// terms of either licence.
	ShapeElection
	// ShapeSplit means different parts of the module are under different
	// licences — named files, named components, or contributions that were
	// never relicensed. Every grant governs some shipped code, so all of them
	// apply and none may be elected away.
	ShapeSplit
	// ShapeBundledGrant means a later grant belongs to third-party code
	// carried inside the module, not to the module's own code. It is neither
	// an election nor a conjunction of the module's obligations: the module is
	// licensed under its own grant, and the bundled text travels with the file
	// it is written in.
	ShapeBundledGrant
)

// String names the shape for a basis string.
func (s CompoundShape) String() string {
	switch s {
	case ShapeElection:
		return "election"
	case ShapeSplit:
		return "split"
	case ShapeBundledGrant:
		return "bundled-grant"
	default:
		return "unstated"
	}
}

// CompoundReading is what the prose of one licence file was read to say.
type CompoundReading struct {
	Shape CompoundShape
	// Own lists the identifiers granted for the module's own code, in SPDX
	// sort order. For an election these are the arms; for a split they are the
	// conjuncts; for a bundled grant it is the single grant the module makes.
	Own []string
	// Bundled lists identifiers carried in the file that grant rights in
	// somebody else's code. Never empty for ShapeBundledGrant, always empty
	// otherwise.
	Bundled []string
	// Evidence is the verbatim phrase from the file that decided the reading,
	// or a stated reason when nothing in the file decided it.
	Evidence string
}

// electionPhrases are the phrases by which a licence file offers a choice.
//
// "may choose" is deliberately absent. Apache-2.0 section 9 reads "you may
// choose to offer, and charge a fee for, acceptance of support, warranty,
// indemnity", so every Apache-2.0 file in the corpus contains it and it
// separates nothing. An election phrase must be one that a licence's own
// boilerplate does not contain.
var electionPhrases = []string{
	"under the terms of either",
	"at your option",
	"either license",
	"either licence",
	"dual-licensed",
	"dual licensed",
	"you may choose either",
	"choice of either",
}

// splitPhrases are the phrases by which a licence file assigns different
// licences to different parts of the work. They name what each grant covers —
// files, components, or contributions — which is the thing an election never
// does.
var splitPhrases = []string{
	"covered by two different licenses",
	"covered by two different licences",
	"the following files",
	"all the remaining",
	"remain licensed under",
	"are licensed under",
	"is licensed under",
	"the remaining files",
	"remaining project files",
}

// licenceTextAnchors maps an SPDX identifier to a phrase that occurs in that
// licence's own text and in no other licence's text. It answers one question:
// where in the file does this grant begin. Ordering is what separates the
// module's own grant from a grant it carries — the module's own comes first,
// and a bundled one follows behind its own copyright notice.
//
// An identifier absent from this table cannot be ordered, and a file whose
// identifiers cannot all be ordered is read as unstated rather than guessed at.
var licenceTextAnchors = map[string]string{
	"MIT":              "permission is hereby granted, free of charge",
	"Apache-2.0":       "terms and conditions for use, reproduction, and distribution",
	"BSD-3-Clause":     "redistribution and use in source and binary forms",
	"BSD-2-Clause":     "redistribution and use in source and binary forms",
	"ISC":              "permission to use, copy, modify, and/or distribute this software",
	"Unlicense":        "free and unencumbered software released into the public domain",
	"MPL-2.0":          "mozilla public license",
	"CC-BY-4.0":        "creative commons attribution 4.0",
	"CC-BY-SA-4.0":     "creative commons attribution-sharealike 4.0",
	"CC-BY-SA-3.0":     "creative commons attribution-sharealike 3.0",
	"OFL-1.1":          "sil open font license",
	"Zlib":             "this software is provided 'as-is', without any express",
	"BSL-1.0":          "boost software license",
	"GPL-2.0":          "gnu general public license",
	"GPL-3.0":          "gnu general public license",
	"AGPL-3.0":         "gnu affero general public license",
	"LGPL-3.0":         "gnu lesser general public license",
	"Python-2.0":       "python software foundation license",
	"BSD-3-Clause-New": "redistribution and use in source and binary forms",
}

// bundledCopyrightWindow is how far back from the start of a later grant the
// reading looks for the copyright notice that introduces it. A bundled grant
// is introduced by its own copyright holder, usually immediately above the
// text and often behind a separator rule; 600 bytes covers a separator, a
// blank line, a sentence of explanation and the notice itself.
const bundledCopyrightWindow = 600

// apachePlaceholderCopyright is the copyright line in the Apache-2.0 appendix.
// It names nobody — it is the boilerplate an adopter fills in — so it must not
// be read as a third party asserting rights in bundled code.
const apachePlaceholderCopyright = "copyright [yyyy]"

// ReadCompoundFile reads the prose of a licence file carrying several grants
// and says how they relate. ids are the distinct SPDX identifiers the detector
// found in the file at near-equal coverage, most-covered first; text is the
// file verbatim.
//
// The readings are tried in order, and the order is load-bearing:
//
//  1. An election, because a file that declares a choice has settled the
//     question and nothing later may overturn it.
//  2. A split, because a file that says which parts each licence covers has
//     also settled it — and a split file names several copyright holders, so
//     testing for a bundled grant first would misread every one of them.
//  3. A bundled grant, read from a later grant standing behind its own
//     copyright notice or behind a "Files:" stanza scoping it to named paths.
//  4. Unstated. The file carries several grants and does not say how they
//     relate; the caller is told so rather than handed a guess.
func ReadCompoundFile(text string, ids []string) CompoundReading {
	ids = dedupeSorted(ids)
	if len(ids) < 2 {
		return CompoundReading{Shape: ShapeUnstated, Own: ids, Evidence: "single grant"}
	}
	lower := strings.ToLower(text)

	if phrase, ok := declaredElection(lower); ok {
		return CompoundReading{Shape: ShapeElection, Own: ids, Evidence: phrase}
	}
	if phrase, ok := firstPhrase(lower, splitPhrases); ok {
		return CompoundReading{Shape: ShapeSplit, Own: ids, Evidence: phrase}
	}
	if reading, ok := bundledGrant(lower, ids); ok {
		return reading
	}
	return CompoundReading{
		Shape:    ShapeUnstated,
		Own:      ids,
		Evidence: "no statement of how the grants relate",
	}
}

// declaredElection reports an explicit offer of a choice: a disjunctive
// SPDX-License-Identifier line, or one of the phrases by which a project says
// the consumer may use either licence.
func declaredElection(lower string) (string, bool) {
	const tag = "spdx-license-identifier:"
	if idx := strings.Index(lower, tag); idx >= 0 {
		line := lower[idx+len(tag):]
		if nl := strings.IndexByte(line, '\n'); nl >= 0 {
			line = line[:nl]
		}
		if strings.Contains(line, " or ") {
			return tag + line, true
		}
	}
	return firstPhrase(lower, electionPhrases)
}

// firstPhrase returns the phrase from phrases that occurs earliest in lower.
func firstPhrase(lower string, phrases []string) (string, bool) {
	best, bestAt := "", -1
	for _, p := range phrases {
		at := strings.Index(lower, p)
		if at < 0 {
			continue
		}
		if bestAt < 0 || at < bestAt {
			best, bestAt = p, at
		}
	}
	return best, bestAt >= 0
}

// bundledGrant reads the file as a module's own grant followed by one or more
// grants in third-party code it carries. Every later grant must stand behind a
// copyright notice naming somebody: that notice is the whole evidence that the
// grant belongs to another author's code rather than to this module's.
func bundledGrant(lower string, ids []string) (CompoundReading, bool) {
	offsets, ok := anchorOffsets(lower, ids)
	if !ok {
		return CompoundReading{}, false
	}
	ordered := make([]string, 0, len(ids))
	for id := range offsets {
		ordered = append(ordered, id)
	}
	sort.Slice(ordered, func(i, j int) bool {
		if offsets[ordered[i]] != offsets[ordered[j]] {
			return offsets[ordered[i]] < offsets[ordered[j]]
		}
		return ordered[i] < ordered[j]
	})

	own := ordered[0]
	var bundled []string
	evidence := ""
	for _, id := range ordered[1:] {
		notice, found := grantIntroduction(lower, offsets[id])
		if !found {
			return CompoundReading{}, false
		}
		if evidence == "" {
			evidence = notice
		}
		bundled = append(bundled, id)
	}
	if len(bundled) == 0 {
		return CompoundReading{}, false
	}
	return CompoundReading{
		Shape:    ShapeBundledGrant,
		Own:      []string{own},
		Bundled:  dedupeSorted(bundled),
		Evidence: evidence,
	}, true
}

// anchorOffsets locates the start of every identifier's licence text. It fails
// when an identifier has no anchor, when an anchor does not occur, or when two
// identifiers land on the same offset — in each case the grants cannot be put
// in order, and an order that is not established is not assumed.
func anchorOffsets(lower string, ids []string) (map[string]int, bool) {
	offsets := make(map[string]int, len(ids))
	used := make(map[int]bool, len(ids))
	for _, id := range ids {
		anchor, known := licenceTextAnchors[id]
		if !known {
			return nil, false
		}
		at := strings.Index(lower, anchor)
		if at < 0 || used[at] {
			return nil, false
		}
		used[at] = true
		offsets[id] = at
	}
	return offsets, true
}

// grantIntroduction returns the marker standing immediately above the grant
// that begins at offset, showing the grant to be somebody else's rather than
// this module's. Two markers count, and the nearer one is reported:
//
//   - a "Files: <glob>" stanza, which scopes the grant to named paths and so
//     says outright that it does not cover the module's own code; and
//   - a copyright notice, which names the author asserting rights in the code
//     the grant covers.
//
// A grant with neither is not read as bundled. The module's own licence is
// then indistinguishable from a second grant over the same code, and the
// caller is told the file said nothing.
func grantIntroduction(lower string, offset int) (string, bool) {
	notice, hasNotice := introducingCopyright(lower, offset)
	stanza, hasStanza := introducingFilesStanza(lower, offset)
	switch {
	case hasNotice && hasStanza:
		if strings.LastIndex(lower[:offset], stanza) > strings.LastIndex(lower[:offset], notice) {
			return stanza, true
		}
		return notice, true
	case hasStanza:
		return stanza, true
	case hasNotice:
		return notice, true
	}
	return "", false
}

// introducingFilesStanza returns the "Files: <glob>" line standing above the
// grant beginning at offset. The convention comes from machine-readable
// copyright files and means the same thing here: this grant covers these paths
// and not the rest of the work.
func introducingFilesStanza(lower string, offset int) (string, bool) {
	start := offset - bundledCopyrightWindow
	if start < 0 {
		start = 0
	}
	window := lower[start:offset]
	at := strings.LastIndex(window, "\nfiles:")
	if at < 0 {
		return "", false
	}
	line := strings.TrimSpace(window[at+1:])
	if nl := strings.IndexByte(line, '\n'); nl >= 0 {
		line = line[:nl]
	}
	if len(line) <= len("files:") {
		return "", false
	}
	return line, true
}

// introducingCopyright returns the copyright notice standing immediately above
// the grant that begins at offset, if there is one.
//
// A notice must carry a year. That requirement does the work of two
// exclusions: the Apache-2.0 appendix placeholder "Copyright [yyyy] [name of
// copyright owner]" names nobody and asserts nothing, and the word "copyright"
// inside a licence's own operative text ("a perpetual ... copyright license to
// reproduce") is not an assertion of authorship either.
func introducingCopyright(lower string, offset int) (string, bool) {
	start := offset - bundledCopyrightWindow
	if start < 0 {
		start = 0
	}
	window := lower[start:offset]
	for {
		at := strings.LastIndex(window, "copyright")
		if at < 0 {
			return "", false
		}
		line := window[at:]
		if nl := strings.IndexByte(line, '\n'); nl >= 0 {
			line = line[:nl]
		}
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, apachePlaceholderCopyright) && containsYear(line) {
			return line, true
		}
		window = window[:at]
	}
}

// containsYear reports whether s carries a four-digit run, the mark of a
// copyright notice as against a mention of the word.
func containsYear(s string) bool {
	digits := 0
	for i := range len(s) {
		if s[i] >= '0' && s[i] <= '9' {
			digits++
			if digits == 4 {
				return true
			}
			continue
		}
		digits = 0
	}
	return false
}
