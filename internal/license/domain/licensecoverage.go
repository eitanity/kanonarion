package domain

import (
	"sort"
	"strings"
)

// LicenseCoverage says what one identified licence governs inside a module:
// the module's own Go code, documentation shipped beside it, or third-party
// material the module carries.
//
// A record that names only WHICH licences a module holds hands a consumer a
// font's share-alike condition as though the Go library imposed it. Coverage is
// the missing half of the fact, and it is derived from the licence files rather
// than stored: it is a function of what was extracted, so it stays consistent
// with the entries the way EffectiveSet and PackageLicenses do.
type LicenseCoverage int

const (
	// CoverageNotDetermined means the artefact does not establish what the
	// licence covers. It is the zero value and a real answer, not an absence:
	// a module whose only grant is a content licence may genuinely be licensed
	// that way, and saying so beats assuming either reading.
	CoverageNotDetermined LicenseCoverage = iota
	// CoverageModuleCode means the licence governs the module's own source.
	CoverageModuleCode
	// CoverageDocumentation means the licence governs documentation the module
	// ships, not the code a consumer compiles.
	CoverageDocumentation
	// CoverageBundledComponent means the licence governs third-party material
	// carried inside the module — a vendored library, an embedded font — and
	// not the module's own code.
	CoverageBundledComponent
	// CoverageAttributionOnly means the file is a NOTICE: an attribution
	// document that grants nothing, so there is no coverage to state. It is a
	// separate answer from NotDetermined because it is not uncertainty — the
	// detector routinely matches a NOTICE against the licence it reproduces
	// (21 of the store's entries are a root NOTICE identified as Apache-2.0),
	// and calling those undetermined would report a settled fact as a doubt.
	CoverageAttributionOnly
)

// String returns the human-readable name of the coverage, spelled as the other
// licence enums spell theirs.
func (c LicenseCoverage) String() string {
	switch c {
	case CoverageModuleCode:
		return "ModuleCode"
	case CoverageDocumentation:
		return "Documentation"
	case CoverageBundledComponent:
		return "BundledComponent"
	case CoverageAttributionOnly:
		return "AttributionOnly"
	default:
		return "NotDetermined"
	}
}

// Covers phrases the coverage for a sentence about one identifier, e.g.
// "CC-BY-SA-4.0 covers documentation".
func (c LicenseCoverage) Covers() string {
	switch c {
	case CoverageModuleCode:
		return "covers this module's code"
	case CoverageDocumentation:
		return "covers documentation"
	case CoverageBundledComponent:
		return "covers a bundled component"
	case CoverageAttributionOnly:
		return "grants nothing: an attribution document"
	default:
		return "covers something this artefact does not establish"
	}
}

// MarshalJSON implements json.Marshaler. The coverage travels as the name, on
// the same terms as LicenseStatus and CopyrightStatus, and it is emitted
// always: an absent field would make "governs the code" indistinguishable from
// "this build does not derive coverage".
func (c LicenseCoverage) MarshalJSON() ([]byte, error) {
	return []byte(`"` + c.String() + `"`), nil
}

// UnmarshalJSON implements json.Unmarshaler.
func (c *LicenseCoverage) UnmarshalJSON(data []byte) error {
	switch string(data) {
	case `"NotDetermined"`:
		*c = CoverageNotDetermined
	case `"ModuleCode"`:
		*c = CoverageModuleCode
	case `"Documentation"`:
		*c = CoverageDocumentation
	case `"BundledComponent"`:
		*c = CoverageBundledComponent
	case `"AttributionOnly"`:
		*c = CoverageAttributionOnly
	default:
		return &licenceCoverageError{got: string(data)}
	}
	return nil
}

type licenceCoverageError struct{ got string }

func (e *licenceCoverageError) Error() string {
	return "invalid LicenseCoverage: " + e.got
}

// licenceSubject is the kind of work a licence instrument grants rights in,
// read from the instrument's own definition of what it licenses.
//
// This is the signal coverage rests on, and it is deliberately NOT the licence
// file's name or its position in the archive — those are what produced the
// defect. chroma's font licence is a root-level COPYING and go-digest's
// documentation licence is a root-level LICENSE.docs, so no rule about where a
// file sits or what it is called separates them from the module's own grant.
// What separates them is the instrument: OFL-1.1 defines "Font Software" and
// grants rights in nothing else, and the Creative Commons attribution family
// grants rights in "Licensed Material" — "the artistic or literary work,
// database, or other material to which the Licensor applied this Public
// License". Those are clauses of the text the detector matched, so the subject
// is a property of the measured licence rather than a guess about the file.
type licenceSubject int

const (
	// subjectUnknown means this table does not say what the instrument
	// licenses. Nothing is ever set aside on an unknown subject, so an
	// identifier absent from the tables below is left exactly as it was found.
	subjectUnknown licenceSubject = iota
	// subjectSoftware is an instrument that grants rights in software.
	subjectSoftware
	// subjectFontSoftware is an instrument that grants rights in fonts.
	subjectFontSoftware
	// subjectContent is an instrument that grants rights in documents, data
	// and other creative works rather than in software.
	subjectContent
)

// softwareLicenceInstruments are the SPDX identifiers whose instruments grant
// rights in software. Every one of them says so in its own operative text —
// "the Software", "the Work", "the Program", "Covered Software", "the source
// code form" — and a module carrying one has a grant over its Go code.
//
// CC0-1.0 is on this list deliberately and is the negative control the ticket
// this fix answers made explicit. It is not a member of the Creative Commons
// attribution family below: it is a public-domain dedication over "the Work"
// with no subject-matter restriction, published by Creative Commons as the
// instrument to use for software, and it is widely used for Go source. Setting
// it aside as content would be exactly the over-capture a first sweep of this
// defect produced.
var softwareLicenceInstruments = map[string]bool{
	"0BSD":                true,
	"AFL-3.0":             true,
	"AGPL-3.0":            true,
	"AGPL-3.0-only":       true,
	"AGPL-3.0-or-later":   true,
	"Apache-1.1":          true,
	"Apache-2.0":          true,
	"Artistic-2.0":        true,
	"BSD-1-Clause":        true,
	"BSD-2-Clause":        true,
	"BSD-2-Clause-Views":  true,
	"BSD-3-Clause":        true,
	"BSD-3-Clause-Clear":  true,
	"BSD-3-Clause-New":    true,
	"BSD-4-Clause":        true,
	"BSL-1.0":             true,
	"BlueOak-1.0.0":       true,
	"CC0-1.0":             true,
	"CDDL-1.0":            true,
	"CDDL-1.1":            true,
	"EPL-1.0":             true,
	"EPL-2.0":             true,
	"GPL-2.0":             true,
	"GPL-2.0-only":        true,
	"GPL-2.0-or-later":    true,
	"GPL-3.0":             true,
	"GPL-3.0-only":        true,
	"GPL-3.0-or-later":    true,
	"ISC":                 true,
	"LGPL-2.1":            true,
	"LGPL-2.1-only":       true,
	"LGPL-2.1-or-later":   true,
	"LGPL-3.0":            true,
	"LGPL-3.0-only":       true,
	"LGPL-3.0-or-later":   true,
	"MIT":                 true,
	"MIT-0":               true,
	"MPL-1.1":             true,
	"MPL-2.0":             true,
	"MS-PL":               true,
	"MS-RL":               true,
	"MulanPSL-2.0":        true,
	"NCSA":                true,
	"OpenSSL":             true,
	"PostgreSQL":          true,
	"PSF-2.0":             true,
	"Python-2.0":          true,
	"Ruby":                true,
	"UPL-1.0":             true,
	"Unlicense":           true,
	"WTFPL":               true,
	"X11":                 true,
	"Zend-2.0":            true,
	"Zlib":                true,
	"Zope-Public-License": true,
}

// nonSoftwareInstrumentFamilies map an SPDX identifier prefix that names a
// licence FAMILY to the subject every member of that family licenses. A prefix
// is used rather than a version-by-version list because the family is what SPDX
// registers and what the instrument text is shared across: OFL-1.0 and OFL-1.1
// carry the same "Font Software" definition, and every CC-BY* version runs over
// the same "Licensed Material".
//
// The prefixes are identifiers, not file names. CC0-1.0 is not matched by
// "CC-BY" and is in the software table above, which is the line this fix has to
// hold: a Creative Commons instrument is not automatically a documentation
// licence, and the attribution family is not automatically a code licence.
var nonSoftwareInstrumentFamilies = []struct {
	prefix  string
	subject licenceSubject
}{
	// SIL Open Font License. DEFINITIONS: `"Font Software" refers to the set
	// of files released by the Copyright Holder(s) under this license and
	// clearly marked as such.` Every permission the instrument grants is over
	// Font Software and over nothing else.
	{"OFL-", subjectFontSoftware},
	// Creative Commons attribution family. The grant runs over "Licensed
	// Material", `the artistic or literary work, database, or other material to
	// which the Licensor applied this Public License`, and the instrument
	// carries no notion of source form and no patent grant.
	{"CC-BY", subjectContent},
	// GNU Free Documentation License. `This License applies to any manual or
	// other work, in any medium, that contains a notice placed by the copyright
	// holder saying it can be distributed under the terms of this License.`
	{"GFDL-", subjectContent},
}

// subjectOf reports what kind of work the instrument named by an SPDX
// identifier licenses. An identifier the tables do not name is subjectUnknown,
// and nothing is set aside on that answer.
func subjectOf(spdx string) licenceSubject {
	if softwareLicenceInstruments[spdx] {
		return subjectSoftware
	}
	for _, f := range nonSoftwareInstrumentFamilies {
		if strings.HasPrefix(spdx, f.prefix) {
			return f.subject
		}
	}
	return subjectUnknown
}

// DeriveGrantCoverage says what each licence the module's ROOT files grant
// covers, keyed by SPDX identifier. expression is the module's own licence
// expression, which settles one case on its own.
//
// The rule has three parts, and each is load-bearing.
//
// A DISJUNCTIVE expression is the module's own statement that either grant
// governs the whole work, so every arm covers it and none is demoted. This is
// the genuine font package: codeberg.org/go-fonts/liberation elects between
// BSD-3-Clause and OFL-1.1, and its OFL-1.1 covers the fonts the module IS.
//
// Otherwise the instrument says what kind of work its grant reaches, and the
// module says whether a grant over its code exists at all. A font licence
// beside a Go library's own MIT grant covers the font the library embeds. The
// same font licence ALONE, in a module with no code grant beside it, may well
// be the module's real licensing — nothing in the artefact says otherwise — so
// it is left undetermined rather than demoted. That asymmetry is what keeps
// this from re-deriving the over-broad list a first sweep of the defect
// produced.
func DeriveGrantCoverage(entries []LicenseFileEntry, expression string) map[string]LicenseCoverage {
	grants := rootGrants(entries)
	if len(grants) == 0 {
		return nil
	}
	if elected := DisjunctionArms(expression); len(elected) >= 2 {
		out := make(map[string]LicenseCoverage, len(grants))
		for _, g := range grants {
			out[g] = CoverageNotDetermined
		}
		for _, e := range elected {
			out[e] = CoverageModuleCode
		}
		return out
	}
	codePresent := false
	for _, g := range grants {
		if subjectOf(g) == subjectSoftware {
			codePresent = true
			break
		}
	}
	out := make(map[string]LicenseCoverage, len(grants))
	for _, g := range grants {
		switch subjectOf(g) {
		case subjectSoftware:
			out[g] = CoverageModuleCode
		case subjectFontSoftware:
			if codePresent {
				out[g] = CoverageBundledComponent
				continue
			}
			out[g] = CoverageNotDetermined
		case subjectContent:
			if codePresent {
				out[g] = CoverageDocumentation
				continue
			}
			out[g] = CoverageNotDetermined
		default:
			out[g] = CoverageNotDetermined
		}
	}
	return out
}

// rootGrants lists the distinct identifiers the module's root licence files
// grant, including a second grant carried inside one file at near-equal
// coverage. That last part is not an extra: chroma's whole defect lives in one
// COPYING whose most-covered match is the embedded font's licence and whose
// alternative match, at the identical confidence, is the module's own MIT. The
// near-equal test is exprCompoundDelta, the one DeriveExpressionResult uses to
// decide the same question, so the two cannot drift apart.
func rootGrants(entries []LicenseFileEntry) []string {
	var ids []string
	for _, e := range entries {
		if e.IsVendored || !exprIsRootLevel(e.Path) || exprIsNoticeName(e.Path) || e.SPDX == "" {
			continue
		}
		ids = append(ids, e.SPDX)
		alts := filterRealSPDX(e.AltMatches)
		if len(alts) == 0 || e.Confidence-alts[0].Confidence > exprCompoundDelta {
			continue
		}
		for _, a := range alts {
			if e.Confidence-a.Confidence <= exprCompoundDelta {
				ids = append(ids, a.SPDX)
			}
		}
	}
	return dedupeSorted(ids)
}

// SetLicenseCoverage fills in the derived Coverage of every entry.
//
// It reconciles with the two coverage statements a file entry already carried
// rather than adding a third answer beside them: a vendored file's licence
// covers a bundled component by definition, a per-file header covers the source
// it was read from, and a licence in a sub-package directory covers that
// package's code. Only a root-level file needs the instrument read, and that is
// the case the defect lives in.
//
// Coverage is derived data. Recompute it from LicenseFiles whenever needed
// rather than storing it, so it is always consistent, and so adding it owes no
// pipeline bump.
func SetLicenseCoverage(r *LicenseRecord) {
	grants := DeriveGrantCoverage(r.LicenseFiles, r.Expression)
	for i := range r.LicenseFiles {
		r.LicenseFiles[i].Coverage = coverageOfEntry(r.LicenseFiles[i], grants)
	}
}

// coverageByPath is the same answer keyed by path, for a caller holding a
// record it did not load through the store. One implementation, so the field on
// the entry and the reading published beside it cannot disagree.
func coverageByPath(entries []LicenseFileEntry, grants map[string]LicenseCoverage) map[string]LicenseCoverage {
	if len(entries) == 0 {
		return nil
	}
	out := make(map[string]LicenseCoverage, len(entries))
	for _, e := range entries {
		out[e.Path] = coverageOfEntry(e, grants)
	}
	return out
}

func coverageOfEntry(e LicenseFileEntry, grants map[string]LicenseCoverage) LicenseCoverage {
	switch {
	case exprIsNoticeName(e.Path):
		// An attribution document, whether or not the detector matched it
		// against the licence it reproduces.
		return CoverageAttributionOnly
	case e.SPDX == "":
		// Nothing was identified, so there is no grant to attribute.
		return CoverageNotDetermined
	case e.IsVendored:
		return CoverageBundledComponent
	case e.IsPerFile:
		return CoverageModuleCode
	case !exprIsRootLevel(e.Path):
		return CoverageModuleCode
	}
	return grants[e.SPDX]
}

// SetAsideGrant is one identifier a record names that does not govern the
// module's code, with what it governs instead.
type SetAsideGrant struct {
	SPDX     string
	Coverage LicenseCoverage
}

// CoverageReading is a licence record read through what each of its licences
// covers: the expression over the grants that reach the module's code, the
// licence covering that code, and the grants set aside with the reason.
//
// It is the answer every licence surface publishes. The record itself is left
// as it was measured — Expression, ExpressionBasis and PrimarySPDX are inside
// the content hash, so correcting them in place would make a stored record
// unverifiable — and this reading is composed from the record's own licence
// files on top.
type CoverageReading struct {
	// Expression is the SPDX expression over the grants covering the module's
	// code. Equal to the record's when nothing was set aside.
	Expression string
	// Basis states how the expression was reached, naming coverage where
	// coverage took part.
	Basis string
	// PrimarySPDX is the licence covering the module's code. An asset or
	// documentation licence never holds it.
	PrimarySPDX string
	// SetAside lists the grants that do not govern the module's code, sorted
	// by identifier. Empty for the ordinary record, which is every record whose
	// licences all cover its code.
	SetAside []SetAsideGrant
	// ByPath says what each licence file covers, keyed by path. It is the same
	// answer LicenseFileEntry.Coverage carries and is computed here as well so
	// a surface can publish it for a record it built rather than loaded.
	ByPath map[string]LicenseCoverage
}

// ReadCoverage reads a licence record through what each of its licences covers.
//
// Two shapes are returned untouched, and both are deliberate. A disjunction is
// the module's own statement that either grant governs the whole work, so a
// font package publishing "BSD-3-Clause OR OFL-1.1" keeps both arms: the module
// has answered the question this reading would otherwise ask. And a lone grant
// is never set aside, because a module whose only licence is a content or font
// instrument may genuinely be licensed that way; there is no code grant beside
// it to prefer, and the honest answer is the one already recorded.
func ReadCoverage(r LicenseRecord) CoverageReading {
	grants := DeriveGrantCoverage(r.LicenseFiles, r.Expression)
	as := CoverageReading{
		Expression:  r.Expression,
		Basis:       r.ExpressionBasis,
		PrimarySPDX: r.PrimarySPDX,
		ByPath:      coverageByPath(r.LicenseFiles, grants),
	}
	arms := ConjunctionArms(r.Expression)
	if len(arms) < 2 {
		return as
	}
	var keep []string
	var aside []SetAsideGrant
	for _, arm := range arms {
		switch grants[arm] {
		case CoverageDocumentation, CoverageBundledComponent:
			aside = append(aside, SetAsideGrant{SPDX: arm, Coverage: grants[arm]})
		default:
			keep = append(keep, arm)
		}
	}
	if len(aside) == 0 || len(keep) == 0 {
		// Nothing to set aside, or nothing left if everything were — either
		// way the record's own reading stands.
		return as
	}

	as.Expression = strings.Join(keep, " AND ")
	as.Basis = coverageBasis(aside, r.ExpressionBasis)
	as.SetAside = aside
	if grants[r.PrimarySPDX] == CoverageDocumentation || grants[r.PrimarySPDX] == CoverageBundledComponent {
		as.PrimarySPDX = primaryAmong(keep, r.LicenseFiles)
	}
	return as
}

// coverageBasis states that coverage took part in the derivation, and keeps the
// reading it displaced. An expression that changed with no recorded reason is
// the thing ExpressionBasis exists to prevent.
func coverageBasis(aside []SetAsideGrant, recorded string) string {
	clauses := make([]string, 0, len(aside))
	for _, a := range aside {
		clauses = append(clauses, a.SPDX+" "+a.Coverage.Covers())
	}
	basis := "coverage: " + strings.Join(clauses, "; ") + ", not this module's code"
	if recorded != "" {
		basis += "; set aside from the recorded reading: " + recorded
	}
	return basis
}

// primaryAmong picks the licence covering the module's code from the kept
// identifiers, preferring the one granted by the highest-ranked root file so
// the answer follows the same order the record's own primary followed. Where no
// root file names a kept identifier — the compound case, whose kept grant is an
// alternative match inside one file — the identifiers are already sorted and
// the first is a determined answer rather than an arbitrary one.
func primaryAmong(keep []string, entries []LicenseFileEntry) string {
	wanted := make(map[string]bool, len(keep))
	for _, k := range keep {
		wanted[k] = true
	}
	candidates := make([]LicenseFileEntry, 0, len(entries))
	for _, e := range entries {
		if e.IsVendored || !exprIsRootLevel(e.Path) || exprIsNoticeName(e.Path) {
			continue
		}
		if wanted[e.SPDX] {
			candidates = append(candidates, e)
		}
	}
	if len(candidates) > 0 {
		sortSlice(candidates, RootCandidateLess)
		return candidates[0].SPDX
	}
	sorted := append([]string(nil), keep...)
	sort.Strings(sorted)
	return sorted[0]
}
