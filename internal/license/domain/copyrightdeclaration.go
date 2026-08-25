package domain

import (
	"maps"

	"github.com/eitanity/kanonarion/internal/coordinate"
)

// CopyrightDeclaration is an operator-recorded copyright line for a module the
// copyright extractor found nothing in, together with the provenance that makes
// it checkable.
//
// It is an assertion about what a person read, not a measurement, so it never
// displaces one: where the pipeline extracted a copyright, the extracted line is
// what the attribution document attributes and the declaration stands beside it
// as corroboration.
type CopyrightDeclaration struct {
	// Copyright is the verbatim line to attribute.
	Copyright string
	// DeclaredBy names the person accountable for the assertion.
	DeclaredBy string
	// DeclaredOn is the ISO 8601 date they read the basis.
	DeclaredOn string
	// Basis cites what they read: the upstream file, commit or repository page.
	Basis string
	// Key is the declaration map key that matched ("path" or "path@version").
	Key string
	// VersionPinned is true when a "path@version" entry matched, false when a
	// module-level "path" entry matched.
	VersionPinned bool
}

// CopyrightDeclarationSet is an immutable, source-agnostic collection of
// operator-recorded copyrights. Adapters build a set; the precedence rule lives
// here so every source resolves identically, on the same terms as
// LicenseOverrideSet.
type CopyrightDeclarationSet struct {
	entries map[string]CopyrightDeclaration // "path" or "path@version" → declaration
}

// NewCopyrightDeclarationSet builds a set from raw "path[@version]" entries. A
// nil or empty map yields a set that never matches. The input is copied so later
// mutation of the caller's map does not affect the set. Key and VersionPinned on
// the input values are ignored: Resolve stamps them from the key that matched.
func NewCopyrightDeclarationSet(entries map[string]CopyrightDeclaration) CopyrightDeclarationSet {
	if len(entries) == 0 {
		return CopyrightDeclarationSet{}
	}
	cp := make(map[string]CopyrightDeclaration, len(entries))
	maps.Copy(cp, entries)
	return CopyrightDeclarationSet{entries: cp}
}

// Resolve returns the declaration for a coordinate, if any. A version-pinned
// entry ("path@version") takes precedence over a module-level entry ("path"),
// which applies to all versions. An entry with an empty copyright line is
// treated as absent — a present-but-blank attribution is meaningless.
func (s CopyrightDeclarationSet) Resolve(coord coordinate.ModuleCoordinate) (CopyrightDeclaration, bool) {
	if len(s.entries) == 0 {
		return CopyrightDeclaration{}, false
	}
	pinned := coord.Path() + "@" + coord.Version()
	if d, ok := s.entries[pinned]; ok && d.Copyright != "" {
		d.Key, d.VersionPinned = pinned, true
		return d, true
	}
	if d, ok := s.entries[coord.Path()]; ok && d.Copyright != "" {
		d.Key, d.VersionPinned = coord.Path(), false
		return d, true
	}
	return CopyrightDeclaration{}, false
}
