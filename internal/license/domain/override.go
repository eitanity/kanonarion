package domain

import "maps"

import "github.com/eitanity/kanonarion/internal/coordinate"

// LicenseOverride is an operator-supplied determination for a single module's
// license. It carries enough provenance for callers to indicate that a result
// came from an override rather than the scanner, and — where the operator
// recorded it — who determined it, when, and on what basis.
type LicenseOverride struct {
	// SPDX is the SPDX identifier the operator asserts for the module.
	SPDX string
	// DeclaredBy names the person accountable for the determination. Empty when
	// the entry was recorded as a bare identifier.
	DeclaredBy string
	// DeclaredOn is the ISO 8601 date they read the basis. Empty with DeclaredBy.
	DeclaredOn string
	// Basis cites what they read: the upstream file, commit or repository page.
	// Empty with DeclaredBy.
	Basis string
	// Key is the override map key that matched ("path" or "path@version").
	Key string
	// VersionPinned is true when a "path@version" entry matched, false when a
	// module-level "path" entry matched.
	VersionPinned bool
}

// Attributed reports whether the determination names who made it, when, and on
// what basis. An unattributed override is still the operator's determination
// and still settles the module; a document publishing it just cannot say whose
// it is, and must say so rather than implying one.
func (o LicenseOverride) Attributed() bool {
	return o.DeclaredBy != "" && o.DeclaredOn != "" && o.Basis != ""
}

// LicenseOverrideSet is an immutable, source-agnostic collection of operator
// license determinations. Adapters (e.g. YAML config, or any alternate backend
// implementing the override port) build a set; the precedence rule lives
// here so every source resolves identically.
type LicenseOverrideSet struct {
	entries map[string]LicenseOverride // "path" or "path@version" → determination
}

// NewLicenseOverrideSet builds a set from raw "path[@version]" entries. A nil
// or empty map yields a set that never matches. The input is copied so later
// mutation of the caller's map does not affect the set. Key and VersionPinned
// on the input values are ignored: Resolve stamps them from the key that
// matched, on the same terms as CopyrightDeclarationSet.
func NewLicenseOverrideSet(entries map[string]LicenseOverride) LicenseOverrideSet {
	if len(entries) == 0 {
		return LicenseOverrideSet{}
	}
	cp := make(map[string]LicenseOverride, len(entries))
	maps.Copy(cp, entries)
	return LicenseOverrideSet{entries: cp}
}

// Resolve returns the override for a coordinate, if any. A version-pinned
// entry ("path@version") takes precedence over a module-level entry ("path"),
// which applies to all versions. An entry with an empty SPDX value is treated
// as no override (a present-but-blank determination is meaningless).
func (s LicenseOverrideSet) Resolve(coord coordinate.ModuleCoordinate) (LicenseOverride, bool) {
	if len(s.entries) == 0 {
		return LicenseOverride{}, false
	}
	pinned := coord.Path() + "@" + coord.Version()
	if o, ok := s.entries[pinned]; ok && o.SPDX != "" {
		o.Key, o.VersionPinned = pinned, true
		return o, true
	}
	if o, ok := s.entries[coord.Path()]; ok && o.SPDX != "" {
		o.Key, o.VersionPinned = coord.Path(), false
		return o, true
	}
	return LicenseOverride{}, false
}
