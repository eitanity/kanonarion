package domain

import fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"

// LicenseOverride is an operator-supplied correction for a single module's
// detected license. It carries enough provenance for callers to indicate that
// a result came from an override rather than the scanner.
type LicenseOverride struct {
	// SPDX is the corrected SPDX identifier the operator asserts for the module.
	SPDX string
	// Key is the override map key that matched ("path" or "path@version").
	Key string
	// VersionPinned is true when a "path@version" entry matched, false when a
	// module-level "path" entry matched.
	VersionPinned bool
}

// LicenseOverrideSet is an immutable, source-agnostic collection of operator
// license corrections. Adapters (e.g. YAML config, or any alternate backend
// implementing the override port) build a set; the precedence rule lives
// here so every source resolves identically.
type LicenseOverrideSet struct {
	entries map[string]string // "path" or "path@version" → SPDX
}

// NewLicenseOverrideSet builds a set from raw "path[@version] → SPDX" entries.
// A nil or empty map yields a set that never matches. The input is copied so
// later mutation of the caller's map does not affect the set.
func NewLicenseOverrideSet(entries map[string]string) LicenseOverrideSet {
	if len(entries) == 0 {
		return LicenseOverrideSet{}
	}
	cp := make(map[string]string, len(entries))
	for k, v := range entries {
		cp[k] = v
	}
	return LicenseOverrideSet{entries: cp}
}

// Resolve returns the override for a coordinate, if any. A version-pinned
// entry ("path@version") takes precedence over a module-level entry ("path"),
// which applies to all versions. An entry with an empty SPDX value is treated
// as no override (a present-but-blank correction is meaningless).
func (s LicenseOverrideSet) Resolve(coord fetchdomain.ModuleCoordinate) (LicenseOverride, bool) {
	if len(s.entries) == 0 {
		return LicenseOverride{}, false
	}
	pinned := coord.Path + "@" + coord.Version
	if spdx, ok := s.entries[pinned]; ok && spdx != "" {
		return LicenseOverride{SPDX: spdx, Key: pinned, VersionPinned: true}, true
	}
	if spdx, ok := s.entries[coord.Path]; ok && spdx != "" {
		return LicenseOverride{SPDX: spdx, Key: coord.Path, VersionPinned: false}, true
	}
	return LicenseOverride{}, false
}
