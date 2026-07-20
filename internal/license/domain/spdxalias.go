package domain

// deprecatedSPDXAliases maps SPDX 2.x identifiers that were deprecated in
// favour of explicit -only / -or-later disambiguation onto their canonical
// -only form. The bare identifier is ambiguous in principle ("GPL-3.0" does
// not say whether the "or any later version" clause applies) but SPDX defines
// the deprecated id as equivalent to the -only variant, and detectors that
// predate the split — licensecheck among them — still emit the bare form.
//
// Normalising at lookup time keeps a single catalogue entry per licence.
// Duplicating entries per alias is what previously let AGPL-3.0 fall through
// unrecognised while GPL-3.0 was covered.
var deprecatedSPDXAliases = map[string]string{
	"AGPL-3.0": "AGPL-3.0-only",
	"GPL-2.0":  "GPL-2.0-only",
	"GPL-3.0":  "GPL-3.0-only",
	"LGPL-2.0": "LGPL-2.0-only",
	"LGPL-2.1": "LGPL-2.1-only",
	"LGPL-3.0": "LGPL-3.0-only",
}

// CanonicalSPDXID resolves a deprecated SPDX identifier to its current
// equivalent. Identifiers that are already canonical, and identifiers that are
// not recognised at all, are returned unchanged — this function normalises
// spelling only and never asserts that the result is catalogued.
//
// It is applied at map lookup, not at detection: the identifier reported by the
// detector is stored and displayed verbatim so cache entries, the persisted
// schema and diff parity are unaffected by normalisation.
func CanonicalSPDXID(spdxID string) string {
	if canonical, ok := deprecatedSPDXAliases[spdxID]; ok {
		return canonical
	}
	return spdxID
}
