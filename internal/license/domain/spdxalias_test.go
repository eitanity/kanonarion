package domain

import "testing"

func TestCanonicalSPDXIDResolvesDeprecatedForms(t *testing.T) {
	cases := map[string]string{
		"AGPL-3.0": "AGPL-3.0-only",
		"GPL-2.0":  "GPL-2.0-only",
		"GPL-3.0":  "GPL-3.0-only",
		"LGPL-2.0": "LGPL-2.0-only",
		"LGPL-2.1": "LGPL-2.1-only",
		"LGPL-3.0": "LGPL-3.0-only",
	}
	for in, want := range cases {
		if got := CanonicalSPDXID(in); got != want {
			t.Errorf("CanonicalSPDXID(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCanonicalSPDXIDPassesThroughUnchanged(t *testing.T) {
	// Canonical identifiers, unrelated identifiers and the empty string must
	// survive normalisation untouched: this function fixes spelling only.
	for _, id := range []string{
		"AGPL-3.0-only", "AGPL-3.0-or-later", "GPL-3.0-or-later",
		"MIT", "Apache-2.0", "BUSL-1.1", "NotALicense", "",
	} {
		if got := CanonicalSPDXID(id); got != id {
			t.Errorf("CanonicalSPDXID(%q) = %q, want unchanged", id, got)
		}
	}
}

// The deprecated aliases are only useful if they land on a catalogued entry.
// This guards against an alias pointing at an id that no map knows.
func TestDeprecatedAliasesResolveInBothMaps(t *testing.T) {
	for bare, canonical := range deprecatedSPDXAliases {
		obl := LookupObligations(bare)
		if obl.Status != ObligationStatusKnown {
			t.Errorf("LookupObligations(%q) status = %v, want Known (via %q)",
				bare, obl.Status, canonical)
		}
		if obl != LookupObligations(canonical) {
			t.Errorf("LookupObligations(%q) != LookupObligations(%q)", bare, canonical)
		}

		strength, ok := CopyleftStrengthOf(bare)
		if !ok {
			t.Errorf("CopyleftStrengthOf(%q) not found (via %q)", bare, canonical)
			continue
		}
		if want, _ := CopyleftStrengthOf(canonical); strength != want {
			t.Errorf("CopyleftStrengthOf(%q) = %v, want %v", bare, strength, want)
		}
	}
}

// AGPL is the case that prompted this: the network-use trigger must survive
// lookup through the deprecated identifier, since that is what detectors emit.
func TestBareAGPLCarriesNetworkCopyleft(t *testing.T) {
	obl := LookupObligations("AGPL-3.0")
	if !obl.NetworkUseTrigger {
		t.Error("LookupObligations(\"AGPL-3.0\").NetworkUseTrigger = false, want true")
	}
	if !obl.DiscloseSource {
		t.Error("LookupObligations(\"AGPL-3.0\").DiscloseSource = false, want true")
	}
	if got, _ := CopyleftStrengthOf("AGPL-3.0"); got != CopyleftNetwork {
		t.Errorf("CopyleftStrengthOf(\"AGPL-3.0\") = %v, want CopyleftNetwork", got)
	}
}
