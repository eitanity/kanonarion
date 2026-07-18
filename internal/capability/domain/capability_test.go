package domain

import "testing"

func TestAllCapabilitiesAreValid(t *testing.T) {
	caps := AllCapabilities()
	if len(caps) != 12 {
		t.Fatalf("AllCapabilities len = %d, want 12", len(caps))
	}
	seen := make(map[Capability]bool)
	for _, c := range caps {
		if !c.Valid() {
			t.Errorf("%q reported invalid but is in AllCapabilities", c)
		}
		if seen[c] {
			t.Errorf("%q appears twice in AllCapabilities", c)
		}
		seen[c] = true
	}
}

func TestCapabilityValidRejectsUnknown(t *testing.T) {
	if Capability("NONSENSE").Valid() {
		t.Error("NONSENSE should be invalid")
	}
	if Capability("").Valid() {
		t.Error("empty capability should be invalid")
	}
}
