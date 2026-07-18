package domain

import (
	"reflect"
	"testing"
)

func report(caps ...Capability) CapabilityReport {
	fs := make([]CapabilityFinding, 0, len(caps))
	for _, c := range caps {
		fs = append(fs, CapabilityFinding{Capability: c})
	}
	return CapabilityReport{Findings: fs}
}

func TestDiffCapabilitiesAddedRemovedCommon(t *testing.T) {
	from := report(CapabilityNetwork, CapabilityFiles)
	to := report(CapabilityFiles, CapabilityExec)

	diff := DiffCapabilities(from, to)

	if !diff.ParityOK {
		t.Error("two Extracted reports should have parity")
	}
	if diff.Caveat != "" {
		t.Errorf("parity diff should have no caveat, got %q", diff.Caveat)
	}
	if !reflect.DeepEqual(diff.Added, []Capability{CapabilityExec}) {
		t.Errorf("Added = %v, want [EXEC]", diff.Added)
	}
	if !reflect.DeepEqual(diff.Removed, []Capability{CapabilityNetwork}) {
		t.Errorf("Removed = %v, want [NETWORK]", diff.Removed)
	}
	if !reflect.DeepEqual(diff.Common, []Capability{CapabilityFiles}) {
		t.Errorf("Common = %v, want [FILES]", diff.Common)
	}
}

func TestDiffCapabilitiesSortsMultipleAdditions(t *testing.T) {
	from := report()
	to := report(CapabilityReflect, CapabilityExec, CapabilityNetwork)
	diff := DiffCapabilities(from, to)
	want := []Capability{CapabilityExec, CapabilityNetwork, CapabilityReflect}
	if !reflect.DeepEqual(diff.Added, want) {
		t.Errorf("Added = %v, want sorted %v", diff.Added, want)
	}
}

func TestDiffCapabilitiesParityBrokenByPartial(t *testing.T) {
	from := report(CapabilityNetwork)
	to := CapabilityReport{Partial: true, Findings: []CapabilityFinding{{Capability: CapabilityNetwork}}}

	diff := DiffCapabilities(from, to)
	if diff.ParityOK {
		t.Error("a Partial side must break parity")
	}
	if diff.Caveat == "" {
		t.Error("broken parity must carry a caveat")
	}
}
