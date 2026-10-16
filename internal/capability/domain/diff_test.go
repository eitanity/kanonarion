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
	from := report(CapabilityNetDial, CapabilityFSRead)
	to := report(CapabilityFSRead, CapabilityExecProcess)

	diff := DiffCapabilities(from, to)

	if !diff.ParityOK {
		t.Error("two Extracted reports should have parity")
	}
	if diff.Caveat != "" {
		t.Errorf("parity diff should have no caveat, got %q", diff.Caveat)
	}
	if !reflect.DeepEqual(diff.Added, []Capability{CapabilityExecProcess}) {
		t.Errorf("Added = %v, want [EXEC_PROCESS]", diff.Added)
	}
	if !reflect.DeepEqual(diff.Removed, []Capability{CapabilityNetDial}) {
		t.Errorf("Removed = %v, want [NET_DIAL]", diff.Removed)
	}
	if !reflect.DeepEqual(diff.Common, []Capability{CapabilityFSRead}) {
		t.Errorf("Common = %v, want [FS_READ]", diff.Common)
	}
}

func TestDiffCapabilitiesSortsMultipleAdditions(t *testing.T) {
	from := report()
	to := report(CapabilityReflectInspect, CapabilityExecProcess, CapabilityNetDial)
	diff := DiffCapabilities(from, to)
	want := []Capability{CapabilityExecProcess, CapabilityNetDial, CapabilityReflectInspect}
	if !reflect.DeepEqual(diff.Added, want) {
		t.Errorf("Added = %v, want sorted %v", diff.Added, want)
	}
}

func TestDiffCapabilitiesParityBrokenByPartial(t *testing.T) {
	from := report(CapabilityNetDial)
	to := CapabilityReport{Partial: true, Findings: []CapabilityFinding{{Capability: CapabilityNetDial}}}

	diff := DiffCapabilities(from, to)
	if diff.ParityOK {
		t.Error("a Partial side must break parity")
	}
	if diff.Caveat == "" {
		t.Error("broken parity must carry a caveat")
	}
}
