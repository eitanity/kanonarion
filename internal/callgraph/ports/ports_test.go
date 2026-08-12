package ports_test

import (
	"sort"
	"testing"

	"github.com/eitanity/kanonarion/internal/callgraph/domain"
	"github.com/eitanity/kanonarion/internal/callgraph/ports"
)

func TestCallEdgeRefLess_StableOrderingWithModulePathTiebreak(t *testing.T) {
	// Input is intentionally unsorted and includes two edges that are equal on
	// FromID and ToID, differing only on ModulePath — the key that stands in for
	// the call site a CallEdgeRef does not carry. A plain sort.Slice is used
	// because the ordering is total: nothing is left for stability to decide.
	in := []ports.CallEdgeRef{
		{FromID: "b.Caller", ToID: "x.Callee", ModulePath: "example.com/z"},
		{FromID: "a.Caller", ToID: "x.Callee", ModulePath: "example.com/m"},
		{FromID: "a.Caller", ToID: "x.Callee", ModulePath: "example.com/a"},
		{FromID: "a.Caller", ToID: "w.Callee", ModulePath: "example.com/q"},
	}
	want := []ports.CallEdgeRef{
		{FromID: "a.Caller", ToID: "w.Callee", ModulePath: "example.com/q"},
		{FromID: "a.Caller", ToID: "x.Callee", ModulePath: "example.com/a"},
		{FromID: "a.Caller", ToID: "x.Callee", ModulePath: "example.com/m"},
		{FromID: "b.Caller", ToID: "x.Callee", ModulePath: "example.com/z"},
	}

	got := append([]ports.CallEdgeRef(nil), in...)
	sort.Slice(got, func(i, j int) bool {
		return ports.CallEdgeRefLess(got[i], got[j])
	})

	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("position %d: got %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestCallEdgeRefLess_Irreflexive(t *testing.T) {
	e := ports.CallEdgeRef{FromID: "a", ToID: "b", ModulePath: "example.com/m"}
	if ports.CallEdgeRefLess(e, e) {
		t.Errorf("CallEdgeRefLess must be irreflexive: equal refs reported as ordered")
	}
}

// TestCallEdgeRefLess_IsTotal checks the ordering covers every field a ref
// carries, so two refs that differ at all are ordered and their relative
// position never depends on the order the query produced them in.
func TestCallEdgeRefLess_IsTotal(t *testing.T) {
	base := ports.CallEdgeRef{
		ModulePath: "example.com/m", ModuleVersion: "v1.0.0", PipelineVersion: "0.4.1",
		FromID: "a.Caller", ToID: "x.Callee",
	}
	variants := []ports.CallEdgeRef{base, base, base, base, base, base, base, base}
	variants[1].ModulePath = "example.com/n"
	variants[2].ModuleVersion = "v1.1.0"
	variants[3].PipelineVersion = "0.4.2"
	variants[4].FromID = "b.Caller"
	variants[5].ToID = "y.Callee"
	variants[6].Confidence = domain.ConfidenceDirect
	variants[7].IsTest = true

	for i := range variants {
		for j := range variants {
			less := ports.CallEdgeRefLess(variants[i], variants[j])
			greater := ports.CallEdgeRefLess(variants[j], variants[i])
			if i == j {
				if less {
					t.Errorf("variant %d is ordered against itself", i)
				}
				continue
			}
			if less == greater {
				t.Errorf("variants %d and %d are not ordered: less=%v greater=%v", i, j, less, greater)
			}
		}
	}

	kindA := base
	kindB := base
	kindB.Kind = domain.EdgeKindReference
	if ports.CallEdgeRefLess(kindA, kindB) == ports.CallEdgeRefLess(kindB, kindA) {
		t.Error("refs differing only in Kind are not ordered")
	}
}
