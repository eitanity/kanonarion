package ports_test

import (
	"sort"
	"testing"

	"github.com/eitanity/kanonarion/internal/callgraph/ports"
)

func TestCallEdgeRefLess_StableOrderingWithModulePathTiebreak(t *testing.T) {
	// Input is intentionally unsorted and includes two edges that are equal on
	// FromID and ToID, differing only on ModulePath — the divergent tiebreak
	// that distinguishes this ordering from domain.CallGraphRecord.Sort.
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
	sort.SliceStable(got, func(i, j int) bool {
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
