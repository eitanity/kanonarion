package domain_test

import (
	"testing"

	domain2 "github.com/eitanity/kanonarion/internal/callgraph/domain"
	"github.com/eitanity/kanonarion/internal/coordinate"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
)

// tiedRecord holds collections whose elements are equal on the identity keys
// the record used to sort by and differ only on the remaining wire fields. Any
// comparator that stops short of the full wire shape leaves their relative
// order to the sort, so the canonical bytes depend on the order they arrived
// in.
func tiedRecord() domain2.CallGraphRecord {
	coord, _ := coordinate.NewModuleCoordinate("example.com/mod", "v1.0.0")
	site := domain2.SourcePosition{File: "a.go", Line: 7}
	return domain2.CallGraphRecord{
		SchemaVersion: domain2.CallGraphSchemaVersion,
		Ecosystem:     fetchdomain.EcosystemGo,
		Coordinate:    coord,
		Nodes: []domain2.CallNode{
			{ID: "example.com/mod.A", Package: "example.com/mod", Symbol: "A"},
			{ID: "example.com/mod.A", Package: "example.com/mod", Symbol: "A", IsTest: true},
			{ID: "example.com/mod.A", Package: "example.com/mod", Symbol: "A", IsExportedAPI: true},
			{ID: "example.com/mod.B", Package: "example.com/mod", Symbol: "B"},
		},
		Edges: []domain2.CallEdge{
			{FromID: "A", ToID: "B", CallSite: site, Kind: domain2.EdgeKindReference, Confidence: domain2.ConfidenceUnknown},
			{FromID: "A", ToID: "B", CallSite: site, Confidence: domain2.ConfidenceUnknown, ReflectDispatch: true},
			{FromID: "A", ToID: "B", CallSite: site, Confidence: domain2.ConfidenceDirect},
			{FromID: "A", ToID: "B", CallSite: site, Confidence: domain2.ConfidenceUnknown},
		},
		Interfaces: []domain2.InterfaceType{
			{ID: "example.com/mod.I", Package: "example.com/mod", Name: "I", Methods: []string{"Do"}},
			{ID: "example.com/mod.I", Package: "example.com/mod", Name: "I", Methods: []string{"Do", "Undo"}},
		},
		Implementations: []domain2.InterfaceImplementation{
			{
				InterfaceID: "example.com/mod.I", TypeID: "example.com/mod.(*T)",
				Package: "example.com/mod",
				Methods: []domain2.ImplementedMethod{{Method: "Do", NodeID: "example.com/mod.(*T).Do"}},
			},
			{
				InterfaceID: "example.com/mod.I", TypeID: "example.com/mod.(*T)",
				Package: "example.com/mod", IsTest: true,
				Methods: []domain2.ImplementedMethod{{Method: "Do", NodeID: "example.com/mod.(*T).Do"}},
			},
		},
	}
}

// permutations returns every ordering of in. The test states its own inputs:
// the canonical order must be a function of the set, so the property is checked
// against every arrangement of the set rather than a sample of them.
func permutations[T any](in []T) [][]T {
	if len(in) <= 1 {
		return [][]T{append([]T(nil), in...)}
	}
	var out [][]T
	for i := range in {
		rest := make([]T, 0, len(in)-1)
		rest = append(rest, in[:i]...)
		rest = append(rest, in[i+1:]...)
		for _, tail := range permutations(rest) {
			out = append(out, append([]T{in[i]}, tail...))
		}
	}
	return out
}

// TestContentHashIndependentOfInputOrder is the property the canonical
// ordering exists to provide: the same set of nodes, edges, interfaces and
// implementations seals to one hash however the analyser happened to emit it.
func TestContentHashIndependentOfInputOrder(t *testing.T) {
	var h domain2.CallGraphRecordHasher
	base := tiedRecord()

	first, err := h.SetContentHash(base)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	check := func(name string, r domain2.CallGraphRecord, i int) {
		got, err := h.SetContentHash(r)
		if err != nil {
			t.Fatalf("SetContentHash on %s permutation %d: %v", name, i, err)
		}
		if got.ContentHash != first.ContentHash {
			t.Fatalf("%s permutation %d hashed to %s, want %s", name, i, got.ContentHash, first.ContentHash)
		}
	}
	for i, p := range permutations(base.Nodes) {
		r := base
		r.Nodes = p
		check("node", r, i)
	}
	for i, p := range permutations(base.Edges) {
		r := base
		r.Edges = p
		check("edge", r, i)
	}
	for i, p := range permutations(base.Interfaces) {
		r := base
		r.Interfaces = p
		check("interface", r, i)
	}
	for i, p := range permutations(base.Implementations) {
		r := base
		r.Implementations = p
		check("implementation", r, i)
	}
}

// TestMarshalPutsCollectionsInCanonicalOrder states that canonicalisation is
// not a precondition a caller can forget. There is no sort step to skip: an
// unsorted record marshals to the canonical order, which is why the hash can be
// trusted to describe the set rather than the arrangement it arrived in.
func TestMarshalPutsCollectionsInCanonicalOrder(t *testing.T) {
	var h domain2.CallGraphRecordHasher
	r := tiedRecord()
	blob, err := h.Marshal(r)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	restored, err := h.Unmarshal(blob)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	for i := 1; i < len(restored.Edges); i++ {
		if domain2.CallEdgeLess(restored.Edges[i], restored.Edges[i-1]) {
			t.Fatalf("edge %d precedes edge %d in the canonical bytes", i, i-1)
		}
	}
	for i := 1; i < len(restored.Nodes); i++ {
		if domain2.CallNodeLess(restored.Nodes[i], restored.Nodes[i-1]) {
			t.Fatalf("node %d precedes node %d in the canonical bytes", i, i-1)
		}
	}
	if len(restored.Edges) != len(r.Edges) || len(restored.Nodes) != len(r.Nodes) {
		t.Fatalf("round trip changed the collections: %d nodes / %d edges, want %d / %d",
			len(restored.Nodes), len(restored.Edges), len(r.Nodes), len(r.Edges))
	}
}

// TestComparatorsAreTotal checks no two distinct elements compare equal: for
// every pair, exactly one of Less(a,b) and Less(b,a) holds.
func TestComparatorsAreTotal(t *testing.T) {
	r := tiedRecord()
	for i := range r.Edges {
		for j := range r.Edges {
			ab := domain2.CallEdgeLess(r.Edges[i], r.Edges[j])
			ba := domain2.CallEdgeLess(r.Edges[j], r.Edges[i])
			if i == j {
				if ab {
					t.Errorf("CallEdgeLess is not irreflexive at %d", i)
				}
				continue
			}
			if ab == ba {
				t.Errorf("edges %d and %d are not ordered: less=%v, greater=%v", i, j, ab, ba)
			}
		}
	}
	for i := range r.Nodes {
		for j := range r.Nodes {
			if i == j {
				if domain2.CallNodeLess(r.Nodes[i], r.Nodes[j]) {
					t.Errorf("CallNodeLess is not irreflexive at %d", i)
				}
				continue
			}
			if domain2.CallNodeLess(r.Nodes[i], r.Nodes[j]) == domain2.CallNodeLess(r.Nodes[j], r.Nodes[i]) {
				t.Errorf("nodes %d and %d are not ordered", i, j)
			}
		}
	}
	if domain2.InterfaceTypeLess(r.Interfaces[0], r.Interfaces[1]) == domain2.InterfaceTypeLess(r.Interfaces[1], r.Interfaces[0]) {
		t.Error("interfaces differing only in their method sets are not ordered")
	}
	if domain2.InterfaceImplementationLess(r.Implementations[0], r.Implementations[1]) ==
		domain2.InterfaceImplementationLess(r.Implementations[1], r.Implementations[0]) {
		t.Error("implementations differing only in IsTest are not ordered")
	}
}

// TestSealedRecordIsInCanonicalOrder: what SetContentHash hands back is arranged
// the way the bytes it hashed are. A sealed record that still carried its input
// arrangement would describe itself twice and disagree.
func TestSealedRecordIsInCanonicalOrder(t *testing.T) {
	var h domain2.CallGraphRecordHasher
	sealed, err := h.SetContentHash(tiedRecord())
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	for i := 1; i < len(sealed.Edges); i++ {
		if domain2.CallEdgeLess(sealed.Edges[i], sealed.Edges[i-1]) {
			t.Errorf("sealed edge %d precedes edge %d", i, i-1)
		}
	}
	for i := 1; i < len(sealed.Nodes); i++ {
		if domain2.CallNodeLess(sealed.Nodes[i], sealed.Nodes[i-1]) {
			t.Errorf("sealed node %d precedes node %d", i, i-1)
		}
	}
	if err := h.VerifyContentHash(sealed); err != nil {
		t.Errorf("VerifyContentHash on the sealed record: %v", err)
	}
}

// TestSealDoesNotRearrangeTheCallersRecord: sealing answers about a record, it
// does not reach back into one.
func TestSealDoesNotRearrangeTheCallersRecord(t *testing.T) {
	var h domain2.CallGraphRecordHasher
	mine := tiedRecord()
	before := append([]domain2.CallEdge(nil), mine.Edges...)
	if _, err := h.SetContentHash(mine); err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	for i := range before {
		if mine.Edges[i] != before[i] {
			t.Fatalf("sealing rearranged the caller's edges at %d", i)
		}
	}
}
