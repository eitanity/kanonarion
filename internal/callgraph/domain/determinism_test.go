package domain_test

import (
	"math/rand"
	"reflect"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/callgraph/domain"
	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/wireshape"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
)

// determinismShuffles is how many independent input orders this guard puts
// through the canonical form. A comparator that is not a total order decides a
// tied pair by whatever the sort happened to do with the input order, so the
// guard has to supply many input orders; one or two would pass by luck.
const determinismShuffles = 50

// sealedCallGraphCollections is every collection the record carries, by Go
// field path — the record has no JSON tags of its own, because the bytes it is
// sealed over come from an unexported canonical shape. The guard shuffles each
// of them, and fails when the record grows one it does not shuffle, so a
// collection cannot join the seal without a decision about its order.
var sealedCallGraphCollections = map[string]bool{
	"Edges":                     true,
	"ExclusionList":             true,
	"FailedPackages":            true,
	"Implementations":           true,
	"Implementations[].Methods": true,
	"Interfaces":                true,
	"Interfaces[].Methods":      true,
	"Nodes":                     true,
	"PrefixAttributedPackages":  true,
	"SynthesisedGoMod.Requires": true,
}

// TestCallGraphRecord_ContentHashIsIndependentOfInputOrder is the determinism
// guard for the call-graph record. This domain is the CONTROL for the sweep
// that added these guards: its comparators were already total, and this test
// passed the first time it ran. If it ever fails, the ordering the rest of the
// repo was modelled on has been broken.
func TestCallGraphRecord_ContentHashIsIndependentOfInputOrder(t *testing.T) {
	t.Parallel()

	unseen := map[string]bool{}
	for k := range sealedCallGraphCollections {
		unseen[k] = true
	}
	for _, path := range wireshape.Collections(t, reflect.TypeOf(domain.CallGraphRecord{}), map[string]string{
		"coordinate.ModuleCoordinate": "the \"path@version\" string, see its MarshalJSON",
	}) {
		if !sealedCallGraphCollections[path] {
			t.Errorf("CallGraphRecord now carries the collection %q, whose order reaches its seal: "+
				"give it a total order in a named comparator and shuffle it here", path)
		}
		delete(unseen, path)
	}
	for path := range unseen {
		t.Errorf("the guard shuffles %q, which the record no longer carries", path)
	}

	var h domain.CallGraphRecordHasher
	var want string
	for i := range determinismShuffles {
		r := makeTiedCallGraphRecord()
		shuffleCallGraphRecord(rand.New(rand.NewSource(int64(i))), &r) /* #nosec G404 -- a determinism guard needs a REPRODUCIBLE shuffle: the seed is the test's evidence, not a secret */
		sealed, err := h.SetContentHash(r)
		if err != nil {
			t.Fatalf("shuffle %d: SetContentHash: %v", i, err)
		}
		if i == 0 {
			want = sealed.ContentHash
			continue
		}
		if sealed.ContentHash != want {
			t.Fatalf("shuffle %d: content hash %s, shuffle 0 gave %s: the canonical order is not a function of the record alone",
				i, sealed.ContentHash, want)
		}
	}
}

// makeTiedCallGraphRecord populates every sealed collection, with pairs that
// tie on the leading key of each comparator.
func makeTiedCallGraphRecord() domain.CallGraphRecord {
	coord, _ := coordinate.NewModuleCoordinate("example.com/mod", "v1.0.0")
	return domain.CallGraphRecord{
		SchemaVersion: domain.CallGraphSchemaVersion,
		Ecosystem:     fetchdomain.EcosystemGo,
		Coordinate:    coord,
		Algorithm:     domain.AlgorithmCHA,
		Nodes: []domain.CallNode{
			{ID: "example.com/mod.Alpha", Module: "example.com/mod", Package: "example.com/mod", Symbol: "Alpha", Position: domain.SourcePosition{File: "a.go", Line: 3}},
			{ID: "example.com/mod.Alpha", Module: "example.com/mod", Package: "example.com/mod", Symbol: "Alpha", Position: domain.SourcePosition{File: "b.go", Line: 3}},
			{ID: "example.com/mod.Beta", Module: "example.com/mod", Package: "example.com/mod", Symbol: "Beta", Position: domain.SourcePosition{File: "a.go", Line: 9}},
		},
		Edges: []domain.CallEdge{
			{FromID: "example.com/mod.Alpha", ToID: "example.com/mod.Beta", CallSite: domain.SourcePosition{File: "a.go", Line: 5}, Confidence: domain.ConfidenceDirect},
			{FromID: "example.com/mod.Alpha", ToID: "example.com/mod.Beta", CallSite: domain.SourcePosition{File: "a.go", Line: 5}, Confidence: domain.ConfidenceDirect, ReflectDispatch: true},
		},
		Interfaces: []domain.InterfaceType{
			{ID: "example.com/mod.Reader", Package: "example.com/mod", Name: "Reader", Methods: []string{"Read", "Close"}},
			{ID: "example.com/mod.Reader", Package: "example.com/mod", Name: "Reader", Position: domain.SourcePosition{File: "b.go", Line: 2}, Methods: []string{"Read"}},
		},
		Implementations: []domain.InterfaceImplementation{
			{
				InterfaceID: "example.com/mod.Reader", TypeID: "example.com/mod.File", Package: "example.com/mod",
				Methods: []domain.ImplementedMethod{
					{Method: "Read", NodeID: "example.com/mod.File.Read"},
					{Method: "Read", NodeID: "example.com/mod.File.ReadAt"},
				},
			},
			{InterfaceID: "example.com/mod.Reader", TypeID: "example.com/mod.File", Package: "example.com/mod", Position: domain.SourcePosition{File: "b.go", Line: 4}},
		},
		ExclusionList:            []string{"example.com/mod/internal", "example.com/mod/testdata"},
		FailedPackages:           []string{"example.com/mod/broken", "example.com/mod/worse"},
		PrefixAttributedPackages: []string{"example.com/mod/x", "example.com/mod/y"},
		SynthesisedGoMod: domain.SynthesisedGoMod{
			ModulePath: "example.com/mod",
			Requires: []domain.SynthesisedRequire{
				{Path: "example.com/dep", Version: "v1.0.0"},
				{Path: "example.com/dep", Version: "v1.1.0"},
			},
		},
		OverallStatus:   domain.CallGraphStatusExtracted,
		NodeCount:       3,
		EdgeCount:       2,
		ExtractedAt:     time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		PipelineVersion: "0.1.0",
	}
}

func shuffleCallGraphRecord(rng *rand.Rand, r *domain.CallGraphRecord) {
	rng.Shuffle(len(r.Nodes), func(i, j int) { r.Nodes[i], r.Nodes[j] = r.Nodes[j], r.Nodes[i] })
	rng.Shuffle(len(r.Edges), func(i, j int) { r.Edges[i], r.Edges[j] = r.Edges[j], r.Edges[i] })
	rng.Shuffle(len(r.Interfaces), func(i, j int) { r.Interfaces[i], r.Interfaces[j] = r.Interfaces[j], r.Interfaces[i] })
	for i := range r.Interfaces {
		m := r.Interfaces[i].Methods
		rng.Shuffle(len(m), func(a, b int) { m[a], m[b] = m[b], m[a] })
	}
	rng.Shuffle(len(r.Implementations), func(i, j int) {
		r.Implementations[i], r.Implementations[j] = r.Implementations[j], r.Implementations[i]
	})
	for i := range r.Implementations {
		m := r.Implementations[i].Methods
		rng.Shuffle(len(m), func(a, b int) { m[a], m[b] = m[b], m[a] })
	}
	rng.Shuffle(len(r.ExclusionList), func(i, j int) { r.ExclusionList[i], r.ExclusionList[j] = r.ExclusionList[j], r.ExclusionList[i] })
	rng.Shuffle(len(r.FailedPackages), func(i, j int) {
		r.FailedPackages[i], r.FailedPackages[j] = r.FailedPackages[j], r.FailedPackages[i]
	})
	rng.Shuffle(len(r.PrefixAttributedPackages), func(i, j int) {
		r.PrefixAttributedPackages[i], r.PrefixAttributedPackages[j] = r.PrefixAttributedPackages[j], r.PrefixAttributedPackages[i]
	})
	req := r.SynthesisedGoMod.Requires
	rng.Shuffle(len(req), func(i, j int) { req[i], req[j] = req[j], req[i] })
}

// TestMemberChangeLess_IsKeyedOnEveryField exercises the generation-diff
// comparator against every field a change carries. One member can change in
// more than one field between two generations, so the id alone is not a key.
func TestMemberChangeLess_IsKeyedOnEveryField(t *testing.T) {
	t.Parallel()

	cases := []struct {
		key          string
		lower, upper domain.MemberChange
	}{
		{"id", domain.MemberChange{ID: "a"}, domain.MemberChange{ID: "b"}},
		{"field", domain.MemberChange{Field: "a"}, domain.MemberChange{Field: "b"}},
		{"left", domain.MemberChange{Left: "a"}, domain.MemberChange{Left: "b"}},
		{"right", domain.MemberChange{Right: "a"}, domain.MemberChange{Right: "b"}},
	}
	for _, tc := range cases {
		if !domain.MemberChangeLess(tc.lower, tc.upper) {
			t.Errorf("%s: the comparator does not order two changes differing only in this field", tc.key)
		}
		if domain.MemberChangeLess(tc.upper, tc.lower) {
			t.Errorf("%s: the comparator is not antisymmetric", tc.key)
		}
		if domain.MemberChangeLess(tc.lower, tc.lower) {
			t.Errorf("%s: the comparator reports a change less than itself", tc.key)
		}
	}
}

// TestSynthesisedRequireLess_IsKeyedOnEveryField pins the require comparator,
// which was keyed on the path alone.
func TestSynthesisedRequireLess_IsKeyedOnEveryField(t *testing.T) {
	t.Parallel()

	if !domain.SynthesisedRequireLess(domain.SynthesisedRequire{Path: "a"}, domain.SynthesisedRequire{Path: "b"}) {
		t.Error("path does not order two requires")
	}
	if !domain.SynthesisedRequireLess(
		domain.SynthesisedRequire{Path: "a", Version: "v1"},
		domain.SynthesisedRequire{Path: "a", Version: "v2"}) {
		t.Error("version does not order two requires on one path")
	}
	if domain.SynthesisedRequireLess(domain.SynthesisedRequire{Path: "a"}, domain.SynthesisedRequire{Path: "a"}) {
		t.Error("the comparator reports a require less than itself")
	}
}

// TestInterfaceTypeLess_OrdersUnequalMethodSets covers the method-list leg of
// the interface comparator: two declarations sharing an ID order by their
// method sets, shorter first, then element by element.
func TestInterfaceTypeLess_OrdersUnequalMethodSets(t *testing.T) {
	t.Parallel()

	short := domain.InterfaceType{ID: "i", Methods: []string{"A"}}
	long := domain.InterfaceType{ID: "i", Methods: []string{"A", "B"}}
	later := domain.InterfaceType{ID: "i", Methods: []string{"B"}}
	if !domain.InterfaceTypeLess(short, long) {
		t.Error("a shorter method set does not sort first")
	}
	if domain.InterfaceTypeLess(long, short) {
		t.Error("the method-set comparison is not antisymmetric on length")
	}
	if !domain.InterfaceTypeLess(short, later) {
		t.Error("method sets of one length do not order element by element")
	}
	if domain.InterfaceTypeLess(short, short) {
		t.Error("an interface compares less than itself")
	}
}
