package domain_test

import (
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/callgraph/domain"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
)

// TestEdgeKindAndReferenceScopeAreHashTransparent is the guard behind the
// decision not to bump the schema version. A record written before either field
// existed carries both at their zero value; if the canonical bytes gained a key
// for them, every stored record would fail its own content-hash verification —
// which this repository reports in the same words it uses for a detected tamper.
func TestEdgeKindAndReferenceScopeAreHashTransparent(t *testing.T) {
	rec := domain.CallGraphRecord{
		SchemaVersion: domain.CallGraphSchemaVersion,
		Ecosystem:     "go",
		Nodes:         []domain.CallNode{{ID: "m.A", Symbol: "A"}},
		Edges:         []domain.CallEdge{{FromID: "m.A", ToID: "m.B", Confidence: domain.ConfidenceDirect}},
	}
	var h domain.CallGraphRecordHasher
	b, err := h.Marshal(rec)
	if err != nil {
		t.Fatalf("CanonicalBytes: %v", err)
	}
	for _, key := range []string{`"kind"`, `"reference_scope"`} {
		if strings.Contains(string(b), key) {
			t.Errorf("canonical bytes carry %s at its zero value; every stored record's hash moves", key)
		}
	}

	// The control: when the fields DO carry a value they must be in the bytes,
	// or two graphs that differ in what they measured would share one identity.
	rec.ReferenceScope = domain.ReferenceScopeAnalysed
	rec.Edges[0].Kind = domain.EdgeKindReference
	b2, err := h.Marshal(rec)
	if err != nil {
		t.Fatalf("CanonicalBytes: %v", err)
	}
	for _, key := range []string{`"kind"`, `"reference_scope"`} {
		if !strings.Contains(string(b2), key) {
			t.Errorf("canonical bytes omit %s when it carries a value", key)
		}
	}
}

// TestEdgeKindRoundTripsThroughTheCanonicalShape keeps the wire and domain
// shapes in step: a kind that marshals but does not unmarshal would silently
// turn every reference back into a call on the way out of the store.
func TestEdgeKindRoundTripsThroughTheCanonicalShape(t *testing.T) {
	rec := domain.CallGraphRecord{
		SchemaVersion:  domain.CallGraphSchemaVersion,
		Ecosystem:      "go",
		Coordinate:     coordinatetest.MustNew("example.com/m", "v1.0.0"),
		ReferenceScope: domain.ReferenceScopeAnalysed,
		Nodes:          []domain.CallNode{{ID: "m.A", Symbol: "A"}},
		Edges: []domain.CallEdge{
			{FromID: "m.A", ToID: "m.B", Confidence: domain.ConfidenceDirect, Kind: domain.EdgeKindReference},
			{FromID: "m.A", ToID: "m.C", Confidence: domain.ConfidenceDirect},
		},
	}
	var h domain.CallGraphRecordHasher
	b, err := h.Marshal(rec)
	if err != nil {
		t.Fatalf("CanonicalBytes: %v", err)
	}
	back, err := h.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if !back.ReferenceScope.IsMeasured() {
		t.Errorf("ReferenceScope lost in the round trip: %q", back.ReferenceScope)
	}
	if len(back.Edges) != 2 {
		t.Fatalf("got %d edges back, want 2", len(back.Edges))
	}
	var refs, calls int
	for _, e := range back.Edges {
		if e.Kind.IsReference() {
			refs++
		} else {
			calls++
		}
	}
	if refs != 1 || calls != 1 {
		t.Errorf("round trip gave %d references and %d calls, want 1 and 1", refs, calls)
	}
}

// TestIsTestHarnessEntry draws the line the go command draws. Everything on the
// left of it is invoked by a harness that is not in the graph; everything on the
// right is ordinary code whose absence of callers is still a measurement.
func TestIsTestHarnessEntry(t *testing.T) {
	tests := []struct {
		name string
		node domain.CallNode
		want bool
	}{
		{"a test function", domain.CallNode{Symbol: "TestThing", IsTest: true}, true},
		{"TestMain", domain.CallNode{Symbol: "TestMain", IsTest: true}, true},
		{"a benchmark", domain.CallNode{Symbol: "BenchmarkThing", IsTest: true}, true},
		{"a fuzz target", domain.CallNode{Symbol: "FuzzThing", IsTest: true}, true},
		{"an example", domain.CallNode{Symbol: "ExampleThing", IsTest: true}, true},
		{"a bare Example", domain.CallNode{Symbol: "Example", IsTest: true}, true},
		{"an underscore-suffixed test", domain.CallNode{Symbol: "Test_thing", IsTest: true}, true},

		{"a method on a test fake is reached by dispatch, not the harness",
			domain.CallNode{Symbol: "TestHook", Receiver: "*fake", IsTest: true}, false},
		{"a helper whose name merely starts with Test",
			domain.CallNode{Symbol: "Testing", IsTest: true}, false},
		{"a bare Test is not a test function",
			domain.CallNode{Symbol: "Test", IsTest: true}, false},
		{"production code named like a test is not in test scope",
			domain.CallNode{Symbol: "TestThing"}, false},
		{"ordinary production code", domain.CallNode{Symbol: "Handle"}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := domain.IsTestHarnessEntry(tc.node); got != tc.want {
				t.Errorf("IsTestHarnessEntry(%+v) = %v, want %v", tc.node, got, tc.want)
			}
		})
	}
}

// TestWeakestConfidence keeps the path rule in one place: a path is only as good
// as its worst hop, and an unrecognised tier is never better than Unknown.
func TestWeakestConfidence(t *testing.T) {
	tests := []struct {
		a, b, want domain.EdgeConfidence
	}{
		{domain.ConfidenceDirect, domain.ConfidenceCHAOverapprox, domain.ConfidenceCHAOverapprox},
		{domain.ConfidenceCHAOverapprox, domain.ConfidenceDirect, domain.ConfidenceCHAOverapprox},
		{domain.ConfidenceDirect, domain.ConfidenceDirect, domain.ConfidenceDirect},
		{domain.ConfidenceVTA, domain.ConfidenceUnknown, domain.ConfidenceUnknown},
		{domain.ConfidenceFramework, domain.ConfidenceVTA, domain.ConfidenceFramework},
		{domain.ConfidenceDirect, "SomethingThisBuildDoesNotKnow", "SomethingThisBuildDoesNotKnow"},
	}
	for _, tc := range tests {
		if got := domain.WeakestConfidence(tc.a, tc.b); got != tc.want {
			t.Errorf("WeakestConfidence(%q, %q) = %q, want %q", tc.a, tc.b, got, tc.want)
		}
	}
}
