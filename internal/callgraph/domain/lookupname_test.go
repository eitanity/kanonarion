package domain_test

import (
	"strings"
	"testing"

	"code.eitanity.com/kanonarion/internal/callgraph/domain"
	"code.eitanity.com/kanonarion/internal/coordinate/coordinatetest"
)

// TestLookupNameIsSealedAndRoundTrips: an empty name adds no key, so a record
// without one keeps its bytes; a name is in the bytes, so it moves the content
// hash, and it comes back on Unmarshal.
func TestLookupNameIsSealedAndRoundTrips(t *testing.T) {
	rec := domain.CallGraphRecord{
		SchemaVersion: domain.CallGraphSchemaVersion,
		Ecosystem:     "go",
		Coordinate:    coordinatetest.MustNew("example.com/m", "v1.0.0"),
		Nodes:         []domain.CallNode{{ID: "m.A", Symbol: "A"}},
		Edges:         []domain.CallEdge{{FromID: "m.A", ToID: "reflect.(Value).MethodByName", Confidence: domain.ConfidenceUnknown, ReflectDispatch: true}},
	}
	var h domain.CallGraphRecordHasher
	b, err := h.Marshal(rec)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if strings.Contains(string(b), `"lookup_name"`) {
		t.Errorf("canonical bytes carry lookup_name at its zero value: %s", b)
	}
	plain, err := h.SetContentHash(rec)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}

	rec.Edges[0].LookupName = "Run"
	named, err := h.SetContentHash(rec)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	if named.ContentHash == plain.ContentHash {
		t.Error("a recorded lookup name does not move the content hash")
	}
	b2, err := h.Marshal(named)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !strings.Contains(string(b2), `"lookup_name":"Run"`) {
		t.Errorf("canonical bytes omit the lookup name: %s", b2)
	}
	back, err := h.Unmarshal(b2)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if len(back.Edges) != 1 || back.Edges[0].LookupName != "Run" {
		t.Errorf("edges after the round trip = %+v, want the name back", back.Edges)
	}
	if err := h.VerifyContentHash(back); err != nil {
		t.Errorf("the round-tripped record does not verify: %v", err)
	}
}

// TestCallEdgeLess_OrdersOnTheLookupNameLast: two edges equal in every other
// field still have one order.
func TestCallEdgeLess_OrdersOnTheLookupNameLast(t *testing.T) {
	a := domain.CallEdge{FromID: "m.A", ToID: "m.B", LookupName: "Run"}
	b := domain.CallEdge{FromID: "m.A", ToID: "m.B", LookupName: "Stop"}
	if !domain.CallEdgeLess(a, b) || domain.CallEdgeLess(b, a) || domain.CallEdgeLess(a, a) {
		t.Error("CallEdgeLess does not order on the lookup name")
	}
}

// TestLookupNames_DecodesEachEncoding: no name set, the empty one, one name and
// a template's list.
func TestLookupNames_DecodesEachEncoding(t *testing.T) {
	for _, tt := range []struct {
		in    string
		names []string
		bound bool
	}{
		{in: "", bound: false},
		{in: domain.TemplateNamesNone, bound: true},
		{in: "Run", names: []string{"Run"}, bound: true},
		{in: domain.TemplateLookupNames([]string{"A", "B"}), names: []string{"A", "B"}, bound: true},
	} {
		names, bound := domain.LookupNames(tt.in)
		if bound != tt.bound || strings.Join(names, ",") != strings.Join(tt.names, ",") {
			t.Errorf("LookupNames(%q) = %q, %t, want %q, %t", tt.in, names, bound, tt.names, tt.bound)
		}
	}
	if got := domain.TemplateLookupNames(nil); got != domain.TemplateNamesNone {
		t.Errorf("TemplateLookupNames(nil) = %q, want %q", got, domain.TemplateNamesNone)
	}
}
