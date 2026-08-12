package domain_test

import (
	"encoding/json"
	"maps"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/callgraph/domain"
	"github.com/eitanity/kanonarion/internal/coordinate"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
)

// interfaceRecord is a record carrying the v13 axes: test-tagged nodes, a
// declared interface, and two implementations of it.
func interfaceRecord(t *testing.T) domain.CallGraphRecord {
	t.Helper()
	coord, err := coordinate.NewModuleCoordinate("example.com/m", "v1.0.0")
	if err != nil {
		t.Fatalf("coordinate: %v", err)
	}
	return domain.CallGraphRecord{
		SchemaVersion: domain.CallGraphSchemaVersion,
		Ecosystem:     fetchdomain.EcosystemGo,
		Coordinate:    coord,
		Algorithm:     domain.AlgorithmCHA,
		Completeness:  domain.CompletenessBuiltWithBodies,
		TestScope:     domain.TestScopeAnalysed,
		Nodes: []domain.CallNode{
			{ID: "example.com/m/adapter.(*Store).Put", Symbol: "Put", Package: "example.com/m/adapter"},
			{ID: "example.com/m/app_test.(*fake).Put", Symbol: "Put", Package: "example.com/m/app_test", IsTest: true},
		},
		Edges: []domain.CallEdge{
			{FromID: "example.com/m/app_test.(*fake).Put", ToID: "example.com/m/adapter.(*Store).Put", Confidence: domain.ConfidenceDirect},
		},
		Interfaces: []domain.InterfaceType{
			{
				ID: "example.com/m/ports.Store", Package: "example.com/m/ports", Name: "Store",
				Methods:  []string{"Put", "Get"},
				Position: domain.SourcePosition{File: "ports/ports.go", Line: 3},
			},
		},
		Implementations: []domain.InterfaceImplementation{
			{
				InterfaceID: "example.com/m/ports.Store",
				TypeID:      "example.com/m/app_test.(*fake)",
				Package:     "example.com/m/app_test",
				Position:    domain.SourcePosition{File: "app/app_test.go", Line: 9},
				IsTest:      true,
				Methods: []domain.ImplementedMethod{
					{Method: "Put", NodeID: "example.com/m/app_test.(*fake).Put"},
					{Method: "Get", NodeID: "example.com/m/app_test.(*fake).Get"},
				},
			},
			{
				InterfaceID: "example.com/m/ports.Store",
				TypeID:      "example.com/m/adapter.(*Store)",
				Package:     "example.com/m/adapter",
				Position:    domain.SourcePosition{File: "adapter/adapter.go", Line: 5},
				Methods: []domain.ImplementedMethod{
					{Method: "Put", NodeID: "example.com/m/adapter.(*Store).Put"},
					{Method: "Get", NodeID: "example.com/m/adapter.(*Store).Get"},
				},
			},
		},
		NodeCount:       2,
		EdgeCount:       1,
		ExtractedAt:     time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC),
		PipelineVersion: "0.3.0",
	}
}

// TestCanonicalOrder_OrdersTheV13Collections: the hash is taken over the
// canonical order, so a record whose interfaces, their methods, its
// implementations, or their methods arrive in a different order still reaches
// the same shape on the wire.
func TestCanonicalOrder_OrdersTheV13Collections(t *testing.T) {
	var h domain.CallGraphRecordHasher
	built := interfaceRecord(t)
	rec := built
	rec.Interfaces = append(rec.Interfaces, domain.InterfaceType{
		ID: "example.com/m/ports.Alpha", Package: "example.com/m/ports", Name: "Alpha",
		Methods: []string{"Zed", "Abel"},
	})
	rec = roundTrip(t, h, rec)

	if got := []string{rec.Interfaces[0].ID, rec.Interfaces[1].ID}; got[0] >= got[1] {
		t.Errorf("interfaces not sorted by ID: %v", got)
	}
	if got := rec.Interfaces[0].Methods; !reflect.DeepEqual(got, []string{"Abel", "Zed"}) {
		t.Errorf("interface methods not sorted: %v", got)
	}
	if a, b := rec.Implementations[0].TypeID, rec.Implementations[1].TypeID; a >= b {
		t.Errorf("implementations not sorted by type ID: %q then %q", a, b)
	}
	for _, im := range rec.Implementations {
		if im.Methods[0].Method != "Get" || im.Methods[1].Method != "Put" {
			t.Errorf("%s methods not sorted: %v", im.TypeID, im.Methods)
		}
	}
}

// TestHash_RoundTripsTheV13Axes: the interface relation and the test axis are
// part of the record's identity, so they must survive Marshal/Unmarshal
// unchanged and the hash must verify over them.
func TestHash_RoundTripsTheV13Axes(t *testing.T) {
	var h domain.CallGraphRecordHasher
	rec := interfaceRecord(t)

	hashed, err := h.SetContentHash(rec)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	raw, err := h.Marshal(hashed)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	back, err := h.Unmarshal(raw)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	// The record is compared against its own canonical order rather than the
	// order it was built in: marshalling is what puts a record in order, so the
	// bytes are entitled to differ from the arrangement handed to them.
	want := hashed
	want.Interfaces = canonicalInterfaces(hashed.Interfaces)
	want.Implementations = canonicalImplementations(hashed.Implementations)
	if !reflect.DeepEqual(back.Interfaces, want.Interfaces) {
		t.Errorf("interfaces did not round trip:\n got %+v\nwant %+v", back.Interfaces, want.Interfaces)
	}
	if !reflect.DeepEqual(back.Implementations, want.Implementations) {
		t.Errorf("implementations did not round trip:\n got %+v\nwant %+v", back.Implementations, want.Implementations)
	}
	if back.TestScope != domain.TestScopeAnalysed {
		t.Errorf("TestScope = %q, want Analysed", back.TestScope)
	}
	if !back.Nodes[1].IsTest {
		t.Error("the node's test role did not round trip")
	}
	if err := h.VerifyContentHash(back); err != nil {
		t.Errorf("VerifyContentHash after round trip: %v", err)
	}
}

// TestHash_TestScopeDetailRoundTrips keeps the reason an axis went unmeasured
// inside the hashed record: a detail that could be edited without changing the
// hash would be a claim nothing protects.
func TestHash_TestScopeDetailRoundTrips(t *testing.T) {
	var h domain.CallGraphRecordHasher
	rec := interfaceRecord(t)
	rec.TestScope = domain.TestScopeExcluded
	rec.TestScopeDetail = "loading the module with test files failed: boom"

	hashed, err := h.SetContentHash(rec)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	raw, err := h.Marshal(hashed)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	back, err := h.Unmarshal(raw)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if back.TestScope != domain.TestScopeExcluded || back.TestScopeDetail != rec.TestScopeDetail {
		t.Errorf("test scope did not round trip: %q / %q", back.TestScope, back.TestScopeDetail)
	}
}

// TestHash_InterfaceRelationIsCovered proves the new collections are inside the
// hash rather than beside it: changing one implementation must change the
// digest, or the relation is not tamper-evident.
func TestHash_InterfaceRelationIsCovered(t *testing.T) {
	var h domain.CallGraphRecordHasher
	base := interfaceRecord(t)
	hashedBase, err := h.SetContentHash(base)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}

	for _, tc := range []struct {
		name  string
		mutny func(r *domain.CallGraphRecord)
	}{
		{"drop an implementation", func(r *domain.CallGraphRecord) { r.Implementations = r.Implementations[:1] }},
		{"retarget a method", func(r *domain.CallGraphRecord) { r.Implementations[0].Methods[0].NodeID = "elsewhere.X" }},
		{"flip an implementation's test role", func(r *domain.CallGraphRecord) { r.Implementations[0].IsTest = !r.Implementations[0].IsTest }},
		{"drop an interface", func(r *domain.CallGraphRecord) { r.Interfaces = nil }},
		{"add an interface method", func(r *domain.CallGraphRecord) { r.Interfaces[0].Methods = append(r.Interfaces[0].Methods, "Delete") }},
		{"flip a node's test role", func(r *domain.CallGraphRecord) { r.Nodes[0].IsTest = !r.Nodes[0].IsTest }},
		{"change the test scope", func(r *domain.CallGraphRecord) { r.TestScope = domain.TestScopeExcluded }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mutated := interfaceRecord(t)
			tc.mutny(&mutated)
			hashedMut, err := h.SetContentHash(mutated)
			if err != nil {
				t.Fatalf("SetContentHash: %v", err)
			}
			if hashedMut.ContentHash == hashedBase.ContentHash {
				t.Errorf("mutation left the content hash unchanged: the axis is outside the hash")
			}
		})
	}
}

// TestHash_MarshalSortsIndependently: marshalCanonical must produce the
// canonical order even for a record the caller never sorted, so a hash never
// depends on the order the analyser happened to append in.
func TestHash_MarshalSortsIndependently(t *testing.T) {
	var h domain.CallGraphRecordHasher
	sorted := interfaceRecord(t)
	unsorted := interfaceRecord(t)
	unsorted.Interfaces[0].Methods = []string{"Put", "Get"}
	unsorted.Implementations[0], unsorted.Implementations[1] = unsorted.Implementations[1], unsorted.Implementations[0]

	a, err := h.SetContentHash(sorted)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	b, err := h.SetContentHash(unsorted)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	if a.ContentHash != b.ContentHash {
		t.Errorf("hash depends on input order: %s vs %s", a.ContentHash, b.ContentHash)
	}
}

// TestHash_OmitsEmptyV13Collections keeps the additive-field contract: a module
// declaring no interfaces must not carry empty keys whose presence alone would
// change every hash.
func TestHash_OmitsEmptyV13Collections(t *testing.T) {
	var h domain.CallGraphRecordHasher
	rec := interfaceRecord(t)
	rec.Interfaces = nil
	rec.Implementations = nil
	rec.TestScope = domain.TestScopeUnknown

	raw, err := h.Marshal(rec)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	for _, key := range []string{`"interfaces"`, `"implementations"`, `"test_scope"`, `"test_scope_detail"`} {
		if strings.Contains(string(raw), key) {
			t.Errorf("empty %s must be omitted from the canonical form: %s", key, raw)
		}
	}
	// And it must still decode to a record that makes no claim about the axis.
	back, err := h.Unmarshal(raw)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if back.TestScope.IsMeasured() {
		t.Error("a record with no recorded test scope must not read as measured")
	}
	if back.Interfaces != nil || back.Implementations != nil {
		t.Errorf("absent collections decoded as non-nil: %v / %v", back.Interfaces, back.Implementations)
	}
}

// TestUnmarshal_RejectsMalformedJSON covers the decode guard on the new shape:
// a blob that is not the canonical form must fail rather than yield a record
// with silently empty collections.
func TestUnmarshal_RejectsMalformedJSON(t *testing.T) {
	var h domain.CallGraphRecordHasher
	if _, err := h.Unmarshal([]byte(`{"interfaces": "not-a-list"}`)); err == nil {
		t.Fatal("expected an error decoding a malformed interfaces field")
	}
}

// TestUnmarshal_BadCoordinateAndTime pins the remaining decode guards so a
// corrupt blob is reported, never returned as a partially-populated record.
func TestUnmarshal_BadCoordinateAndTime(t *testing.T) {
	var h domain.CallGraphRecordHasher
	rec := interfaceRecord(t)
	hashed, err := h.SetContentHash(rec)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	raw, err := h.Marshal(hashed)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var generic map[string]json.RawMessage
	if uerr := json.Unmarshal(raw, &generic); uerr != nil {
		t.Fatalf("re-decoding canonical form: %v", uerr)
	}

	t.Run("bad timestamp", func(t *testing.T) {
		broken := cloneWith(t, generic, "extracted_at", `"not-a-time"`)
		if _, err := h.Unmarshal(broken); err == nil {
			t.Error("expected an error for an unparseable extracted_at")
		}
	})
	t.Run("zero coordinate", func(t *testing.T) {
		broken := cloneWith(t, generic, "coordinate", `{"path":"","version":""}`)
		if _, err := h.Unmarshal(broken); err == nil {
			t.Error("expected an error for a coordinate naming no module")
		}
	})
	t.Run("wrong ecosystem", func(t *testing.T) {
		broken := cloneWith(t, generic, "ecosystem", `"npm"`)
		if _, err := h.Unmarshal(broken); err == nil {
			t.Error("expected an error for a foreign ecosystem")
		}
	})
}

func cloneWith(t *testing.T, base map[string]json.RawMessage, key, value string) []byte {
	t.Helper()
	out := make(map[string]json.RawMessage, len(base))
	maps.Copy(out, base)
	out[key] = json.RawMessage(value)
	raw, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("marshalling mutated blob: %v", err)
	}
	return raw
}

// TestSortAndMarshal_AcrossSeveralInterfaces exercises the comparators that
// only fire once a record holds more than one interface and implementations of
// more than one of them — the shape every real module has, and the one where a
// mis-ordered canonical form would silently change the hash.
func TestSortAndMarshal_AcrossSeveralInterfaces(t *testing.T) {
	var h domain.CallGraphRecordHasher
	build := func() domain.CallGraphRecord {
		rec := interfaceRecord(t)
		rec.Interfaces = append(rec.Interfaces, domain.InterfaceType{
			ID: "example.com/m/ports.Alpha", Package: "example.com/m/ports", Name: "Alpha",
			Methods: []string{"Run"},
		})
		rec.Implementations = append(rec.Implementations, domain.InterfaceImplementation{
			InterfaceID: "example.com/m/ports.Alpha",
			TypeID:      "example.com/m/runner.(*R)",
			Package:     "example.com/m/runner",
			Methods:     []domain.ImplementedMethod{{Method: "Run", NodeID: "example.com/m/runner.(*R).Run"}},
		})
		return rec
	}

	sorted := roundTrip(t, h, build())
	if sorted.Interfaces[0].ID != "example.com/m/ports.Alpha" {
		t.Errorf("interfaces not sorted across declarations: %v", sorted.Interfaces)
	}
	if sorted.Implementations[0].InterfaceID != "example.com/m/ports.Alpha" {
		t.Errorf("implementations not grouped by interface: %v", sorted.Implementations)
	}

	// Marshal sorts on its own copy, so a record handed over in any order must
	// hash identically to the sorted one.
	reversed := build()
	reversed.Interfaces[0], reversed.Interfaces[1] = reversed.Interfaces[1], reversed.Interfaces[0]
	reversed.Implementations[0], reversed.Implementations[2] = reversed.Implementations[2], reversed.Implementations[0]

	a, err := h.SetContentHash(sorted)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	b, err := h.SetContentHash(reversed)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	if a.ContentHash != b.ContentHash {
		t.Errorf("canonical form depends on input order across interfaces: %s vs %s", a.ContentHash, b.ContentHash)
	}
}

// TestParseInterfaceMethodID_MalformedShapes covers the guards that keep a
// mangled ID from being read as a valid per-method query, which would send the
// lookup after an interface nobody named.
func TestParseInterfaceMethodID_MalformedShapes(t *testing.T) {
	for _, in := range []string{
		"pkg/path.(Store",       // opened but never closed
		"pkg/path.(Store).B(C)", // the method half is not an identifier
		"pkg/path.(Store).a.b",  // ditto, via a qualified tail
		"pkg/path.(*Store).Put", // a concrete method: a node, not an interface
	} {
		if _, _, ok := domain.ParseInterfaceMethodID(in); ok {
			t.Errorf("ParseInterfaceMethodID(%q) accepted a malformed ID", in)
		}
	}
}

// TestClassifyNegativeVerdict_TestScopeSinkWithoutANode: when the queried
// symbol is not a node at all, the sink still has to name something the reader
// can act on, so it falls back to the method name rather than an empty site.
func TestClassifyNegativeVerdict_TestScopeSinkWithoutANode(t *testing.T) {
	v := domain.ClassifyNegativeVerdict(domain.NegativeVerdictInputs{
		MethodName: "Put",
		Found:      false,
		TestScope:  domain.TestScopeUnknown,
	})
	if v.Outcome != domain.VerdictUnresolved {
		t.Fatalf("outcome = %s, want UNRESOLVED", v.Outcome)
	}
	for _, s := range v.Sinks {
		if s.Kind == domain.SinkTestScopeUnmeasured {
			if s.Site != "Put" {
				t.Errorf("sink site = %q, want the method name as the fallback", s.Site)
			}
			return
		}
	}
	t.Errorf("no test-scope sink among %v", v.Sinks)
}

// canonicalInterfaces and canonicalImplementations put a collection into the
// order the canonical bytes carry, using the record's own comparators.
func canonicalInterfaces(in []domain.InterfaceType) []domain.InterfaceType {
	out := append([]domain.InterfaceType(nil), in...)
	for i := range out {
		methods := append([]string(nil), out[i].Methods...)
		sort.Strings(methods)
		out[i].Methods = methods
	}
	sort.Slice(out, func(i, j int) bool { return domain.InterfaceTypeLess(out[i], out[j]) })
	return out
}

func canonicalImplementations(in []domain.InterfaceImplementation) []domain.InterfaceImplementation {
	out := append([]domain.InterfaceImplementation(nil), in...)
	for i := range out {
		methods := append([]domain.ImplementedMethod(nil), out[i].Methods...)
		sort.Slice(methods, func(a, b int) bool { return domain.ImplementedMethodLess(methods[a], methods[b]) })
		out[i].Methods = methods
	}
	sort.Slice(out, func(i, j int) bool { return domain.InterfaceImplementationLess(out[i], out[j]) })
	return out
}

// roundTrip marshals a record and reads it back, which is how a caller sees the
// canonical order of a record it built in any order.
func roundTrip(t *testing.T, h domain.CallGraphRecordHasher, rec domain.CallGraphRecord) domain.CallGraphRecord {
	t.Helper()
	raw, err := h.Marshal(rec)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	back, err := h.Unmarshal(raw)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	return back
}
