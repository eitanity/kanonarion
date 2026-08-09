package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	cgdomain "github.com/eitanity/kanonarion/internal/callgraph/domain"
)

// referenceAxisRecord is a two-edge record: one call, one reference. It is the
// smallest graph on which the two edges must read differently.
func referenceAxisRecord() cgdomain.CallGraphRecord {
	rec := builtRecord(
		[]cgdomain.CallNode{
			{ID: "example.com/m.register", Symbol: "register"},
			{ID: "example.com/m.Handler", Symbol: "Handler"},
			{ID: "example.com/m.helper", Symbol: "helper"},
		},
		[]cgdomain.CallEdge{
			{FromID: "example.com/m.register", ToID: "example.com/m.helper", Confidence: cgdomain.ConfidenceDirect},
			{FromID: "example.com/m.register", ToID: "example.com/m.Handler", Confidence: cgdomain.ConfidenceDirect, Kind: cgdomain.EdgeKindReference},
		},
	)
	rec.NodeCount = len(rec.Nodes)
	rec.EdgeCount = len(rec.Edges)
	return rec
}

// TestCallGraphShowJSON_EdgeStatesItsKind: the record dump must distinguish a
// registration from an invocation.
//
// It did not. Every edge marshalled with the same fields, so a consumer
// counting edges out of the dump counted a place a function value was TAKEN as
// a place it was CALLED — the exact conflation the reference axis exists to
// prevent. `callers` labelled it; the record dump silently did not.
func TestCallGraphShowJSON_EdgeStatesItsKind(t *testing.T) {
	out := toCallGraphJSON(referenceAxisRecord())

	byTo := map[string]callEdgeJSON{}
	for _, e := range out.Edges {
		byTo[e.ToID] = e
	}
	if got := byTo["example.com/m.helper"].Kind; got != "Call" {
		t.Errorf("call edge kind = %q, want \"Call\"", got)
	}
	if got := byTo["example.com/m.Handler"].Kind; got != "Reference" {
		t.Errorf("reference edge kind = %q, want \"Reference\"", got)
	}
}

// TestCallGraphShowJSON_KindIsAlwaysPresent: the kind is spelled out on every
// edge rather than omitted for calls.
//
// An omitted field puts the reader back where they started — they cannot tell a
// call from a producer that never recorded kinds — which is the same failure in
// a quieter form.
func TestCallGraphShowJSON_KindIsAlwaysPresent(t *testing.T) {
	b, err := json.Marshal(toCallGraphJSON(referenceAxisRecord()))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var doc struct {
		Edges []map[string]any `json:"edges"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for i, e := range doc.Edges {
		if _, ok := e["kind"]; !ok {
			t.Errorf("edge %d marshalled without a kind field: %v", i, e)
		}
	}
}

// TestCallGraphShowJSON_CarriesTheReferenceAxis: the axis a confident negative
// rests on must be visible on the record, the way test_scope is.
func TestCallGraphShowJSON_CarriesTheReferenceAxis(t *testing.T) {
	out := toCallGraphJSON(referenceAxisRecord())
	if out.ReferenceScope != string(cgdomain.ReferenceScopeAnalysed) {
		t.Errorf("reference_scope = %q, want %q", out.ReferenceScope, cgdomain.ReferenceScopeAnalysed)
	}
	if out.ReferenceEdgeCount != 1 {
		t.Errorf("reference_edge_count = %d, want 1", out.ReferenceEdgeCount)
	}
}

// TestCallGraphShowJSON_UnmeasuredReferenceAxisIsStillEmitted is the
// zero-paired control. An unmeasured axis is the value that matters most — it
// is what makes an empty callers answer UNRESOLVED — so the field must be
// present and empty rather than absent, and the count must not imply a search.
func TestCallGraphShowJSON_UnmeasuredReferenceAxisIsStillEmitted(t *testing.T) {
	rec := referenceAxisRecord()
	rec.ReferenceScope = cgdomain.ReferenceScopeUnknown
	rec.Edges = rec.Edges[:1]
	rec.EdgeCount = 1

	b, err := json.Marshal(toCallGraphJSON(rec))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	v, ok := doc["reference_scope"]
	if !ok {
		t.Fatal("reference_scope absent from an unmeasured record — the reader cannot tell it from a measured one")
	}
	if v != "" {
		t.Errorf("reference_scope = %v, want the empty string", v)
	}
	if _, ok := doc["reference_edge_count"]; !ok {
		t.Error("reference_edge_count absent")
	}
	// The control: test_scope is measured on the same record, so an empty
	// reference axis cannot be an artefact of the record being empty.
	if doc["test_scope"] != string(cgdomain.TestScopeAnalysed) {
		t.Errorf("test_scope = %v, want %q — the control axis must be measured", doc["test_scope"], cgdomain.TestScopeAnalysed)
	}
}

// TestCallGraphShow_PrintsTheReferenceScopeLine: the text surface states the
// axis on every record, the way it states test scope.
func TestCallGraphShow_PrintsTheReferenceScopeLine(t *testing.T) {
	var buf bytes.Buffer
	if err := printCallGraphRecord(referenceAxisRecord(), 10, 10, &buf); err != nil {
		t.Fatalf("printCallGraphRecord: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"reference scope: analysed", "1 of 2 edges"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

// TestCallGraphShow_PrintsTheUnmeasuredReferenceScopeLine: a record that never
// looked says so, and says what that costs a reader — the sentence is the whole
// point of printing the axis at all.
func TestCallGraphShow_PrintsTheUnmeasuredReferenceScopeLine(t *testing.T) {
	rec := referenceAxisRecord()
	rec.ReferenceScope = cgdomain.ReferenceScopeUnknown

	var buf bytes.Buffer
	if err := printCallGraphRecord(rec, 10, 10, &buf); err != nil {
		t.Fatalf("printCallGraphRecord: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"reference scope: not recorded", "UNRESOLVED"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
	// Control: the measured test axis still prints beside it.
	if !strings.Contains(out, "test scope: analysed") {
		t.Errorf("the control axis stopped printing:\n%s", out)
	}
}
