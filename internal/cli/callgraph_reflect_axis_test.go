package cli

import (
	"encoding/json"
	"testing"

	cgdomain "github.com/eitanity/kanonarion/internal/callgraph/domain"
)

// The analyser records one attribute about reflection on every call edge, and
// until now it reached no reader at all: a `callgraph-show --json` edge carried
// from_id, to_id, the call site, the confidence and the kind, and not this.
// Anyone asking what the analysis could see about reflection — including
// kanonarion's own reachability report — had no way to find out.

// reflectAxisRecord is the smallest graph on which the attribute must read
// differently edge by edge: one plain call, one call into a reflect method that
// bounds perfectly, one into a reflect method that picks its target at run time.
//
// The last two both carry the attribute. That is the point of having both: the
// attribute means "the callee is in package reflect" and says nothing about
// whether the callee can be bound, so a surface that conflates them overstates
// the calls an analysis cannot follow by about two orders of magnitude.
func reflectAxisRecord() cgdomain.CallGraphRecord {
	rec := builtRecord(
		[]cgdomain.CallNode{
			{ID: "example.com/m.bind", Symbol: "bind"},
			{ID: "example.com/m.helper", Symbol: "helper"},
			{ID: "reflect.TypeOf", Package: "reflect", Symbol: "TypeOf", IsExternal: true},
			{ID: "reflect.(Value).MethodByName", Package: "reflect", Receiver: "Value", Symbol: "MethodByName", IsExternal: true},
		},
		[]cgdomain.CallEdge{
			{FromID: "example.com/m.bind", ToID: "example.com/m.helper", Confidence: cgdomain.ConfidenceDirect},
			{FromID: "example.com/m.bind", ToID: "reflect.TypeOf", Confidence: cgdomain.ConfidenceUnknown, ReflectDispatch: true},
			{FromID: "example.com/m.bind", ToID: "reflect.(Value).MethodByName", Confidence: cgdomain.ConfidenceUnknown, ReflectDispatch: true},
		},
	)
	rec.NodeCount = len(rec.Nodes)
	rec.EdgeCount = len(rec.Edges)
	return rec
}

// TestCallGraphShowJSON_EdgeStatesItsReflectAttribute: the record dump carries
// what the analyser measured about reflection, edge by edge.
//
// This is a deliberate addition to a surface that was previously asserted
// byte-identical. It adds a key and changes no existing one.
func TestCallGraphShowJSON_EdgeStatesItsReflectAttribute(t *testing.T) {
	t.Parallel()

	out := toCallGraphJSON(reflectAxisRecord())
	byTo := map[string]callEdgeJSON{}
	for _, e := range *out.Edges {
		byTo[e.ToID] = e
	}
	if byTo["example.com/m.helper"].ReflectDispatch {
		t.Error("a plain call between two of the module's own functions is reported as touching reflect")
	}
	for _, to := range []string{"reflect.TypeOf", "reflect.(Value).MethodByName"} {
		if !byTo[to].ReflectDispatch {
			t.Errorf("the edge to %s does not carry the attribute the analyser recorded on it", to)
		}
	}
}

// TestCallGraphShowJSON_ReflectAttributeIsAlwaysPresent: the key is spelled out
// on every edge rather than omitted where it is false.
//
// It follows the reasoning already written on the kind field beside it: an
// absent field puts the reader back where they started, unable to tell a
// measured false from a producer that never recorded the attribute. There is no
// third state to tell them from — the migration that added the column purged
// every row written before it — so false here always means measured.
func TestCallGraphShowJSON_ReflectAttributeIsAlwaysPresent(t *testing.T) {
	t.Parallel()

	raw, err := json.Marshal(toCallGraphJSON(reflectAxisRecord()))
	if err != nil {
		t.Fatalf("marshalling: %v", err)
	}
	var doc struct {
		Edges []map[string]any `json:"edges"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	if len(doc.Edges) != 3 {
		t.Fatalf("the dump holds %d edges, want 3", len(doc.Edges))
	}
	want := map[string]bool{
		"example.com/m.helper":         false,
		"reflect.TypeOf":               true,
		"reflect.(Value).MethodByName": true,
	}
	for _, e := range doc.Edges {
		got, present := e["reflect_dispatch"]
		if !present {
			t.Errorf("the edge to %v carries no reflect_dispatch key: %v", e["to_id"], e)
			continue
		}
		to, _ := e["to_id"].(string)
		if got != want[to] {
			t.Errorf("the edge to %s reports reflect_dispatch %v, want %t", to, got, want[to])
		}
	}
}
