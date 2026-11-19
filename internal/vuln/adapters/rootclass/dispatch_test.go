package rootclass_test

import (
	"strings"
	"testing"

	cgdomain "code.eitanity.com/kanonarion/internal/callgraph/domain"
	vuldomain "code.eitanity.com/kanonarion/internal/vuln/domain"
)

var bodyEscape = cgdomain.DispatchEscape{
	Kind: cgdomain.EscapeConversion, Type: "*Body", Via: "io.Reader",
	Function: "example.com/app/handlers.Upload", Site: cgdomain.SourcePosition{File: "h.go", Line: 3},
}

func dispatched(n *cgdomain.CallNode) {
	n.DependencyDispatch = cgdomain.DependencyDispatch{
		Escape: bodyEscape, Interfaces: []string{"io.Reader"},
		ProductionEscape: bodyEscape, ProductionInterfaces: []string{"io.Reader"},
	}
}

// dispatchedInTestOnly is the same fact with its only hand-off in a test.
func dispatchedInTestOnly(n *cgdomain.CallNode) {
	n.DependencyDispatch = cgdomain.DependencyDispatch{Escape: bodyEscape, Interfaces: []string{"io.Reader"}}
}

// A root nothing in the module calls, whose type the module hands to a
// dependency, is entered from outside: the graph's silence was the claim. With
// an in-module caller recorded it keeps its kind.
func TestClassify_AMethodADependencyCanCallIsIngressWhenNothingElseCallsIt(t *testing.T) {
	const read = "example.com/app/handlers.(*Body).Read"
	const caller = "example.com/app/handlers.copyAll"

	root := classifyEntry(t, appRecord([]cgdomain.CallNode{node(read, "*Body", "Read", exported, dispatched)}, nil), "Read", "*Body")
	if root.Kind != vuldomain.RootIngress || !strings.Contains(root.Reason, "io.Reader") {
		t.Errorf("root = %s (%s), want ingress naming io.Reader", root.Kind, root.Reason)
	}
	if !root.Ancestry.Found || root.Ancestry.Hops != 0 {
		t.Errorf("ancestry = %+v, want the method itself as the entry point", root.Ancestry)
	}

	control := classifyEntry(t, appRecord([]cgdomain.CallNode{node(read, "*Body", "Read", exported)}, nil), "Read", "*Body")
	if control.Kind != vuldomain.RootExportedAPI {
		t.Errorf("without the fact the root = %s, want exported-api as before", control.Kind)
	}
	testOnly := classifyEntry(t, appRecord([]cgdomain.CallNode{node(read, "*Body", "Read", exported, dispatchedInTestOnly)}, nil), "Read", "*Body")
	if testOnly.Kind != vuldomain.RootExportedAPI || testOnly.Ancestry.Found {
		t.Errorf("with only a test's hand-off the root = %s (ancestry %+v), want exported-api as before", testOnly.Kind, testOnly.Ancestry)
	}

	called := classifyEntry(t, appRecord(
		[]cgdomain.CallNode{node(read, "*Body", "Read", exported, dispatched), node(caller, "", "copyAll")},
		[]cgdomain.CallEdge{{FromID: caller, ToID: read, Confidence: cgdomain.ConfidenceDirect}}), "Read", "*Body")
	if called.Kind != vuldomain.RootInternal {
		t.Errorf("with an in-module caller the root = %s, want internal as before", called.Kind)
	}
}

// The distance search falls back to the methods a dependency can call only
// where no named entry point is above the node, so a distance it found before
// is unchanged.
func TestClassify_DependencyDispatchIsTheAncestorOnlyWhereNothingElseIs(t *testing.T) {
	const (
		read   = "example.com/app/handlers.(*body).Read"
		helper = "example.com/app/handlers.fill"
		main   = "example.com/app/handlers.main"
		mid    = "example.com/app/handlers.mid"
	)
	nodes := []cgdomain.CallNode{node(read, "*body", "Read", dispatched), node(helper, "", "fill")}
	edges := []cgdomain.CallEdge{{FromID: read, ToID: helper, Confidence: cgdomain.ConfidenceDirect}}

	a := classifyEntry(t, appRecord(nodes, edges), "fill", "").Ancestry
	if !a.Found || a.Hops != 1 || a.EntryPointID != read || !strings.Contains(a.EntryPointReason, "io.Reader") {
		t.Errorf("ancestry = %+v, want the dispatched method one hop up", a)
	}
	testOnly := []cgdomain.CallNode{node(read, "*body", "Read", dispatchedInTestOnly), node(helper, "", "fill")}
	if a := classifyEntry(t, appRecord(testOnly, edges), "fill", "").Ancestry; a.Found {
		t.Errorf("ancestry = %+v, want none: the only hand-off is in a test", a)
	}

	nodes = append(nodes, node(main, "", "main"), node(mid, "", "mid"))
	edges = append(edges,
		cgdomain.CallEdge{FromID: main, ToID: mid, Confidence: cgdomain.ConfidenceDirect},
		cgdomain.CallEdge{FromID: mid, ToID: helper, Confidence: cgdomain.ConfidenceDirect})
	b := classifyEntry(t, appRecord(nodes, edges), "fill", "").Ancestry
	if !b.Found || b.EntryPointID != main || b.Hops != 2 {
		t.Errorf("ancestry = %+v, want main two hops up: a named entry point keeps the distance it had", b)
	}
}
