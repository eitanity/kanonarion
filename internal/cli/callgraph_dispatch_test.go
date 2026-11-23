package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	cgapp "code.eitanity.com/kanonarion/internal/callgraph/application"
	cgdomain "code.eitanity.com/kanonarion/internal/callgraph/domain"
	cgports "code.eitanity.com/kanonarion/internal/callgraph/ports"
	"code.eitanity.com/kanonarion/internal/cli/testfakes"
)

const (
	dispatchedMethod = "example.com/m.(*Body).Read"
	plainMethod      = "example.com/m.(*Body).reset"
)

var bodyDispatch = cgdomain.DependencyDispatch{
	Escape: cgdomain.DispatchEscape{
		Kind: cgdomain.EscapeConversion, Type: "*Body", Via: "io.Reader",
		Function: "example.com/m.Upload", Site: cgdomain.SourcePosition{File: "m.go", Line: 7},
	},
	Interfaces: []string{"io.Reader"},
}

func dispatchFake() *testfakes.FakeQueryCallGraph {
	return fakeWithRecord("example.com/m", "v1.0.0", cgapp.PipelineVersion, builtRecord([]cgdomain.CallNode{
		{ID: dispatchedMethod, Symbol: "Read", Receiver: "*Body", DependencyDispatch: bodyDispatch},
		{ID: plainMethod, Symbol: "reset", Receiver: "*Body"},
		{ID: "example.com/m.Upload", Symbol: "Upload"},
	}, nil))
}

func callerRef(from, to string) cgports.CallEdgeRef {
	return cgports.CallEdgeRef{ModulePath: "example.com/m", ModuleVersion: "v1.0.0", PipelineVersion: cgapp.PipelineVersion,
		FromID: from, ToID: to, Confidence: cgdomain.ConfidenceDirect}
}

// An empty answer for a method its type hands to a dependency is UNRESOLVED,
// naming the sink and the interface; a method without the fact stays ABSENT.
func TestRunCallers_EmptyDependencyDispatchIsUnresolved(t *testing.T) {
	uc := dispatchFake()
	var buf bytes.Buffer
	if err := runCallers(context.Background(), dispatchedMethod, false, uc, &buf, buildScope{}, cgports.EdgeQueryOptions{}); err != nil {
		t.Fatalf("runCallers: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "answer: UNRESOLVED") ||
		!strings.Contains(out, "dependency-dispatch-unmeasured at "+dispatchedMethod) ||
		!strings.Contains(out, "a dependency can call it through io.Reader") {
		t.Errorf("want UNRESOLVED naming the sink and io.Reader, got:\n%s", out)
	}

	buf.Reset()
	if err := runCallers(context.Background(), plainMethod, false, uc, &buf, buildScope{}, cgports.EdgeQueryOptions{}); err != nil {
		t.Fatalf("runCallers: %v", err)
	}
	if !strings.Contains(buf.String(), "answer: RESOLVED-ABSENT") {
		t.Errorf("a method without the fact must answer as before, got:\n%s", buf.String())
	}
}

// A non-empty answer stays present and says what it cannot list, on text and on
// the --json surface; without the fact neither says anything.
func TestRunCallers_PresentDependencyDispatchCarriesTheNotice(t *testing.T) {
	uc := dispatchFake()
	uc.SetCallersFor(dispatchedMethod, []cgports.CallEdgeRef{callerRef("example.com/m.Upload", dispatchedMethod)})
	uc.SetCallersFor(plainMethod, []cgports.CallEdgeRef{callerRef("example.com/m.Upload", plainMethod)})

	var buf bytes.Buffer
	if err := runCallers(context.Background(), dispatchedMethod, false, uc, &buf, buildScope{}, cgports.EdgeQueryOptions{}); err != nil {
		t.Fatalf("runCallers: %v", err)
	}
	if out := buf.String(); !strings.Contains(out, "answer: RESOLVED-PRESENT — 1 caller of "+dispatchedMethod+"; calls a dependency makes through an interface are not listed — dependency-dispatch-unmeasured at "+dispatchedMethod) ||
		!strings.Contains(out, "io.Reader") {
		t.Errorf("want the present answer to carry the notice, got:\n%s", out)
	}

	storeDispatchNotice.reset()
	defer storeDispatchNotice.reset()
	buf.Reset()
	if err := runCallers(context.Background(), dispatchedMethod, true, uc, &buf, buildScope{}, cgports.EdgeQueryOptions{}); err != nil {
		t.Fatalf("runCallers --json: %v", err)
	}
	var rows []map[string]any
	if err := json.Unmarshal(buf.Bytes(), &rows); err != nil || len(rows) != 1 {
		t.Fatalf("--json must stay the bare array of edges, got %q (%v)", buf.String(), err)
	}
	var stderr bytes.Buffer
	storeDispatchNotice.flush(&stderr)
	if !strings.Contains(stderr.String(), "dependency-dispatch-unmeasured at "+dispatchedMethod) {
		t.Errorf("--json must state the notice on stderr, got %q", stderr.String())
	}

	buf.Reset()
	if err := runCallers(context.Background(), plainMethod, false, uc, &buf, buildScope{}, cgports.EdgeQueryOptions{}); err != nil {
		t.Fatalf("runCallers: %v", err)
	}
	if strings.Contains(buf.String(), "answer:") {
		t.Errorf("a method without the fact prints no answer line, got:\n%s", buf.String())
	}
	if err := runCallers(context.Background(), plainMethod, true, uc, &buf, buildScope{}, cgports.EdgeQueryOptions{}); err != nil {
		t.Fatalf("runCallers --json: %v", err)
	}
	stderr.Reset()
	storeDispatchNotice.flush(&stderr)
	if stderr.Len() != 0 {
		t.Errorf("a method without the fact states nothing on stderr, got %q", stderr.String())
	}
}

// The transitive walk names every symbol in its closure that carries the fact,
// the root among them, on the answer line and in the document.
func TestRunCallersTransitive_DependencyDispatchInTheClosure(t *testing.T) {
	uc := dispatchFake()
	uc.SetTraverseCallers([]cgports.CallEdgeRef{callerRef(dispatchedMethod, plainMethod)}, []string{dispatchedMethod})

	var buf bytes.Buffer
	if err := runCallersTransitive(context.Background(), plainMethod, 0, false, uc, &buf, buildScope{}, cgports.EdgeQueryOptions{}, nil); err != nil {
		t.Fatalf("runCallersTransitive: %v", err)
	}
	if out := buf.String(); !strings.Contains(out, "answer: RESOLVED-PRESENT") || !strings.Contains(out, "dependency-dispatch-unmeasured at "+dispatchedMethod) {
		t.Errorf("want the closure's dispatch named on the answer line, got:\n%s", out)
	}

	buf.Reset()
	if err := runCallersTransitive(context.Background(), plainMethod, 0, true, uc, &buf, buildScope{}, cgports.EdgeQueryOptions{}, nil); err != nil {
		t.Fatalf("runCallersTransitive --json: %v", err)
	}
	var doc transitiveResult
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("decoding: %v", err)
	}
	if len(doc.DependencyDispatch) != 1 || doc.DependencyDispatch[0].Site != dispatchedMethod ||
		doc.DependencyDispatch[0].Kind != string(cgdomain.SinkDependencyDispatchUnmeasured) {
		t.Errorf("dependency_dispatch = %+v, want the one method", doc.DependencyDispatch)
	}

	empty := dispatchFake()
	buf.Reset()
	if err := runCallersTransitive(context.Background(), dispatchedMethod, 0, false, empty, &buf, buildScope{}, cgports.EdgeQueryOptions{}, nil); err != nil {
		t.Fatalf("runCallersTransitive: %v", err)
	}
	if !strings.Contains(buf.String(), "answer: UNRESOLVED") || !strings.Contains(buf.String(), "dependency-dispatch-unmeasured") {
		t.Errorf("an empty closure over the method is UNRESOLVED, got:\n%s", buf.String())
	}
}

// callgraph-show --json shows the fact callers acts on, on the node carrying
// it, and leaves the key out of every other node.
func TestCallGraphJSON_DependencyDispatchOnTheNode(t *testing.T) {
	withProd := bodyDispatch
	withProd.ProductionEscape, withProd.ProductionInterfaces = bodyDispatch.Escape, bodyDispatch.Interfaces
	b, err := json.Marshal(toCallGraphJSON(cgdomain.CallGraphRecord{Nodes: []cgdomain.CallNode{
		{ID: dispatchedMethod, Symbol: "Read", DependencyDispatch: withProd},
		{ID: "example.com/m.(Secret).LogValue", Symbol: "LogValue", DependencyDispatch: bodyDispatch},
		{ID: plainMethod, Symbol: "reset"},
	}}))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Nodes []map[string]json.RawMessage `json:"nodes"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	const escape = `"escape":{"kind":"interface-conversion","type":"*Body","via":"io.Reader","function":"example.com/m.Upload","site_file":"m.go","site_line":7},"interfaces":["io.Reader"]`
	for i, want := range []string{
		`{` + escape + `,"production":{` + escape + `}}`,
		`{` + escape + `}`,
		``,
	} {
		if got := string(doc.Nodes[i]["dependency_dispatch"]); got != want {
			t.Errorf("node %d dependency_dispatch = %s, want %s", i, got, want)
		}
	}
}
