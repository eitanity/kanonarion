package staticcha_test

import (
	"context"
	"log/slog"
	"testing"

	"github.com/eitanity/kanonarion/internal/callgraph/adapters/analyser/staticcha"
	"github.com/eitanity/kanonarion/internal/callgraph/domain"
)

// analyseFiles zips files as testCoord, runs Analyse, and returns the record,
// skipping the test if go/packages could not load the module (e.g. no toolchain
// in the sandbox).
func analyseFiles(t *testing.T, files map[string]string) domain.CallGraphRecord {
	t.Helper()
	a := staticcha.New("0.1.0", "", slog.Default())
	zipPath := writeZipToTemp(t, makeZip(t, testCoord, files))
	rec, err := a.Analyse(context.Background(), zipPath, testCoord)
	if err != nil {
		t.Fatalf("Analyse: %v", err)
	}
	if rec.OverallStatus == domain.CallGraphStatusLoadFailed {
		t.Skipf("go/packages load failed; skipping: %s", rec.FailureDetail)
	}
	return rec
}

func nodeByID(rec domain.CallGraphRecord, id string) (domain.CallNode, bool) {
	for _, n := range rec.Nodes {
		if n.ID == id {
			return n, true
		}
	}
	return domain.CallNode{}, false
}

// edgeToExists reports whether some edge whose caller node has symbol fromSym
// points at the node with ID toID.
func edgeToExists(rec domain.CallGraphRecord, fromSym, toID string) (domain.CallEdge, bool) {
	symByID := make(map[string]string, len(rec.Nodes))
	for _, n := range rec.Nodes {
		symByID[n.ID] = n.Symbol
	}
	for _, e := range rec.Edges {
		if e.ToID == toID && symByID[e.FromID] == fromSym {
			return e, true
		}
	}
	return domain.CallEdge{}, false
}

// TestDevirt_SingleImplementer_CHADroppedEdge is the crux regression: the sole
// implementer lives in a dependency whose concrete type is never converted to
// the interface in a built package, so it is not a runtime type and its method
// never enters ssautil.AllFunctions — exactly the condition under which CHA
// silently drops the interface-dispatch edge (the zenbpm zenServiceClient
// miss). Without the devirtualization pass Drive has no outgoing edge at all;
// the pass must recover Drive→(dep.Client).Run.
func TestDevirt_SingleImplementer_CHADroppedEdge(t *testing.T) {
	files := map[string]string{
		"go.mod": "module example.com/cgtestmod\n\ngo 1.21\n\nrequire example.com/dep v0.0.0\n\nreplace example.com/dep => ./dep\n",
		"cgtestmod.go": `package cgtestmod

import "example.com/dep"

type Runner interface {
	Run()
}

// Drive invokes Run through the interface.
func Drive(r Runner) {
	r.Run()
}

// The blank reference keeps dep imported so its types are registered, but never
// converts Client to Runner — so CHA never sees Client as a Runner implementer.
var _ = dep.Client{}
`,
		"dep/go.mod": "module example.com/dep\n\ngo 1.21\n",
		"dep/dep.go": `package dep

// Client structurally implements example.com/cgtestmod.Runner.
type Client struct{}

func (Client) Run() {}
`,
	}
	rec := analyseFiles(t, files)

	const targetID = "example.com/dep.(Client).Run"
	target, ok := nodeByID(rec, targetID)
	if !ok {
		t.Fatalf("expected recovered target node %q; nodes: %v", targetID, rec.Nodes)
	}
	if !target.IsExternal {
		t.Errorf("target node from a dependency package should be IsExternal=true, got %+v", target)
	}
	if target.Symbol != "Run" || target.Receiver != "Client" {
		t.Errorf("target node metadata wrong: %+v", target)
	}

	edge, ok := edgeToExists(rec, "Drive", targetID)
	if !ok {
		t.Fatalf("expected devirtualized edge Drive→%s; edges: %v", targetID, rec.Edges)
	}
	if edge.Confidence != domain.ConfidenceDirect {
		t.Errorf("devirtualized edge confidence = %q, want Direct", edge.Confidence)
	}
}

// TestDevirt_SingleImplementer_BuiltBody covers the sole implementer with a
// built body: the edge targets the real SSA node (CHA already reaches it; the
// devirt pass must not duplicate or corrupt it).
func TestDevirt_SingleImplementer_BuiltBody(t *testing.T) {
	files := map[string]string{
		"go.mod": "module example.com/cgtestmod\n\ngo 1.21\n",
		"cgtestmod.go": `package cgtestmod

type Runner interface {
	Run()
}

type Local struct{}

func (Local) Run() {}

func Drive(r Runner) {
	r.Run()
}
`,
	}
	rec := analyseFiles(t, files)

	const implID = "example.com/cgtestmod.(Local).Run"
	if _, ok := nodeByID(rec, implID); !ok {
		t.Fatalf("expected implementer node %q; nodes: %v", implID, rec.Nodes)
	}
	if _, ok := edgeToExists(rec, "Drive", implID); !ok {
		t.Fatalf("expected edge Drive→%s; edges: %v", implID, rec.Edges)
	}

	// No duplicate edges for the same site.
	seen := make(map[string]int)
	for _, e := range rec.Edges {
		if e.ToID == implID {
			seen[e.FromID]++
		}
	}
	for from, n := range seen {
		if n > 1 {
			t.Errorf("duplicate edge %s→%s (%d occurrences)", from, implID, n)
		}
	}
}

// TestDevirt_ZeroImplementers: no concrete type implements the interface, so no
// devirtualized edge (and no implementer node) is added.
func TestDevirt_ZeroImplementers(t *testing.T) {
	files := map[string]string{
		"go.mod": "module example.com/cgtestmod\n\ngo 1.21\n",
		"cgtestmod.go": `package cgtestmod

type Ghost interface {
	Vanish()
}

func Poof(g Ghost) {
	g.Vanish()
}
`,
	}
	rec := analyseFiles(t, files)

	for _, n := range rec.Nodes {
		if n.Symbol == "Vanish" {
			t.Errorf("no type implements Ghost; unexpected Vanish node %+v", n)
		}
	}
	for _, e := range rec.Edges {
		if to, ok := nodeByID(rec, e.ToID); ok && to.Symbol == "Vanish" {
			t.Errorf("unexpected edge to a Vanish method: %+v", e)
		}
	}
}

// TestDevirt_MultipleImplementers: two concrete types implement the interface,
// so the single-implementer pass adds nothing and leaves resolution to CHA/VTA.
// Both built implementers must still be reachable via CHA's own edges.
func TestDevirt_MultipleImplementers(t *testing.T) {
	files := map[string]string{
		"go.mod": "module example.com/cgtestmod\n\ngo 1.21\n",
		"cgtestmod.go": `package cgtestmod

type Runner interface {
	Run()
}

type A struct{}

func (A) Run() {}

type B struct{}

func (B) Run() {}

func Drive(r Runner) {
	r.Run()
}
`,
	}
	rec := analyseFiles(t, files)

	// Both implementers are built, so CHA supplies both edges; the devirt pass
	// must not have skipped or mangled them.
	for _, recv := range []string{"A", "B"} {
		id := "example.com/cgtestmod.(" + recv + ").Run"
		if _, ok := edgeToExists(rec, "Drive", id); !ok {
			t.Errorf("expected edge Drive→%s; edges: %v", id, rec.Edges)
		}
	}
}
