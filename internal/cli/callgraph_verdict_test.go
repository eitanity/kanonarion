package cli

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"

	cgdomain "github.com/eitanity/kanonarion/internal/callgraph/domain"
	cgports "github.com/eitanity/kanonarion/internal/callgraph/ports"
	"github.com/eitanity/kanonarion/internal/cli/testfakes"
)

// builtRecord is a fully-built module record with the given nodes and edges.
func builtRecord(nodes []cgdomain.CallNode, edges []cgdomain.CallEdge) cgdomain.CallGraphRecord {
	return cgdomain.CallGraphRecord{
		Completeness: cgdomain.CompletenessBuiltWithBodies,
		Nodes:        nodes,
		Edges:        edges,
	}
}

func fakeWithRecord(path, version, pipeline string, rec cgdomain.CallGraphRecord) *testfakes.FakeQueryCallGraph {
	uc := testfakes.NewFakeQueryCallGraph()
	uc.SetList([]cgports.CallGraphSummary{
		{ModulePath: path, ModuleVersion: version, PipelineVersion: pipeline},
	})
	uc.AddRecord(coordinate.ModuleCoordinate{Path: path, Version: version}, pipeline, rec)
	return uc
}

// TestRunCallers_ResolvedAbsent: a known node in a fully-built module with no
// unresolved dispatch reports a confident RESOLVED-ABSENT.
func TestRunCallers_ResolvedAbsent(t *testing.T) {
	uc := fakeWithRecord("example.com/m", "v1.0.0", "0.2.0",
		builtRecord([]cgdomain.CallNode{{ID: "example.com/m.Root", Symbol: "Root"}}, nil))
	var buf bytes.Buffer
	if err := runCallers(context.Background(), "example.com/m.Root", false, uc, &buf); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(buf.String(), "verdict: RESOLVED-ABSENT") {
		t.Errorf("expected RESOLVED-ABSENT verdict, got: %q", buf.String())
	}
}

// TestRunCallers_UnresolvedInterfaceDispatch reproduces the zenbpm hop: a callers
// query on an interface method returns UNRESOLVED naming the over-approximated
// invoke site, not an empty confident negative.
func TestRunCallers_UnresolvedInterfaceDispatch(t *testing.T) {
	rec := builtRecord(
		[]cgdomain.CallNode{
			{ID: "example.com/m.(*Target).Do", Symbol: "Do"},
			{ID: "example.com/m.(*OtherImpl).Do", Symbol: "Do"},
		},
		[]cgdomain.CallEdge{
			{FromID: "example.com/m.Client", ToID: "example.com/m.(*OtherImpl).Do", Confidence: cgdomain.ConfidenceCHAOverapprox},
		},
	)
	uc := fakeWithRecord("example.com/m", "v1.0.0", "0.2.0", rec)
	var buf bytes.Buffer
	if err := runCallers(context.Background(), "example.com/m.(*Target).Do", false, uc, &buf); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "verdict: UNRESOLVED") {
		t.Fatalf("expected UNRESOLVED verdict, got: %q", out)
	}
	if !strings.Contains(out, "example.com/m.Client") {
		t.Errorf("expected the invoke site named, got: %q", out)
	}
}

// TestRunCallees_TypeOnlyModuleUnresolved: an empty callees answer over a module
// built below full fidelity is UNRESOLVED, not a confident absence.
func TestRunCallees_TypeOnlyModuleUnresolved(t *testing.T) {
	rec := cgdomain.CallGraphRecord{
		Completeness: cgdomain.CompletenessTypeOnly,
		Nodes:        []cgdomain.CallNode{{ID: "example.com/m.Leaf", Symbol: "Leaf"}},
	}
	uc := fakeWithRecord("example.com/m", "v1.0.0", "0.2.0", rec)
	var buf bytes.Buffer
	if err := runCallees(context.Background(), "example.com/m.Leaf", false, uc, &buf); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(buf.String(), "verdict: UNRESOLVED") {
		t.Errorf("expected UNRESOLVED for type-only module, got: %q", buf.String())
	}
}

// TestRunCallees_JSONOmitsVerdict: JSON output for an empty answer stays the bare
// edge array (verdict is a text-mode signal), preserving the existing shape.
func TestRunCallees_JSONOmitsVerdict(t *testing.T) {
	uc := fakeWithRecord("example.com/m", "v1.0.0", "0.2.0",
		builtRecord([]cgdomain.CallNode{{ID: "example.com/m.Leaf", Symbol: "Leaf"}}, nil))
	var buf bytes.Buffer
	if err := runCallees(context.Background(), "example.com/m.Leaf", true, uc, &buf); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(buf.String(), "verdict") {
		t.Errorf("JSON output must not carry a verdict line, got: %q", buf.String())
	}
	if !strings.Contains(buf.String(), "[]") {
		t.Errorf("expected empty JSON array, got: %q", buf.String())
	}
}

// TestRunCallersTransitive_UnresolvedInterfaceDispatch: the transitive path also
// downgrades an empty answer with an unresolved invoke site.
func TestRunCallersTransitive_UnresolvedInterfaceDispatch(t *testing.T) {
	rec := builtRecord(
		[]cgdomain.CallNode{
			{ID: "example.com/m.(*Target).Do", Symbol: "Do"},
			{ID: "example.com/m.(*OtherImpl).Do", Symbol: "Do"},
		},
		[]cgdomain.CallEdge{
			{FromID: "example.com/m.Client", ToID: "example.com/m.(*OtherImpl).Do", Confidence: cgdomain.ConfidenceUnknown},
		},
	)
	uc := fakeWithRecord("example.com/m", "v1.0.0", "0.2.0", rec)
	var buf bytes.Buffer
	if err := runCallersTransitive(context.Background(), "example.com/m.(*Target).Do", 0, false, uc, &buf); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(buf.String(), "verdict: UNRESOLVED") {
		t.Errorf("expected UNRESOLVED transitive verdict, got: %q", buf.String())
	}
}

// TestRunCalleesTransitive_ResolvedAbsent: an empty transitive callees answer over
// a fully-built leaf is a confident absence.
func TestRunCalleesTransitive_ResolvedAbsent(t *testing.T) {
	uc := fakeWithRecord("example.com/m", "v1.0.0", "0.2.0",
		builtRecord([]cgdomain.CallNode{{ID: "example.com/m.Leaf", Symbol: "Leaf"}}, nil))
	var buf bytes.Buffer
	if err := runCalleesTransitive(context.Background(), "example.com/m.Leaf", 0, false, uc, &buf); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(buf.String(), "verdict: RESOLVED-ABSENT") {
		t.Errorf("expected RESOLVED-ABSENT transitive verdict, got: %q", buf.String())
	}
}

// TestNegativeCallVerdict_ModuleNotResolved: a symbol whose module is not in the
// store yields a RESOLVED-ABSENT default (the caller has already errored on it).
func TestNegativeCallVerdict_ModuleNotResolved(t *testing.T) {
	uc := testfakes.NewFakeQueryCallGraph() // no summaries
	v, err := negativeCallVerdict(context.Background(), "example.com/x.Fn", true, uc)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v.Outcome != cgdomain.VerdictResolvedAbsent {
		t.Errorf("unresolvable module should be RESOLVED-ABSENT, got %s", v.Outcome)
	}
}

// TestNegativeCallVerdict_NodeAbsentBelowFull: the symbol never became a node
// (its package was type-only), so the below-full level still downgrades it.
func TestNegativeCallVerdict_NodeAbsentBelowFull(t *testing.T) {
	rec := cgdomain.CallGraphRecord{Completeness: cgdomain.CompletenessMetadataOnly}
	uc := fakeWithRecord("example.com/m", "v1.0.0", "0.2.0", rec)
	v, err := negativeCallVerdict(context.Background(), "example.com/m.Ghost", false, uc)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v.Outcome != cgdomain.VerdictUnresolved {
		t.Fatalf("expected UNRESOLVED, got %s", v.Outcome)
	}
	if len(v.Sinks) == 0 || v.Sinks[0].Site != "Ghost" {
		t.Errorf("expected fallback site to be the method name, got %+v", v.Sinks)
	}
}

// TestNegativeCallVerdict_ListError surfaces a store list error.
func TestNegativeCallVerdict_ListError(t *testing.T) {
	uc := testfakes.NewFakeQueryCallGraph()
	uc.Err = errors.New("boom")
	if _, err := negativeCallVerdict(context.Background(), "example.com/m.Fn", true, uc); err == nil {
		t.Fatal("expected error from list failure")
	}
}

func TestWriteCallVerdict_Absent(t *testing.T) {
	var buf bytes.Buffer
	if err := writeCallVerdict(&buf, "callers", "m.F", cgdomain.Verdict{Outcome: cgdomain.VerdictResolvedAbsent}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(buf.String(), "RESOLVED-ABSENT") || !strings.Contains(buf.String(), "callers of m.F") {
		t.Errorf("unexpected output: %q", buf.String())
	}
}
