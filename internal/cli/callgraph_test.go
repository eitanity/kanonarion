package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"

	cgapp "github.com/eitanity/kanonarion/internal/callgraph/application"
	cgdomain "github.com/eitanity/kanonarion/internal/callgraph/domain"
	cgports "github.com/eitanity/kanonarion/internal/callgraph/ports"
	"github.com/eitanity/kanonarion/internal/cli/testfakes"
)

func makeCGCoord(t *testing.T) coordinate.ModuleCoordinate {
	t.Helper()
	c, err := coordinate.NewModuleCoordinate("example.com/cg", "v1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func makeCGRecord(t *testing.T) cgdomain.CallGraphRecord {
	t.Helper()
	coord := makeCGCoord(t)
	return cgdomain.CallGraphRecord{
		Coordinate:    coord,
		Algorithm:     cgdomain.AlgorithmCHA,
		OverallStatus: cgdomain.CallGraphStatusExtracted,
		Nodes: []cgdomain.CallNode{
			{ID: "example.com/cg.Main", Package: "example.com/cg", Symbol: "Main", IsExportedAPI: true},
			{ID: "fmt.Println", Package: "fmt", Symbol: "Println", IsExternal: true},
		},
		Edges: []cgdomain.CallEdge{
			{FromID: "example.com/cg.Main", ToID: "fmt.Println", Confidence: cgdomain.ConfidenceDirect},
		},
		NodeCount: 2,
		EdgeCount: 1,
	}
}

func TestPrintCallGraphSummary_TextBasic(t *testing.T) {
	r := makeCGRecord(t)
	var buf bytes.Buffer
	if err := printCallGraphSummary(r, false, false, "", &buf, callGraphRunJSON{}); err != nil {
		t.Fatal(err)
	}
	got := buf.String()
	if !strings.Contains(got, "example.com/cg@v1.0.0") {
		t.Errorf("expected coord in output, got: %q", got)
	}
	if !strings.Contains(got, "2 nodes") {
		t.Errorf("expected node count, got: %q", got)
	}
	if strings.Contains(got, "(cached)") {
		t.Errorf("unexpected '(cached)'")
	}
}

func TestPrintCallGraphSummary_TextCached(t *testing.T) {
	r := makeCGRecord(t)
	var buf bytes.Buffer
	if err := printCallGraphSummary(r, true, false, "", &buf, callGraphRunJSON{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "(cached)") {
		t.Errorf("expected '(cached)', got: %q", buf.String())
	}
}

func TestPrintCallGraphSummary_TextFailure(t *testing.T) {
	coord := makeCGCoord(t)
	r := cgdomain.CallGraphRecord{
		Coordinate:    coord,
		Algorithm:     cgdomain.AlgorithmCHA,
		OverallStatus: cgdomain.CallGraphStatusLoadFailed,
		FailureDetail: "analysis failed",
	}
	var buf bytes.Buffer
	if err := printCallGraphSummary(r, false, false, "", &buf, callGraphRunJSON{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "analysis failed") {
		t.Errorf("expected failure detail, got: %q", buf.String())
	}
}

func TestPrintCallGraphSummary_JSON(t *testing.T) {
	r := makeCGRecord(t)
	var buf bytes.Buffer
	if err := printCallGraphSummary(r, false, true, "", &buf, callGraphRunJSON{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), `"coordinate"`) {
		t.Errorf("expected snake_case JSON output, got: %q", buf.String())
	}
	if strings.Contains(buf.String(), `"Coordinate"`) {
		t.Errorf("raw PascalCase key leaked: %q", buf.String())
	}
}

func TestPrintCallGraphRecord_WithNodes(t *testing.T) {
	r := makeCGRecord(t)
	var buf bytes.Buffer
	if err := printCallGraphRecord(r, 0, 0, &buf); err != nil {
		t.Fatal(err)
	}
	got := buf.String()
	if !strings.Contains(got, "example.com/cg.Main") {
		t.Errorf("expected node ID in output, got: %q", got)
	}
	if !strings.Contains(got, "[api]") {
		t.Errorf("expected [api] tag for exported node, got: %q", got)
	}
	if !strings.Contains(got, "[external]") {
		t.Errorf("expected [external] tag, got: %q", got)
	}
	if !strings.Contains(got, "→") {
		t.Errorf("expected edge arrow, got: %q", got)
	}
}

func TestPrintCallGraphRecord_LimitNodes(t *testing.T) {
	r := makeCGRecord(t)
	var buf bytes.Buffer
	if err := printCallGraphRecord(r, 1, 0, &buf); err != nil {
		t.Fatal(err)
	}
	// with limit=1, only 1 node line should appear in the nodes section
	got := buf.String()
	if !strings.Contains(got, "showing 1") {
		t.Errorf("expected 'showing 1' in output, got: %q", got)
	}
}

func TestPrintCallGraphRecord_Failure(t *testing.T) {
	coord := makeCGCoord(t)
	r := cgdomain.CallGraphRecord{
		Coordinate:    coord,
		Algorithm:     cgdomain.AlgorithmCHA,
		OverallStatus: cgdomain.CallGraphStatusLoadFailed,
		FailureDetail: "ssa build failed",
	}
	var buf bytes.Buffer
	if err := printCallGraphRecord(r, 0, 0, &buf); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "ssa build failed") {
		t.Errorf("expected failure detail, got: %q", buf.String())
	}
}

func TestPrintEdgeRefs_Empty(t *testing.T) {
	var buf bytes.Buffer
	if err := printEdgeRefs("callers", "example.com/cg.Main", nil, false, &buf); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "No callers") {
		t.Errorf("expected 'No callers', got: %q", buf.String())
	}
}

func TestPrintEdgeRefs_TextCallers(t *testing.T) {
	refs := []cgports.CallEdgeRef{
		{FromID: "example.com/cg.Caller", ToID: "example.com/cg.Main", Confidence: cgdomain.ConfidenceDirect, ModulePath: "example.com/cg", ModuleVersion: "v1.0.0"},
	}
	var buf bytes.Buffer
	if err := printEdgeRefs("callers", "example.com/cg.Main", refs, false, &buf); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "Caller") {
		t.Errorf("expected caller in output, got: %q", buf.String())
	}
}

func TestPrintEdgeRefs_TextCallees(t *testing.T) {
	refs := []cgports.CallEdgeRef{
		{FromID: "example.com/cg.Main", ToID: "fmt.Println", Confidence: cgdomain.ConfidenceDirect, ModulePath: "example.com/cg", ModuleVersion: "v1.0.0"},
	}
	var buf bytes.Buffer
	if err := printEdgeRefs("callees", "example.com/cg.Main", refs, false, &buf); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "fmt.Println") {
		t.Errorf("expected callee in output, got: %q", buf.String())
	}
}

func TestPrintEdgeRefs_JSON(t *testing.T) {
	refs := []cgports.CallEdgeRef{
		{FromID: "a.F", ToID: "b.G", Confidence: cgdomain.ConfidenceDirect, ModulePath: "example.com/x", ModuleVersion: "v1.0.0"},
	}
	var buf bytes.Buffer
	if err := printEdgeRefs("callees", "a.F", refs, true, &buf); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), `"from_id"`) && !strings.Contains(buf.String(), `"FromID"`) && !strings.Contains(buf.String(), `"from"`) {
		t.Errorf("expected JSON output with from field, got: %q", buf.String())
	}
}

func TestPrintTransitiveResult_Empty(t *testing.T) {
	var buf bytes.Buffer
	if err := printTransitiveResult("callers", "x.F", 0, nil, nil, false, &buf, cgports.EdgeQueryOptions{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "No transitive callers") {
		t.Errorf("expected empty message, got: %q", buf.String())
	}
}

func TestPrintTransitiveResult_WithNodes(t *testing.T) {
	nodes := []string{"a.F", "b.G"}
	var buf bytes.Buffer
	if err := printTransitiveResult("callers", "x.F", 3, nodes, nil, false, &buf, cgports.EdgeQueryOptions{}); err != nil {
		t.Fatal(err)
	}
	got := buf.String()
	if !strings.Contains(got, "a.F") {
		t.Errorf("expected node in output, got: %q", got)
	}
	if !strings.Contains(got, "depth limit: 3") {
		t.Errorf("expected depth note, got: %q", got)
	}
}

func TestPrintTransitiveResult_JSON(t *testing.T) {
	var buf bytes.Buffer
	if err := printTransitiveResult("callees", "x.F", 0, []string{"a.F"}, nil, true, &buf, cgports.EdgeQueryOptions{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), `"root"`) {
		t.Errorf("expected JSON output, got: %q", buf.String())
	}
}

func TestCallGraphList_EmptyStore(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := Run([]string{"callgraph-list", "--store-root", t.TempDir()}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(stdout.String(), "the store holds no call graph record at all") {
		t.Errorf("expected the empty-store statement, got: %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "to produce one: kanonarion callgraph") {
		t.Errorf("expected the produce-a-record remedy, got: %q", stdout.String())
	}
}

func TestRunCallGraphList_WithRecords(t *testing.T) {
	uc := testfakes.NewFakeQueryCallGraph()
	uc.SetList([]cgports.CallGraphSummary{
		{
			ModulePath:      "example.com/app",
			ModuleVersion:   "v1.0.0",
			PipelineVersion: cgapp.PipelineVersion,
			OverallStatus:   cgdomain.CallGraphStatusExtracted,
			NodeCount:       5,
			EdgeCount:       8,
		},
	})
	var buf bytes.Buffer
	err := runCallGraphList(context.Background(), "", 20, 0, uc, &buf, io.Discard)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "example.com/app@v1.0.0") {
		t.Errorf("expected module in output, got: %q", out)
	}
	if !strings.Contains(out, "nodes") {
		t.Errorf("expected 'nodes' in output, got: %q", out)
	}
}

func TestRunCallGraphList_NoMatchingPipelineVersion(t *testing.T) {
	uc := testfakes.NewFakeQueryCallGraph()
	var buf bytes.Buffer
	err := runCallGraphList(context.Background(), "", 20, 0, uc, &buf, io.Discard)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(buf.String(), "the store holds no call graph record at all") {
		t.Errorf("expected the empty-store statement, got: %q", buf.String())
	}
}

func TestRunCallGraphList_WithModuleFilter(t *testing.T) {
	uc := testfakes.NewFakeQueryCallGraph()
	uc.SetList([]cgports.CallGraphSummary{
		{ModulePath: "example.com/app", ModuleVersion: "v1.0.0", PipelineVersion: cgapp.PipelineVersion},
	})
	var buf bytes.Buffer
	err := runCallGraphList(context.Background(), "example.com/app", 20, 0, uc, &buf, io.Discard)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(buf.String(), "example.com/app@v1.0.0") {
		t.Errorf("expected module in output, got: %q", buf.String())
	}
}

func TestRunCallGraphShow_NotFound(t *testing.T) {
	uc := testfakes.NewFakeQueryCallGraph()
	var buf bytes.Buffer
	err := runCallGraphShow(context.Background(), "github.com/missing/pkg@v1.0.0", callGraphShowFlags{nodeFilter: "", limitNodes: 50, limitEdges: 100}, false, uc, &buf)
	if err == nil {
		t.Fatal("expected error for missing record")
	}
	if !strings.Contains(err.Error(), "no callgraph record") {
		t.Errorf("expected 'no callgraph record' in error, got: %v", err)
	}
}

func TestRunCallers_WithResults(t *testing.T) {
	uc := testfakes.NewFakeQueryCallGraph()
	uc.SetCallers([]cgports.CallEdgeRef{
		{ModulePath: "example.com/app", ModuleVersion: "v1.0.0", FromID: "example.com/app.Main", ToID: "example.com/app.Helper"},
	})
	var buf bytes.Buffer
	err := runCallers(context.Background(), "example.com/app.Helper", false, uc, &buf, buildScope{}, cgports.EdgeQueryOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "caller of example.com/app.Helper") {
		t.Errorf("expected header in output, got: %q", out)
	}
	if !strings.Contains(out, "example.com/app.Main") {
		t.Errorf("expected caller in output, got: %q", out)
	}
}

func TestRunCallers_GenuineZero(t *testing.T) {
	// The symbol IS a node in an analysed module but has zero callers: a
	// genuine zero, reported as such with exit 0.
	uc := testfakes.NewFakeQueryCallGraph()
	coord := coordinatetest.MustNew("example.com/app", "v1.0.0")
	uc.SetList([]cgports.CallGraphSummary{
		{ModulePath: "example.com/app", ModuleVersion: "v1.0.0", PipelineVersion: cgapp.PipelineVersion},
	})
	uc.AddRecord(coord, cgapp.PipelineVersion, cgdomain.CallGraphRecord{
		Nodes: []cgdomain.CallNode{{ID: "example.com/app.Root"}},
	})
	var buf bytes.Buffer
	if err := runCallers(context.Background(), "example.com/app.Root", false, uc, &buf, buildScope{}, cgports.EdgeQueryOptions{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(buf.String(), "No callers found for example.com/app.Root") {
		t.Errorf("expected genuine-zero message, got: %q", buf.String())
	}
}

func TestRunCallers_UnknownSymbolInAnalysedModule(t *testing.T) {
	// The module is analysed but the symbol is NOT a node in its graph:
	// absence-as-answer must be a directing error, not a silent empty result
	uc := testfakes.NewFakeQueryCallGraph()
	coord := coordinatetest.MustNew("example.com/app", "v1.0.0")
	uc.SetList([]cgports.CallGraphSummary{
		{ModulePath: "example.com/app", ModuleVersion: "v1.0.0", PipelineVersion: cgapp.PipelineVersion},
	})
	uc.AddRecord(coord, cgapp.PipelineVersion, cgdomain.CallGraphRecord{
		Nodes: []cgdomain.CallNode{{ID: "example.com/app.Real"}},
	})
	var buf bytes.Buffer
	err := runCallers(context.Background(), "example.com/app.NoSuchSymbol", false, uc, &buf, buildScope{}, cgports.EdgeQueryOptions{})
	if err == nil {
		t.Fatal("expected a directing error for an unknown symbol, got nil")
	}
	if !strings.Contains(err.Error(), "is not a node in the analysed call graph") {
		t.Errorf("expected unknown-node diagnostic, got: %v", err)
	}
}

func TestRunCallees_WithResults(t *testing.T) {
	uc := testfakes.NewFakeQueryCallGraph()
	uc.SetCallees([]cgports.CallEdgeRef{
		{ModulePath: "example.com/app", ModuleVersion: "v1.0.0", FromID: "example.com/app.Main", ToID: "example.com/app.Helper"},
	})
	var buf bytes.Buffer
	err := runCallees(context.Background(), "example.com/app.Main", false, uc, &buf, buildScope{}, cgports.EdgeQueryOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "callee of example.com/app.Main") {
		t.Errorf("expected header in output, got: %q", out)
	}
	if !strings.Contains(out, "example.com/app.Helper") {
		t.Errorf("expected callee in output, got: %q", out)
	}
}

func TestRunCallees_GenuineZero(t *testing.T) {
	// The symbol IS a node (a leaf) in an analysed module but has zero callees:
	// a genuine zero, reported as such with exit 0.
	uc := testfakes.NewFakeQueryCallGraph()
	coord := coordinatetest.MustNew("example.com/app", "v1.0.0")
	uc.SetList([]cgports.CallGraphSummary{
		{ModulePath: "example.com/app", ModuleVersion: "v1.0.0", PipelineVersion: cgapp.PipelineVersion},
	})
	uc.AddRecord(coord, cgapp.PipelineVersion, cgdomain.CallGraphRecord{
		Nodes: []cgdomain.CallNode{{ID: "example.com/app.Leaf"}},
	})
	var buf bytes.Buffer
	if err := runCallees(context.Background(), "example.com/app.Leaf", false, uc, &buf, buildScope{}, cgports.EdgeQueryOptions{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(buf.String(), "No callees found for example.com/app.Leaf") {
		t.Errorf("expected genuine-zero message, got: %q", buf.String())
	}
}

func TestRunCallees_UnknownSymbolInAnalysedModule(t *testing.T) {
	// The module is analysed but the symbol is NOT a node in its graph:
	// absence-as-answer must be a directing error, not a silent empty result
	uc := testfakes.NewFakeQueryCallGraph()
	coord := coordinatetest.MustNew("example.com/app", "v1.0.0")
	uc.SetList([]cgports.CallGraphSummary{
		{ModulePath: "example.com/app", ModuleVersion: "v1.0.0", PipelineVersion: cgapp.PipelineVersion},
	})
	uc.AddRecord(coord, cgapp.PipelineVersion, cgdomain.CallGraphRecord{
		Nodes: []cgdomain.CallNode{{ID: "example.com/app.Real"}},
	})
	var buf bytes.Buffer
	err := runCallees(context.Background(), "example.com/app.NoSuchSymbol", false, uc, &buf, buildScope{}, cgports.EdgeQueryOptions{})
	if err == nil {
		t.Fatal("expected a directing error for an unknown symbol, got nil")
	}
	if !strings.Contains(err.Error(), "is not a node in the analysed call graph") {
		t.Errorf("expected unknown-node diagnostic, got: %v", err)
	}
}

func TestRunCallersTransitive_WithResults(t *testing.T) {
	uc := testfakes.NewFakeQueryCallGraph()
	uc.SetTraverseCallers(
		[]cgports.CallEdgeRef{
			{FromID: "example.com/app.Helper", ToID: "fmt.Println", ModulePath: "example.com/app", ModuleVersion: "v1.0.0"},
			{FromID: "example.com/app.Main", ToID: "example.com/app.Helper", ModulePath: "example.com/app", ModuleVersion: "v1.0.0"},
		},
		[]string{"example.com/app.Helper", "example.com/app.Main"},
	)
	var buf bytes.Buffer
	err := runCallersTransitive(context.Background(), "fmt.Println", 0, false, uc, &buf, buildScope{}, cgports.EdgeQueryOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "Transitive callers of fmt.Println") {
		t.Errorf("expected header in output, got: %q", out)
	}
	if !strings.Contains(out, "example.com/app.Helper") {
		t.Errorf("expected Helper in output, got: %q", out)
	}
	if !strings.Contains(out, "example.com/app.Main") {
		t.Errorf("expected Main in output, got: %q", out)
	}
}

func TestRunCallersTransitive_DepthLimit(t *testing.T) {
	uc := testfakes.NewFakeQueryCallGraph()
	uc.SetTraverseCallers(
		[]cgports.CallEdgeRef{
			{FromID: "example.com/app.Helper", ToID: "fmt.Println", ModulePath: "example.com/app", ModuleVersion: "v1.0.0"},
		},
		[]string{"example.com/app.Helper"},
	)
	var buf bytes.Buffer
	err := runCallersTransitive(context.Background(), "fmt.Println", 1, false, uc, &buf, buildScope{}, cgports.EdgeQueryOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "depth limit: 1") {
		t.Errorf("expected depth limit note, got: %q", out)
	}
	if !strings.Contains(out, "example.com/app.Helper") {
		t.Errorf("expected Helper in output, got: %q", out)
	}
}

func TestRunCallersTransitive_NoResults(t *testing.T) {
	// A genuine zero: the symbol IS a node in a module served at this pipeline
	// version, and the walk reaches nothing.
	uc := testfakes.NewFakeQueryCallGraph()
	coord := coordinatetest.MustNew("example.com/app", "v1.0.0")
	uc.SetList([]cgports.CallGraphSummary{
		{ModulePath: "example.com/app", ModuleVersion: "v1.0.0", PipelineVersion: cgapp.PipelineVersion},
	})
	uc.AddRecord(coord, cgapp.PipelineVersion, cgdomain.CallGraphRecord{
		Nodes: []cgdomain.CallNode{{ID: "example.com/app.Main"}},
	})
	var buf bytes.Buffer
	err := runCallersTransitive(context.Background(), "example.com/app.Main", 0, false, uc, &buf, buildScope{}, cgports.EdgeQueryOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(buf.String(), "No transitive callers found for example.com/app.Main") {
		t.Errorf("expected empty message, got: %q", buf.String())
	}
}

// TestRunCallersTransitive_NeverAnalysedIsAnError: a transitive walk over a store
// that has never seen the symbol's module is emptied by the absence of a
// measurement, and saying "no transitive callers" would report that as a fact
// about the code. The single-hop query has always refused this; so does this one.
func TestRunCallersTransitive_NeverAnalysedIsAnError(t *testing.T) {
	uc := testfakes.NewFakeQueryCallGraph()
	var buf bytes.Buffer
	err := runCallersTransitive(context.Background(), "example.com/app.Main", 0, false, uc, &buf, buildScope{}, cgports.EdgeQueryOptions{})
	if err == nil {
		t.Fatalf("expected an error, got output: %q", buf.String())
	}
	if !strings.Contains(err.Error(), "has not been analysed") {
		t.Errorf("expected the never-analysed diagnostic, got: %v", err)
	}
}

func TestRunCallersTransitive_JSON(t *testing.T) {
	uc := testfakes.NewFakeQueryCallGraph()
	uc.SetTraverseCallers(
		[]cgports.CallEdgeRef{
			{FromID: "example.com/app.Helper", ToID: "fmt.Println", ModulePath: "example.com/app", ModuleVersion: "v1.0.0"},
			{FromID: "example.com/app.Main", ToID: "example.com/app.Helper", ModulePath: "example.com/app", ModuleVersion: "v1.0.0"},
		},
		[]string{"example.com/app.Helper", "example.com/app.Main"},
	)
	var buf bytes.Buffer
	err := runCallersTransitive(context.Background(), "fmt.Println", 0, true, uc, &buf, buildScope{}, cgports.EdgeQueryOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	for _, field := range []string{`"root"`, `"direction"`, `"callers"`, `"nodes"`, `"edges"`} {
		if !strings.Contains(out, field) {
			t.Errorf("expected %q in JSON output, got: %q", field, out)
		}
	}
}

func TestRunCalleesTransitive_WithResults(t *testing.T) {
	uc := testfakes.NewFakeQueryCallGraph()
	uc.SetTraverseCallees(
		[]cgports.CallEdgeRef{
			{FromID: "example.com/app.Main", ToID: "example.com/app.Helper", ModulePath: "example.com/app", ModuleVersion: "v1.0.0"},
			{FromID: "example.com/app.Helper", ToID: "fmt.Println", ModulePath: "example.com/app", ModuleVersion: "v1.0.0"},
		},
		[]string{"example.com/app.Helper", "fmt.Println"},
	)
	var buf bytes.Buffer
	err := runCalleesTransitive(context.Background(), "example.com/app.Main", 0, false, uc, &buf, buildScope{}, cgports.EdgeQueryOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "Transitive callees of example.com/app.Main") {
		t.Errorf("expected header in output, got: %q", out)
	}
	if !strings.Contains(out, "example.com/app.Helper") {
		t.Errorf("expected Helper in output, got: %q", out)
	}
	if !strings.Contains(out, "fmt.Println") {
		t.Errorf("expected fmt.Println in output, got: %q", out)
	}
}

func TestRunCalleesTransitive_DepthLimit(t *testing.T) {
	uc := testfakes.NewFakeQueryCallGraph()
	uc.SetTraverseCallees(
		[]cgports.CallEdgeRef{
			{FromID: "example.com/app.Main", ToID: "example.com/app.Helper", ModulePath: "example.com/app", ModuleVersion: "v1.0.0"},
		},
		[]string{"example.com/app.Helper"},
	)
	var buf bytes.Buffer
	err := runCalleesTransitive(context.Background(), "example.com/app.Main", 1, false, uc, &buf, buildScope{}, cgports.EdgeQueryOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "depth limit: 1") {
		t.Errorf("expected depth limit note, got: %q", out)
	}
	if !strings.Contains(out, "example.com/app.Helper") {
		t.Errorf("expected Helper in output, got: %q", out)
	}
}

func TestRunCalleesTransitive_NoResults(t *testing.T) {
	// A genuine zero: the symbol IS a node in a module served at this pipeline
	// version, and the walk reaches nothing.
	uc := testfakes.NewFakeQueryCallGraph()
	coord := coordinatetest.MustNew("example.com/app", "v1.0.0")
	uc.SetList([]cgports.CallGraphSummary{
		{ModulePath: "example.com/app", ModuleVersion: "v1.0.0", PipelineVersion: cgapp.PipelineVersion},
	})
	uc.AddRecord(coord, cgapp.PipelineVersion, cgdomain.CallGraphRecord{
		Nodes: []cgdomain.CallNode{{ID: "example.com/app.Main"}},
	})
	var buf bytes.Buffer
	err := runCalleesTransitive(context.Background(), "example.com/app.Main", 0, false, uc, &buf, buildScope{}, cgports.EdgeQueryOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(buf.String(), "No transitive callees found for example.com/app.Main") {
		t.Errorf("expected empty message, got: %q", buf.String())
	}
}

// TestRunCalleesTransitive_NeverAnalysedIsAnError: a transitive walk over a store
// that has never seen the symbol's module is emptied by the absence of a
// measurement, and saying "no transitive callees" would report that as a fact
// about the code. The single-hop query has always refused this; so does this one.
func TestRunCalleesTransitive_NeverAnalysedIsAnError(t *testing.T) {
	uc := testfakes.NewFakeQueryCallGraph()
	var buf bytes.Buffer
	err := runCalleesTransitive(context.Background(), "example.com/app.Main", 0, false, uc, &buf, buildScope{}, cgports.EdgeQueryOptions{})
	if err == nil {
		t.Fatalf("expected an error, got output: %q", buf.String())
	}
	if !strings.Contains(err.Error(), "has not been analysed") {
		t.Errorf("expected the never-analysed diagnostic, got: %v", err)
	}
}

func TestRunCalleesTransitive_JSON(t *testing.T) {
	uc := testfakes.NewFakeQueryCallGraph()
	uc.SetTraverseCallees(
		[]cgports.CallEdgeRef{
			{FromID: "example.com/app.Main", ToID: "example.com/app.Helper", ModulePath: "example.com/app", ModuleVersion: "v1.0.0"},
			{FromID: "example.com/app.Helper", ToID: "fmt.Println", ModulePath: "example.com/app", ModuleVersion: "v1.0.0"},
		},
		[]string{"example.com/app.Helper", "fmt.Println"},
	)
	var buf bytes.Buffer
	err := runCalleesTransitive(context.Background(), "example.com/app.Main", 0, true, uc, &buf, buildScope{}, cgports.EdgeQueryOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	for _, field := range []string{`"root"`, `"direction"`, `"callees"`, `"nodes"`, `"edges"`} {
		if !strings.Contains(out, field) {
			t.Errorf("expected %q in JSON output, got: %q", field, out)
		}
	}
}

func TestCallNodeRole_External(t *testing.T) {
	n := cgdomain.CallNode{IsExternal: true}
	if got := callNodeRole(n); got != "external" {
		t.Errorf("callNodeRole = %q, want 'external'", got)
	}
}

func TestCallNodeRole_API(t *testing.T) {
	n := cgdomain.CallNode{IsExportedAPI: true}
	if got := callNodeRole(n); got != "api" {
		t.Errorf("callNodeRole = %q, want 'api'", got)
	}
}

func TestCallNodeRole_Internal(t *testing.T) {
	n := cgdomain.CallNode{}
	if got := callNodeRole(n); got != "internal" {
		t.Errorf("callNodeRole = %q, want 'internal'", got)
	}
}

func TestToCallGraphJSON_WrapsNodes(t *testing.T) {
	coord := makeCGCoord(t)
	r := cgdomain.CallGraphRecord{
		Coordinate:    coord,
		Algorithm:     cgdomain.AlgorithmCHA,
		OverallStatus: cgdomain.CallGraphStatusExtracted,
		Nodes: []cgdomain.CallNode{
			{ID: "example.com/cg.Main", Symbol: "Main", IsExportedAPI: true},
			{ID: "fmt.Println", Symbol: "Println", IsExternal: true},
		},
		NodeCount: 2,
	}
	j := toCallGraphJSON(r)
	if len(j.Nodes) != 2 {
		t.Fatalf("expected 2 nodes, got %d", len(j.Nodes))
	}
	if j.Nodes[0].Role != "api" {
		t.Errorf("node[0].Role = %q, want 'api'", j.Nodes[0].Role)
	}
	if j.Nodes[1].Role != "external" {
		t.Errorf("node[1].Role = %q, want 'external'", j.Nodes[1].Role)
	}
}

func TestFilterCallGraphRecord_MatchNode(t *testing.T) {
	coord := makeCGCoord(t)
	r := cgdomain.CallGraphRecord{
		Coordinate: coord,
		Nodes: []cgdomain.CallNode{
			{ID: "example.com/cg.Main", Symbol: "Main"},
			{ID: "fmt.Println", Symbol: "Println"},
		},
		Edges: []cgdomain.CallEdge{
			{FromID: "example.com/cg.Main", ToID: "fmt.Println"},
		},
		NodeCount: 2,
		EdgeCount: 1,
	}
	filtered, outcome := filterCallGraphRecord(r, "Main")
	if filtered.NodeCount != 2 {
		t.Errorf("expected 2 nodes (matched + connected), got %d", filtered.NodeCount)
	}
	if filtered.EdgeCount != 1 {
		t.Errorf("expected 1 edge, got %d", filtered.EdgeCount)
	}
	if outcome.matched != 1 {
		t.Errorf("expected 1 matched node (the connected one is not a match), got %d", outcome.matched)
	}
	if outcome.candidates != 2 {
		t.Errorf("expected 2 candidates, got %d", outcome.candidates)
	}
}

func TestFilterCallGraphRecord_NoMatch(t *testing.T) {
	coord := makeCGCoord(t)
	r := cgdomain.CallGraphRecord{
		Coordinate: coord,
		Nodes:      []cgdomain.CallNode{{ID: "example.com/cg.Main", Symbol: "Main"}},
		NodeCount:  1,
	}
	filtered, outcome := filterCallGraphRecord(r, "NoSuchSymbol")
	if filtered.NodeCount != 0 {
		t.Errorf("expected 0 nodes after no-match filter, got %d", filtered.NodeCount)
	}
	if outcome.matched != 0 {
		t.Errorf("expected 0 matches, got %d", outcome.matched)
	}
	if !outcome.applied() {
		t.Error("expected the outcome to report that a filter was applied")
	}
	if outcome.example != "example.com/cg.Main" {
		t.Errorf("expected an example node ID from the unfiltered record, got %q", outcome.example)
	}
}

func TestRunCallGraphShow_Found_Text(t *testing.T) {
	uc := testfakes.NewFakeQueryCallGraph()
	rec := makeCGRecord(t)
	coord := makeCGCoord(t)
	uc.AddRecord(coord, cgapp.PipelineVersion, rec)
	var buf bytes.Buffer
	err := runCallGraphShow(context.Background(), "example.com/cg@v1.0.0", callGraphShowFlags{nodeFilter: "", limitNodes: 50, limitEdges: 100}, false, uc, &buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "example.com/cg@v1.0.0") {
		t.Errorf("expected coord in output, got: %q", out)
	}
	if !strings.Contains(out, "example.com/cg.Main") {
		t.Errorf("expected node in output, got: %q", out)
	}
}

func TestRunCallGraphShow_Found_JSON(t *testing.T) {
	uc := testfakes.NewFakeQueryCallGraph()
	rec := makeCGRecord(t)
	coord := makeCGCoord(t)
	uc.AddRecord(coord, cgapp.PipelineVersion, rec)
	var buf bytes.Buffer
	err := runCallGraphShow(context.Background(), "example.com/cg@v1.0.0", callGraphShowFlags{nodeFilter: "", limitNodes: 50, limitEdges: 100}, true, uc, &buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	// curated snake_case keys, no raw PascalCase domain fields.
	for _, want := range []string{`"coordinate"`, `"schema_version"`, `"node_count"`} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %s in JSON output, got: %q", want, out)
		}
	}
	for _, bad := range []string{`"Coordinate"`, `"SchemaVersion"`, `"NodeCount"`} {
		if strings.Contains(out, bad) {
			t.Errorf("raw PascalCase key %s leaked: %q", bad, out)
		}
	}
}

func TestRunCallGraphShow_WithNodeFilter(t *testing.T) {
	uc := testfakes.NewFakeQueryCallGraph()
	rec := makeCGRecord(t)
	coord := makeCGCoord(t)
	uc.AddRecord(coord, cgapp.PipelineVersion, rec)
	var buf bytes.Buffer
	err := runCallGraphShow(context.Background(), "example.com/cg@v1.0.0", callGraphShowFlags{nodeFilter: "Main", limitNodes: 50, limitEdges: 100}, false, uc, &buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(buf.String(), "Main") {
		t.Errorf("expected 'Main' in filtered output, got: %q", buf.String())
	}
}

func TestRunCallGraphShow_Error(t *testing.T) {
	uc := testfakes.NewFakeQueryCallGraph()
	uc.Err = errors.New("db error")
	var buf bytes.Buffer
	err := runCallGraphShow(context.Background(), "example.com/cg@v1.0.0", callGraphShowFlags{nodeFilter: "", limitNodes: 50, limitEdges: 100}, false, uc, &buf)
	if err == nil {
		t.Fatal("expected error from GetCallGraphRecord failure")
	}
	if !strings.Contains(err.Error(), "getting callgraph record") {
		t.Errorf("expected 'getting callgraph record' in error, got: %v", err)
	}
}

func TestSBOMList_EmptyStore(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := Run([]string{"sbom-list", "--store-root", t.TempDir()}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(stdout.String(), "the store holds no SBOM record at all") {
		t.Errorf("expected the empty-store statement, got: %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "to produce one: kanonarion sbom") {
		t.Errorf("expected the produce-a-record remedy, got: %q", stdout.String())
	}
}

// --- unresolved-symbol vs genuine-zero test pair ---

func TestRunCallers_UnresolvedSymbol_IsError(t *testing.T) {
	uc := testfakes.NewFakeQueryCallGraph()
	// No analysed modules at all; FindCallers returns empty.
	var buf bytes.Buffer
	err := runCallers(context.Background(), "example.com/notanalysed/pkg.Foo", false, uc, &buf, buildScope{}, cgports.EdgeQueryOptions{})
	if err == nil {
		t.Fatal("expected an error for an unresolved symbol, got nil")
	}
	if !strings.Contains(err.Error(), "not in the call-graph store") {
		t.Errorf("expected unresolved diagnostic, got: %v", err)
	}
	if buf.Len() != 0 {
		t.Errorf("expected no stdout for an unresolved symbol, got: %q", buf.String())
	}
}

func TestRunCallers_AnalysedButZeroEdges_IsNotError(t *testing.T) {
	uc := testfakes.NewFakeQueryCallGraph()
	coord := coordinatetest.MustNew("example.com/app", "v1.0.0")
	uc.SetList([]cgports.CallGraphSummary{
		{ModulePath: "example.com/app", ModuleVersion: "v1.0.0", PipelineVersion: cgapp.PipelineVersion},
	})
	// Module is analysed and the symbol is a real node; it simply has no callers.
	uc.AddRecord(coord, cgapp.PipelineVersion, cgdomain.CallGraphRecord{
		Nodes: []cgdomain.CallNode{{ID: "example.com/app/pkg.Orphan"}},
	})
	var buf bytes.Buffer
	err := runCallers(context.Background(), "example.com/app/pkg.Orphan", false, uc, &buf, buildScope{}, cgports.EdgeQueryOptions{})
	if err != nil {
		t.Fatalf("analysed-but-zero must not be an error, got: %v", err)
	}
	if !strings.Contains(buf.String(), "No callers found") {
		t.Errorf("expected zero-result message, got: %q", buf.String())
	}
}

func TestRunCallees_UnresolvedSymbol_IsError(t *testing.T) {
	uc := testfakes.NewFakeQueryCallGraph()
	var buf bytes.Buffer
	err := runCallees(context.Background(), "example.com/notanalysed/pkg.Foo", false, uc, &buf, buildScope{}, cgports.EdgeQueryOptions{})
	if err == nil {
		t.Fatal("expected an error for an unresolved symbol, got nil")
	}
	if !strings.Contains(err.Error(), "not in the call-graph store") {
		t.Errorf("expected unresolved diagnostic, got: %v", err)
	}
}

// TestRunCallers_GenuineZeroJSON_IsEmptyArrayNotNull preserves the
// "[] not null" invariant for the only case where an empty result is valid
// output: the module is analysed but the symbol has no edges.
func TestRunCallers_GenuineZeroJSON_IsEmptyArrayNotNull(t *testing.T) {
	uc := testfakes.NewFakeQueryCallGraph()
	coord := coordinatetest.MustNew("example.com/app", "v1.0.0")
	uc.SetList([]cgports.CallGraphSummary{
		{ModulePath: "example.com/app", ModuleVersion: "v1.0.0", PipelineVersion: cgapp.PipelineVersion},
	})
	uc.AddRecord(coord, cgapp.PipelineVersion, cgdomain.CallGraphRecord{
		Nodes: []cgdomain.CallNode{{ID: "example.com/app.Orphan"}},
	})
	var buf bytes.Buffer
	if err := runCallers(context.Background(), "example.com/app.Orphan", true, uc, &buf, buildScope{}, cgports.EdgeQueryOptions{}); err != nil {
		t.Fatalf("genuine-zero must not error: %v", err)
	}
	out := strings.TrimSpace(buf.String())
	if out == "null" {
		t.Errorf("emitted null instead of []")
	}
	var v []any
	if err := json.Unmarshal([]byte(out), &v); err != nil || len(v) != 0 {
		t.Errorf("expected empty JSON array, got: %q (err=%v)", out, err)
	}
}

// TestUnresolvedSymbolMessage_IntentAware covers both branches of
// the unresolved-symbol diagnostic (author-mode vs consumer-mode).
func TestUnresolvedSymbolMessage_IntentAware(t *testing.T) {
	author := unresolvedSymbolMessage("example.com/me/internal/x.Fn", "example.com/me")
	if !strings.Contains(author, "author-mode") || !strings.Contains(author, "kanonarion local") {
		t.Errorf("expected author-mode direction, got: %q", author)
	}
	consumer := unresolvedSymbolMessage("other.com/dep/pkg.Fn", "example.com/me")
	if !strings.Contains(consumer, "consumer-mode") || !strings.Contains(consumer, "kanonarion callgraph") {
		t.Errorf("expected consumer-mode direction, got: %q", consumer)
	}
	noMod := unresolvedSymbolMessage("anything.Fn", "")
	if !strings.Contains(noMod, "consumer-mode") {
		t.Errorf("empty local module must fall back to consumer-mode, got: %q", noMod)
	}
}

// --- Partial-graph verdict soundness ---

// partialAppCoord and the two helpers below build a fake store whose call graph
// for example.com/app is Partial, with example.com/app/broken having failed to
// typecheck.
func setupPartialStore(t *testing.T, callers []cgports.CallEdgeRef) *testfakes.FakeQueryCallGraph {
	t.Helper()
	uc := testfakes.NewFakeQueryCallGraph()
	coord := coordinatetest.MustNew("example.com/app", "v1.0.0")
	uc.SetList([]cgports.CallGraphSummary{
		{ModulePath: "example.com/app", ModuleVersion: "v1.0.0", PipelineVersion: cgapp.PipelineVersion},
	})
	uc.AddRecord(coord, cgapp.PipelineVersion, cgdomain.CallGraphRecord{
		OverallStatus:  cgdomain.CallGraphStatusPartial,
		FailedPackages: []string{"example.com/app/broken"},
		// The clean helper is a node; the broken package produced none.
		Nodes: []cgdomain.CallNode{{ID: "example.com/app.Helper", Package: "example.com/app"}},
	})
	if callers != nil {
		uc.SetCallers(callers)
	}
	return uc
}

// The query root lives in a package that did not typecheck, so its edges were
// dropped. That is a gap in the analysis, not a property of the symbol, and it
// is reported as one: the answer is served with the gap stated on it and its
// verdict downgraded. It used to be a hard error, which suppressed the call
// sites a consumer's own complete graph had recorded.
func TestRunCallers_RootInFailedPackage_Unmeasured(t *testing.T) {
	uc := setupPartialStore(t, nil)
	var buf bytes.Buffer
	if err := runCallers(context.Background(), "example.com/app/broken.Broken", false, uc, &buf, buildScope{}, cgports.EdgeQueryOptions{}); err != nil {
		t.Fatalf("a dropped-edge package was refused rather than reported: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "example.com/app/broken") || !strings.Contains(out, "did not typecheck") {
		t.Errorf("expected the dropped package named, got: %q", out)
	}
	if !strings.Contains(out, "answer: UNRESOLVED") {
		t.Errorf("expected the empty answer downgraded, got: %q", out)
	}
}

func TestRunCallees_RootInFailedPackage_Unmeasured(t *testing.T) {
	uc := setupPartialStore(t, nil)
	var buf bytes.Buffer
	if err := runCallees(context.Background(), "example.com/app/broken.Broken", false, uc, &buf, buildScope{}, cgports.EdgeQueryOptions{}); err != nil {
		t.Fatalf("a dropped-edge package was refused rather than reported: %v", err)
	}
	if !strings.Contains(buf.String(), "example.com/app/broken") {
		t.Errorf("expected the dropped package named, got: %q", buf.String())
	}
}

func TestRunCallersTransitive_RootInFailedPackage_Unmeasured(t *testing.T) {
	uc := setupPartialStore(t, nil)
	var buf bytes.Buffer
	if err := runCallersTransitive(context.Background(), "example.com/app/broken.Broken", 0, false, uc, &buf, buildScope{}, cgports.EdgeQueryOptions{}); err != nil {
		t.Fatalf("a dropped-edge package was refused rather than reported: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "transitive callers") || !strings.Contains(out, "example.com/app/broken") {
		t.Errorf("expected the transitive answer to state its gap, got: %q", out)
	}
}

func TestRunCallers_PartialGraph_CleanRoot_Caveat(t *testing.T) {
	// The root package typechecked, but the overall graph is Partial. The result
	// is shown, prefixed with a caveat so it is never read as an Extracted-graph
	// answer.
	uc := setupPartialStore(t, []cgports.CallEdgeRef{
		{ModulePath: "example.com/app", ModuleVersion: "v1.0.0", FromID: "example.com/app.Main", ToID: "example.com/app.Helper"},
	})
	var buf bytes.Buffer
	if err := runCallers(context.Background(), "example.com/app.Helper", false, uc, &buf, buildScope{}, cgports.EdgeQueryOptions{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "notice: call graph is Partial") || !strings.Contains(out, "example.com/app/broken") {
		t.Errorf("expected Partial caveat naming the failed package, got: %q", out)
	}
	if !strings.Contains(out, "example.com/app.Main") {
		t.Errorf("expected the caller to still be shown, got: %q", out)
	}
}

func TestRunCallers_PartialGraph_JSON_NoCaveatLine(t *testing.T) {
	// In JSON mode the caveat must not corrupt the array output; the hard-error
	// case is still an error, but a clean-root Partial result stays valid JSON.
	uc := setupPartialStore(t, []cgports.CallEdgeRef{
		{ModulePath: "example.com/app", ModuleVersion: "v1.0.0", FromID: "example.com/app.Main", ToID: "example.com/app.Helper"},
	})
	var buf bytes.Buffer
	if err := runCallers(context.Background(), "example.com/app.Helper", true, uc, &buf, buildScope{}, cgports.EdgeQueryOptions{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(buf.String(), "notice:") {
		t.Errorf("JSON output must not contain the text caveat, got: %q", buf.String())
	}
	var refs []map[string]any
	if err := json.Unmarshal(buf.Bytes(), &refs); err != nil {
		t.Errorf("JSON output not parseable: %v (%q)", err, buf.String())
	}
}

func TestRunCallers_ExtractedGraph_NoCaveat(t *testing.T) {
	// An Extracted graph must never carry a Partial caveat.
	uc := testfakes.NewFakeQueryCallGraph()
	coord := coordinatetest.MustNew("example.com/app", "v1.0.0")
	uc.SetList([]cgports.CallGraphSummary{
		{ModulePath: "example.com/app", ModuleVersion: "v1.0.0", PipelineVersion: cgapp.PipelineVersion},
	})
	uc.AddRecord(coord, cgapp.PipelineVersion, cgdomain.CallGraphRecord{
		OverallStatus: cgdomain.CallGraphStatusExtracted,
		Nodes:         []cgdomain.CallNode{{ID: "example.com/app.Helper", Package: "example.com/app"}},
	})
	uc.SetCallers([]cgports.CallEdgeRef{
		{ModulePath: "example.com/app", ModuleVersion: "v1.0.0", FromID: "example.com/app.Main", ToID: "example.com/app.Helper"},
	})
	var buf bytes.Buffer
	if err := runCallers(context.Background(), "example.com/app.Helper", false, uc, &buf, buildScope{}, cgports.EdgeQueryOptions{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(buf.String(), "notice:") {
		t.Errorf("Extracted graph must not carry a Partial caveat, got: %q", buf.String())
	}
}

func TestSymbolFailedPackage(t *testing.T) {
	failed := []string{"example.com/app/broken", "example.com/app/other"}
	cases := []struct {
		symbol string
		want   string
	}{
		{"example.com/app/broken.Broken", "example.com/app/broken"},
		{"example.com/app/broken.(*T).M", "example.com/app/broken"},
		{"example.com/app/broken/sub.Fn", ""}, // sub-package is a different package
		{"example.com/app.Clean", ""},
		{"example.com/app/brokenish.Fn", ""}, // prefix but not a package boundary
	}
	for _, tc := range cases {
		got, hit := symbolFailedPackage(tc.symbol, failed)
		if tc.want == "" && hit {
			t.Errorf("symbolFailedPackage(%q) = %q, want no hit", tc.symbol, got)
		}
		if tc.want != "" && got != tc.want {
			t.Errorf("symbolFailedPackage(%q) = %q, want %q", tc.symbol, got, tc.want)
		}
	}
}

// TestWorktreeNotice_SpeaksOnlyWhenThereIsADecision. The notice exists because a
// routing decision the reader cannot see is the same failure as no routing at
// all — but a reader with one checkout has no decision, and a line on every
// answer would be noise on every answer.
func TestWorktreeNotice_SpeaksOnlyWhenThereIsADecision(t *testing.T) {
	cases := []struct {
		name   string
		r      cgports.WorktreeRouting
		report bool
	}{
		{"one analysed checkout, standing in it",
			cgports.WorktreeRouting{LocatedTrees: 1, CallerRoot: "/src/mod", ServedRoot: "/src/mod", Matched: true}, false},
		{"one analysed checkout, standing outside any module",
			cgports.WorktreeRouting{LocatedTrees: 1, ServedRoot: "/src/mod"}, false},
		{"two checkouts",
			cgports.WorktreeRouting{LocatedTrees: 2, CallerRoot: "/src/a", ServedRoot: "/src/a", Matched: true}, true},
		{"standing in a tree that has never been analysed",
			cgports.WorktreeRouting{LocatedTrees: 1, CallerRoot: "/src/fresh", ServedRoot: "/src/mod"}, true},
		{"every generation predates the recorded tree",
			cgports.WorktreeRouting{UnlocatedGenerations: 3, CallerRoot: "/src/mod"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.r.WorthReporting(); got != tc.report {
				t.Fatalf("WorthReporting() = %v, want %v", got, tc.report)
			}
		})
	}
}

// TestWorktreeNoticeText_NamesTheTreeAndTheRemedy. A reader served from another
// checkout has to be able to see that, and to see what to run about it;
// otherwise a silent wrong tree has been replaced by a slightly better silence.
func TestWorktreeNoticeText_NamesTheTreeAndTheRemedy(t *testing.T) {
	coord, err := coordinate.NewLocalCoordinate("example.com/mod")
	if err != nil {
		t.Fatalf("NewLocalCoordinate: %v", err)
	}

	hit := worktreeNoticeText(coord, cgports.WorktreeRouting{
		LocatedTrees: 2, CallerRoot: "/src/a", ServedRoot: "/src/a",
		ServedDigest: "analysed-sha256:aaa", Matched: true,
	})
	for _, want := range []string{"you are in", "/src/a", "analysed-sha256:aaa", "2 working trees"} {
		if !strings.Contains(hit, want) {
			t.Errorf("the matched notice does not mention %q: %s", want, hit)
		}
	}

	miss := worktreeNoticeText(coord, cgports.WorktreeRouting{
		LocatedTrees: 2, CallerRoot: "/src/fresh", ServedRoot: "/src/b",
		ServedDigest: "analysed-sha256:bbb",
	})
	for _, want := range []string{"NOT answered", "/src/fresh", "/src/b", "kanonarion local /src/fresh"} {
		if !strings.Contains(miss, want) {
			t.Errorf("the miss notice does not mention %q: %s", want, miss)
		}
	}

	// Generations written before the tree was recorded are named as that, not
	// attributed to a checkout nothing says they came from.
	predating := worktreeNoticeText(coord, cgports.WorktreeRouting{
		UnlocatedGenerations: 2, CallerRoot: "/src/mod", ServedDigest: "sha256:old",
	})
	if !strings.Contains(predating, "before the analysed tree was recorded") {
		t.Errorf("an unlocated generation was not named as one: %s", predating)
	}
	if strings.Contains(predating, "working tree at ") {
		t.Errorf("an unlocated generation was reported as a located tree: %s", predating)
	}
}

// The run that produced the incomplete graph is where the remedy is worth most,
// and it was the one place not stating it: the reader saw a failed-package list
// and a loader message and had to work out for themselves whether to go looking
// for a compile error or to warm the module cache.
func TestPrintCallGraphSummary_ColdCachePartialPrintsTheRemedy(t *testing.T) {
	coord, err := coordinate.NewLocalCoordinate("example.com/app")
	if err != nil {
		t.Fatalf("coordinate: %v", err)
	}
	r := cgdomain.CallGraphRecord{
		Coordinate:     coord,
		Algorithm:      cgdomain.AlgorithmCHA,
		OverallStatus:  cgdomain.CallGraphStatusPartial,
		FailureCause:   cgdomain.FailureCauseEnvironment,
		FailedPackages: []string{"example.com/app/needsdep"},
	}
	var buf bytes.Buffer
	if err := printCallGraphSummary(r, false, false, "/work/tree", &buf, callGraphRunJSON{}); err != nil {
		t.Fatal(err)
	}
	got := buf.String()
	if !strings.Contains(got, cgdomain.ColdModuleCacheRemedy) {
		t.Errorf("the one-step way to make the modules available is not named:\n%s", got)
	}
	if !strings.Contains(got, "kanonarion local /work/tree") {
		t.Errorf("the remedy does not name the directory this run was pointed at:\n%s", got)
	}
	if strings.Contains(got, "--force") {
		t.Errorf("a record that is not served back was given a bypass flag:\n%s", got)
	}
}

// A complete graph gains no remedy: there is nothing to remedy, and a run that
// prints one teaches its reader to distrust an answer that is sound.
func TestPrintCallGraphSummary_CompleteGraphGetsNoRemedy(t *testing.T) {
	var buf bytes.Buffer
	if err := printCallGraphSummary(makeCGRecord(t), false, false, "/work/tree", &buf, callGraphRunJSON{}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "re-analyse") {
		t.Errorf("a complete graph was told how to re-analyse itself:\n%s", buf.String())
	}
}

// TestWorktreeNoticeText_CannotDescribeAZipAnalysisAsAnUnlocatedTree.
//
// The counts are taken over worktree rows and the served record over all of
// them, so the notice could join two true halves into a sentence neither
// supports: one located tree, no unlocated generations, and an answer from "a
// generation that recorded no working tree". A zip analysis states no root
// because it reads none, which is a different fact and a different remedy.
func TestWorktreeNoticeText_CannotDescribeAZipAnalysisAsAnUnlocatedTree(t *testing.T) {
	coord, err := coordinate.NewLocalCoordinate("example.com/mod")
	if err != nil {
		t.Fatalf("NewLocalCoordinate: %v", err)
	}
	got := worktreeNoticeText(coord, cgports.WorktreeRouting{
		LocatedTrees: 1, UnlocatedGenerations: 0,
		CallerRoot:   "/src/fresh",
		ServedSource: cgdomain.AnalysisSourceModuleZip,
	})
	if strings.Contains(got, "recorded no working tree") {
		t.Errorf("a zip analysis was reported as a generation that recorded no working tree: %s", got)
	}
	if strings.Contains(got, "(tree )") {
		t.Errorf("an empty tree digest was printed as the answer's identity: %s", got)
	}
	if !strings.Contains(got, "module zip") {
		t.Errorf("the notice does not say what the answer was read from: %s", got)
	}
	if !strings.Contains(got, "kanonarion local /src/fresh") {
		t.Errorf("the notice names no remedy: %s", got)
	}
}
