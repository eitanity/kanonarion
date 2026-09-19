package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"

	cgapp "github.com/eitanity/kanonarion/internal/callgraph/application"
	cgdomain "github.com/eitanity/kanonarion/internal/callgraph/domain"
	"github.com/eitanity/kanonarion/internal/cli/testfakes"
)

// cappableRecord is a record with more nodes than any cap a test applies to it,
// and a DIFFERENT number of edges, so a cap wired to the wrong array reports a
// number no correct implementation could produce.
func cappableRecord(t *testing.T) cgdomain.CallGraphRecord {
	t.Helper()
	const (
		nodes = 12
		edges = 20
	)
	r := cgdomain.CallGraphRecord{
		Coordinate:    makeCGCoord(t),
		Algorithm:     cgdomain.AlgorithmCHA,
		OverallStatus: cgdomain.CallGraphStatusExtracted,
		NodeCount:     nodes,
		EdgeCount:     edges,
	}
	for i := range nodes {
		id := fmt.Sprintf("example.com/cg/pkg.Fn%02d", i)
		r.Nodes = append(r.Nodes, cgdomain.CallNode{
			ID: id, Module: "example.com/cg", Package: "example.com/cg/pkg", Symbol: fmt.Sprintf("Fn%02d", i),
		})
	}
	for i := range edges {
		r.Edges = append(r.Edges, cgdomain.CallEdge{
			FromID:     fmt.Sprintf("example.com/cg/pkg.Fn%02d", i%nodes),
			ToID:       fmt.Sprintf("example.com/cg/pkg.Fn%02d", (i+1)%nodes),
			Confidence: cgdomain.ConfidenceDirect,
		})
	}
	return r
}

// showCappedJSON runs the command's JSON path over cappableRecord and returns both the
// decoded document and the exact bytes, because two of these assertions are byte
// comparisons and not field comparisons.
func showCappedJSON(t *testing.T, f callGraphShowFlags) (callGraphRecordJSON, []byte) {
	t.Helper()
	uc := testfakes.NewFakeQueryCallGraph()
	uc.AddRecord(makeCGCoord(t), cgapp.PipelineVersion, cappableRecord(t))
	prev := jsonOut
	jsonOut = true
	defer func() { jsonOut = prev }()

	var buf bytes.Buffer
	if err := runCallGraphShow(context.Background(), "example.com/cg@v1.0.0", f, true, uc, &buf); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var got callGraphRecordJSON
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("decoding JSON: %v\n%s", err, buf.String())
	}
	return got, buf.Bytes()
}

func showCappedText(t *testing.T, f callGraphShowFlags) string {
	t.Helper()
	uc := testfakes.NewFakeQueryCallGraph()
	uc.AddRecord(makeCGCoord(t), cgapp.PipelineVersion, cappableRecord(t))
	var buf bytes.Buffer
	if err := runCallGraphShow(context.Background(), "example.com/cg@v1.0.0", f, false, uc, &buf); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return buf.String()
}

func wantCap(t *testing.T, got *arrayCapJSON, want arrayCapJSON) {
	t.Helper()
	if got == nil {
		t.Fatalf("expected a cap statement for %s, got none", want.Subject)
	}
	if *got != want {
		t.Errorf("cap statement = %+v, want %+v", *got, want)
	}
}

// The defect: --limit-nodes was read into a local, used only by the text
// printer, and discarded under --json.
func TestRunCallGraphShow_JSONAppliesAnExplicitNodeCap(t *testing.T) {
	got, _ := showCappedJSON(t, callGraphShowFlags{limitNodes: 5, limitNodesSet: true})

	if len(*got.Nodes) != 5 {
		t.Errorf("nodes returned = %d, want the 5 asked for", len(*got.Nodes))
	}
	if got.NodeCount != 12 {
		t.Errorf("node_count = %d, want the record's true total 12", got.NodeCount)
	}
	wantCap(t, got.NodeCap, arrayCapJSON{
		Truncated: true, Limit: 5, Subject: "nodes", Returned: 5, Available: 12, Remedy: "--limit-nodes 0",
	})
	// The edge array was not asked about and must be untouched and unclaimed.
	if len(*got.Edges) != 20 || got.EdgeCap != nil {
		t.Errorf("edges = %d with edge_cap %+v, want all 20 and no statement", len(*got.Edges), got.EdgeCap)
	}
}

// Asserted on its own run: a cap wired to the other array would pass a test that
// moved both at once.
func TestRunCallGraphShow_JSONAppliesAnExplicitEdgeCap(t *testing.T) {
	got, _ := showCappedJSON(t, callGraphShowFlags{limitEdges: 10, limitEdgesSet: true})

	if len(*got.Edges) != 10 {
		t.Errorf("edges returned = %d, want the 10 asked for", len(*got.Edges))
	}
	if got.EdgeCount != 20 {
		t.Errorf("edge_count = %d, want the record's true total 20", got.EdgeCount)
	}
	wantCap(t, got.EdgeCap, arrayCapJSON{
		Truncated: true, Limit: 10, Subject: "edges", Returned: 10, Available: 20, Remedy: "--limit-edges 0",
	})
	if len(*got.Nodes) != 12 || got.NodeCap != nil {
		t.Errorf("nodes = %d with node_cap %+v, want all 12 and no statement", len(*got.Nodes), got.NodeCap)
	}
}

// Both caps at once, at different limits, so neither can be reading the other's
// number or naming the other's remedy.
func TestRunCallGraphShow_JSONCapsTheTwoArraysIndependently(t *testing.T) {
	got, _ := showCappedJSON(t, callGraphShowFlags{
		limitNodes: 3, limitNodesSet: true, limitEdges: 7, limitEdgesSet: true,
	})

	if len(*got.Nodes) != 3 || len(*got.Edges) != 7 {
		t.Fatalf("returned %d nodes and %d edges, want 3 and 7", len(*got.Nodes), len(*got.Edges))
	}
	wantCap(t, got.NodeCap, arrayCapJSON{
		Truncated: true, Limit: 3, Subject: "nodes", Returned: 3, Available: 12, Remedy: "--limit-nodes 0",
	})
	wantCap(t, got.EdgeCap, arrayCapJSON{
		Truncated: true, Limit: 7, Subject: "edges", Returned: 7, Available: 20, Remedy: "--limit-edges 0",
	})
}

// Zero is a cap the caller TYPED, so the document states it — and states that it
// withheld nothing. The absence of the field means something else entirely.
func TestRunCallGraphShow_JSONExplicitZeroCapReturnsEverythingAndSaysSo(t *testing.T) {
	got, _ := showCappedJSON(t, callGraphShowFlags{limitNodes: 0, limitNodesSet: true})

	if len(*got.Nodes) != 12 {
		t.Errorf("nodes returned = %d, want every one of the 12", len(*got.Nodes))
	}
	wantCap(t, got.NodeCap, arrayCapJSON{
		Truncated: false, Limit: 0, Subject: "nodes", Returned: 12, Available: 12, Remedy: "--limit-nodes 0",
	})
}

// A cap that could not bite is still reported, because a consumer cannot read a
// field that is not there: "not truncated" and "this build does not say" must be
// different readings.
func TestRunCallGraphShow_JSONCapLargerThanTheRecordReportsItDidNotBite(t *testing.T) {
	got, _ := showCappedJSON(t, callGraphShowFlags{
		limitNodes: 1000, limitNodesSet: true, limitEdges: 1000, limitEdgesSet: true,
	})

	if len(*got.Nodes) != 12 || len(*got.Edges) != 20 {
		t.Fatalf("returned %d nodes and %d edges, want the record whole", len(*got.Nodes), len(*got.Edges))
	}
	wantCap(t, got.NodeCap, arrayCapJSON{
		Truncated: false, Limit: 1000, Subject: "nodes", Returned: 12, Available: 12, Remedy: "--limit-nodes 0",
	})
	wantCap(t, got.EdgeCap, arrayCapJSON{
		Truncated: false, Limit: 1000, Subject: "edges", Returned: 20, Available: 20, Remedy: "--limit-edges 0",
	})
}

// The control that protects every existing consumer.
//
// --limit-nodes defaults to 50 and --limit-edges to 100 to keep a terminal
// readable. Letting those defaults reach the document would silently start
// truncating every caller that never asked for a cap — a worse defect than the
// one being fixed — so an unset cap must leave the document exactly as it was:
// byte-identical to the same read with the defaults nowhere near it.
func TestRunCallGraphShow_JSONUnsetCapsLeaveTheDocumentUnchanged(t *testing.T) {
	_, withDefaults := showCappedJSON(t, callGraphShowFlags{limitNodes: 50, limitEdges: 100})
	got, withoutCaps := showCappedJSON(t, callGraphShowFlags{})

	if !bytes.Equal(withDefaults, withoutCaps) {
		t.Errorf("the flag defaults changed the document:\n%s\nwant:\n%s", withDefaults, withoutCaps)
	}
	if len(*got.Nodes) != 12 || len(*got.Edges) != 20 {
		t.Errorf("returned %d nodes and %d edges, want the whole record", len(*got.Nodes), len(*got.Edges))
	}
	if got.NodeCap != nil || got.EdgeCap != nil {
		t.Errorf("caps claimed on a read that asked for none: %+v %+v", got.NodeCap, got.EdgeCap)
	}
	if strings.Contains(string(withoutCaps), "node_cap") || strings.Contains(string(withoutCaps), "edge_cap") {
		t.Errorf("cap keys present on an uncapped read:\n%s", withoutCaps)
	}
}

// --node is the model for the cap statement, not its subject: it goes on
// reporting itself, against the population it filtered, while the cap reports
// against the array that filter produced.
func TestRunCallGraphShow_JSONNodeFilterAndCapBothReportThemselves(t *testing.T) {
	got, _ := showCappedJSON(t, callGraphShowFlags{
		nodeFilter: "Fn0", limitNodes: 2, limitNodesSet: true,
	})

	if got.NodeFilter == nil {
		t.Fatal("expected node_filter to survive alongside a cap")
	}
	if got.NodeFilter.CandidateNodes != 12 || got.NodeFilter.MatchedNodes != 10 {
		t.Errorf("node_filter candidates/matched = %d/%d, want 12/10",
			got.NodeFilter.CandidateNodes, got.NodeFilter.MatchedNodes)
	}
	if len(*got.Nodes) != 2 {
		t.Fatalf("nodes returned = %d, want the 2 asked for", len(*got.Nodes))
	}
	// available is the filtered array, not the record: the cap is a statement
	// about the rows in front of the reader.
	if got.NodeCap == nil || got.NodeCap.Available != got.NodeCount {
		t.Errorf("node_cap = %+v, want available to equal the filtered population %d", got.NodeCap, got.NodeCount)
	}
	if !got.NodeCap.Truncated || got.NodeCap.Returned != 2 {
		t.Errorf("node_cap = %+v, want a cap that bit and returned 2", got.NodeCap)
	}
}

// The text path is unchanged in every respect, defaults included: it applies the
// cap it was given whether or not the caller typed it, and says so in the words
// it always used.
func TestRunCallGraphShow_TextPathIsUnaffectedByWhetherTheCapWasTyped(t *testing.T) {
	typed := showCappedText(t, callGraphShowFlags{limitNodes: 5, limitNodesSet: true, limitEdges: 4, limitEdgesSet: true})
	defaulted := showCappedText(t, callGraphShowFlags{limitNodes: 5, limitEdges: 4})
	if typed != defaulted {
		t.Errorf("the text path read the typed-ness of a cap:\n%s\nwant:\n%s", typed, defaulted)
	}
	for _, want := range []string{"Nodes (12 total, showing 5):", "Edges (20 total, showing 4):"} {
		if !strings.Contains(typed, want) {
			t.Errorf("expected %q in the text output, got:\n%s", want, typed)
		}
	}
	// And the whole record when the cap is lifted, as before.
	whole := showCappedText(t, callGraphShowFlags{limitNodes: 0, limitEdges: 0})
	if !strings.Contains(whole, "Nodes (12 total, showing 12):") ||
		!strings.Contains(whole, "Edges (20 total, showing 20):") {
		t.Errorf("expected the uncapped text output to show everything, got:\n%s", whole)
	}
}

// A negative limit is unlimited on both surfaces, which is what the text
// printer's `limit > 0` gate has always meant. The document must not disagree
// with the printer about what an invocation asked for.
func TestApplyArrayCap_NonPositiveLimitsWithholdNothing(t *testing.T) {
	rows := []int{1, 2, 3}
	for _, limit := range []int{0, -1} {
		kept, stated := applyArrayCap(rows, limit, "rows", "--limit-rows 0")
		if len(kept) != 3 || stated.Truncated || stated.Returned != 3 || stated.Available != 3 {
			t.Errorf("limit %d: kept %d with %+v, want the rows whole and nothing claimed", limit, len(kept), stated)
		}
	}
}

func TestApplyArrayCap_EmptyArrayReportsAnEmptyPopulation(t *testing.T) {
	kept, stated := applyArrayCap([]int{}, 5, "rows", "--limit-rows 0")
	if len(kept) != 0 || stated.Truncated || stated.Available != 0 || stated.Returned != 0 {
		t.Errorf("kept %d with %+v, want an empty population and no claim of truncation", len(kept), stated)
	}
}

// The guard that keeps the fix wired up.
//
// Every assertion above hands runCallGraphShow the "was it typed" fields
// directly. Deleting the two lines in the command constructor that fill them
// would leave all of them green and put the defect back exactly as it was: the
// caps would parse, the command would exit 0, and the document would be
// byte-identical to a run without them. So the constructor is checked at the
// source.
func TestCallGraphShowRecordsWhetherEachCapWasTyped(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "callgraph_show.go", nil, 0)
	if err != nil {
		t.Fatalf("parsing callgraph_show.go: %v", err)
	}
	var ctor *ast.FuncDecl
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Name.Name == "newCallGraphShowCmd" {
			ctor = fn
		}
	}
	if ctor == nil {
		t.Fatal("newCallGraphShowCmd not found: the guard would pass vacuously")
	}

	// Collect every Flags().Changed("x") argument the constructor asks for.
	asked := map[string]bool{}
	ast.Inspect(ctor, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) != 1 {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Changed" {
			return true
		}
		lit, ok := call.Args[0].(*ast.BasicLit)
		if ok && lit.Kind == token.STRING {
			asked[strings.Trim(lit.Value, `"`)] = true
		}
		return true
	})

	for _, flag := range []string{"limit-nodes", "limit-edges"} {
		if !asked[flag] {
			t.Errorf("newCallGraphShowCmd never asks whether %s was set, so the JSON path "+
				"cannot tell a typed cap from the default and will discard it", flag)
		}
	}
}
