package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	cgapp "github.com/eitanity/kanonarion/internal/callgraph/application"
	cgdomain "github.com/eitanity/kanonarion/internal/callgraph/domain"
	"github.com/eitanity/kanonarion/internal/cli/testfakes"
)

// nodeFilterRecord is a record shaped like the one the defect was measured on: a
// project's own nodes plus nodes belonging to a dependency, whose module path is
// visible only inside the fully-qualified node ID.
func nodeFilterRecord(t *testing.T) cgdomain.CallGraphRecord {
	t.Helper()
	coord := makeCGCoord(t)
	return cgdomain.CallGraphRecord{
		Coordinate:    coord,
		Algorithm:     cgdomain.AlgorithmCHA,
		OverallStatus: cgdomain.CallGraphStatusExtracted,
		Nodes: []cgdomain.CallNode{
			{ID: "example.com/cg.Main", Module: "example.com/cg", Package: "example.com/cg", Symbol: "Main", IsExportedAPI: true},
			{ID: "example.com/cg/render.Template", Module: "example.com/cg", Package: "example.com/cg/render", Symbol: "Template"},
			{ID: "example.com/tmpl/v3.TxtFuncMap", Module: "example.com/tmpl/v3", Package: "example.com/tmpl/v3", Symbol: "TxtFuncMap", IsExternal: true},
			{ID: "example.com/tmpl/v3.FuncMap", Module: "example.com/tmpl/v3", Package: "example.com/tmpl/v3", Symbol: "FuncMap", IsExternal: true},
		},
		Edges: []cgdomain.CallEdge{
			{FromID: "example.com/cg.Main", ToID: "example.com/cg/render.Template", Confidence: cgdomain.ConfidenceDirect},
			{FromID: "example.com/cg/render.Template", ToID: "example.com/tmpl/v3.TxtFuncMap", Confidence: cgdomain.ConfidenceDirect},
		},
		NodeCount: 4,
		EdgeCount: 2,
	}
}

func filteredIDs(r cgdomain.CallGraphRecord) map[string]bool {
	ids := make(map[string]bool, len(r.Nodes))
	for _, n := range r.Nodes {
		ids[n.ID] = true
	}
	return ids
}

// A module path is the natural way to ask "what does my project touch in this
// dependency". Matching the bare symbol name made it return a silent zero.
func TestFilterCallGraphRecord_ModulePathSelectsTheModulesNodes(t *testing.T) {
	filtered, outcome := filterCallGraphRecord(nodeFilterRecord(t), "example.com/tmpl")
	if outcome.matched != 2 {
		t.Fatalf("expected the module's 2 nodes to match, got %d", outcome.matched)
	}
	ids := filteredIDs(filtered)
	for _, want := range []string{"example.com/tmpl/v3.TxtFuncMap", "example.com/tmpl/v3.FuncMap"} {
		if !ids[want] {
			t.Errorf("expected %s in the filtered nodes, got %v", want, ids)
		}
	}
	// The caller of a matched node comes along, as it does for any filter.
	if !ids["example.com/cg/render.Template"] {
		t.Errorf("expected the connected caller to be kept, got %v", ids)
	}
}

func TestFilterCallGraphRecord_PackagePathSelectsThePackagesNodes(t *testing.T) {
	filtered, outcome := filterCallGraphRecord(nodeFilterRecord(t), "example.com/cg/render")
	if outcome.matched != 1 {
		t.Fatalf("expected 1 matched node for the package path, got %d", outcome.matched)
	}
	if !filteredIDs(filtered)["example.com/cg/render.Template"] {
		t.Errorf("expected the package's node in the filtered set, got %v", filteredIDs(filtered))
	}
}

func TestFilterCallGraphRecord_BareSymbolStillMatches(t *testing.T) {
	_, outcome := filterCallGraphRecord(nodeFilterRecord(t), "TxtFuncMap")
	if outcome.matched != 1 {
		t.Fatalf("expected the bare symbol name to keep matching exactly 1 node, got %d", outcome.matched)
	}
}

// An unmatched filter must say so, and say what it was compared against, rather
// than serving a bare zero that reads as an empty region.
func TestRunCallGraphShow_UnmatchedNodeFilterIsNamed(t *testing.T) {
	uc := testfakes.NewFakeQueryCallGraph()
	uc.AddRecord(makeCGCoord(t), cgapp.PipelineVersion, nodeFilterRecord(t))
	var buf bytes.Buffer
	err := runCallGraphShow(context.Background(), "example.com/cg@v1.0.0",
		callGraphShowFlags{nodeFilter: "no/such/module", limitNodes: 0, limitEdges: 0}, false, uc, &buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, `no node matched "no/such/module"`) {
		t.Errorf("expected the unmatched-filter line naming the pattern, got: %q", out)
	}
	if !strings.Contains(out, nodeFilterComparand) {
		t.Errorf("expected the line to name what the pattern was compared against, got: %q", out)
	}
	if !strings.Contains(out, "all 4 node(s)") {
		t.Errorf("expected the line to name how many nodes were compared, got: %q", out)
	}
	if !strings.Contains(out, "example.com/cg.Main") {
		t.Errorf("expected an example node ID showing the compared shape, got: %q", out)
	}
}

// The remedy the notice prints must be an invocation this CLI's own parser
// accepts, including when --source is in play.
func TestRunCallGraphShow_UnmatchedNodeFilterRemedyParses(t *testing.T) {
	rec := nodeFilterRecord(t)
	rec.AnalysisSource = cgdomain.AnalysisSourceWorktree
	uc := testfakes.NewFakeQueryCallGraph()
	uc.AddRecord(makeCGCoord(t), cgapp.PipelineVersion, rec)
	var buf bytes.Buffer
	err := runCallGraphShow(context.Background(), "example.com/cg@v1.0.0",
		callGraphShowFlags{nodeFilter: "no/such/module", source: "worktree", limitNodes: 0, limitEdges: 0}, false, uc, &buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	line := ""
	for _, l := range strings.Split(buf.String(), "\n") {
		if strings.Contains(l, "to list every node: ") {
			line = strings.TrimSpace(strings.SplitN(l, "to list every node: ", 2)[1])
		}
	}
	if line == "" {
		t.Fatalf("expected a remedy line, got: %q", buf.String())
	}
	if !strings.Contains(line, "--source worktree") {
		t.Errorf("expected the remedy to carry the source restriction, got %q", line)
	}
	if err := parseInvocation(t, line); err != nil {
		t.Errorf("remedy line does not parse: %v", err)
	}
}

// A filter that matched says nothing extra: the notice distinguishes an
// unmatched pattern, so printing it on every filtered read would tell an
// operator nothing.
func TestRunCallGraphShow_MatchedNodeFilterPrintsNoNotice(t *testing.T) {
	uc := testfakes.NewFakeQueryCallGraph()
	uc.AddRecord(makeCGCoord(t), cgapp.PipelineVersion, nodeFilterRecord(t))
	var buf bytes.Buffer
	err := runCallGraphShow(context.Background(), "example.com/cg@v1.0.0",
		callGraphShowFlags{nodeFilter: "example.com/tmpl", limitNodes: 0, limitEdges: 0}, false, uc, &buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if strings.Contains(out, "no node matched") {
		t.Errorf("expected no unmatched-filter notice for a matching filter, got: %q", out)
	}
	if !strings.Contains(out, "example.com/tmpl/v3.TxtFuncMap") {
		t.Errorf("expected the dependency's node in the output, got: %q", out)
	}
}

// A JSON consumer cannot read the text notice, so the same statement is carried
// as a field: an empty node list alone cannot tell an unmatched pattern from an
// empty region.
func TestRunCallGraphShow_JSONCarriesTheNodeFilter(t *testing.T) {
	uc := testfakes.NewFakeQueryCallGraph()
	uc.AddRecord(makeCGCoord(t), cgapp.PipelineVersion, nodeFilterRecord(t))
	prev := jsonOut
	jsonOut = true
	defer func() { jsonOut = prev }()

	var buf bytes.Buffer
	err := runCallGraphShow(context.Background(), "example.com/cg@v1.0.0",
		callGraphShowFlags{nodeFilter: "no/such/module", limitNodes: 0, limitEdges: 0}, true, uc, &buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var got callGraphRecordJSON
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("decoding JSON: %v", err)
	}
	if got.NodeFilter == nil {
		t.Fatalf("expected node_filter in the JSON, got %s", buf.String())
	}
	if got.NodeFilter.Pattern != "no/such/module" {
		t.Errorf("pattern = %q, want the pattern given", got.NodeFilter.Pattern)
	}
	if got.NodeFilter.MatchedNodes != 0 || got.NodeFilter.CandidateNodes != 4 {
		t.Errorf("matched/candidates = %d/%d, want 0/4", got.NodeFilter.MatchedNodes, got.NodeFilter.CandidateNodes)
	}
	if got.NodeFilter.ComparedAgainst != nodeFilterComparand {
		t.Errorf("compared_against = %q, want %q", got.NodeFilter.ComparedAgainst, nodeFilterComparand)
	}
}

// An unfiltered read makes no claim about matching at all.
func TestRunCallGraphShow_JSONOmitsNodeFilterWhenUnfiltered(t *testing.T) {
	uc := testfakes.NewFakeQueryCallGraph()
	uc.AddRecord(makeCGCoord(t), cgapp.PipelineVersion, nodeFilterRecord(t))
	prev := jsonOut
	jsonOut = true
	defer func() { jsonOut = prev }()

	var buf bytes.Buffer
	err := runCallGraphShow(context.Background(), "example.com/cg@v1.0.0",
		callGraphShowFlags{limitNodes: 0, limitEdges: 0}, true, uc, &buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(buf.String(), "node_filter") {
		t.Errorf("expected no node_filter field on an unfiltered read, got %s", buf.String())
	}
}

// A record with no nodes at all still gets a filter statement, and one that does
// not invent an example it does not have.
func TestWriteNodeFilterNotice_EmptyRecordStatesZeroCandidates(t *testing.T) {
	uc := testfakes.NewFakeQueryCallGraph()
	empty := nodeFilterRecord(t)
	empty.Nodes, empty.Edges, empty.NodeCount, empty.EdgeCount = nil, nil, 0, 0
	uc.AddRecord(makeCGCoord(t), cgapp.PipelineVersion, empty)
	var buf bytes.Buffer
	err := runCallGraphShow(context.Background(), "example.com/cg@v1.0.0",
		callGraphShowFlags{nodeFilter: "anything", limitNodes: 0, limitEdges: 0}, false, uc, &buf)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "all 0 node(s)") {
		t.Errorf("expected the notice to state that nothing was there to compare, got: %q", out)
	}
	if strings.Contains(out, "(e.g. ") {
		t.Errorf("expected no invented example on an empty record, got: %q", out)
	}
}

// failingWriter is the fault seam for the notice's write path: the error is
// reported rather than swallowed, so a truncated pipe cannot turn the refusal
// into the silent zero it exists to replace.
type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("pipe closed") }

// The example shown in the refusal must illustrate the spelling the refusal is
// asking for: a node whose ID carries a package path, not one the analyser could
// only render from its signature.
func TestExampleNodeID_PrefersAPackageQualifiedID(t *testing.T) {
	nodes := []cgdomain.CallNode{
		{ID: "(*crypto.Hash).String"},
		{ID: "example.com/cg/render.Template"},
	}
	if got := exampleNodeID(nodes); got != "example.com/cg/render.Template" {
		t.Errorf("exampleNodeID = %q, want the package-qualified ID", got)
	}
	if got := exampleNodeID(nodes[:1]); got != "(*crypto.Hash).String" {
		t.Errorf("exampleNodeID = %q, want the only ID available", got)
	}
	if got := exampleNodeID(nil); got != "" {
		t.Errorf("exampleNodeID = %q, want no invented example", got)
	}
}

// The writer's own error path is stated rather than dropped.
func TestWriteNodeFilterNotice_WriteFailure(t *testing.T) {
	err := writeNodeFilterNotice(failingWriter{}, makeCGCoord(t), "",
		nodeFilterOutcome{pattern: "x", candidates: 1, example: "a.B"})
	if err == nil {
		t.Fatal("expected an error from a failing writer")
	}
	if !strings.Contains(err.Error(), "node filter notice") {
		t.Errorf("expected the error to name what failed, got %v", err)
	}
}
