package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	cgapp "github.com/eitanity/kanonarion/internal/callgraph/application"
	"github.com/eitanity/kanonarion/internal/callgraph/domain"
	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/spf13/cobra"
)

// callGraphShowFlags is the show command's own options.
type callGraphShowFlags struct {
	limitNodes int
	limitEdges int
	nodeFilter string
	history    bool
	source     string
}

func newCallGraphShowCmd(stdout, stderr io.Writer) *cobra.Command {
	var f callGraphShowFlags

	cmd := &cobra.Command{
		Use:   "callgraph-show <module>@<version>",
		Short: "Show the full call graph record for a module",
		Example: `  kanonarion callgraph-show github.com/spf13/cobra@v1.8.1
  kanonarion callgraph-show github.com/spf13/cobra@v1.8.1 --json
  kanonarion callgraph-show github.com/spf13/cobra@v1.8.1 --node Execute
  kanonarion callgraph-show github.com/spf13/cobra@v1.8.1 --history
  kanonarion callgraph-show example.com/mod@local --source worktree`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return usageErr(cmd)
			}
			logger := buildLogger(logLevel, stderr)
			ctr, cleanup, err := NewContainer(storeRoot, "", "", false, activeConfig, logger)
			if err != nil {
				return fmt.Errorf("initialising store: %w", err)
			}
			defer func() { _ = cleanup() }()
			return runCallGraphShow(cmd.Context(), args[0], f, jsonOut, ctr.QueryCallGraph, stdout)
		},
	}

	cmd.Flags().StringVar(&f.nodeFilter, "node", "", "filter output to edges involving this symbol name")
	cmd.Flags().IntVar(&f.limitNodes, "limit-nodes", 50, "max nodes to print (0=unlimited)")
	cmd.Flags().IntVar(&f.limitEdges, "limit-edges", 100, "max edges to print (0=unlimited)")
	cmd.Flags().BoolVar(&f.history, "history", false, "show every stored generation for the module instead of the composed answer")
	cmd.Flags().StringVar(&f.source, "source", "", "restrict to graphs built from one source: zip or worktree")

	return cmd
}

// parseAnalysisSource maps the --source flag onto the domain value, refusing a
// name the domain does not define rather than silently answering from every
// source. A typo that widened the answer instead of narrowing it would be
// invisible in the output.
func parseAnalysisSource(v string) (domain.AnalysisSource, error) {
	switch v {
	case "":
		return domain.AnalysisSourceUnrecorded, nil
	case string(domain.AnalysisSourceModuleZip):
		return domain.AnalysisSourceModuleZip, nil
	case string(domain.AnalysisSourceWorktree):
		return domain.AnalysisSourceWorktree, nil
	default:
		return domain.AnalysisSourceUnrecorded, fmt.Errorf(
			"unknown analysis source %q: use %q (a fetched module zip) or %q (a directory on disk)",
			v, domain.AnalysisSourceModuleZip, domain.AnalysisSourceWorktree)
	}
}

func runCallGraphShow(ctx context.Context, moduleArg string, f callGraphShowFlags, jsonOut bool, uc QueryCallGraphUseCase, stdout io.Writer) error {
	coord, err := parseCoordinate(moduleArg)
	if err != nil {
		return fmt.Errorf("invalid coordinate %q: %w", moduleArg, err)
	}
	source, err := parseAnalysisSource(f.source)
	if err != nil {
		return err
	}
	if f.history {
		return runCallGraphHistory(ctx, coord, uc, stdout)
	}

	r, found, err := uc.GetCallGraphRecordFrom(ctx, coord, cgapp.PipelineVersion, source)
	if err != nil {
		return fmt.Errorf("getting callgraph record: %w", err)
	}
	if !found {
		if source != domain.AnalysisSourceUnrecorded {
			return &exitError{code: ExitNotFound, msg: fmt.Sprintf(
				"no %s-sourced callgraph record for %s — the ledger may hold one from another source; try --history",
				source, coord)}
		}
		return &exitError{code: ExitNotFound, msg: fmt.Sprintf("no callgraph record for %s — run 'kanonarion callgraph' first", coord)}
	}
	nodeFilter, limitNodes, limitEdges := f.nodeFilter, f.limitNodes, f.limitEdges

	if nodeFilter != "" {
		r = filterCallGraphRecord(r, nodeFilter)
	}

	if jsonOut {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(toCallGraphJSON(r)); err != nil {
			return fmt.Errorf("encoding JSON: %w", err)
		}
		return nil
	}

	return printCallGraphRecord(r, limitNodes, limitEdges, stdout)
}

// runCallGraphHistory prints every generation the ledger holds for a coordinate,
// oldest first, and marks the one composition serves.
//
// It is the read that makes the ledger observable. Without it, "both records
// survive a re-analysis" is a claim about a table nobody can see, and a reported
// non-determination names two records an operator has no way to look at. Each
// row carries the graph digest — what that record says the graph IS, with the
// measurement time and the fetch provenance blanked — because the content hash
// cannot answer "do these two agree": two analyses a second apart that produced
// the identical graph carry different content hashes.
func runCallGraphHistory(ctx context.Context, coord coordinate.ModuleCoordinate, uc QueryCallGraphUseCase, stdout io.Writer) error {
	recs, err := uc.CallGraphHistory(ctx, coord, cgapp.PipelineVersion)
	if err != nil {
		return fmt.Errorf("reading callgraph history: %w", err)
	}
	if len(recs) == 0 {
		if _, werr := fmt.Fprintf(stdout, "no callgraph records for %s\n", coord); werr != nil {
			return fmt.Errorf("writing output: %w", werr)
		}
		return nil
	}

	// A conflict is reported, not hidden: the history view is precisely where an
	// operator goes to see why the composed read refused to pick.
	servedHash := ""
	served, found, gerr := uc.GetCallGraphRecord(ctx, coord, cgapp.PipelineVersion)
	switch {
	case gerr != nil:
		if _, werr := fmt.Fprintf(stdout, "composed answer: unavailable — %v\n\n", gerr); werr != nil {
			return fmt.Errorf("writing output: %w", werr)
		}
	case found:
		servedHash = served.ContentHash
	}

	if _, werr := fmt.Fprintf(stdout, "%d generation(s) for %s at pipeline %s:\n",
		len(recs), coord, cgapp.PipelineVersion); werr != nil {
		return fmt.Errorf("writing output: %w", werr)
	}
	for _, r := range recs {
		marker := " "
		if r.ContentHash != "" && r.ContentHash == servedHash {
			marker = "*"
		}
		if _, werr := fmt.Fprintf(stdout,
			"%s %s  %-16s %-17s %d node(s) / %d edge(s)\n    source:   %s\n    from:     %s\n    graph:    %s\n    record:   %s\n",
			marker, r.ExtractedAt.UTC().Format(time.RFC3339), r.OverallStatus.String(),
			r.Completeness.String(), r.NodeCount, r.EdgeCount,
			r.AnalysisSource.String(), historyOrigin(r), domain.GraphDigest(r), r.ContentHash); werr != nil {
			return fmt.Errorf("writing output: %w", werr)
		}
	}
	if _, werr := fmt.Fprintln(stdout,
		"\n* served by the composed read (highest completeness, then most recent, within one analysis source)"); werr != nil {
		return fmt.Errorf("writing output: %w", werr)
	}
	return nil
}

// historyOrigin renders what a generation was computed from: the artefact for a
// zip, the tree digest for a working tree.
//
// The two are not interchangeable and are not shown under one label. A worktree
// record has no artefact identity because nothing was fetched — inapplicable,
// not missing — and printing "(none)" there would read as a defect rather than
// as the truth about a directory on disk.
func historyOrigin(r domain.CallGraphRecord) string {
	if r.AnalysisSource == domain.AnalysisSourceWorktree {
		if r.WorktreeDigest == "" {
			return "(worktree, no digest recorded)"
		}
		return "tree " + r.WorktreeDigest
	}
	if r.ArtefactIdentity == "" {
		return "(no artefact recorded)"
	}
	return r.ArtefactIdentity
}

// callNodeJSON is the curated snake_case shape of a call graph node plus a
// computed Role field. Raw domain.CallNode is never marshalled directly so the
// public CLI surface stays stable and snake_cased.
type callNodeJSON struct {
	ID            string `json:"id"`
	Module        string `json:"module"`
	Package       string `json:"package"`
	Symbol        string `json:"symbol"`
	Receiver      string `json:"receiver,omitempty"`
	IsExternal    bool   `json:"is_external"`
	IsExportedAPI bool   `json:"is_exported_api"`
	PositionFile  string `json:"position_file,omitempty"`
	PositionLine  int    `json:"position_line,omitempty"`
	IsTest        bool   `json:"is_test"`
	Role          string `json:"role"`
}

type callEdgeJSON struct {
	FromID       string `json:"from_id"`
	ToID         string `json:"to_id"`
	CallSiteFile string `json:"call_site_file,omitempty"`
	CallSiteLine int    `json:"call_site_line,omitempty"`
	Confidence   string `json:"confidence"`
}

type coordinateJSON struct {
	Path    string `json:"path"`
	Version string `json:"version"`
}

// callGraphRecordJSON is the curated snake_case shape of a call graph record.
type callGraphRecordJSON struct {
	SchemaVersion string         `json:"schema_version"`
	Coordinate    coordinateJSON `json:"coordinate"`
	Algorithm     string         `json:"algorithm"`
	// Completeness and AnalysisSource are emitted even when empty. A consumer
	// that cannot see the fidelity cannot tell a fully-built graph from a
	// type-only one, and one that cannot see the source cannot tell which bytes
	// the record is about; in both cases an absent field is itself the answer
	// ("not recorded") and must be visible as one.
	Completeness    string         `json:"completeness"`
	AnalysisSource  string         `json:"analysis_source"`
	WorktreeDigest  string         `json:"worktree_digest,omitempty"`
	Nodes           []callNodeJSON `json:"nodes"`
	Edges           []callEdgeJSON `json:"edges"`
	OverallStatus   string         `json:"overall_status"`
	FailureDetail   string         `json:"failure_detail,omitempty"`
	FailedPackages  []string       `json:"failed_packages,omitempty"`
	ExclusionReason string         `json:"exclusion_reason,omitempty"`
	ExclusionList   []string       `json:"exclusion_list,omitempty"`
	NodeCount       int            `json:"node_count"`
	EdgeCount       int            `json:"edge_count"`
	ExtractedAt     string         `json:"extracted_at"`
	PipelineVersion string         `json:"pipeline_version"`
	ContentHash     string         `json:"content_hash"`
	// TestScope says whether _test.go declarations were part of the analysis.
	// It is emitted even when empty: a consumer that cannot see the axis cannot
	// tell an unmeasured one from a measured-and-empty one.
	TestScope       string `json:"test_scope"`
	TestScopeDetail string `json:"test_scope_detail,omitempty"`
	TestNodeCount   int    `json:"test_node_count"`
	// InterfaceCount and ImplementationCount summarise the type-level relation
	// the implementers query reads; the relation itself is listed by that
	// command rather than inlined into every record dump.
	InterfaceCount      int `json:"interface_count"`
	ImplementationCount int `json:"implementation_count"`
}

func callNodeRole(n domain.CallNode) string {
	if n.IsExternal {
		return "external"
	}
	if n.IsTest {
		return "test"
	}
	if n.IsExportedAPI {
		return "api"
	}
	return "internal"
}

func toCallGraphJSON(r domain.CallGraphRecord) callGraphRecordJSON {
	nodes := make([]callNodeJSON, len(r.Nodes))
	for i, n := range r.Nodes {
		nodes[i] = callNodeJSON{
			ID:            n.ID,
			Module:        n.Module,
			Package:       n.Package,
			Symbol:        n.Symbol,
			Receiver:      n.Receiver,
			IsExternal:    n.IsExternal,
			IsExportedAPI: n.IsExportedAPI,
			PositionFile:  n.Position.File,
			PositionLine:  n.Position.Line,
			IsTest:        n.IsTest,
			Role:          callNodeRole(n),
		}
	}
	edges := make([]callEdgeJSON, len(r.Edges))
	for i, e := range r.Edges {
		edges[i] = callEdgeJSON{
			FromID:       e.FromID,
			ToID:         e.ToID,
			CallSiteFile: e.CallSite.File,
			CallSiteLine: e.CallSite.Line,
			Confidence:   string(e.Confidence),
		}
	}
	testNodes := 0
	for i := range r.Nodes {
		if r.Nodes[i].IsTest {
			testNodes++
		}
	}
	return callGraphRecordJSON{
		SchemaVersion:   r.SchemaVersion,
		Coordinate:      coordinateJSON{Path: r.Coordinate.Path(), Version: r.Coordinate.Version()},
		Algorithm:       string(r.Algorithm),
		Completeness:    string(r.Completeness),
		AnalysisSource:  string(r.AnalysisSource),
		WorktreeDigest:  r.WorktreeDigest,
		Nodes:           nodes,
		Edges:           edges,
		OverallStatus:   r.OverallStatus.String(),
		FailureDetail:   r.FailureDetail,
		FailedPackages:  r.FailedPackages,
		ExclusionReason: r.ExclusionReason,
		ExclusionList:   r.ExclusionList,
		NodeCount:       r.NodeCount,
		EdgeCount:       r.EdgeCount,
		ExtractedAt:     isoTime(r.ExtractedAt),
		PipelineVersion: r.PipelineVersion,
		ContentHash:     r.ContentHash,

		TestScope:           string(r.TestScope),
		TestScopeDetail:     r.TestScopeDetail,
		TestNodeCount:       testNodes,
		InterfaceCount:      len(r.Interfaces),
		ImplementationCount: len(r.Implementations),
	}
}

// writeFidelityLine reports, on every record, how much of the module was built
// and what the analysis read.
//
// Both were stored and neither was ever printed, which made the completeness
// ladder unobservable from the tool: an operator could not tell a graph built
// with bodies from one that only had types, and the two answer "no callers" very
// differently. The source is on the same line because it decides which QUESTION
// the record answers — a working tree and a published zip are different bytes —
// and a record that does not say is reported as not recording it rather than
// silently reading as a zip.
func writeFidelityLine(stdout io.Writer, r domain.CallGraphRecord) error {
	line := fmt.Sprintf("  fidelity: %s   source: %s", r.Completeness.String(), r.AnalysisSource.String())
	if r.AnalysisSource == domain.AnalysisSourceWorktree && r.WorktreeDigest != "" {
		line += "  (tree " + r.WorktreeDigest + ")"
	}
	if _, err := fmt.Fprintln(stdout, line); err != nil {
		return fmt.Errorf("writing fidelity: %w", err)
	}
	return nil
}

// writeTestScopeLine reports the test axis on every record, including when it
// was not measured. A record that says nothing about test scope is read by a
// human as one where test code simply did not appear, which is exactly the
// confusion the axis exists to remove.
func writeTestScopeLine(stdout io.Writer, r domain.CallGraphRecord) error {
	testNodes := 0
	for i := range r.Nodes {
		if r.Nodes[i].IsTest {
			testNodes++
		}
	}
	var line string
	switch {
	case r.TestScope.IsMeasured():
		line = fmt.Sprintf("  test scope: analysed — %d of %d nodes are test declarations", testNodes, r.NodeCount)
	case r.TestScope == domain.TestScopeExcluded:
		line = "  test scope: EXCLUDED — _test.go declarations were not analysed"
		if r.TestScopeDetail != "" {
			line += " (" + r.TestScopeDetail + ")"
		}
	default:
		line = "  test scope: not recorded — this record makes no claim about _test.go declarations"
	}
	if _, err := fmt.Fprintln(stdout, line); err != nil {
		return fmt.Errorf("writing test scope: %w", err)
	}
	return nil
}

func filterCallGraphRecord(r domain.CallGraphRecord, sym string) domain.CallGraphRecord {
	// Keep the matched nodes plus all nodes and edges directly connected to them.
	symLower := strings.ToLower(sym)
	wantIDs := make(map[string]bool)
	for _, n := range r.Nodes {
		if strings.Contains(strings.ToLower(n.Symbol), symLower) {
			wantIDs[n.ID] = true
		}
	}
	var edges []domain.CallEdge
	edgeIDs := make(map[string]bool)
	for _, e := range r.Edges {
		if wantIDs[e.FromID] || wantIDs[e.ToID] {
			edges = append(edges, e)
			edgeIDs[e.FromID] = true
			edgeIDs[e.ToID] = true
		}
	}
	var nodes []domain.CallNode
	for _, n := range r.Nodes {
		if wantIDs[n.ID] || edgeIDs[n.ID] {
			nodes = append(nodes, n)
		}
	}
	r.Nodes = nodes
	r.Edges = edges
	r.NodeCount = len(nodes)
	r.EdgeCount = len(edges)
	r.ContentHash = ""
	return r
}

func printCallGraphRecord(r domain.CallGraphRecord, limitNodes, limitEdges int, stdout io.Writer) error {
	if _, err := fmt.Fprintf(stdout, "%s@%s  [%s]  %s\n",
		r.Coordinate.Path(), r.Coordinate.Version(),
		string(r.Algorithm), r.OverallStatus.String(),
	); err != nil {
		return fmt.Errorf("writing header: %w", err)
	}
	if r.FailureDetail != "" {
		if _, err := fmt.Fprintf(stdout, "  failure: %s\n", r.FailureDetail); err != nil {
			return fmt.Errorf("writing failure detail: %w", err)
		}
	}
	if err := writeFailedPackages(stdout, r); err != nil {
		return err
	}
	if err := writeExclusionInfo(stdout, r); err != nil {
		return err
	}

	if err := writeFidelityLine(stdout, r); err != nil {
		return err
	}
	if err := writeTestScopeLine(stdout, r); err != nil {
		return err
	}
	if len(r.Interfaces) > 0 {
		if _, err := fmt.Fprintf(stdout, "  interfaces: %d declared, %d implementations recorded (query with 'kanonarion implementers')\n",
			len(r.Interfaces), len(r.Implementations)); err != nil {
			return fmt.Errorf("writing interface summary: %w", err)
		}
	}

	if _, err := fmt.Fprintf(stdout, "Legend: [api] exported symbol  [external] outside this module  [test] declared in a _test.go file  (no tag) unexported\n"); err != nil {
		return fmt.Errorf("writing legend: %w", err)
	}

	nodes := r.Nodes
	if limitNodes > 0 && len(nodes) > limitNodes {
		nodes = nodes[:limitNodes]
	}
	if _, err := fmt.Fprintf(stdout, "\nNodes (%d total, showing %d):\n", r.NodeCount, len(nodes)); err != nil {
		return fmt.Errorf("writing nodes header: %w", err)
	}
	for _, n := range nodes {
		ext := ""
		if n.IsExternal {
			ext = " [external]"
		}
		api := ""
		if n.IsExportedAPI {
			api = " [api]"
		}
		test := ""
		if n.IsTest {
			test = " [test]"
		}
		if _, err := fmt.Fprintf(stdout, "  %s%s%s%s\n", n.ID, ext, api, test); err != nil {
			return fmt.Errorf("writing node: %w", err)
		}
	}

	edges := r.Edges
	if limitEdges > 0 && len(edges) > limitEdges {
		edges = edges[:limitEdges]
	}
	if _, err := fmt.Fprintf(stdout, "\nEdges (%d total, showing %d):\n", r.EdgeCount, len(edges)); err != nil {
		return fmt.Errorf("writing edges header: %w", err)
	}
	for _, e := range edges {
		if _, err := fmt.Fprintf(stdout, "  %s → %s  [%s]\n", e.FromID, e.ToID, string(e.Confidence)); err != nil {
			return fmt.Errorf("writing edge: %w", err)
		}
	}
	return nil
}
