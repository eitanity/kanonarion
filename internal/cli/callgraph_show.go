package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	cgapp "github.com/eitanity/kanonarion/internal/callgraph/application"
	"github.com/eitanity/kanonarion/internal/callgraph/domain"
	"github.com/spf13/cobra"
)

func newCallGraphShowCmd(stdout, stderr io.Writer) *cobra.Command {
	var limitNodes, limitEdges int
	var nodeFilter string

	cmd := &cobra.Command{
		Use:   "callgraph-show <module>@<version>",
		Short: "Show the full call graph record for a module",
		Example: `  kanonarion callgraph-show github.com/spf13/cobra@v1.8.1
  kanonarion callgraph-show github.com/spf13/cobra@v1.8.1 --json
  kanonarion callgraph-show github.com/spf13/cobra@v1.8.1 --node Execute`,
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
			return runCallGraphShow(cmd.Context(), args[0], nodeFilter, limitNodes, limitEdges, jsonOut, ctr.QueryCallGraph, stdout)
		},
	}

	cmd.Flags().StringVar(&nodeFilter, "node", "", "filter output to edges involving this symbol name")
	cmd.Flags().IntVar(&limitNodes, "limit-nodes", 50, "max nodes to print (0=unlimited)")
	cmd.Flags().IntVar(&limitEdges, "limit-edges", 100, "max edges to print (0=unlimited)")

	return cmd
}

func runCallGraphShow(ctx context.Context, moduleArg, nodeFilter string, limitNodes, limitEdges int, jsonOut bool, uc QueryCallGraphUseCase, stdout io.Writer) error {
	coord, err := parseCoordinate(moduleArg)
	if err != nil {
		return fmt.Errorf("invalid coordinate %q: %w", moduleArg, err)
	}

	r, found, err := uc.GetCallGraphRecord(ctx, coord, cgapp.PipelineVersion)
	if err != nil {
		return fmt.Errorf("getting callgraph record: %w", err)
	}
	if !found {
		return fmt.Errorf("no callgraph record for %s — run 'kanonarion callgraph' first", coord)
	}

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
	SchemaVersion   string         `json:"schema_version"`
	Coordinate      coordinateJSON `json:"coordinate"`
	Algorithm       string         `json:"algorithm"`
	Nodes           []callNodeJSON `json:"nodes"`
	Edges           []callEdgeJSON `json:"edges"`
	OverallStatus   string         `json:"overall_status"`
	FailureDetail   string         `json:"failure_detail,omitempty"`
	ExclusionReason string         `json:"exclusion_reason,omitempty"`
	ExclusionList   []string       `json:"exclusion_list,omitempty"`
	NodeCount       int            `json:"node_count"`
	EdgeCount       int            `json:"edge_count"`
	ExtractedAt     string         `json:"extracted_at"`
	PipelineVersion string         `json:"pipeline_version"`
	ContentHash     string         `json:"content_hash"`
}

func callNodeRole(n domain.CallNode) string {
	if n.IsExternal {
		return "external"
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
	return callGraphRecordJSON{
		SchemaVersion:   r.SchemaVersion,
		Coordinate:      coordinateJSON{Path: r.Coordinate.Path, Version: r.Coordinate.Version},
		Algorithm:       string(r.Algorithm),
		Nodes:           nodes,
		Edges:           edges,
		OverallStatus:   r.OverallStatus.String(),
		FailureDetail:   r.FailureDetail,
		ExclusionReason: r.ExclusionReason,
		ExclusionList:   r.ExclusionList,
		NodeCount:       r.NodeCount,
		EdgeCount:       r.EdgeCount,
		ExtractedAt:     isoTime(r.ExtractedAt),
		PipelineVersion: r.PipelineVersion,
		ContentHash:     r.ContentHash,
	}
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
		r.Coordinate.Path, r.Coordinate.Version,
		string(r.Algorithm), r.OverallStatus.String(),
	); err != nil {
		return fmt.Errorf("writing header: %w", err)
	}
	if r.FailureDetail != "" {
		if _, err := fmt.Fprintf(stdout, "  failure: %s\n", r.FailureDetail); err != nil {
			return fmt.Errorf("writing failure detail: %w", err)
		}
	}
	if err := writeExclusionInfo(stdout, r); err != nil {
		return err
	}

	if _, err := fmt.Fprintf(stdout, "Legend: [api] exported symbol  [external] outside this module  (no tag) unexported\n"); err != nil {
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
		if _, err := fmt.Fprintf(stdout, "  %s%s%s\n", n.ID, ext, api); err != nil {
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
