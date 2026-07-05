package reachability

import (
	"context"
	"fmt"

	callgraphdomain "github.com/eitanity/kanonarion/internal/callgraph/domain"
	cgports "github.com/eitanity/kanonarion/internal/callgraph/ports"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/vuln/ports"
)

// CallGraphStoreLoader adapts a cgports.CallGraphStore to ports.CallGraphLoader.
type CallGraphStoreLoader struct {
	store           cgports.CallGraphStore
	pipelineVersion string
}

// NewCallGraphStoreLoader returns a loader that fetches call graph records from store.
func NewCallGraphStoreLoader(store cgports.CallGraphStore, pipelineVersion string) *CallGraphStoreLoader {
	return &CallGraphStoreLoader{store: store, pipelineVersion: pipelineVersion}
}

// Load retrieves the stored call graph record for coord and maps it to the
// vuln-local projection so callgraph/domain stays confined to this adapter.
func (l *CallGraphStoreLoader) Load(ctx context.Context, coord fetchdomain.ModuleCoordinate) (ports.CallGraphProjection, error) {
	rec, ok, err := l.store.GetCallGraphRecord(ctx, coord, l.pipelineVersion)
	if err != nil {
		return ports.CallGraphProjection{}, fmt.Errorf("loading call graph for %s: %w", coord, err)
	}
	if !ok {
		return ports.CallGraphProjection{}, fmt.Errorf("%w: %s", ports.ErrCallGraphNotFound, coord)
	}
	return projectCallGraph(rec), nil
}

// projectCallGraph maps a callgraph/domain.CallGraphRecord to the minimal
// vuln-local projection the reachability analyser consumes.
func projectCallGraph(rec callgraphdomain.CallGraphRecord) ports.CallGraphProjection {
	proj := ports.CallGraphProjection{
		Nodes: make([]ports.CallGraphNode, 0, len(rec.Nodes)),
		Edges: make([]ports.CallGraphEdge, 0, len(rec.Edges)),
	}
	for _, n := range rec.Nodes {
		proj.Nodes = append(proj.Nodes, ports.CallGraphNode{
			ID:            n.ID,
			Module:        n.Module,
			Package:       n.Package,
			Symbol:        n.Symbol,
			Receiver:      n.Receiver,
			IsExternal:    n.IsExternal,
			IsExportedAPI: n.IsExportedAPI,
		})
	}
	for _, e := range rec.Edges {
		proj.Edges = append(proj.Edges, ports.CallGraphEdge{FromID: e.FromID, ToID: e.ToID})
	}
	return proj
}

// Ensure CallGraphStoreLoader implements ports.CallGraphLoader.
var _ ports.CallGraphLoader = (*CallGraphStoreLoader)(nil)
