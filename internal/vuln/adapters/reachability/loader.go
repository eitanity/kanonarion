package reachability

import (
	"context"
	"fmt"

	"github.com/eitanity/kanonarion/internal/coordinate"

	callgraphdomain "github.com/eitanity/kanonarion/internal/callgraph/domain"
	cgports "github.com/eitanity/kanonarion/internal/callgraph/ports"

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
func (l *CallGraphStoreLoader) Load(ctx context.Context, coord coordinate.ModuleCoordinate) (ports.CallGraphProjection, error) {
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
		Nodes:        make([]ports.CallGraphNode, 0, len(rec.Nodes)),
		Edges:        make([]ports.CallGraphEdge, 0, len(rec.Edges)),
		Completeness: string(rec.Completeness),
		Algorithm:    string(rec.Algorithm),
		ArtifactKind: string(rec.ArtifactKind),
		// The eligibility rule is the callgraph domain's, applied here rather than
		// restated in the vuln context: the on-demand spawner asks the same
		// question the extraction use case asks, and both must get the same answer.
		ServableAsCacheHit: callgraphdomain.RecordIsCacheable(rec),
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
	// Reference edges are projected alongside calls, deliberately. A handler
	// registered with a router is code the application really runs, and dropping
	// the registration would leave its whole subgraph unreachable — the
	// false-negative direction, which is the one that matters here. Reachability
	// already drops confidence for the same reason: it asks whether a path
	// exists, and the strength of that path is stated by the root
	// classification's entry-point distance rather than by silently omitting
	// hops.
	for _, e := range rec.Edges {
		proj.Edges = append(proj.Edges, ports.CallGraphEdge{FromID: e.FromID, ToID: e.ToID})
	}
	return proj
}

// Ensure CallGraphStoreLoader implements ports.CallGraphLoader.
var _ ports.CallGraphLoader = (*CallGraphStoreLoader)(nil)
