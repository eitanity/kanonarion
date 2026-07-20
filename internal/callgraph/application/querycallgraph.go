package application

import (
	"context"
	"fmt"
	"sort"

	"github.com/eitanity/kanonarion/internal/coordinate"

	"github.com/eitanity/kanonarion/internal/callgraph/domain"
	cgports "github.com/eitanity/kanonarion/internal/callgraph/ports"
)

// QueryCallGraphUseCase provides read-only access to stored call graph records.
type QueryCallGraphUseCase struct {
	store cgports.CallGraphStore
}

// NewQueryCallGraphUseCase constructs a QueryCallGraphUseCase.
func NewQueryCallGraphUseCase(store cgports.CallGraphStore) *QueryCallGraphUseCase {
	return &QueryCallGraphUseCase{store: store}
}

// GetCallGraphRecord retrieves the call graph record for a module coordinate.
func (uc *QueryCallGraphUseCase) GetCallGraphRecord(ctx context.Context, coord coordinate.ModuleCoordinate, pipelineVersion string) (domain.CallGraphRecord, bool, error) {
	rec, found, err := uc.store.GetCallGraphRecord(ctx, coord, pipelineVersion)
	if err != nil {
		return domain.CallGraphRecord{}, false, fmt.Errorf("getting call graph record for %s: %w", coord, err)
	}
	return rec, found, nil
}

// ListCallGraphRecords returns summaries matching the given filter.
func (uc *QueryCallGraphUseCase) ListCallGraphRecords(ctx context.Context, filter cgports.CallGraphFilter) ([]cgports.CallGraphSummary, error) {
	sums, err := uc.store.ListCallGraphRecords(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("listing call graph records: %w", err)
	}
	return sums, nil
}

// FindCallers returns all edges where the callee matches symbolID.
func (uc *QueryCallGraphUseCase) FindCallers(ctx context.Context, symbolID, pipelineVersion string) ([]cgports.CallEdgeRef, error) {
	refs, err := uc.store.FindCallers(ctx, symbolID, pipelineVersion)
	if err != nil {
		return nil, fmt.Errorf("finding callers of %q: %w", symbolID, err)
	}
	return refs, nil
}

// FindCallees returns all edges where the caller matches symbolID.
func (uc *QueryCallGraphUseCase) FindCallees(ctx context.Context, symbolID, pipelineVersion string) ([]cgports.CallEdgeRef, error) {
	refs, err := uc.store.FindCallees(ctx, symbolID, pipelineVersion)
	if err != nil {
		return nil, fmt.Errorf("finding callees of %q: %w", symbolID, err)
	}
	return refs, nil
}

// TraverseCallers performs a BFS from symbolID following caller edges.
// maxDepth 0 means unlimited. Returns all reachable edges and nodes (excluding the root).
func (uc *QueryCallGraphUseCase) TraverseCallers(ctx context.Context, symbolID, pipelineVersion string, maxDepth int) (edges []cgports.CallEdgeRef, nodes []string, err error) {
	return uc.traverseTransitive(ctx, symbolID, pipelineVersion, maxDepth,
		uc.store.FindCallers,
		func(e cgports.CallEdgeRef) string { return e.FromID },
	)
}

// TraverseCallees performs a BFS from symbolID following callee edges.
// maxDepth 0 means unlimited. Returns all reachable edges and nodes (excluding the root).
func (uc *QueryCallGraphUseCase) TraverseCallees(ctx context.Context, symbolID, pipelineVersion string, maxDepth int) (edges []cgports.CallEdgeRef, nodes []string, err error) {
	return uc.traverseTransitive(ctx, symbolID, pipelineVersion, maxDepth,
		uc.store.FindCallees,
		func(e cgports.CallEdgeRef) string { return e.ToID },
	)
}

// traverseTransitive performs a BFS from root using queryFn. neighborOf extracts
// the "next hop" symbol from each returned edge. maxDepth 0 means unlimited.
func (uc *QueryCallGraphUseCase) traverseTransitive(
	ctx context.Context,
	root, pipelineVersion string,
	maxDepth int,
	queryFn func(context.Context, string, string) ([]cgports.CallEdgeRef, error),
	neighborOf func(cgports.CallEdgeRef) string,
) (edges []cgports.CallEdgeRef, nodes []string, err error) {
	visited := map[string]bool{root: true}
	queue := []string{root}

	for depth := 0; len(queue) > 0 && (maxDepth == 0 || depth < maxDepth); depth++ {
		var next []string
		for _, sym := range queue {
			hops, qerr := queryFn(ctx, sym, pipelineVersion)
			if qerr != nil {
				return nil, nil, fmt.Errorf("querying at depth %d: %w", depth+1, qerr)
			}
			for _, e := range hops {
				edges = append(edges, e)
				if nb := neighborOf(e); !visited[nb] {
					visited[nb] = true
					next = append(next, nb)
				}
			}
		}
		queue = next
	}

	for n := range visited {
		if n != root {
			nodes = append(nodes, n)
		}
	}
	sort.Strings(nodes)
	sort.Slice(edges, func(i, j int) bool {
		return cgports.CallEdgeRefLess(edges[i], edges[j])
	})
	return edges, nodes, nil
}
