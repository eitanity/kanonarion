package application

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/gotoolchain"

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

// ErrNoCallGraphHistory is returned by CallGraphHistory when the store cannot
// answer a history question at all.
//
// It is a capability statement, not an absence: a store that does not implement
// CallGraphRecordLister has no generations to report, which is different from a
// ledger that holds none for this coordinate.
var ErrNoCallGraphHistory = errors.New("this call graph store does not keep a record history")

// CallGraphHistory returns every generation the ledger holds for one coordinate
// and pipeline version, oldest first.
//
// It is the read that makes the ledger observable. Without it "both records
// survive" is a claim about a table nobody can see, and a reported
// non-determination names two records a reader has no way to look at.
func (uc *QueryCallGraphUseCase) CallGraphHistory(ctx context.Context, coord coordinate.ModuleCoordinate, pipelineVersion string) ([]domain.CallGraphRecord, error) {
	lister, ok := uc.store.(cgports.CallGraphRecordLister)
	if !ok {
		return nil, ErrNoCallGraphHistory
	}
	recs, err := lister.ListCallGraphRecordsFor(ctx, coord, pipelineVersion)
	if err != nil {
		return nil, fmt.Errorf("listing call graph generations for %s: %w", coord, err)
	}
	return recs, nil
}

// GetCallGraphRecordFrom retrieves the composed record for a coordinate,
// restricted to the dimension values the request names. A store that cannot
// scope by them answers ErrNoCallGraphHistory's sibling condition by falling
// back to the unscoped read — there is nothing to restrict when only one value
// of each dimension can exist.
func (uc *QueryCallGraphUseCase) GetCallGraphRecordFrom(ctx context.Context, coord coordinate.ModuleCoordinate, pipelineVersion string, req domain.ComposeRequest) (domain.CallGraphRecord, bool, error) {
	reader, ok := uc.store.(cgports.CallGraphSourceReader)
	if !ok {
		return uc.GetCallGraphRecord(ctx, coord, pipelineVersion)
	}
	rec, found, err := reader.GetCallGraphRecordFrom(ctx, coord, pipelineVersion, req)
	if err != nil {
		return domain.CallGraphRecord{}, false, fmt.Errorf("getting call graph record for %s: %w", coord, err)
	}
	return rec, found, nil
}

// WorktreeRouting reports which working tree answered for a local coordinate,
// and how many the ledger holds for it. found is false when the store cannot
// distinguish trees, or holds no worktree generation for the coordinate.
//
// It is a capability question first: a store with no notion of a tree does not
// implement the read, and the caller then prints no notice rather than inventing
// one that says the answer came from somewhere it cannot know.
func (uc *QueryCallGraphUseCase) WorktreeRouting(ctx context.Context, coord coordinate.ModuleCoordinate, pipelineVersion string) (cgports.WorktreeRouting, bool, error) {
	router, ok := uc.store.(cgports.CallGraphWorktreeRouter)
	if !ok {
		return cgports.WorktreeRouting{}, false, nil
	}
	r, found, err := router.WorktreeRouting(ctx, coord, pipelineVersion)
	if err != nil {
		return cgports.WorktreeRouting{}, false, fmt.Errorf("resolving the working tree that answers for %s: %w", coord, err)
	}
	return r, found, nil
}

// ForeignModulesBuilt names the modules OTHER than the analysed one whose
// packages the served record for this coordinate built with bodies, with the
// version resolution gave each.
//
// found is false when the store cannot answer the question or holds no served
// generation for the coordinate. It is never an empty set: an answer qualified
// from a store that was not asked would be a claim about which record answered
// that nothing established.
func (uc *QueryCallGraphUseCase) ForeignModulesBuilt(ctx context.Context, coord coordinate.ModuleCoordinate, pipelineVersion string, toolchain gotoolchain.Version) ([]domain.ForeignModule, bool, error) {
	reader, ok := uc.store.(cgports.CallGraphForeignModuleReader)
	if !ok {
		return nil, false, nil
	}
	mods, found, err := reader.ForeignModulesBuilt(ctx, coord, pipelineVersion, toolchain)
	if err != nil {
		return nil, false, fmt.Errorf("reading the foreign modules built into the record for %s: %w", coord, err)
	}
	return mods, found, nil
}

// ListCallGraphRecords returns summaries matching the given filter.
func (uc *QueryCallGraphUseCase) ListCallGraphRecords(ctx context.Context, filter cgports.CallGraphFilter) ([]cgports.CallGraphSummary, error) {
	sums, err := uc.store.ListCallGraphRecords(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("listing call graph records: %w", err)
	}
	return sums, nil
}

// ListCallGraphCoordinates returns the coordinates the ledger holds an analysis
// of, without composing any of them.
//
// A store that cannot answer it from columns falls back to the composing
// listing, which answers the same question at a cost; the fallback is here
// rather than at each call site so no caller has to know which kind of store it
// is wired to.
//
// The fallback leaves Generations empty. A composed summary describes the
// generation the ladder picked, and reporting it as "the generations this
// coordinate holds" would state a composed answer as a row's own — exactly the
// claim this read exists to avoid. Empty says the store did not enumerate them.
func (uc *QueryCallGraphUseCase) ListCallGraphCoordinates(ctx context.Context, filter cgports.CallGraphFilter) ([]cgports.CallGraphCoordinate, error) {
	if lister, ok := uc.store.(cgports.CallGraphCoordinateLister); ok {
		coords, lerr := lister.ListCallGraphCoordinates(ctx, filter)
		if lerr != nil {
			return nil, fmt.Errorf("listing analysed coordinates: %w", lerr)
		}
		return coords, nil
	}
	sums, err := uc.ListCallGraphRecords(ctx, filter)
	if err != nil {
		return nil, err
	}
	out := make([]cgports.CallGraphCoordinate, 0, len(sums))
	for _, s := range sums {
		out = append(out, cgports.CallGraphCoordinate{
			ModulePath:      s.ModulePath,
			ModuleVersion:   s.ModuleVersion,
			PipelineVersion: s.PipelineVersion,
			AnyPartial:      s.OverallStatus == domain.CallGraphStatusPartial,
			AnyBelowFull: s.Completeness != domain.CompletenessUnknown &&
				!s.Completeness.IsBuiltWithBodies(),
		})
	}
	return out, nil
}

// FindCallers returns all edges where the callee matches symbolID, restricted
// to the modules in scope (the zero ModuleSet imposes no restriction).
func (uc *QueryCallGraphUseCase) FindCallers(ctx context.Context, symbolID, pipelineVersion string, scope coordinate.ModuleSet, opts cgports.EdgeQueryOptions) ([]cgports.CallEdgeRef, error) {
	refs, err := uc.store.FindCallers(ctx, symbolID, pipelineVersion, scope, opts)
	if err != nil {
		return nil, fmt.Errorf("finding callers of %q: %w", symbolID, err)
	}
	return refs, nil
}

// FindCallees returns all edges where the caller matches symbolID, restricted
// to the modules in scope (the zero ModuleSet imposes no restriction).
func (uc *QueryCallGraphUseCase) FindCallees(ctx context.Context, symbolID, pipelineVersion string, scope coordinate.ModuleSet, opts cgports.EdgeQueryOptions) ([]cgports.CallEdgeRef, error) {
	refs, err := uc.store.FindCallees(ctx, symbolID, pipelineVersion, scope, opts)
	if err != nil {
		return nil, fmt.Errorf("finding callees of %q: %w", symbolID, err)
	}
	return refs, nil
}

// TraverseCallers performs a BFS from symbolID following caller edges.
// maxDepth 0 means unlimited. Returns all reachable edges and nodes (excluding the root).
//
// scope is applied at every hop, not only to the first: a frontier expanded
// through an out-of-build module version would carry the traversal into code the
// build does not contain, and every node discovered beyond it would inherit that
// mistake.
func (uc *QueryCallGraphUseCase) TraverseCallers(ctx context.Context, symbolID, pipelineVersion string, maxDepth int, scope coordinate.ModuleSet, opts cgports.EdgeQueryOptions) (edges []cgports.CallEdgeRef, nodes []string, err error) {
	return uc.traverseTransitive(ctx, symbolID, pipelineVersion, maxDepth, scope, opts,
		uc.store.FindCallers,
		func(e cgports.CallEdgeRef) string { return e.FromID },
	)
}

// TraverseCallees performs a BFS from symbolID following callee edges.
// maxDepth 0 means unlimited. Returns all reachable edges and nodes (excluding the root).
// scope is applied at every hop, as in TraverseCallers.
func (uc *QueryCallGraphUseCase) TraverseCallees(ctx context.Context, symbolID, pipelineVersion string, maxDepth int, scope coordinate.ModuleSet, opts cgports.EdgeQueryOptions) (edges []cgports.CallEdgeRef, nodes []string, err error) {
	return uc.traverseTransitive(ctx, symbolID, pipelineVersion, maxDepth, scope, opts,
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
	scope coordinate.ModuleSet,
	opts cgports.EdgeQueryOptions,
	queryFn func(context.Context, string, string, coordinate.ModuleSet, cgports.EdgeQueryOptions) ([]cgports.CallEdgeRef, error),
	neighborOf func(cgports.CallEdgeRef) string,
) (edges []cgports.CallEdgeRef, nodes []string, err error) {
	visited := map[string]bool{root: true}
	queue := []string{root}

	for depth := 0; len(queue) > 0 && (maxDepth == 0 || depth < maxDepth); depth++ {
		var next []string
		for _, sym := range queue {
			hops, qerr := queryFn(ctx, sym, pipelineVersion, scope, opts)
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
