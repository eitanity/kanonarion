package application

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
	"time"

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

// TraversalRequest is one transitive walk: where to start, how far to follow,
// what counts as in scope, and who to narrate to.
//
// It is a struct rather than a parameter list because the list had reached six
// before the progress reporter joined it, and a seventh positional argument of
// the same shape as its neighbours is a call site nobody can read.
type TraversalRequest struct {
	// SymbolID is the root. It is never among the returned nodes.
	SymbolID string
	// PipelineVersion selects which generation of each module's graph answers.
	PipelineVersion string
	// MaxDepth is how many levels may be expanded; 0 is unlimited and is the
	// only value that guarantees the whole closure.
	MaxDepth int
	// Scope is applied at every hop, not only to the first: a frontier expanded
	// through an out-of-build module version would carry the traversal into code
	// the build does not contain, and every node discovered beyond it would
	// inherit that mistake.
	Scope coordinate.ModuleSet
	// Opts narrows the edge query itself.
	Opts cgports.EdgeQueryOptions
	// Progress is called on a wall-clock interval for as long as the traversal
	// runs, not at level boundaries. nil narrates nothing, which is what every
	// caller that does not want output passes.
	Progress cgports.TraversalProgressReporter
	// ProgressInterval is the gap between two narration lines. Cadence is a
	// presentation decision, so it travels with the reporter rather than being
	// settled here; a non-positive value with a reporter attached falls back to
	// defaultTraversalProgressInterval, because a caller who plumbed a reporter
	// and forgot the cadence wanted narration, and silence is the defect this
	// exists to end.
	ProgressInterval time.Duration
}

// TraversalResult is a transitive walk's answer together with what the walk
// knows about its own completeness.
type TraversalResult struct {
	// Edges and Nodes are the answer, canonically sorted. Nodes excludes the
	// root.
	Edges []cgports.CallEdgeRef
	Nodes []string
	// Truncated reports that the walk exited still holding a frontier: symbols
	// it had discovered and would have expanded had the bound allowed it. That
	// makes the answer something other than the closure, and the frontier says
	// so exactly and for free — where inferring it from the node count would
	// mean running a second, unbounded traversal to learn what the first already
	// held.
	//
	// It is NOT "a --depth was given". A bound that happens to reach the closure
	// exits with an empty frontier and is complete; marking that partial would
	// report a gap in the evidence where there is none.
	Truncated bool
}

// TraverseCallers performs a BFS from req.SymbolID following caller edges.
func (uc *QueryCallGraphUseCase) TraverseCallers(ctx context.Context, req TraversalRequest) (TraversalResult, error) {
	return uc.traverseTransitive(ctx, req,
		uc.callersOfFrontier(),
		func(e cgports.CallEdgeRef) string { return e.FromID },
	)
}

// TraverseCallees performs a BFS from req.SymbolID following callee edges.
func (uc *QueryCallGraphUseCase) TraverseCallees(ctx context.Context, req TraversalRequest) (TraversalResult, error) {
	return uc.traverseTransitive(ctx, req,
		uc.calleesOfFrontier(),
		func(e cgports.CallEdgeRef) string { return e.ToID },
	)
}

// frontierQuery answers one level of a traversal: every edge reaching, or
// reached from, any symbol in the frontier.
type frontierQuery func(ctx context.Context, symbolIDs []string, pipelineVersion string, scope coordinate.ModuleSet, opts cgports.EdgeQueryOptions) ([]cgports.CallEdgeRef, error)

// callersOfFrontier picks how a caller level is asked for: one statement when
// the store offers the set query, otherwise one symbol at a time. Chosen once
// per traversal, so a store cannot answer some levels one way and some the
// other.
func (uc *QueryCallGraphUseCase) callersOfFrontier() frontierQuery {
	if f, ok := uc.store.(cgports.CallGraphFrontierFinder); ok {
		return f.FindCallersOfEach
	}
	return perSymbol(uc.store.FindCallers)
}

// calleesOfFrontier is callersOfFrontier for the other direction.
func (uc *QueryCallGraphUseCase) calleesOfFrontier() frontierQuery {
	if f, ok := uc.store.(cgports.CallGraphFrontierFinder); ok {
		return f.FindCalleesOfEach
	}
	return perSymbol(uc.store.FindCallees)
}

// perSymbol is the frontier query for a store with no set query: ask the
// single-symbol one per symbol. Same answer, at the cost the set query exists to
// avoid. Ids are de-duplicated because the set query answers a repeated id once
// and the two routes must not differ.
func perSymbol(query func(context.Context, string, string, coordinate.ModuleSet, cgports.EdgeQueryOptions) ([]cgports.CallEdgeRef, error)) frontierQuery {
	return func(ctx context.Context, symbolIDs []string, pipelineVersion string, scope coordinate.ModuleSet, opts cgports.EdgeQueryOptions) ([]cgports.CallEdgeRef, error) {
		var out []cgports.CallEdgeRef
		seen := make(map[string]bool, len(symbolIDs))
		for _, sym := range symbolIDs {
			if seen[sym] {
				continue
			}
			seen[sym] = true
			hops, err := query(ctx, sym, pipelineVersion, scope, opts)
			if err != nil {
				return nil, err
			}
			out = append(out, hops...)
		}
		return out, nil
	}
}

// defaultTraversalProgressInterval is the fallback gap between two narration
// lines, used only when a caller attaches a reporter and states no cadence. The
// interval a command actually narrates at travels on the request.
const defaultTraversalProgressInterval = 5 * time.Second

// traversalNarrator publishes where a traversal has got to, for a ticker to read
// and report.
//
// The numbers are atomics rather than the traversal's own visited map and queue
// because the narration runs on its own goroutine: it must read the two counts
// while the traversal is writing the structures they come from, and reading
// those directly is a data race.
type traversalNarrator struct {
	depth   atomic.Int64
	visited atomic.Int64
}

// at records the level about to be expanded and the symbols visited so far.
func (n *traversalNarrator) at(depth, visited int) {
	n.depth.Store(int64(depth))
	n.visited.Store(int64(visited))
}

// startTraversalNarration begins narrating on wall-clock time and returns the
// narrator the traversal publishes to, together with the function that stops it.
//
// Time and not level boundaries, because a level is not bounded in time: one
// wide frontier against a large edge table is minutes inside a single store
// query that has not returned, and a reporter that can only speak between levels
// says nothing for the whole of it. That is the silence a read command must
// never answer with, and the first level is exactly where it bites — a traversal
// that spends its whole life there reaches no boundary at all.
//
// The returned stop waits for the ticker goroutine to have exited, so no line
// can be written after the traversal has returned and no goroutine outlives the
// call. Callers defer it, which covers the error paths too.
func startTraversalNarration(p cgports.TraversalProgressReporter, interval time.Duration) (*traversalNarrator, func()) {
	n := &traversalNarrator{}
	n.at(1, 0)
	if p == nil {
		return n, func() {}
	}
	if interval <= 0 {
		interval = defaultTraversalProgressInterval
	}

	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				p.Advance(int(n.depth.Load()), int(n.visited.Load()))
			}
		}
	}()

	// Once, because close of a closed channel panics and a read command must not
	// die of being stopped twice.
	var once sync.Once
	return n, func() {
		once.Do(func() {
			close(done)
			wg.Wait()
		})
	}
}

// traverseTransitive performs a BFS from root using queryFn. neighborOf extracts
// the "next hop" symbol from each returned edge. maxDepth 0 means unlimited.
//
// queryFn is asked ONCE PER LEVEL, with the whole frontier, which queue holds
// before anything is asked. Asking per symbol instead cost a store round trip
// per visited node.
//
// The set is the same either way: visited is checked before a symbol is queued,
// so the per-symbol queries were over disjoint endpoints and their union is what
// one statement returns. The arrival order differs and does not matter, because
// the canonical sort below is total over every field a ref carries.
//
// queue at loop exit is the truncation signal. The loop ends either because the
// frontier emptied — every reachable symbol expanded, so the answer is the
// closure — or because the depth bound stopped it while symbols were still
// waiting. Non-empty therefore means "this is not all of them", exactly, for
// both directions, without a second traversal to compare against.
func (uc *QueryCallGraphUseCase) traverseTransitive(
	ctx context.Context,
	req TraversalRequest,
	queryFn frontierQuery,
	neighborOf func(cgports.CallEdgeRef) string,
) (TraversalResult, error) {
	root := req.SymbolID
	visited := map[string]bool{root: true}
	queue := []string{root}

	narrator, stop := startTraversalNarration(req.Progress, req.ProgressInterval)
	defer stop()

	var edges []cgports.CallEdgeRef
	for depth := 0; len(queue) > 0 && (req.MaxDepth == 0 || depth < req.MaxDepth); depth++ {
		narrator.at(depth+1, len(visited)-1)
		hops, qerr := queryFn(ctx, queue, req.PipelineVersion, req.Scope, req.Opts)
		if qerr != nil {
			return TraversalResult{}, fmt.Errorf("querying at depth %d: %w", depth+1, qerr)
		}
		var next []string
		for _, e := range hops {
			edges = append(edges, e)
			if nb := neighborOf(e); !visited[nb] {
				visited[nb] = true
				next = append(next, nb)
			}
		}
		queue = next
	}

	res := TraversalResult{Edges: edges, Truncated: len(queue) > 0}
	for n := range visited {
		if n != root {
			res.Nodes = append(res.Nodes, n)
		}
	}
	sort.Strings(res.Nodes)
	sort.Slice(res.Edges, func(i, j int) bool {
		return cgports.CallEdgeRefLess(res.Edges[i], res.Edges[j])
	})
	return res, nil
}
