package application_test

import (
	"context"
	"reflect"
	"testing"

	"github.com/eitanity/kanonarion/internal/callgraph/application"
	"github.com/eitanity/kanonarion/internal/callgraph/domain"
	cgports "github.com/eitanity/kanonarion/internal/callgraph/ports"
	"github.com/eitanity/kanonarion/internal/coordinate"
)

// frontierFake answers edge queries from an adjacency map and counts how many
// times it was asked. It offers no set query, so a traversal over it takes the
// per-symbol fallback; frontierBatchFake is the same store with the set query
// added, so one test can compare the two routes over identical data.
type frontierFake struct {
	callers map[string][]string
	callees map[string][]string

	// symbolCalls counts single-symbol edge queries, frontierCalls counts set
	// queries, and frontiers records the frontier each set query was given.
	symbolCalls   int
	frontierCalls int
	frontiers     [][]string
}

// edgesTo builds the refs for one symbol; asCallee decides which endpoint it
// sits on.
func edgesTo(adj map[string][]string, sym string, asCallee bool) []cgports.CallEdgeRef {
	var out []cgports.CallEdgeRef
	for _, other := range adj[sym] {
		ref := cgports.CallEdgeRef{
			ModulePath:      "example.com/mod",
			ModuleVersion:   "v1.0.0",
			PipelineVersion: "0.1.0",
			Confidence:      domain.ConfidenceDirect,
		}
		if asCallee {
			ref.FromID, ref.ToID = other, sym
		} else {
			ref.FromID, ref.ToID = sym, other
		}
		out = append(out, ref)
	}
	return out
}

func (s *frontierFake) PutCallGraphRecord(context.Context, domain.CallGraphRecord) error {
	return nil
}

func (s *frontierFake) GetCallGraphRecord(context.Context, coordinate.ModuleCoordinate, string) (domain.CallGraphRecord, bool, error) {
	return domain.CallGraphRecord{}, false, nil
}

func (s *frontierFake) ListCallGraphRecords(context.Context, cgports.CallGraphFilter) ([]cgports.CallGraphSummary, error) {
	return nil, nil
}

func (s *frontierFake) FindCallers(_ context.Context, sym, _ string, _ coordinate.ModuleSet, _ cgports.EdgeQueryOptions) ([]cgports.CallEdgeRef, error) {
	s.symbolCalls++
	return edgesTo(s.callers, sym, true), nil
}

func (s *frontierFake) FindCallees(_ context.Context, sym, _ string, _ coordinate.ModuleSet, _ cgports.EdgeQueryOptions) ([]cgports.CallEdgeRef, error) {
	s.symbolCalls++
	return edgesTo(s.callees, sym, false), nil
}

var _ cgports.CallGraphStore = (*frontierFake)(nil)

// frontierBatchFake is frontierFake that also answers for a whole frontier.
type frontierBatchFake struct {
	frontierFake
}

func (s *frontierBatchFake) FindCallersOfEach(_ context.Context, syms []string, _ string, _ coordinate.ModuleSet, _ cgports.EdgeQueryOptions) ([]cgports.CallEdgeRef, error) {
	s.frontierCalls++
	s.frontiers = append(s.frontiers, append([]string(nil), syms...))
	var out []cgports.CallEdgeRef
	for _, sym := range syms {
		out = append(out, edgesTo(s.callers, sym, true)...)
	}
	return out, nil
}

func (s *frontierBatchFake) FindCalleesOfEach(_ context.Context, syms []string, _ string, _ coordinate.ModuleSet, _ cgports.EdgeQueryOptions) ([]cgports.CallEdgeRef, error) {
	s.frontierCalls++
	s.frontiers = append(s.frontiers, append([]string(nil), syms...))
	var out []cgports.CallEdgeRef
	for _, sym := range syms {
		out = append(out, edgesTo(s.callees, sym, false)...)
	}
	return out, nil
}

var (
	_ cgports.CallGraphStore          = (*frontierBatchFake)(nil)
	_ cgports.CallGraphFrontierFinder = (*frontierBatchFake)(nil)
)

// layeredCallers is a graph whose levels are 3, 5 and 7 wide — all different, so
// a wrong frontier cannot coincide with a right one. 16 symbols are expanded in
// all and the walk crosses 4 levels: the cost of the per-symbol route and of the
// set route respectively.
func layeredCallers() map[string][]string {
	return map[string][]string{
		"root": {"a1", "a2", "a3"},
		"a1":   {"b1", "b2"},
		"a2":   {"b3"},
		"a3":   {"b4", "b5"},
		"b1":   {"c1", "c2"},
		"b2":   {"c3"},
		"b3":   {"c4"},
		"b4":   {"c5", "c6"},
		"b5":   {"c7"},
	}
}

// traversal is the request every case here makes, varying only the bound. The
// root and pipeline version are fixtures, and no scope or narration is asked
// for.
func traversal(depth int) application.TraversalRequest {
	return application.TraversalRequest{
		SymbolID:        "root",
		PipelineVersion: "0.1.0",
		MaxDepth:        depth,
		Scope:           coordinate.ModuleSet{},
		Opts:            cgports.EdgeQueryOptions{},
	}
}

// TestTraverseCallers_QueriesOncePerLevel is the regression for the cost defect:
// the traversal asked the store once per VISITED NODE. The counts come from the
// store as it is asked, not from a number written into the fixture.
func TestTraverseCallers_QueriesOncePerLevel(t *testing.T) {
	ctx := context.Background()
	graph := layeredCallers()

	perSymbol := &frontierFake{callers: graph}
	if _, err := application.NewQueryCallGraphUseCase(perSymbol).
		TraverseCallers(ctx, traversal(0)); err != nil {
		t.Fatalf("per-symbol traversal: %v", err)
	}

	batched := &frontierBatchFake{frontierFake{callers: graph}}
	if _, err := application.NewQueryCallGraphUseCase(batched).
		TraverseCallers(ctx, traversal(0)); err != nil {
		t.Fatalf("batched traversal: %v", err)
	}

	// The fallback route is asked about every expanded symbol — the cost the
	// capability exists to remove, stated so the comparison is visible.
	const expanded = 16
	if perSymbol.symbolCalls != expanded {
		t.Errorf("per-symbol route made %d queries, want %d (the root and the 15 nodes above it)",
			perSymbol.symbolCalls, expanded)
	}

	// The store that can batch is asked once per level and never per symbol.
	const levels = 4
	if batched.frontierCalls != levels {
		t.Errorf("batched route made %d frontier queries, want %d (one per level)",
			batched.frontierCalls, levels)
	}
	if batched.symbolCalls != 0 {
		t.Errorf("batched route fell back to %d single-symbol queries, want 0", batched.symbolCalls)
	}

	// Each frontier is a whole level and together they cover every expanded
	// symbol once. Asking per symbol would show 16 frontiers of one.
	wantSizes := []int{1, 3, 5, 7}
	var gotSizes []int
	seen := map[string]bool{}
	for _, f := range batched.frontiers {
		gotSizes = append(gotSizes, len(f))
		for _, sym := range f {
			if seen[sym] {
				t.Errorf("symbol %q was put in a frontier twice", sym)
			}
			seen[sym] = true
		}
	}
	if !reflect.DeepEqual(gotSizes, wantSizes) {
		t.Errorf("frontier sizes = %v, want %v", gotSizes, wantSizes)
	}
	if len(seen) != expanded {
		t.Errorf("the frontiers held %d distinct symbols, want %d", len(seen), expanded)
	}
}

// TestTraverseCallers_BothRoutesGiveTheSameAnswer is the acceptance the cost fix
// had to meet: the query moved and nothing else, so both routes must return the
// identical answer. Both sides are produced by the traversal from the same
// adjacency map, so neither is a value written into the fixture.
func TestTraverseCallers_BothRoutesGiveTheSameAnswer(t *testing.T) {
	ctx := context.Background()
	graph := layeredCallers()

	for _, depth := range []int{0, 1, 2, 3, 4, 5} {
		want, err := application.NewQueryCallGraphUseCase(&frontierFake{callers: graph}).
			TraverseCallers(ctx, traversal(depth))
		if err != nil {
			t.Fatalf("depth %d, per-symbol traversal: %v", depth, err)
		}
		got, err := application.NewQueryCallGraphUseCase(&frontierBatchFake{frontierFake{callers: graph}}).
			TraverseCallers(ctx, traversal(depth))
		if err != nil {
			t.Fatalf("depth %d, batched traversal: %v", depth, err)
		}
		if !reflect.DeepEqual(got.Nodes, want.Nodes) {
			t.Errorf("depth %d: batched nodes = %v, per-symbol nodes = %v", depth, got.Nodes, want.Nodes)
		}
		if !reflect.DeepEqual(got.Edges, want.Edges) {
			t.Errorf("depth %d: batched edges = %v, per-symbol edges = %v", depth, got.Edges, want.Edges)
		}
		// The completeness marker is part of the answer and must agree too: a
		// route that batched its way past the bound would report a different
		// frontier at exit.
		if got.Truncated != want.Truncated {
			t.Errorf("depth %d: batched truncated = %v, per-symbol truncated = %v", depth, got.Truncated, want.Truncated)
		}
	}
}

// TestTraverseCallees_QueriesOncePerLevel pins the same property on the other
// direction.
func TestTraverseCallees_QueriesOncePerLevel(t *testing.T) {
	ctx := context.Background()
	graph := layeredCallers()

	batched := &frontierBatchFake{frontierFake{callees: graph}}
	got, err := application.NewQueryCallGraphUseCase(batched).
		TraverseCallees(ctx, traversal(0))
	if err != nil {
		t.Fatalf("batched traversal: %v", err)
	}
	if batched.frontierCalls != 4 {
		t.Errorf("batched route made %d frontier queries, want 4 (one per level)", batched.frontierCalls)
	}

	perSymbol := &frontierFake{callees: graph}
	want, err := application.NewQueryCallGraphUseCase(perSymbol).
		TraverseCallees(ctx, traversal(0))
	if err != nil {
		t.Fatalf("per-symbol traversal: %v", err)
	}
	if perSymbol.symbolCalls != 16 {
		t.Errorf("per-symbol route made %d queries, want 16", perSymbol.symbolCalls)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("the two routes disagree:\n batched  %+v\n per-sym  %+v", got, want)
	}
}
