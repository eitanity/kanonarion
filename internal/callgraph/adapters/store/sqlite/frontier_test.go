package sqlite_test

import (
	"context"
	"fmt"
	"reflect"
	"testing"

	"github.com/eitanity/kanonarion/internal/callgraph/adapters/store/sqlite"
	domain2 "github.com/eitanity/kanonarion/internal/callgraph/domain"
	"github.com/eitanity/kanonarion/internal/callgraph/ports"
	"github.com/eitanity/kanonarion/internal/coordinate"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
)

// makeFanRecord builds n edges, caller i calling callee i. Every symbol is
// distinct, so the two query forms partition the same rows and no deduplication
// can hide a difference between them.
func makeFanRecord(coord coordinate.ModuleCoordinate, pv string, n int) domain2.CallGraphRecord {
	var h domain2.CallGraphRecordHasher
	r := domain2.CallGraphRecord{
		SchemaVersion: domain2.CallGraphSchemaVersion,
		Ecosystem:     fetchdomain.EcosystemGo,
		Coordinate:    coord,
		Algorithm:     domain2.AlgorithmCHA,
	}
	for i := range n {
		from := fmt.Sprintf("example.com/mod.From%04d", i)
		to := fmt.Sprintf("example.com/mod.To%04d", i)
		r.Nodes = append(r.Nodes, domain2.CallNode{
			ID: from, Module: "example.com/mod", Package: "example.com/mod",
			Symbol: fmt.Sprintf("From%04d", i),
		})
		r.Edges = append(r.Edges, domain2.CallEdge{
			FromID:     from,
			ToID:       to,
			CallSite:   domain2.SourcePosition{File: "fan.go", Line: i + 1},
			Confidence: domain2.ConfidenceDirect,
		})
	}
	r.OverallStatus = domain2.CallGraphStatusExtracted
	r.Completeness = domain2.CompletenessBuiltWithBodies
	r.NodeCount = len(r.Nodes)
	r.EdgeCount = len(r.Edges)
	r.ExtractedAt = testTime
	r.PipelineVersion = pv
	r.AnalysisSource = domain2.AnalysisSourceModuleZip
	r.ArtefactIdentity = "zip:h1:" + coord.Path() + "@" + coord.Version()
	hashed, err := h.SetContentHash(r)
	if err != nil {
		panic("SetContentHash: " + err.Error())
	}
	return hashed
}

// sortedRefs puts refs in the canonical order, so two answers holding the same
// edges compare equal whatever order the statements returned them in.
func sortedRefs(refs []ports.CallEdgeRef) []ports.CallEdgeRef {
	out := append([]ports.CallEdgeRef(nil), refs...)
	sortRefs(out)
	return out
}

func sortRefs(refs []ports.CallEdgeRef) {
	for i := 1; i < len(refs); i++ {
		for j := i; j > 0 && ports.CallEdgeRefLess(refs[j], refs[j-1]); j-- {
			refs[j], refs[j-1] = refs[j-1], refs[j]
		}
	}
}

// TestFindCallersOfEach_MatchesTheSingleSymbolQueries is the property the
// traversal's answer rests on: the set query returns exactly what the
// single-symbol queries return. The expected answer is BUILT by those queries,
// not written into the fixture. 450 symbols is over the 400-symbol chunk, so the
// comparison crosses a chunk boundary.
func TestFindCallersOfEach_MatchesTheSingleSymbolQueries(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	const n = 450
	if err := s.PutCallGraphRecord(ctx, makeFanRecord(testCoord, "0.1.0", n)); err != nil {
		t.Fatalf("put: %v", err)
	}

	ids := make([]string, 0, n)
	for i := range n {
		ids = append(ids, fmt.Sprintf("example.com/mod.To%04d", i))
	}

	var want []ports.CallEdgeRef
	for _, id := range ids {
		refs, err := s.FindCallers(ctx, id, "0.1.0", coordinate.ModuleSet{}, ports.EdgeQueryOptions{})
		if err != nil {
			t.Fatalf("FindCallers(%s): %v", id, err)
		}
		want = append(want, refs...)
	}
	if len(want) != n {
		t.Fatalf("the single-symbol queries found %d edges, want %d — the fixture is not what the test assumes", len(want), n)
	}

	got, err := s.FindCallersOfEach(ctx, ids, "0.1.0", coordinate.ModuleSet{}, ports.EdgeQueryOptions{})
	if err != nil {
		t.Fatalf("FindCallersOfEach: %v", err)
	}
	if !reflect.DeepEqual(sortedRefs(got), sortedRefs(want)) {
		t.Errorf("the set query returned %d edges and the single-symbol queries %d; the sets differ",
			len(got), len(want))
	}
}

// TestFindCalleesOfEach_MatchesTheSingleSymbolQueries is the other direction.
func TestFindCalleesOfEach_MatchesTheSingleSymbolQueries(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	const n = 450
	if err := s.PutCallGraphRecord(ctx, makeFanRecord(testCoord, "0.1.0", n)); err != nil {
		t.Fatalf("put: %v", err)
	}

	ids := make([]string, 0, n)
	for i := range n {
		ids = append(ids, fmt.Sprintf("example.com/mod.From%04d", i))
	}

	var want []ports.CallEdgeRef
	for _, id := range ids {
		refs, err := s.FindCallees(ctx, id, "0.1.0", coordinate.ModuleSet{}, ports.EdgeQueryOptions{})
		if err != nil {
			t.Fatalf("FindCallees(%s): %v", id, err)
		}
		want = append(want, refs...)
	}
	if len(want) != n {
		t.Fatalf("the single-symbol queries found %d edges, want %d — the fixture is not what the test assumes", len(want), n)
	}

	got, err := s.FindCalleesOfEach(ctx, ids, "0.1.0", coordinate.ModuleSet{}, ports.EdgeQueryOptions{})
	if err != nil {
		t.Fatalf("FindCalleesOfEach: %v", err)
	}
	if !reflect.DeepEqual(sortedRefs(got), sortedRefs(want)) {
		t.Errorf("the set query returned %d edges and the single-symbol queries %d; the sets differ",
			len(got), len(want))
	}
}

// TestFindCallersOfEach_RepeatedAndEmpty pins two inputs a traversal does not
// produce but a caller may. The empty case matters because `IN ()` is a syntax
// error, so it has to be answered before the statement is built.
func TestFindCallersOfEach_RepeatedAndEmpty(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	if err := s.PutCallGraphRecord(ctx, makeRecord(testCoord, "0.1.0")); err != nil {
		t.Fatalf("put: %v", err)
	}

	once, err := s.FindCallersOfEach(ctx, []string{"example.com/mod.Bar"}, "0.1.0", coordinate.ModuleSet{}, ports.EdgeQueryOptions{})
	if err != nil {
		t.Fatalf("FindCallersOfEach: %v", err)
	}
	twice, err := s.FindCallersOfEach(ctx,
		[]string{"example.com/mod.Bar", "example.com/mod.Bar"}, "0.1.0", coordinate.ModuleSet{}, ports.EdgeQueryOptions{})
	if err != nil {
		t.Fatalf("FindCallersOfEach (repeated): %v", err)
	}
	if !reflect.DeepEqual(once, twice) {
		t.Errorf("a repeated id changed the answer: %d edges once, %d edges twice", len(once), len(twice))
	}

	empty, err := s.FindCallersOfEach(ctx, nil, "0.1.0", coordinate.ModuleSet{}, ports.EdgeQueryOptions{})
	if err != nil {
		t.Fatalf("FindCallersOfEach (no ids): %v", err)
	}
	if len(empty) != 0 {
		t.Errorf("a query about no symbols returned %d edges, want 0", len(empty))
	}
}

// TestFindCallersOfEach_HonoursExcludeTests: a set query that dropped the
// narrowing would widen a traversal the reader deliberately narrowed.
func TestFindCallersOfEach_HonoursExcludeTests(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	if err := s.PutCallGraphRecord(ctx, makeRecord(testCoord, "0.1.0")); err != nil {
		t.Fatalf("put: %v", err)
	}

	ids := []string{"example.com/mod.Bar", "example.com/mod.Baz"}
	for _, opts := range []ports.EdgeQueryOptions{{}, {ExcludeTests: true}} {
		var want []ports.CallEdgeRef
		for _, id := range ids {
			refs, err := s.FindCallers(ctx, id, "0.1.0", coordinate.ModuleSet{}, opts)
			if err != nil {
				t.Fatalf("FindCallers: %v", err)
			}
			want = append(want, refs...)
		}
		got, err := s.FindCallersOfEach(ctx, ids, "0.1.0", coordinate.ModuleSet{}, opts)
		if err != nil {
			t.Fatalf("FindCallersOfEach: %v", err)
		}
		if !reflect.DeepEqual(sortedRefs(got), sortedRefs(want)) {
			t.Errorf("ExcludeTests=%v: the set query returned %d edges, the single-symbol queries %d",
				opts.ExcludeTests, len(got), len(want))
		}
	}
}

// TestFindCallersOfEach_HonoursScope: the zero ModuleSet restricts nothing and
// an empty one matches nothing, and the set query must agree with the
// single-symbol query on both.
func TestFindCallersOfEach_HonoursScope(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()

	if err := s.PutCallGraphRecord(ctx, makeRecord(testCoord, "0.1.0")); err != nil {
		t.Fatalf("put: %v", err)
	}

	ids := []string{"example.com/mod.Bar", "example.com/mod.Baz"}
	for name, scope := range map[string]coordinate.ModuleSet{
		"unrestricted": {},
		"empty":        coordinate.NewModuleSet(nil),
	} {
		var want []ports.CallEdgeRef
		for _, id := range ids {
			refs, err := s.FindCallers(ctx, id, "0.1.0", scope, ports.EdgeQueryOptions{})
			if err != nil {
				t.Fatalf("%s: FindCallers: %v", name, err)
			}
			want = append(want, refs...)
		}
		got, err := s.FindCallersOfEach(ctx, ids, "0.1.0", scope, ports.EdgeQueryOptions{})
		if err != nil {
			t.Fatalf("%s: FindCallersOfEach: %v", name, err)
		}
		if !reflect.DeepEqual(sortedRefs(got), sortedRefs(want)) {
			t.Errorf("%s scope: the set query returned %d edges, the single-symbol queries %d",
				name, len(got), len(want))
		}
	}
}

// Dropping this would silently put every traversal back on the per-symbol route.
var _ ports.CallGraphFrontierFinder = (*sqlite.Store)(nil)
