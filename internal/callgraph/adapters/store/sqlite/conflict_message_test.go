package sqlite_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	domain2 "github.com/eitanity/kanonarion/internal/callgraph/domain"
	"github.com/eitanity/kanonarion/internal/callgraph/ports"
	"github.com/eitanity/kanonarion/internal/coordinate"
)

// conflictPhrase is the sentinel's own text, which is also how the domain's
// message opens. Counting it is the whole of this test.
const conflictPhrase = "conflicting call graph records"

// TestConflictRefusal_NamesItselfOnce.
//
// A refused traversal used to say "conflicting call graph records" three times
// in one sentence before naming the coordinate: the sentinel wrapping the
// composed read, the sentinel wrapping the omission summary, and the domain
// message that opens with the phrase. The reader has to get past all three to
// reach the module, the toolchains and the remedy — which is the part they can
// act on.
//
// The count is asserted on both surfaces because the two wraps are in different
// places: one module read directly, and one omitted from a store-wide edge
// query. Routing is asserted alongside it, since the fix takes the sentinel's
// text out of the message while leaving the sentinel on the chain, and a fix
// that dropped the sentinel would turn exit 10 into exit 20.
func TestConflictRefusal_NamesItselfOnce(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)

	// Two toolchains, two different graphs: an identical graph claim is never a
	// disagreement whatever the labels say, so the callees differ too.
	a := ledgerRecord(t, ledgerSpec{
		source: domain2.AnalysisSourceModuleZip, artefact: "zip:h1:a",
		completeness: domain2.CompletenessBuiltWithBodies,
		toolchain:    "go1.26.5", callee: "example.com/mod.Bar", at: testTime,
	})
	b := ledgerRecord(t, ledgerSpec{
		source: domain2.AnalysisSourceModuleZip, artefact: "zip:h1:a",
		completeness: domain2.CompletenessBuiltWithBodies,
		toolchain:    "go1.27.1", callee: "example.com/mod.Baz", at: testTime.Add(time.Hour),
	})
	for _, r := range []domain2.CallGraphRecord{a, b} {
		if perr := s.PutCallGraphRecord(ctx, r); perr != nil {
			t.Fatalf("PutCallGraphRecord: %v", perr)
		}
	}

	_, _, gerr := s.GetCallGraphRecord(ctx, testCoord, testPipeline)
	if !errors.Is(gerr, ports.ErrCallGraphConflict) {
		t.Fatalf("GetCallGraphRecord err = %v, want ErrCallGraphConflict", gerr)
	}

	_, ferr := s.FindCallers(ctx, "example.com/mod.Bar", testPipeline,
		coordinate.ModuleSet{}, ports.EdgeQueryOptions{})
	if !errors.Is(ferr, ports.ErrCallGraphConflict) {
		t.Fatalf("FindCallers err = %v, want ErrCallGraphConflict", ferr)
	}

	for _, tc := range []struct {
		surface string
		err     error
	}{
		{surface: "a coordinate read directly", err: gerr},
		{surface: "a coordinate omitted from an edge query", err: ferr},
	} {
		if n := strings.Count(tc.err.Error(), conflictPhrase); n != 1 {
			t.Errorf("%s says %q %d times, want once:\n%s", tc.surface, conflictPhrase, n, tc.err)
		}
	}

	// The omission summary is content, not repetition: it says how much of the
	// answer was withheld, which nothing else in the sentence does.
	if !strings.Contains(ferr.Error(), "module(s) omitted") {
		t.Errorf("the edge query's refusal no longer says how much it withheld:\n%s", ferr)
	}
	// And the part the reader acts on is still there.
	if !strings.Contains(ferr.Error(), testCoord.String()) ||
		!strings.Contains(ferr.Error(), domain2.ConflictFieldToolchain) {
		t.Errorf("the refusal no longer names the coordinate and the field:\n%s", ferr)
	}
}

// TestEdgeQuery_ToolchainPreferenceServesTheTraversal is the traversal half of
// the ticket: a store-wide caller query spans every module in the store, so one
// disputed coordinate refuses a question about a different module entirely.
//
// The preference reaches here as EdgeQueryOptions.Toolchain, which the read leg
// passes on as ComposeRequest.ToolchainPreference. The unset case is the control
// — removing the ability to refuse would be a worse defect than the refusal —
// and the unrelated-toolchain case is the one that proves it resolves a tie
// rather than filtering.
func TestEdgeQuery_ToolchainPreferenceServesTheTraversal(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t)

	a := ledgerRecord(t, ledgerSpec{
		source: domain2.AnalysisSourceModuleZip, artefact: "zip:h1:a",
		completeness: domain2.CompletenessBuiltWithBodies,
		toolchain:    "go1.26.5", callee: "example.com/mod.Bar", at: testTime,
	})
	b := ledgerRecord(t, ledgerSpec{
		source: domain2.AnalysisSourceModuleZip, artefact: "zip:h1:a",
		completeness: domain2.CompletenessBuiltWithBodies,
		toolchain:    "go1.27.1", callee: "example.com/mod.Baz", at: testTime.Add(time.Hour),
	})
	for _, r := range []domain2.CallGraphRecord{a, b} {
		if perr := s.PutCallGraphRecord(ctx, r); perr != nil {
			t.Fatalf("PutCallGraphRecord: %v", perr)
		}
	}

	if _, err := s.FindCallees(ctx, "example.com/mod.Foo", testPipeline,
		coordinate.ModuleSet{}, ports.EdgeQueryOptions{}); !errors.Is(err, ports.ErrCallGraphConflict) {
		t.Fatalf("with no preference the traversal did not refuse: %v", err)
	}

	edges, err := s.FindCallees(ctx, "example.com/mod.Foo", testPipeline,
		coordinate.ModuleSet{}, ports.EdgeQueryOptions{Toolchain: "go1.27.1"})
	if err != nil {
		t.Fatalf("with a preference the traversal still refused: %v", err)
	}
	if len(edges) != 1 {
		t.Fatalf("the traversal returned %d edge(s), want the preferred generation's 1: %+v", len(edges), edges)
	}
	if edges[0].ToID != "example.com/mod.Baz" {
		t.Errorf("the traversal answered from the other toolchain's graph: %s", edges[0].ToID)
	}
}
