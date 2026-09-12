package sqlite_test

import (
	"context"
	"testing"
	"time"

	domain2 "github.com/eitanity/kanonarion/internal/callgraph/domain"
	"github.com/eitanity/kanonarion/internal/coordinate"
)

// Two generations of one coordinate can share extracted_at. A fast-fail
// analysis writes in well under a second, so a retry loop or a scripted
// re-analysis lands both inside one tick of whatever precision the column holds
// — and before this, "newest" had no answer there and the ladder fell through to
// the content hash, which orders by an arbitrary digest.
//
// The subject has to be CONSTRUCTED. No coordinate in the maintainer's store
// holds two generations in one second, so a run reporting "no records affected"
// is measuring an empty population and shows nothing.
//
// The assertion is append order both ways round: the ledger is append-only, so
// the later append is the later run. Asserting it in one direction only would
// pass on a content-hash tiebreak whenever the digests happened to fall that
// way, which is exactly how the defect stayed invisible.
func TestGenerationTie_TheLaterAppendAnswers(t *testing.T) {
	local, err := coordinate.NewLocalCoordinate("example.com/project")
	if err != nil {
		t.Fatalf("NewLocalCoordinate: %v", err)
	}
	tied := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)

	for _, tc := range []struct{ first, second string }{
		{"example.com/mod.Bar", "example.com/mod.Baz"},
		// The same pair appended the other way round. One of these two orders puts
		// the smaller content hash first and the other puts it second, so a
		// tiebreak on the hash cannot satisfy both.
		{"example.com/mod.Baz", "example.com/mod.Bar"},
	} {
		t.Run(tc.first+" then "+tc.second, func(t *testing.T) {
			s := openTestStore(t)
			ctx := context.Background()
			for _, callee := range []string{tc.first, tc.second} {
				rec := ledgerRecord(t, ledgerSpec{
					coord: local, source: domain2.AnalysisSourceWorktree,
					completeness: domain2.CompletenessBuiltWithBodies,
					worktree:     "wt-a", scanDigest: "scan-a", root: "/trees/a",
					at: tied, callee: callee,
				})
				if perr := s.PutCallGraphRecord(ctx, rec); perr != nil {
					t.Fatalf("PutCallGraphRecord(%s): %v", callee, perr)
				}
			}

			// Composed repeatedly: the answer must be the same every time, not
			// whichever row the engine happened to return first.
			for i := range 20 {
				got, ok, gerr := s.GetCallGraphRecord(ctx, local, testPipeline)
				if gerr != nil {
					t.Fatalf("GetCallGraphRecord: %v", gerr)
				}
				if !ok {
					t.Fatal("GetCallGraphRecord found nothing")
				}
				if len(got.Edges) != 1 {
					t.Fatalf("composed record has %d edges, want 1", len(got.Edges))
				}
				if got.Edges[0].ToID != tc.second {
					t.Fatalf("composition %d served the generation calling %q; the later append calls %q",
						i, got.Edges[0].ToID, tc.second)
				}
			}
		})
	}
}

// The tie must not overrule the ladder above it. A tied pair still ranks by
// completeness first, so a stronger earlier generation is not displaced by a
// weaker one appended after it.
func TestGenerationTie_AppendOrderIsBelowCompleteness(t *testing.T) {
	local, err := coordinate.NewLocalCoordinate("example.com/project")
	if err != nil {
		t.Fatalf("NewLocalCoordinate: %v", err)
	}
	tied := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	s := openTestStore(t)
	ctx := context.Background()

	built := ledgerRecord(t, ledgerSpec{
		coord: local, source: domain2.AnalysisSourceWorktree,
		completeness: domain2.CompletenessBuiltWithBodies,
		worktree:     "wt-a", scanDigest: "scan-a", root: "/trees/a",
		at: tied, callee: "example.com/mod.Bar",
	})
	metadata := ledgerRecord(t, ledgerSpec{
		coord: local, source: domain2.AnalysisSourceWorktree,
		completeness: domain2.CompletenessMetadataOnly,
		worktree:     "wt-a", scanDigest: "scan-a", root: "/trees/a",
		at: tied, callee: "example.com/mod.Baz",
		status: domain2.CallGraphStatusLoadFailed,
	})
	for _, r := range []domain2.CallGraphRecord{built, metadata} {
		if perr := s.PutCallGraphRecord(ctx, r); perr != nil {
			t.Fatalf("PutCallGraphRecord: %v", perr)
		}
	}

	got, ok, gerr := s.GetCallGraphRecord(ctx, local, testPipeline)
	if gerr != nil {
		t.Fatalf("GetCallGraphRecord: %v", gerr)
	}
	if !ok {
		t.Fatal("GetCallGraphRecord found nothing")
	}
	if got.Completeness != domain2.CompletenessBuiltWithBodies {
		t.Errorf("served completeness %q, want %q: append order is the last tiebreak, not the first",
			got.Completeness, domain2.CompletenessBuiltWithBodies)
	}
}
