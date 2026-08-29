package cli

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/cli/testfakes"
	"github.com/eitanity/kanonarion/internal/coordinate"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
)

// The defect this file pins: the walk-containment search reads the newest 50
// walks and, failing, said "no walk found containing X" — a flat negative from a
// search that never exhausted the population. On a store holding more than 50
// walks the module may sit in walk 51, and `dependents` then denies coverage the
// store holds.
//
// The store this was filed against holds 14 walks, below the bound, so the
// defect is not reproducible there. These fixtures put the population above the
// bound, which is what reproduces it.

// walkSearchFixture builds a fake holding count walks, newest first, with the
// target coordinate present only in the walk at containingIndex (-1 for none).
func walkSearchFixture(t *testing.T, count, containingIndex int, target coordinate.ModuleCoordinate) *testfakes.FakeQueryWalks {
	t.Helper()
	uc := testfakes.NewFakeQueryWalks()
	summaries := make([]walkports.WalkSummary, 0, count)
	base := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	for i := range count {
		id := fmt.Sprintf("walk-%03d", i)
		root := mustCoord(t, fmt.Sprintf("example.com/proj%d", i), "v1.0.0")
		nodes := []walkdomain.GraphNode{{Coordinate: root}}
		if i == containingIndex {
			nodes = append(nodes, walkdomain.GraphNode{Coordinate: target})
		}
		uc.AddWalk(walkdomain.WalkRecord{
			ID:     id,
			Target: root,
			Graph:  walkdomain.Graph{Target: root, Nodes: nodes},
		})
		summaries = append(summaries, walkports.WalkSummary{
			ID: id, Target: root, Scope: walkdomain.WalkScopeCode,
			StartedAt: base.Add(-time.Duration(i) * time.Minute),
		})
	}
	uc.SetSummaries(summaries)
	return uc
}

// A store larger than the bound, with the target only in an older walk: the
// search does not find it, and its error names the bound it stopped at and how
// many walks the store actually holds.
func TestFindWalkContaining_BoundedSearchNamesItsBoundAndTheStoreSize(t *testing.T) {
	target := mustCoord(t, "example.com/dep", "v1.2.3")
	const population = 60
	uc := walkSearchFixture(t, population, population-1, target)

	_, err := findWalkContaining(context.Background(), uc, target, "kanonarion dependents X --walk-id <id>")
	if err == nil {
		t.Fatal("expected the bounded search to fail on a target outside its window")
	}
	msg := err.Error()
	for _, want := range []string{
		fmt.Sprintf("%d most recent walks searched", walkSearchLimit),
		fmt.Sprintf("the store holds %d", population),
		"--walk-id",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("the negative does not carry %q: %s", want, msg)
		}
	}
}

// The zero-paired control. On a store below the bound the search DID exhaust the
// population, so the negative is a plain absence and carries no hedge. A caveat
// emitted unconditionally would teach a reader to discount the one case where
// the absence is real, and this test fails if it is.
func TestFindWalkContaining_ExhaustedSearchStatesAPlainAbsence(t *testing.T) {
	target := mustCoord(t, "example.com/dep", "v1.2.3")
	const population = 5
	uc := walkSearchFixture(t, population, -1, target)

	_, err := findWalkContaining(context.Background(), uc, target, "kanonarion dependents X --walk-id <id>")
	if err == nil {
		t.Fatal("expected a negative for a coordinate no walk contains")
	}
	msg := err.Error()
	for _, hedge := range []string{"most recent", "among the", "--walk-id", "raise"} {
		if strings.Contains(msg, hedge) {
			t.Errorf("a search that exhausted the store hedged with %q: %s", hedge, msg)
		}
	}
	if want := fmt.Sprintf("all %d walk(s) searched", population); !strings.Contains(msg, want) {
		t.Errorf("the negative does not state that it exhausted the population (%q): %s", want, msg)
	}
}

// The bound still does what it is for: a hit inside the window is returned, and
// no walk beyond the window is read to find it.
func TestFindWalkContaining_FindsTheNewestWalkInsideTheBound(t *testing.T) {
	target := mustCoord(t, "example.com/dep", "v1.2.3")
	uc := walkSearchFixture(t, 60, 3, target)

	found, err := findWalkContaining(context.Background(), uc, target, "kanonarion dependents X --walk-id <id>")
	if err != nil {
		t.Fatalf("findWalkContaining: %v", err)
	}
	if found.walkID != "walk-003" {
		t.Errorf("found walk %q, want walk-003", found.walkID)
	}
}

// The sweep: every ListWalks call site that fixes a Limit above 1 is a bounded
// SEARCH and owes a statement of its bound; every site fixing Limit 1 is a
// lookup of the newest matching walk and owes nothing. The two sites the sweep
// found are dispositioned here so a third cannot be added silently — a fixed
// limit above 1 that neither states its bound nor documents its window has to
// come back to this test.
func TestWalkSearchBounds_AreDispositioned(t *testing.T) {
	// dependents' containment search: bounded, and its negative says so —
	// asserted by the two tests above.
	if walkSearchLimit <= 1 {
		t.Errorf("walkSearchLimit = %d; a search bound at 1 is a lookup and this file is about searches", walkSearchLimit)
	}
	// context's vulnerability window: a deliberate recency window that cannot
	// report a false absence, because a module's verdict comes from the
	// vulnerability ledger rather than from this set. It keeps its cap and
	// states its basis where the answer is rendered — asserted in the context
	// tests — so what it owes is disclosure, not a wider search.
	if vulnContextWalkWindow <= 1 {
		t.Errorf("vulnContextWalkWindow = %d; a window of 1 is a lookup", vulnContextWalkWindow)
	}
}
