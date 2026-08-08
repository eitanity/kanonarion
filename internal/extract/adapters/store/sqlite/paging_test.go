package sqlite

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/extract/domain"
	"github.com/eitanity/kanonarion/internal/extract/ports"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
)

// Two defects, both invisible until a caller could actually page this listing.
//
// First, the offset was emitted as `OFFSET ?` with no LIMIT whenever the limit
// was zero, which SQLite rejects outright — so "everything from row N" was the
// one filter combination that could not be asked. The existing filter test
// discarded the error (`summaries, _ =`) and only ever paged with a limit, so
// nothing caught it.
//
// Second, the ordering was `started_at DESC` alone. started_at is a
// second-resolution timestamp and runs of one batch share it; over rows that
// compare equal, a page boundary is decided by whatever the query plan
// produced, so a row can appear on two pages or on none.

func pagingStore(t *testing.T, ids ...string) *Store {
	t.Helper()
	store, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("opening store: %v", err)
	}
	coord, err := coordinate.NewModuleCoordinate("example.com/mod", "v1.0.0")
	if err != nil {
		t.Fatalf("building coordinate: %v", err)
	}
	hasher := domain.ExtractionRunHasher{}
	// One instant for every run: the tie is the subject.
	at := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	for _, id := range ids {
		run := domain.ExtractionRun{
			SchemaVersion:   domain.ExtractionRunSchemaVersion,
			Ecosystem:       fetchdomain.EcosystemGo,
			ID:              id,
			WalkID:          "walk-1",
			RequestedStages: []string{"license"},
			PerModuleResults: map[coordinate.ModuleCoordinate]domain.ModuleExtractionResult{
				coord: {Coordinate: coord},
			},
			StartedAt:     at,
			CompletedAt:   at,
			OverallStatus: domain.ExtractionRunSucceeded,
		}
		run, err = hasher.SetContentHash(run)
		if err != nil {
			t.Fatalf("hashing run %s: %v", id, err)
		}
		if err := store.PutExtractionRun(t.Context(), run); err != nil {
			t.Fatalf("putting run %s: %v", id, err)
		}
	}
	return store
}

// An offset with no limit is "everything from row N" and must be answerable.
func TestListExtractionRuns_OffsetWithoutALimit(t *testing.T) {
	store := pagingStore(t, "run-1", "run-2", "run-3", "run-4")

	got, err := store.ListExtractionRuns(t.Context(), ports.ExtractionRunFilter{Offset: 2})
	if err != nil {
		t.Fatalf("paging with no limit: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d runs from offset 2 of 4, want 2", len(got))
	}
}

// Consecutive pages over rows sharing a timestamp partition the population:
// every run appears exactly once, and in the order the unpaged listing gives.
func TestListExtractionRuns_PagesPartitionATiedOrdering(t *testing.T) {
	ids := []string{"run-1", "run-2", "run-3", "run-4", "run-5"}
	store := pagingStore(t, ids...)

	full, err := store.ListExtractionRuns(t.Context(), ports.ExtractionRunFilter{})
	if err != nil {
		t.Fatalf("listing runs: %v", err)
	}
	if len(full) != len(ids) {
		t.Fatalf("unpaged listing holds %d runs, want %d", len(full), len(ids))
	}

	var paged []string
	for offset := 0; offset < len(ids); offset += 2 {
		page, perr := store.ListExtractionRuns(t.Context(), ports.ExtractionRunFilter{Limit: 2, Offset: offset})
		if perr != nil {
			t.Fatalf("page at offset %d: %v", offset, perr)
		}
		for _, r := range page {
			paged = append(paged, r.ID)
		}
	}
	if len(paged) != len(full) {
		t.Fatalf("paging returned %d runs, want %d", len(paged), len(full))
	}
	for i := range full {
		if paged[i] != full[i].ID {
			t.Errorf("paged run %d = %s, want %s (the unpaged order)", i, paged[i], full[i].ID)
		}
	}
}
