package sqlite

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	"github.com/eitanity/kanonarion/internal/extract/domain"
	"github.com/eitanity/kanonarion/internal/extract/ports"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
)

func TestStore(t *testing.T) {
	ctx := t.Context()
	tmpDir, err := os.MkdirTemp("", "extract-sqlite-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	dbPath := filepath.Join(tmpDir, "test.db")
	store, err := Open(dbPath)
	if err != nil {
		t.Fatalf("failed to open store: %v", err)
	}

	coord := coordinatetest.MustNew("github.com/foo/bar", "v1.0.0")
	hasher := domain.ExtractionRunHasher{}

	run := domain.ExtractionRun{
		SchemaVersion:   domain.ExtractionRunSchemaVersion,
		Ecosystem:       fetchdomain.EcosystemGo,
		ID:              "run-1",
		WalkID:          "walk-1",
		RequestedStages: []string{"license"},
		PerModuleResults: map[coordinate.ModuleCoordinate]domain.ModuleExtractionResult{
			coord: {
				Coordinate: coord,
				Stages: map[string]domain.StageResult{
					"license": {Status: domain.StageSucceeded, DurationMs: 100},
				},
			},
		},
		StartedAt:     time.Now().UTC().Truncate(time.Second),
		CompletedAt:   time.Now().UTC().Truncate(time.Second),
		OverallStatus: domain.ExtractionRunSucceeded,
		ContentHash:   "",
	}
	run, serr := hasher.SetContentHash(run)
	if serr != nil {
		t.Fatalf("SetContentHash: %v", serr)
	}

	t.Run("Put and Get", func(t *testing.T) {
		err := store.PutExtractionRun(ctx, run)
		if err != nil {
			t.Fatalf("PutExtractionRun failed: %v", err)
		}

		got, err := store.GetExtractionRun(ctx, run.ID)
		if err != nil {
			t.Fatalf("GetExtractionRun failed: %v", err)
		}

		if got.ID != run.ID {
			t.Errorf("ID mismatch: got %s, want %s", got.ID, run.ID)
		}
		if got.ContentHash != run.ContentHash {
			t.Errorf("ContentHash mismatch: got %s, want %s", got.ContentHash, run.ContentHash)
		}
		if !got.StartedAt.Equal(run.StartedAt) {
			t.Errorf("StartedAt mismatch: got %v, want %v", got.StartedAt, run.StartedAt)
		}
	})

	t.Run("Get Not Found", func(t *testing.T) {
		_, err := store.GetExtractionRun(ctx, "non-existent")
		if !errors.Is(err, ports.ErrExtractionRunNotFound) {
			t.Errorf("error = %v, want %v", err, ports.ErrExtractionRunNotFound)
		}
	})

	t.Run("List with filters", func(t *testing.T) {
		// Add another run
		run2 := run
		run2.ID = "run-2"
		run2.WalkID = "walk-2"
		run2.OverallStatus = domain.ExtractionRunPartial
		run2, serr := hasher.SetContentHash(run2)
		if serr != nil {
			t.Fatalf("SetContentHash: %v", serr)
		}
		if perr := store.PutExtractionRun(ctx, run2); perr != nil {
			t.Fatalf("PutExtractionRun: %v", perr)
		}

		summaries, err := store.ListExtractionRuns(ctx, ports.ExtractionRunFilter{})
		if err != nil {
			t.Fatalf("ListExtractionRuns failed: %v", err)
		}
		if len(summaries) != 2 {
			t.Errorf("got %d summaries, want 2", len(summaries))
		}

		// Filter by WalkID
		summaries = mustList(ctx, t, store, ports.ExtractionRunFilter{WalkID: "walk-2"})
		if len(summaries) != 1 || summaries[0].ID != "run-2" {
			t.Errorf("WalkID filter failed: got %v", summaries)
		}

		// Filter by Status
		partial := domain.ExtractionRunPartial
		summaries = mustList(ctx, t, store, ports.ExtractionRunFilter{OverallStatus: &partial})
		if len(summaries) != 1 || summaries[0].ID != "run-2" {
			t.Errorf("Status filter failed: got %v", summaries)
		}

		// Filter by Since/Until
		since := run.StartedAt.Add(-time.Hour)
		until := run.StartedAt.Add(time.Hour)
		summaries = mustList(ctx, t, store, ports.ExtractionRunFilter{Since: &since, Until: &until})
		if len(summaries) < 1 {
			t.Errorf("Since/Until filter failed: got %d", len(summaries))
		}

		// Limit and Offset
		summaries = mustList(ctx, t, store, ports.ExtractionRunFilter{Limit: 1, Offset: 1})
		if len(summaries) != 1 {
			t.Errorf("Limit/Offset filter failed: got %d", len(summaries))
		}

		// Filter by ID
		summaries = mustList(ctx, t, store, ports.ExtractionRunFilter{IDs: []string{"run-2"}})
		if len(summaries) != 1 || summaries[0].ID != "run-2" {
			t.Errorf("IDs filter failed: got %v", summaries)
		}
	})

	t.Run("Integrity failure", func(t *testing.T) {
		// Tamper with DB directly to cause integrity failure on Get
		_, err = store.db.DB().ExecContext(ctx, "UPDATE extraction_runs SET raw_record = ? WHERE id = ?", []byte("invalid json"), "run-1")
		if err != nil {
			t.Fatalf("failed to tamper with DB: %v", err)
		}

		_, err = store.GetExtractionRun(ctx, "run-1")
		if err == nil {
			t.Error("GetExtractionRun should have failed for tampered data")
		}
	})

	// A record that does not decode is a damaged row. It used to be listed as a
	// run that covered no modules. run-1 was made undecodable above.
	t.Run("Undecodable record", func(t *testing.T) {
		if _, err := store.ListExtractionRuns(ctx, ports.ExtractionRunFilter{IDs: []string{"run-1"}}); err == nil {
			t.Error("ListExtractionRuns listed a run whose raw_record does not decode")
		}
	})

	// A timestamp column that does not parse is a damaged row. It used to be
	// listed as a run that started and completed at the zero time.
	t.Run("Unparseable timestamp", func(t *testing.T) {
		if _, err := store.db.DB().ExecContext(ctx, "UPDATE extraction_runs SET started_at = ? WHERE id = ?", "not-a-time", "run-2"); err != nil {
			t.Fatalf("failed to tamper with DB: %v", err)
		}
		if _, err := store.ListExtractionRuns(ctx, ports.ExtractionRunFilter{IDs: []string{"run-2"}}); err == nil {
			t.Error("ListExtractionRuns listed a run whose started_at does not parse")
		}
	})
}

// mustList lists extraction runs, failing the test if the read fails.
func mustList(ctx context.Context, t *testing.T, store *Store, filter ports.ExtractionRunFilter) []ports.ExtractionRunSummary {
	t.Helper()
	summaries, err := store.ListExtractionRuns(ctx, filter)
	if err != nil {
		t.Fatalf("ListExtractionRuns(%+v): %v", filter, err)
	}
	return summaries
}
