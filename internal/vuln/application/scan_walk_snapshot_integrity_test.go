package application

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	"github.com/eitanity/kanonarion/internal/vuln/domain"
	"github.com/eitanity/kanonarion/internal/vuln/ports"
	"github.com/eitanity/kanonarion/internal/vuln/vulntest"
)

func testSnapshot() domain.DatabaseSnapshot {
	return vulntest.MustNew("vuln.go.dev", "2026-07-27T16:28:49Z")
}

// snapshotFaultStore fails the one read under test. The embedded nil port
// supplies the rest of the interface and would panic if anything else were
// called — which is the assertion: the abort must happen on the snapshot read,
// before the run touches the store for anything else.
type snapshotFaultStore struct {
	ports.VulnerabilityStore
	err error
}

func (s *snapshotFaultStore) GetDatabaseSnapshot(context.Context, domain.DatabaseSnapshot) (io.ReadCloser, error) {
	return nil, s.err
}

// The whole point of the sentinel split: a corrupt snapshot ends the run, while
// every other snapshot read failure keeps the fallback it was written for.
// Asserted as one relation rather than two independent facts — before this
// change both branches passed through the same warn-and-continue arm, so
// either assertion alone would have held while the distinction did not exist.
func TestPreExtractVulnDB_IntegrityAbortsOtherFailuresFallBack(t *testing.T) {
	snapshot := testSnapshot()

	t.Run("integrity failure aborts", func(t *testing.T) {
		uc := &ScanWalkUseCase{
			logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
			vulnStore: &snapshotFaultStore{
				err: fmt.Errorf("reading snapshot blob: %w", ports.ErrSnapshotIntegrity),
			},
		}
		dir, cleanup, err := uc.preExtractVulnDB(context.Background(), &snapshot)
		if cleanup != nil {
			cleanup()
		}
		if err == nil {
			t.Fatal("a corrupt snapshot must end the run: every finding in it would be derived from a database the records do not name")
		}
		if !errors.Is(err, ports.ErrSnapshotIntegrity) {
			t.Errorf("the sentinel must survive wrapping so a caller can still route on it, got: %v", err)
		}
		if dir != "" {
			t.Errorf("no extraction directory may be offered after an abort, got %q", dir)
		}
		// The operator is told what to do, that the evidence is intact, and that
		// the remedy will destroy it — a --fresh re-fetch upserts on
		// (source, version) and overwrites the altered bytes in place.
		for _, want := range []string{"--fresh", "untouched as evidence", "copy the store", "overwrites", snapshot.Version()} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("abort message missing %q: %v", want, err)
			}
		}
	})

	t.Run("an absent or unreadable snapshot keeps the fallback", func(t *testing.T) {
		uc := &ScanWalkUseCase{
			logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
			vulnStore: &snapshotFaultStore{
				err: errors.New("snapshot not found"),
			},
		}
		dir, cleanup, err := uc.preExtractVulnDB(context.Background(), &snapshot)
		if cleanup != nil {
			cleanup()
		}
		if err != nil {
			t.Fatalf("a non-integrity failure must keep the per-module extraction fallback, got: %v", err)
		}
		if dir != "" {
			t.Errorf("a failed pre-extraction yields no shared directory, got %q", dir)
		}
	})

	// The record sentinel is a different blast radius — one module's finding, not
	// the database every finding rests on — and must not trip the abort.
	t.Run("the record sentinel does not abort", func(t *testing.T) {
		uc := &ScanWalkUseCase{
			logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
			vulnStore: &snapshotFaultStore{
				err: fmt.Errorf("reading: %w", ports.ErrVulnIntegrity),
			},
		}
		if _, cleanup, err := uc.preExtractVulnDB(context.Background(), &snapshot); err != nil {
			cleanup()
			t.Fatalf("ErrVulnIntegrity must not abort the run from the snapshot path, got: %v", err)
		} else {
			cleanup()
		}
	})
}

// A module scan that reached the store itself and found the snapshot corrupt
// must not be folded into a per-module failure record while the run completes.
// That is the same swallow one layer down.
func TestFirstSnapshotIntegrityFailure(t *testing.T) {
	a := coordinatetest.MustNew("example.com/a", "v1.0.0")
	b := coordinatetest.MustNew("example.com/b", "v1.0.0")
	c := coordinatetest.MustNew("example.com/c", "v1.0.0")
	coords := []coordinate.ModuleCoordinate{a, b, c}

	t.Run("ordinary module failures do not abort", func(t *testing.T) {
		results := map[coordinate.ModuleCoordinate]moduleResult{
			a: {coord: a, err: errors.New("govulncheck exited 2")},
			b: {coord: b},
		}
		if err := firstSnapshotIntegrityFailure(coords, results); err != nil {
			t.Fatalf("a module's own failure must stay a module's failure, got: %v", err)
		}
	})

	t.Run("an integrity failure aborts and names the module", func(t *testing.T) {
		results := map[coordinate.ModuleCoordinate]moduleResult{
			a: {coord: a, err: errors.New("govulncheck exited 2")},
			b: {coord: b, err: fmt.Errorf("preparing db: %w", ports.ErrSnapshotIntegrity)},
			c: {coord: c, err: fmt.Errorf("preparing db: %w", ports.ErrSnapshotIntegrity)},
		}
		err := firstSnapshotIntegrityFailure(coords, results)
		if err == nil {
			t.Fatal("a snapshot integrity failure inside the pool must end the run")
		}
		if !errors.Is(err, ports.ErrSnapshotIntegrity) {
			t.Errorf("the sentinel must survive wrapping, got: %v", err)
		}
		// Stable order: the same corruption must always report the same module,
		// not whichever one map iteration reached first.
		if !strings.Contains(err.Error(), "example.com/b") {
			t.Errorf("expected the first failing coordinate in walk order, got: %v", err)
		}
	})

	t.Run("a missing result is not an abort", func(t *testing.T) {
		if err := firstSnapshotIntegrityFailure(coords, map[coordinate.ModuleCoordinate]moduleResult{}); err != nil {
			t.Fatalf("no results is not an integrity failure, got: %v", err)
		}
	})
}
