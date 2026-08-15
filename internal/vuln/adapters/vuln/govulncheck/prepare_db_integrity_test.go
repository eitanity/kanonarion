package govulncheck

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/vuln/domain"
	"github.com/eitanity/kanonarion/internal/vuln/ports"
	"github.com/eitanity/kanonarion/internal/vuln/vulntest"
)

// snapshotFaultStore fails the snapshot read under test. The embedded nil port
// supplies the rest of the interface: nothing else may be called before the
// scanner decides what to do about the snapshot.
type snapshotFaultStore struct {
	ports.VulnerabilityStore
	err error
}

func (s *snapshotFaultStore) GetDatabaseSnapshot(context.Context, domain.DatabaseSnapshot) (io.ReadCloser, error) {
	return nil, s.err
}

// The fallback to the live database is the failure, not the remedy: the live
// database is a different advisory set from the one the record about to be
// written names, so a finding derived from it cites a snapshot whose bytes were
// never consulted. Every way of failing to reach the pinned snapshot therefore
// refuses, and the sentinel says which kind of failure it was so the run can
// route on it — a corrupt snapshot is evidence to preserve, an absent one is
// something to re-fetch.
func TestPrepareDBArg_EveryUnreachableSnapshotRefuses(t *testing.T) {
	snapshot := vulntest.MustNew("vuln.go.dev", "2026-07-27T16:28:49Z")
	const liveDB = "https://vuln.go.dev"

	newScanner := func(err error) *Scanner {
		return &Scanner{
			logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
			vulnStore: &snapshotFaultStore{err: err},
		}
	}

	t.Run("integrity failure is fatal", func(t *testing.T) {
		arg, _, cleanup, err := newScanner(fmt.Errorf("reading blob: %w", ports.ErrSnapshotIntegrity)).
			prepareDBArg(context.Background(), snapshot, "")
		if cleanup != nil {
			cleanup()
		}
		if err == nil {
			t.Fatal("a corrupt snapshot must fail the scan, not silently answer from a different database")
		}
		if !errors.Is(err, ports.ErrSnapshotIntegrity) {
			t.Errorf("the sentinel must survive wrapping so the run can route on it, got: %v", err)
		}
		if arg == liveDB {
			t.Error("the live database must never be offered after an integrity failure — that is the swallow being removed")
		}
		if arg != "" {
			t.Errorf("no database argument may be returned after an abort, got %q", arg)
		}
		if !strings.Contains(err.Error(), "--fresh") {
			t.Errorf("the operator must be pointed at the remedy, got: %v", err)
		}
	})

	// The two failures that used to keep the fallback. Each produced a scan run
	// entirely against the live database whose every record named the pinned
	// snapshot, announced by one log warning: an unrecoverable claim about the
	// evidence, made in the one place nothing downstream reads.
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"an absent snapshot", errors.New("snapshot not found")},
		{"the record sentinel, which has a different blast radius", fmt.Errorf("reading: %w", ports.ErrVulnIntegrity)},
	} {
		t.Run(tc.name+" refuses too", func(t *testing.T) {
			arg, _, cleanup, err := newScanner(tc.err).prepareDBArg(context.Background(), snapshot, "")
			if cleanup != nil {
				cleanup()
			}
			if err == nil {
				t.Fatal("a snapshot the store will not produce must refuse: the record would name it regardless")
			}
			if !errors.Is(err, ports.ErrSnapshotUnavailable) {
				t.Errorf("the availability sentinel must survive wrapping, got: %v", err)
			}
			if errors.Is(err, ports.ErrSnapshotIntegrity) {
				t.Errorf("an absent snapshot is not a tampered one, and a caller preserving evidence must be able to tell: %v", err)
			}
			if arg == liveDB {
				t.Error("the live database must never be offered")
			}
			if arg != "" {
				t.Errorf("no database argument may be returned after a refusal, got %q", arg)
			}
		})
	}

	// A pre-extracted directory short-circuits before the store is consulted, so
	// the walk path is unaffected by any of the above.
	t.Run("a pre-extracted directory of the right generation never reaches the store", func(t *testing.T) {
		s := &Scanner{
			logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
			vulnStore: &snapshotFaultStore{err: ports.ErrSnapshotIntegrity},
		}
		dir := preExtractedDirAt(t, snapshot.Version())
		arg, _, cleanup, err := s.prepareDBArg(context.Background(), snapshot, dir)
		if cleanup != nil {
			cleanup()
		}
		if err != nil {
			t.Fatalf("the shared extraction path must not consult the store, got: %v", err)
		}
		if arg != "file://"+dir {
			t.Errorf("expected the pre-extracted directory, got %q", arg)
		}
	})

	// The directory is the one input that arrives already opened by someone else.
	// Trusting it is how a scan could read one generation while its record named
	// another, so it states its own generation or it is not used.
	t.Run("a pre-extracted directory of another generation is refused", func(t *testing.T) {
		s := &Scanner{
			logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
			vulnStore: &snapshotFaultStore{err: errors.New("must not be consulted")},
		}
		arg, _, cleanup, err := s.prepareDBArg(context.Background(), snapshot, preExtractedDirAt(t, "2026-01-01T00:00:00Z"))
		if cleanup != nil {
			cleanup()
		}
		if err == nil {
			t.Fatal("a directory holding a different generation must not be handed to the analyser")
		}
		if !errors.Is(err, ports.ErrSnapshotUnavailable) {
			t.Errorf("the availability sentinel must survive wrapping, got: %v", err)
		}
		if !strings.Contains(err.Error(), "2026-01-01T00:00:00Z") {
			t.Errorf("the refusal must name the generation the directory actually holds, got: %v", err)
		}
		if arg != "" {
			t.Errorf("no database argument may be returned after a refusal, got %q", arg)
		}
	})

	// A directory that will not say which generation it is cannot be checked, and
	// an unnameable database is not one a verdict may be sealed against.
	t.Run("a pre-extracted directory that states no generation is refused", func(t *testing.T) {
		s := &Scanner{
			logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
			vulnStore: &snapshotFaultStore{err: errors.New("must not be consulted")},
		}
		_, _, cleanup, err := s.prepareDBArg(context.Background(), snapshot, t.TempDir())
		if cleanup != nil {
			cleanup()
		}
		if !errors.Is(err, ports.ErrSnapshotUnavailable) {
			t.Errorf("a directory with no index/db.json must be refused, got: %v", err)
		}
	})
}
