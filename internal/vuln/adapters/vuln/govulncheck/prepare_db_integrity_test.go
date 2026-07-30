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
// never consulted. A corrupt snapshot therefore fails instead of falling back,
// while the failures the fallback was actually written for keep it.
func TestPrepareDBArg_IntegrityFailsWhileOtherFailuresFallBack(t *testing.T) {
	snapshot := vulntest.MustNew("vuln.go.dev", "2026-07-27T16:28:49Z")
	const liveDB = "https://vuln.go.dev"

	newScanner := func(err error) *Scanner {
		return &Scanner{
			logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
			vulnStore: &snapshotFaultStore{err: err},
		}
	}

	t.Run("integrity failure is fatal", func(t *testing.T) {
		arg, cleanup, err := newScanner(fmt.Errorf("reading blob: %w", ports.ErrSnapshotIntegrity)).
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

	t.Run("an absent snapshot keeps the live-database fallback", func(t *testing.T) {
		arg, cleanup, err := newScanner(errors.New("snapshot not found")).
			prepareDBArg(context.Background(), snapshot, "")
		if cleanup != nil {
			cleanup()
		}
		if err != nil {
			t.Fatalf("a non-integrity failure must keep the fallback it was written for, got: %v", err)
		}
		if arg != liveDB {
			t.Errorf("expected the live-database fallback, got %q", arg)
		}
	})

	// The record sentinel has a different blast radius and must not trip this.
	t.Run("the record sentinel keeps the fallback", func(t *testing.T) {
		arg, cleanup, err := newScanner(fmt.Errorf("reading: %w", ports.ErrVulnIntegrity)).
			prepareDBArg(context.Background(), snapshot, "")
		if cleanup != nil {
			cleanup()
		}
		if err != nil {
			t.Fatalf("ErrVulnIntegrity is a record failure, not a database one, got: %v", err)
		}
		if arg != liveDB {
			t.Errorf("expected the live-database fallback, got %q", arg)
		}
	})

	// A pre-extracted directory short-circuits before the store is consulted, so
	// the walk path is unaffected by any of the above.
	t.Run("a pre-extracted directory never reaches the store", func(t *testing.T) {
		s := &Scanner{
			logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
			vulnStore: &snapshotFaultStore{err: ports.ErrSnapshotIntegrity},
		}
		arg, cleanup, err := s.prepareDBArg(context.Background(), snapshot, "/tmp/pre-extracted")
		if cleanup != nil {
			cleanup()
		}
		if err != nil {
			t.Fatalf("the shared extraction path must not consult the store, got: %v", err)
		}
		if arg != "file:///tmp/pre-extracted" {
			t.Errorf("expected the pre-extracted directory, got %q", arg)
		}
	})
}
