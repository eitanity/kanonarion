package sqlite_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/adapters/factstore/sqlite"
	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	domain2 "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/fetch/fetchtest"
)

// The shared contract, pinned on the store every other implementation stands in
// for. It covers both halves of the defect at once: the coordinate is found
// though neither measurement sits at a guessable fetch pipeline version, and the
// record served is the stronger measurement rather than the newest.
func TestComposeFetchRecord_ComposesAcrossFetchPipelineVersions(t *testing.T) {
	fetchtest.AssertComposesAcrossPipelineVersions(t, openMemStore(t))
}

// The same contract under the decorator the production path actually uses. A
// decorator that dropped the optional capability would make every extraction
// stage refuse with ErrComposedReadUnsupported whenever auditing was enabled —
// which is always, in production — so the wrapping is where this would break
// while the store itself stayed correct.
func TestAuditingStore_ComposesAcrossFetchPipelineVersions(t *testing.T) {
	fetchtest.AssertComposesAcrossPipelineVersions(t, openAuditingStore(t))
}

// The measurement that made this ticket: a module whose only fetch record sits
// at a retired fetch pipeline version is invisible to a version-keyed read and
// visible to the composed one. This is the store-level form of
// `kanonarion license al.essio.dev/pkg/shellescape@v1.6.0`, whose only record was
// written at fetch pipeline 0.3.0 while the current version was 0.4.0.
func TestComposeFetchRecord_FindsAModuleMeasuredOnlyUnderARetiredVersion(t *testing.T) {
	s := openMemStore(t)
	ctx := context.Background()
	coord := coordinatetest.MustNew("example.com/retired", "v1.6.0")

	if err := s.PutFetchRecord(ctx, fetchtest.Sealed(t,
		fetchtest.Coordinate(coord),
		fetchtest.PipelineVersion("0.3.0"),
		fetchtest.Content("retired-zip"),
		fetchtest.Status(domain2.Verified),
		fetchtest.FetchedAt(time.Date(2026, 7, 8, 16, 24, 38, 0, time.UTC)),
	)); err != nil {
		t.Fatalf("PutFetchRecord: %v", err)
	}

	// What every extraction stage used to do: ask at the current fetch pipeline
	// version, and be told the module was never fetched.
	if _, ok, err := s.GetFetchRecord(ctx, coord, "0.4.0"); err != nil {
		t.Fatalf("GetFetchRecord at the current version: %v", err)
	} else if ok {
		t.Fatal("the version-keyed read found a record at 0.4.0; the fixture writes only 0.3.0, so this test no longer measures the gap")
	}

	got, ok, err := s.ComposeFetchRecord(ctx, coord)
	if err != nil {
		t.Fatalf("ComposeFetchRecord: %v", err)
	}
	if !ok {
		t.Fatal("ComposeFetchRecord reported absence for a module measured at fetch pipeline 0.3.0; a coordinate-only read must not be keyed by fetch pipeline version")
	}
	if got.PipelineVersion != "0.3.0" {
		t.Errorf("served record pipeline version = %q, want %q", got.PipelineVersion, "0.3.0")
	}
}

// Absence still means absence. The wider read must not turn "nothing measured"
// into an error or into some other coordinate's record.
func TestComposeFetchRecord_AbsenceForAnUnmeasuredCoordinate(t *testing.T) {
	s := openMemStore(t)
	ctx := context.Background()

	if err := s.PutFetchRecord(ctx, fetchtest.Sealed(t,
		fetchtest.Module("example.com/other", "v1.0.0"),
		fetchtest.PipelineVersion("0.4.0"),
		fetchtest.Content("other-zip"),
	)); err != nil {
		t.Fatalf("PutFetchRecord: %v", err)
	}

	_, ok, err := s.ComposeFetchRecord(ctx, coordinatetest.MustNew("example.com/absent", "v1.0.0"))
	if err != nil {
		t.Fatalf("ComposeFetchRecord: %v", err)
	}
	if ok {
		t.Error("ComposeFetchRecord answered a coordinate the ledger holds nothing about")
	}
}

// The zero coordinate names no module, so the composed read owes it the same
// refusal every other read owes: absence is the wrong answer to a question about
// nothing.
func TestComposeFetchRecord_RefusesTheZeroCoordinate(t *testing.T) {
	s := openMemStore(t)
	coordinatetest.AssertRefusesZeroCoordinate(t, "ComposeFetchRecord", func() error {
		_, _, err := s.ComposeFetchRecord(context.Background(), coordinate.ModuleCoordinate{})
		return err //nolint:wrapcheck // the assertion inspects this error verbatim
	})
}

// Widening the read must not weaken the divergence guard. Two measurements at
// two different fetch pipeline versions that disagree on the module hash they
// both carry describe one pinned version as two different artefacts, and the read
// fails closed on that rather than picking one.
func TestComposeFetchRecord_DivergenceAcrossPipelineVersionsIsAnError(t *testing.T) {
	s := openMemStore(t)
	ctx := context.Background()
	coord := coordinatetest.MustNew("example.com/diverged", "v1.0.0")

	for _, seed := range []struct{ pipeline, zip string }{
		{"0.3.0", "zip-one"},
		{"0.4.0", "zip-two"},
	} {
		if err := s.PutFetchRecord(ctx, fetchtest.Sealed(t,
			fetchtest.Coordinate(coord),
			fetchtest.PipelineVersion(seed.pipeline),
			fetchtest.Content(seed.zip),
		)); err != nil {
			t.Fatalf("PutFetchRecord at %s: %v", seed.pipeline, err)
		}
	}

	_, ok, err := s.ComposeFetchRecord(ctx, coord)
	if ok {
		t.Error("ComposeFetchRecord served a record for a coordinate whose measurements disagree on the module hash")
	}
	var d *domain2.Divergence
	if !errors.As(err, &d) {
		t.Fatalf("ComposeFetchRecord error = %v, want a *domain.Divergence", err)
	}
	if d.Field != "module_hash" {
		t.Errorf("divergence field = %q, want %q", d.Field, "module_hash")
	}
	// The report names both generations. Naming one arbitrary version would send
	// an operator to half the rows.
	if d.PipelineVersion != "0.3.0, 0.4.0" {
		t.Errorf("divergence pipeline version = %q, want %q", d.PipelineVersion, "0.3.0, 0.4.0")
	}
}

// openAuditingStore opens the audit-decorated store the production container
// wires, on a temp directory owned by the test.
func openAuditingStore(t *testing.T) *sqlite.AuditingStore {
	t.Helper()
	dir := t.TempDir()
	inner, err := sqlite.Open(filepath.Join(dir, "facts.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	store, err := sqlite.NewAuditingStore(inner, filepath.Join(dir, "audit.jsonl"))
	if err != nil {
		t.Fatalf("NewAuditingStore: %v", err)
	}
	t.Cleanup(func() {
		if cerr := store.Close(); cerr != nil {
			t.Errorf("store.Close: %v", cerr)
		}
	})
	return store
}
