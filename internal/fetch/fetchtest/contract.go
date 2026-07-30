package fetchtest

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	"github.com/eitanity/kanonarion/internal/fetch/domain"
)

// RecordWriter is the write half of ports.FactStore. The contract assertions
// below take this rather than the full interface so a fake that only writes —
// and the audit decorator, which is not a whole store either — can be checked
// without growing a read path it does not have.
type RecordWriter interface {
	PutFetchRecord(ctx context.Context, record domain.SealedRecord) error
}

// AssertRefusesUnsealed is the ports.FactStore contract test for the one value
// the PutFetchRecord signature cannot exclude.
//
// SealedRecord is meant to be self-evidencing: Seal and Rehydrate are the only
// ways to make one, so holding one proves the record was hashed. The exported
// struct leaves a gap — domain.SealedRecord{} compiles in any package and seals
// nothing — and an implementation that stores it appends an all-empty row that
// every later read treats as a genuine measurement of the empty module at the
// empty version.
//
// It lives here so the rule has one definition rather than one per store. Every
// FactStore implementation should call it, fakes included: a fake that accepts
// an unsealed record lets an application-layer test go green on a write the real
// store rejects, which is the failure this whole guard exists to prevent.
//
// It asserts the refusal only. Whether the refusal also left the store untouched
// needs a reader, so that leg stays with the implementation that has one.
func AssertRefusesUnsealed(t testing.TB, w RecordWriter) {
	t.Helper()
	err := putRecovering(w)
	if err == nil {
		t.Fatal("fetchtest: the zero SealedRecord was accepted; an unsealed record must never reach storage")
	}
	if !errors.Is(err, domain.ErrUnsealedRecord) {
		t.Fatalf("fetchtest: PutFetchRecord(zero) error = %v, want %v", err, domain.ErrUnsealedRecord)
	}
}

// AssertRefusesZeroIdentity asserts that op refuses the zero artefact identity
// with domain.ErrZeroIdentity.
//
// It exists for the same reason AssertRefusesUnsealed and
// coordinatetest.AssertRefusesZeroCoordinate do: the rule needs one definition
// rather than one per store. Unexporting ArtefactIdentity's fields makes a
// hand-built identity impossible, but Go always permits the zero value, and the
// zero identity names no artefact at all — it would key a row on the empty hash
// on a write, and on a read it asks about nothing, to which absence is the
// wrong answer.
//
// Every implementation that takes an identity should call it, fakes included: a
// fake that accepts the zero identity lets an application-layer test go green
// on a call the real store rejects.
//
// It asserts the refusal only. Whether the refusal also left the store
// untouched needs a reader, so that leg stays with the implementation that has
// one.
func AssertRefusesZeroIdentity(t testing.TB, name string, op func() error) {
	t.Helper()
	err := recovering(op)
	if err == nil {
		t.Fatalf("fetchtest: %s accepted the zero artefact identity; it names no artefact and must never reach storage", name)
	}
	if !errors.Is(err, domain.ErrZeroIdentity) {
		t.Fatalf("fetchtest: %s(zero) error = %v, want %v", name, err, domain.ErrZeroIdentity)
	}
}

// ComposedStore is the write half of ports.FactStore plus the coordinate-only
// read of ports.FactRecordComposer. The assertion below takes this rather than
// the full store so a fake that has no version-keyed read is still held to the
// composed one.
type ComposedStore interface {
	PutFetchRecord(ctx context.Context, record domain.SealedRecord) error
	ComposeFetchRecord(ctx context.Context, coord coordinate.ModuleCoordinate) (domain.CompositeRecord, bool, error)
}

// AssertComposesAcrossPipelineVersions is the ports.FactRecordComposer contract
// test, and it pins both halves of the defect the capability was added for.
//
// It seeds one coordinate with two measurements at two different FETCH pipeline
// versions — an older one whose checksum-database lookup answered, and a newer
// one whose lookup failed — and asserts three things:
//
//   - the coordinate is found at all, though neither measurement sits at the
//     pipeline version a reader would have guessed. A version-keyed read reports
//     absence here, which is how a third of a real store became unextractable:
//     the stage asked at the version it knew and the ledger answered "nothing",
//     while the artefact sat in the blob store the whole time.
//   - BOTH measurements reach the composer. Filtering before composing hides from
//     the composer exactly the records it exists to rank.
//   - the record served is the older, STRONGER one. A first-hit-wins fallback
//     list returns whichever version it happened to name first, so a failed
//     lookup appended after a good one becomes the answer — the defect
//     domain.Compose's own doc says it was written to prevent. This is asserted
//     against the served record's content hash, not against a version string.
//
// Every implementation should call it, fakes included: a fake that answers a
// coordinate-only read by consulting one pipeline version lets an
// application-layer test go green on a read the real store answers differently.
func AssertComposesAcrossPipelineVersions(t testing.TB, s ComposedStore) {
	t.Helper()
	ctx := context.Background()
	coord := coordinatetest.MustNew("example.com/composed", "v1.0.0")

	// Both measurements describe the same artefact — same zip hash — so they do
	// not diverge; what differs is the strength of the evidence behind them.
	stronger := Record(t,
		Coordinate(coord),
		PipelineVersion("fetch-old"),
		Content("composed-zip"),
		Status(domain.Verified),
		FetchedAt(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)),
	)
	weaker := Record(t,
		Coordinate(coord),
		PipelineVersion("fetch-new"),
		Content("composed-zip"),
		Status(domain.Verified),
		SumDBLookupFailed(true),
		FetchedAt(time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)),
	)
	for _, r := range []domain.FactRecord{stronger, weaker} {
		sealed, err := domain.Rehydrate(r)
		if err != nil {
			t.Fatalf("fetchtest: sealing seed record at pipeline %s: %v", r.PipelineVersion, err)
		}
		if err := s.PutFetchRecord(ctx, sealed); err != nil {
			t.Fatalf("fetchtest: seeding record at pipeline %s: %v", r.PipelineVersion, err)
		}
	}

	got, ok, err := s.ComposeFetchRecord(ctx, coord)
	if err != nil {
		t.Fatalf("fetchtest: ComposeFetchRecord(%s) error = %v, want nil", coord, err)
	}
	if !ok {
		t.Fatalf("fetchtest: ComposeFetchRecord(%s) reported absence; measurements exist at pipeline %q and %q, and a coordinate-only read must not be keyed by fetch pipeline version",
			coord, stronger.PipelineVersion, weaker.PipelineVersion)
	}
	if got.MeasurementCount != 2 {
		t.Fatalf("fetchtest: ComposeFetchRecord(%s) composed %d measurements, want 2; a read that filters by pipeline version before composing hides from the composer the records it exists to rank",
			coord, got.MeasurementCount)
	}
	if got.ContentHash != stronger.ContentHash {
		t.Fatalf("fetchtest: ComposeFetchRecord(%s) served the record with content hash %q, want %q — the older measurement whose checksum-database lookup answered. Serving %q would serve a failed lookup because it was appended later.",
			coord, got.ContentHash, stronger.ContentHash, weaker.ContentHash)
	}
}

// ComposeCoordinate is the composed read a fact-store fake owes, factored out so
// each fake answers it the way the real store does rather than approximating it.
// It selects the measurements describing coord — whatever pipeline version filed
// them — orders them as an append-only ledger would, and folds them exactly as
// the sqlite store's read does, divergence guard included. The bool is false when
// the ledger holds nothing about the coordinate.
//
// Records are ordered by measurement time, then pipeline version, then content
// hash. A fake holds its records in a map, and map iteration order is random, so
// without a total order a fake would compose a differently-ordered slice on every
// run — which matters for a local coordinate, where Compose reads the ORDER as
// the sequence of observations rather than as competing claims.
func ComposeCoordinate(coord coordinate.ModuleCoordinate, records []domain.FactRecord) (domain.CompositeRecord, bool, error) {
	matching := make([]domain.FactRecord, 0, len(records))
	for _, r := range records {
		if r.ModulePath == coord.Path() && r.ModuleVersion == coord.Version() {
			matching = append(matching, r)
		}
	}
	if len(matching) == 0 {
		return domain.CompositeRecord{}, false, nil
	}
	sort.SliceStable(matching, func(i, j int) bool {
		a, b := matching[i], matching[j]
		if !a.FetchedAt.Equal(b.FetchedAt) {
			return a.FetchedAt.Before(b.FetchedAt)
		}
		if a.PipelineVersion != b.PipelineVersion {
			return a.PipelineVersion < b.PipelineVersion
		}
		return a.ContentHash < b.ContentHash
	})
	if d := domain.FindDivergence(matching); d != nil {
		return domain.CompositeRecord{}, false, d
	}
	composed, err := domain.Compose(matching)
	if err != nil {
		return domain.CompositeRecord{}, false, fmt.Errorf("composing records for %s: %w", coord, err)
	}
	return composed, true, nil
}

// recovering turns a panic into an error so AssertRefusesZeroIdentity reports a
// contract failure rather than a stack trace, on the same terms as
// putRecovering below.
func recovering(op func() error) (err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("panicked instead of refusing the zero artefact identity: %v", p)
		}
	}()
	return op()
}

// putRecovering turns a panic into an error so the assertion above reports a
// contract failure rather than a stack trace. An implementation that reaches its
// storage before checking the record panics here as readily as it corrupts
// anything else — the fakes, whose maps are nil until seeded, do exactly that —
// and "it panicked" is the same verdict as "it did not refuse", stated where the
// reader is looking.
func putRecovering(w RecordWriter) (err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("panicked instead of refusing the zero SealedRecord: %v", p)
		}
	}()
	// Returned undecorated: the assertion matches it with errors.Is and prints it
	// on failure, so a wrapper here would only put this helper's name in front of
	// the implementation's own answer.
	//nolint:wrapcheck // the caller inspects and reports this error verbatim
	return w.PutFetchRecord(context.Background(), domain.SealedRecord{})
}
