package sqlite_test

import (
	"context"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"
	domain2 "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/fetch/fetchtest"
)

// A re-measurement of one artefact is APPENDED, and a reader gets the
// composition of every measurement rather than whichever row happened to be
// written last.
//
// This is the property the whole change turns on. The store used to key on
// (path, version, pipeline) alone, so it recorded fifteen writes for
// github.com/CycloneDX/cyclonedx-go@v0.11.0 in its audit log while keeping one
// row — and the investigation into a verification demotion had no surviving
// evidence to read.
func TestLedger_ReMeasurementIsAppendedNotOverwritten(t *testing.T) {
	s := openMemStore(t)
	ctx := context.Background()
	coord := coordinate.ModuleCoordinate{Path: "example.com/mod", Version: "v1.0.0"}

	base := []fetchtest.Option{
		fetchtest.Coordinate(coord),
		fetchtest.PipelineVersion("0.4.0"),
		fetchtest.ModuleHash(fetchtest.H1("zip==")),
		fetchtest.GoModHash(fetchtest.H1("mod==")),
		fetchtest.Status(domain2.Verified),
	}
	for i, at := range []time.Time{
		time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC),
		time.Date(2026, 1, 3, 0, 0, 0, 0, time.UTC),
	} {
		opts := append(append([]fetchtest.Option{}, base...), fetchtest.FetchedAt(at))
		if err := s.PutFetchRecord(ctx, mustSeal(t, fetchtest.Record(t, opts...))); err != nil {
			t.Fatalf("append %d: %v", i+1, err)
		}
	}

	held, err := s.ListFetchRecords(ctx, coord, "0.4.0")
	if err != nil {
		t.Fatalf("ListFetchRecords: %v", err)
	}
	if len(held) != 3 {
		t.Fatalf("ledger holds %d measurements, want 3: re-measurements are overwriting", len(held))
	}

	got, ok, err := s.GetFetchRecord(ctx, coord, "0.4.0")
	if err != nil || !ok {
		t.Fatalf("GetFetchRecord: ok=%v err=%v", ok, err)
	}
	if got.MeasurementCount != 3 {
		t.Errorf("MeasurementCount = %d, want 3", got.MeasurementCount)
	}
	if !got.FirstFetchedAt.Equal(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("FirstFetchedAt = %v, want the earliest measurement", got.FirstFetchedAt)
	}
	if !got.LatestFetchedAt.Equal(time.Date(2026, 1, 3, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("LatestFetchedAt = %v, want the most recent measurement", got.LatestFetchedAt)
	}
}

// Two measurements taken within the same second are still two rows. fetched_at
// persists at second precision, so without a tiebreaker in the key the second
// would collide with the first and be lost — and losing a measurement is exactly
// what this ledger exists to stop.
func TestLedger_MeasurementsSharingAnInstantAreBothKept(t *testing.T) {
	s := openMemStore(t)
	ctx := context.Background()
	coord := coordinate.ModuleCoordinate{Path: "example.com/mod", Version: "v1.0.0"}
	at := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	for _, detail := range []string{"first measurement", "second measurement"} {
		r := fetchtest.Record(t,
			fetchtest.Coordinate(coord),
			fetchtest.PipelineVersion("0.4.0"),
			fetchtest.ModuleHash(fetchtest.H1("zip==")),
			fetchtest.Status(domain2.Verified),
			fetchtest.FetchedAt(at),
			fetchtest.Detail(detail),
		)
		if err := s.PutFetchRecord(ctx, mustSeal(t, r)); err != nil {
			t.Fatalf("append %q: %v", detail, err)
		}
	}

	held, err := s.ListFetchRecords(ctx, coord, "0.4.0")
	if err != nil {
		t.Fatalf("ListFetchRecords: %v", err)
	}
	if len(held) != 2 {
		t.Errorf("ledger holds %d measurements, want 2: a measurement was lost to a key collision", len(held))
	}
}

// A coordinate holding records that disagree on a hash they both carry is
// reported as a divergence rather than silently resolved: the store cannot
// arbitrate between two claims about one pinned version.
func TestLedger_DivergentRecordsFailTheRead(t *testing.T) {
	s := openMemStore(t)
	ctx := context.Background()
	coord := coordinate.ModuleCoordinate{Path: "example.com/mod", Version: "v1.0.0"}

	for i, hash := range []string{"zip-a==", "zip-b=="} {
		r := fetchtest.Record(t,
			fetchtest.Coordinate(coord),
			fetchtest.PipelineVersion("0.4.0"),
			fetchtest.ModuleHash(fetchtest.H1(hash)),
			fetchtest.Status(domain2.Verified),
			fetchtest.FetchedAt(time.Date(2026, 1, i+1, 0, 0, 0, 0, time.UTC)),
		)
		if err := s.PutFetchRecord(ctx, mustSeal(t, r)); err != nil {
			t.Fatalf("append %d: %v", i+1, err)
		}
	}

	_, ok, err := s.GetFetchRecord(ctx, coord, "0.4.0")
	if err == nil {
		t.Fatal("a coordinate described by two different artefacts read without error")
	}
	if ok {
		t.Error("a divergent coordinate was reported as found")
	}
	var divergence *domain2.Divergence
	if !asDivergence(err, &divergence) {
		t.Fatalf("error is not a Divergence, so a consuming command cannot fail closed on it: %v", err)
	}
	if divergence.Field != "module_hash" {
		t.Errorf("Field = %q, want module_hash", divergence.Field)
	}
}

// asDivergence is errors.As specialised to *domain2.Divergence, kept local so
// the test reads as the assertion it is.
func asDivergence(err error, target **domain2.Divergence) bool {
	d, ok := err.(*domain2.Divergence) //nolint:errorlint // the store returns it directly
	if ok {
		*target = d
	}
	return ok
}

// A go.mod-only record beside a full record for one coordinate is the ordinary
// upgrade path and must read cleanly.
func TestLedger_GoModOnlyBesideFullRecordReadsCleanly(t *testing.T) {
	s := openMemStore(t)
	ctx := context.Background()
	coord := coordinate.ModuleCoordinate{Path: "example.com/mod", Version: "v1.0.0"}

	shallow := fetchtest.Record(t,
		fetchtest.Coordinate(coord),
		fetchtest.PipelineVersion("0.4.0"),
		fetchtest.GoModOnly("gomod"),
		fetchtest.GoModHash(fetchtest.H1("mod==")),
		fetchtest.Status(domain2.VerifiedBySumDBOnly),
		fetchtest.FetchedAt(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)),
	)
	full := fetchtest.Record(t,
		fetchtest.Coordinate(coord),
		fetchtest.PipelineVersion("0.4.0"),
		fetchtest.ModuleHash(fetchtest.H1("zip==")),
		fetchtest.GoModHash(fetchtest.H1("mod==")),
		fetchtest.Status(domain2.Verified),
		fetchtest.FetchedAt(time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)),
	)
	for _, r := range []domain2.FactRecord{shallow, full} {
		if err := s.PutFetchRecord(ctx, mustSeal(t, r)); err != nil {
			t.Fatalf("append: %v", err)
		}
	}

	got, ok, err := s.GetFetchRecord(ctx, coord, "0.4.0")
	if err != nil {
		t.Fatalf("the upgrade path was reported as an integrity failure: %v", err)
	}
	if !ok {
		t.Fatal("GetFetchRecord found nothing")
	}
	// The full record is the stronger anchor, so it is what a reader is served.
	if got.IsGoModOnly() {
		t.Error("the shallower measurement was served over the full one")
	}
}

// A tampered row stops the LIST read too, rather than being quietly skipped:
// reporting a tampered store as a smaller one is the same silence in a
// different place.
func TestLedger_TamperedRowFailsTheListRead(t *testing.T) {
	s := openMemStore(t)
	ctx := context.Background()

	r := sampleRecord(t, "github.com/foo/bar", "v1.0.0", "0.1.0")
	if err := s.PutFetchRecord(ctx, mustSeal(t, r)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.InternalDB().DB().Exec(
		"UPDATE fetch_records SET verification_detail = 'rewritten in place'"); err != nil {
		t.Fatal(err)
	}

	if _, err := s.ListFetchRecords(ctx,
		coordinate.ModuleCoordinate{Path: r.ModulePath, Version: r.ModuleVersion}, r.PipelineVersion); err == nil {
		t.Error("a tampered row was listed without error")
	}
}

// The new fields are omitempty, so a record written before they existed produces
// byte-identical canonical JSON and still verifies its stored hash. Without
// this, every record in an existing store would fail its integrity check the
// moment the fields landed.
func TestLedger_PreFieldRecordsStillVerify(t *testing.T) {
	s := openMemStore(t)
	ctx := context.Background()

	// A record carrying none of the ledger's new fields, exactly as a pre-change
	// pipeline would have written it.
	r := sampleRecord(t, "github.com/foo/bar", "v1.0.0", "0.1.0")
	if r.MeasurementKind != "" || r.SumDBCheck != "" || r.VCSCheck != "" {
		t.Fatalf("fixture unexpectedly carries the new fields: %+v", r)
	}
	if err := s.PutFetchRecord(ctx, mustSeal(t, r)); err != nil {
		t.Fatalf("appending a pre-field record: %v", err)
	}
	if _, ok, err := s.GetFetchRecord(ctx,
		coordinate.ModuleCoordinate{Path: r.ModulePath, Version: r.ModuleVersion}, r.PipelineVersion); err != nil || !ok {
		t.Fatalf("a pre-field record did not survive a round trip: ok=%v err=%v", ok, err)
	}
}
