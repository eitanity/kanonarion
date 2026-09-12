package sqlite_test

import (
	"context"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	domain2 "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/fetch/fetchtest"
)

// fetch_records holds two generations of stamp: a whole second on measurements
// written before sub-second precision existed, and a fixed-width fraction after.
// The column is append-only evidence and is not rewritten, so both live in it.
//
// Read as TEXT the two invert inside a shared second: '.' is 0x2E and 'Z' is
// 0x5A, so "…07.500000000Z" sorts BEFORE "…07Z" while the instant it names is
// half a second AFTER it. The ledger's own sequence then comes back reversed,
// on a surface whose order is part of its meaning.
//
// The fixture constructs the straddle a binary upgrade produces: a legacy row
// and a modern row inside one second. Its seal is untouched — the whole-second
// row is exactly what the earlier writer produced for that record, so it still
// verifies, which is the reason the column is not rewritten in the first place.
func TestMixedPrecision_LedgerReadsInTrueOrder(t *testing.T) {
	s := openMemStore(t)
	ctx := context.Background()
	coord := coordinatetest.MustNew("example.com/mod", "v1.0.0")
	const pipeline = "0.4.0"

	second := time.Date(2026, 5, 6, 7, 8, 9, 0, time.UTC)
	legacy := fetchtest.Record(t,
		fetchtest.Coordinate(coord),
		fetchtest.PipelineVersion(pipeline),
		fetchtest.ModuleHash(fetchtest.H1("legacy==")),
		fetchtest.GoModHash(fetchtest.H1("mod==")),
		fetchtest.Status(domain2.Verified),
		fetchtest.FetchedAt(second),
	)
	modern := fetchtest.Record(t,
		fetchtest.Coordinate(coord),
		fetchtest.PipelineVersion(pipeline),
		fetchtest.ModuleHash(fetchtest.H1("modern==")),
		fetchtest.GoModHash(fetchtest.H1("mod==")),
		fetchtest.Status(domain2.Verified),
		fetchtest.FetchedAt(second.Add(500*time.Millisecond)),
	)
	for _, r := range []domain2.FactRecord{legacy, modern} {
		if err := s.PutFetchRecord(ctx, mustSeal(t, r)); err != nil {
			t.Fatalf("PutFetchRecord: %v", err)
		}
	}

	// Age the first row's column into the encoding the earlier writer used. The
	// blob is untouched, so this is the row that writer would have left.
	const legacyStamp = "2026-05-06T07:08:09Z"
	res, err := s.InternalDB().DB().ExecContext(ctx,
		`UPDATE fetch_records SET fetched_at = ? WHERE content_hash = ?`,
		legacyStamp, legacy.ContentHash)
	if err != nil {
		t.Fatalf("ageing the legacy row: %v", err)
	}
	if n, aerr := res.RowsAffected(); aerr != nil || n != 1 {
		t.Fatalf("aged %d rows (err %v), want 1: the fixture is not the subject it claims", n, aerr)
	}

	// The fixture must actually invert as text, or the test proves nothing.
	modernStamp := second.Add(500 * time.Millisecond).UTC().Format(domain2.CanonicalTimeFormat)
	if modernStamp >= legacyStamp {
		t.Fatalf("the fixture does not invert: %q does not sort before %q", modernStamp, legacyStamp)
	}

	held, err := s.ListFetchRecords(ctx, coord, pipeline)
	if err != nil {
		t.Fatalf("ListFetchRecords: %v", err)
	}
	if len(held) != 2 {
		t.Fatalf("ledger holds %d measurements, want 2", len(held))
	}
	if !held[0].FetchedAt.Equal(second) {
		t.Errorf("first measurement is at %v, want %v: the ledger came back out of its own order",
			held[0].FetchedAt, second)
	}
	if !held[1].FetchedAt.Equal(second.Add(500 * time.Millisecond)) {
		t.Errorf("second measurement is at %v, want %v", held[1].FetchedAt, second.Add(500*time.Millisecond))
	}
}

// Within one second at one precision the ledger falls to append order, because
// that is the only sequence an append-only table actually has.
func TestMixedPrecision_TiedStampsReadInAppendOrder(t *testing.T) {
	s := openMemStore(t)
	ctx := context.Background()
	coord := coordinatetest.MustNew("example.com/mod", "v1.0.0")
	const pipeline = "0.4.0"
	at := time.Date(2026, 5, 6, 7, 8, 9, 123456789, time.UTC)

	hashes := []string{"first==", "second=="}
	for _, h := range hashes {
		r := fetchtest.Record(t,
			fetchtest.Coordinate(coord),
			fetchtest.PipelineVersion(pipeline),
			fetchtest.ModuleHash(fetchtest.H1(h)),
			fetchtest.GoModHash(fetchtest.H1("mod==")),
			fetchtest.Status(domain2.Verified),
			fetchtest.FetchedAt(at),
		)
		if err := s.PutFetchRecord(ctx, mustSeal(t, r)); err != nil {
			t.Fatalf("PutFetchRecord: %v", err)
		}
	}

	held, err := s.ListFetchRecords(ctx, coord, pipeline)
	if err != nil {
		t.Fatalf("ListFetchRecords: %v", err)
	}
	if len(held) != 2 {
		t.Fatalf("ledger holds %d measurements, want 2", len(held))
	}
	for i, want := range hashes {
		if got := held[i].ModuleHash; got != fetchtest.H1(want).String() {
			t.Errorf("measurement %d is %q, want %q: the tie did not fall to append order", i, got, fetchtest.H1(want))
		}
	}
}
