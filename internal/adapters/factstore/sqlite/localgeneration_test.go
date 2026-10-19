package sqlite_test

import (
	"context"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	domain2 "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/fetch/fetchtest"
)

// A store holding a row read from a local directory under a published
// coordinate (written before local code had its own identity) still answers
// for the published module: both reads leave the row out, count it, and do not
// report the disagreement it would otherwise make.
func TestComposedRead_LeavesOutALocalGenerationUnderAPublishedCoordinate(t *testing.T) {
	s := openMemStore(t)
	ctx := context.Background()
	coord := coordinatetest.MustNew("github.com/foo/bar", "v1.6.0")

	published := sampleRecord(t, coord.Path(), coord.Version(), "0.5.0")
	local := sampleRecord(t, coord.Path(), coord.Version(), "local-0.1.0",
		fetchtest.Status(domain2.LocalSource), fetchtest.ModuleHash(fetchtest.H1("dir==")))
	for _, r := range []domain2.FactRecord{published, local} {
		if err := s.PutFetchRecord(ctx, mustSeal(t, r)); err != nil {
			t.Fatalf("Put: %v", err)
		}
	}

	got, ok, err := s.ComposeFetchRecord(ctx, coord)
	if err != nil || !ok {
		t.Fatalf("ComposeFetchRecord: ok=%v err=%v, want the published record", ok, err)
	}
	if got.ContentHash != published.ContentHash || got.MeasurementCount != 1 || got.SupersededLocalGenerations != 1 {
		t.Errorf("composed = %s (%d composed, %d superseded), want %s, 1 and 1",
			got.ContentHash, got.MeasurementCount, got.SupersededLocalGenerations, published.ContentHash)
	}

	if _, held, gerr := s.GetFetchRecord(ctx, coord, "local-0.1.0"); gerr != nil || held {
		t.Errorf("GetFetchRecord at the local generation = ok %v, err %v; want absent", held, gerr)
	}
	rows, err := s.ListFetchRecords(ctx, coord, "local-0.1.0")
	if err != nil || len(rows) != 1 {
		t.Errorf("ListFetchRecords = %d rows, err %v; the row stays in the ledger", len(rows), err)
	}
}

// The store names the directory's artefact as superseded under the published
// coordinate, and nothing for a coordinate with no local-source row.
func TestSupersededLocalArtefacts_FromTheLedger(t *testing.T) {
	s := openMemStore(t)
	ctx := context.Background()
	coord := coordinatetest.MustNew("github.com/foo/bar", "v1.6.0")
	other := coordinatetest.MustNew("github.com/foo/other", "v1.0.0")
	for _, r := range []domain2.FactRecord{
		sampleRecord(t, coord.Path(), coord.Version(), "0.5.0"),
		sampleRecord(t, coord.Path(), coord.Version(), "local-0.1.0",
			fetchtest.Status(domain2.LocalSource), fetchtest.ModuleHash(fetchtest.H1("dir=="))),
		sampleRecord(t, other.Path(), other.Version(), "0.5.0"),
	} {
		if err := s.PutFetchRecord(ctx, mustSeal(t, r)); err != nil {
			t.Fatalf("Put: %v", err)
		}
	}
	ids, err := s.SupersededLocalArtefacts(ctx, coord)
	if err != nil || len(ids) != 1 || !ids[fetchtest.ZipArtefact("dir==").String()] {
		t.Errorf("superseded = %v, %v; want the directory's artefact", ids, err)
	}
	if ids, err := s.SupersededLocalArtefacts(ctx, other); err != nil || len(ids) != 0 {
		t.Errorf("superseded = %v, %v for a coordinate with no local row", ids, err)
	}
}
