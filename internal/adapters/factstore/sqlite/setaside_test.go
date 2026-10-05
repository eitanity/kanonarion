package sqlite_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/adapters/factstore/sqlite"
	"github.com/eitanity/kanonarion/internal/adapters/recordseal"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	domain2 "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/fetch/fetchtest"
	"github.com/eitanity/kanonarion/internal/fetch/ports"
)

// respell rewrites r's row as a build spelling fetched_at differently would have
// stored it, resealed over that spelling, and returns the seal.
func respell(t *testing.T, s *sqlite.Store, r domain2.FactRecord) string {
	t.Helper()
	fetchedAt, seal := fetchtest.Respelt(t, r)
	res, err := s.InternalDB().DB().Exec(`UPDATE fetch_records SET fetched_at = ?, content_hash = ? WHERE content_hash = ?`,
		fetchedAt, seal, r.ContentHash)
	if err != nil {
		t.Fatalf("installing the respelt row: %v", err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		t.Fatalf("respelt %d rows, want 1", n)
	}
	return seal
}

// measurements holds two measurements of one artefact; the newer is the weaker.
func measurements(t *testing.T, s *sqlite.Store) (older, newer domain2.FactRecord) {
	t.Helper()
	at := time.Date(2026, 5, 6, 7, 8, 9, 0, time.UTC)
	older = sampleRecord(t, "github.com/foo/bar", "v1.0.0", "0.4.0", fetchtest.FetchedAt(at))
	newer = sampleRecord(t, "github.com/foo/bar", "v1.0.0", "0.4.0",
		fetchtest.FetchedAt(at.Add(time.Hour)), fetchtest.Status(domain2.VerifiedBySumDBOnly))
	for _, r := range []domain2.FactRecord{older, newer} {
		if err := s.PutFetchRecord(context.Background(), mustSeal(t, r)); err != nil {
			t.Fatalf("PutFetchRecord: %v", err)
		}
	}
	return older, newer
}

// A measurement this build cannot reproduce is set aside and named, and every
// read composes over the rest; with every measurement set aside each read is
// NothingServable naming them all. None of it is reported as a hash mismatch.
func TestFetchRecords_DriftedMeasurementSetAside(t *testing.T) {
	s := openMemStore(t)
	ctx := context.Background()
	var reported []recordseal.SetAsideRow
	s.ReportSetAside(func(rows []recordseal.SetAsideRow) { reported = append(reported, rows...) })
	older, newer := measurements(t, s)
	coord := coordinatetest.MustNew(older.ModulePath, older.ModuleVersion)

	seal := respell(t, s, newer)

	listed, err := s.ListFetchRecords(ctx, coord, "0.4.0")
	if err != nil || len(listed) != 1 || listed[0].ContentHash != older.ContentHash {
		t.Fatalf("ListFetchRecords = %d rows, %v; want only the readable measurement", len(listed), err)
	}
	got, ok, err := s.GetFetchRecord(ctx, coord, "0.4.0")
	if err != nil || !ok || got.ContentHash != older.ContentHash {
		t.Errorf("GetFetchRecord = %s, %v, %v; want the readable measurement", got.ContentHash, ok, err)
	}
	got, ok, err = s.ComposeFetchRecord(ctx, coord)
	if err != nil || !ok || got.ContentHash != older.ContentHash {
		t.Errorf("ComposeFetchRecord = %s, %v, %v; want the readable measurement", got.ContentHash, ok, err)
	}
	if len(reported) == 0 {
		t.Fatal("nothing reported")
	}
	for _, r := range reported {
		if r.Kind != sqlite.RecordKind || r.ID != coord.String() || r.ContentHash != seal ||
			r.Generation.PipelineVersion != "0.4.0" || !errors.Is(r.Reason, recordseal.ErrGenerationDrift) {
			t.Errorf("reported %+v, want the measurement named by %s", r, seal)
		}
	}

	respell(t, s, older)
	_, listErr := s.ListFetchRecords(ctx, coord, "0.4.0")
	_, _, getErr := s.GetFetchRecord(ctx, coord, "0.4.0")
	_, _, composeErr := s.ComposeFetchRecord(ctx, coord)
	for name, err := range map[string]error{"ListFetchRecords": listErr, "GetFetchRecord": getErr, "ComposeFetchRecord": composeErr} {
		var none *recordseal.NothingServable
		if !errors.As(err, &none) || len(none.Aside.Rows) != 2 || strings.Contains(err.Error(), "mismatch") {
			t.Errorf("every measurement set aside: %s = %v, want *recordseal.NothingServable naming both", name, err)
		}
	}
}

// The auditing decorator carries the reporter to the store it wraps.
func TestAuditingStore_ReportsSetAside(t *testing.T) {
	a := openAuditingStore(t)
	var reported []recordseal.SetAsideRow
	a.ReportSetAside(func(rows []recordseal.SetAsideRow) { reported = append(reported, rows...) })
	r := sampleRecord(t, "github.com/foo/bar", "v1.0.0", "0.4.0")
	if err := a.PutFetchRecord(context.Background(), mustSeal(t, r)); err != nil {
		t.Fatal(err)
	}
	fetchedAt, seal := fetchtest.Respelt(t, r)
	if _, err := a.InternalDB().DB().Exec(`UPDATE fetch_records SET fetched_at = ?, content_hash = ?`, fetchedAt, seal); err != nil {
		t.Fatal(err)
	}
	_, _, err := a.ComposeFetchRecord(context.Background(), coordinatetest.MustNew(r.ModulePath, r.ModuleVersion))
	if !errors.As(err, new(*recordseal.NothingServable)) || len(reported) != 1 || reported[0].ContentHash != seal {
		t.Errorf("ComposeFetchRecord = %v, reported %+v; want the measurement named through the decorator", err, reported)
	}
}

// Tamper control: a value altered after sealing, or fetched_at moved to another
// instant, hashes to nothing; the read fails as an integrity failure naming the
// hash mismatch, and nothing is set aside.
func TestFetchRecords_AlteredMeasurementStillFailsTheRead(t *testing.T) {
	for name, alter := range map[string]string{
		"value":   `UPDATE fetch_records SET verification_detail = 'rewritten in place' WHERE content_hash = ?`,
		"instant": `UPDATE fetch_records SET fetched_at = '2026-05-06T07:08:10.5Z' WHERE content_hash = ?`,
	} {
		t.Run(name, func(t *testing.T) {
			s := openMemStore(t)
			var reported []recordseal.SetAsideRow
			s.ReportSetAside(func(rows []recordseal.SetAsideRow) { reported = append(reported, rows...) })
			older, newer := measurements(t, s)
			if _, err := s.InternalDB().DB().Exec(alter, newer.ContentHash); err != nil {
				t.Fatal(err)
			}
			coord := coordinatetest.MustNew(older.ModulePath, older.ModuleVersion)
			_, _, err := s.GetFetchRecord(context.Background(), coord, "0.4.0")
			if err == nil || !strings.Contains(err.Error(), "rehydrating stored fetch record for "+coord.String()) ||
				!strings.Contains(err.Error(), "content hash mismatch") || !errors.Is(err, ports.ErrFetchRecordIntegrity) ||
				errors.As(err, new(*recordseal.SetAside)) {
				t.Errorf("GetFetchRecord = %v, want the integrity failure naming the hash mismatch", err)
			}
			if len(reported) != 0 {
				t.Errorf("an altered row was set aside: %+v", reported)
			}
		})
	}
}
