package sqlite_test

import (
	"errors"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/adapters/sqlitestore"
	sbomstore "github.com/eitanity/kanonarion/internal/sbom/adapters/store/sqlite"
	"github.com/eitanity/kanonarion/internal/sbom/domain"
	"github.com/eitanity/kanonarion/internal/sbom/ports"
)

func openTestStore(t *testing.T) *sbomstore.Store {
	t.Helper()
	s, err := sbomstore.Open(":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func makeRecord(id, walkID string) domain.SBOMRecord {
	return domain.SBOMRecord{
		ID:              id,
		Ecosystem:       domain.EcosystemGo,
		WalkID:          walkID,
		Format:          domain.CycloneDX16,
		Content:         []byte(`{"bomFormat":"CycloneDX"}`),
		ContentHash:     "abc123",
		GeneratedAt:     time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		PipelineVersion: "0.3.0",
		Operator:        "test",
	}
}

func TestPutAndGetSBOMRecord(t *testing.T) {
	s := openTestStore(t)
	rec := makeRecord("sbom-001", "walk-001")

	if err := s.PutSBOMRecord(t.Context(), rec); err != nil {
		t.Fatalf("PutSBOMRecord: %v", err)
	}

	got, err := s.GetSBOMRecord(t.Context(), "sbom-001")
	if err != nil {
		t.Fatalf("GetSBOMRecord: %v", err)
	}
	if got.ID != rec.ID {
		t.Errorf("ID: got %q, want %q", got.ID, rec.ID)
	}
	if got.WalkID != rec.WalkID {
		t.Errorf("WalkID: got %q, want %q", got.WalkID, rec.WalkID)
	}
	if got.ContentHash != rec.ContentHash {
		t.Errorf("ContentHash: got %q, want %q", got.ContentHash, rec.ContentHash)
	}
}

func TestSBOMRecord_EcosystemPresentAfterRoundTrip(t *testing.T) {
	s := openTestStore(t)
	rec := makeRecord("sbom-eco", "walk-eco")
	if err := s.PutSBOMRecord(t.Context(), rec); err != nil {
		t.Fatalf("PutSBOMRecord: %v", err)
	}
	got, err := s.GetSBOMRecord(t.Context(), "sbom-eco")
	if err != nil {
		t.Fatalf("GetSBOMRecord: %v", err)
	}
	if got.Ecosystem != domain.EcosystemGo {
		t.Errorf("Ecosystem after round-trip = %q, want %q", got.Ecosystem, domain.EcosystemGo)
	}
}

func TestSBOMRecord_RejectsForeignEcosystem(t *testing.T) {
	s := openTestStore(t)
	rec := makeRecord("sbom-npm", "walk-npm")
	rec.Ecosystem = "npm"
	if err := s.PutSBOMRecord(t.Context(), rec); err != nil {
		t.Fatalf("PutSBOMRecord: %v", err)
	}
	if _, err := s.GetSBOMRecord(t.Context(), "sbom-npm"); !errors.Is(err, domain.ErrUnsupportedEcosystem) {
		t.Errorf("expected ErrUnsupportedEcosystem, got %v", err)
	}
}

func TestGetSBOMRecordNotFound(t *testing.T) {
	s := openTestStore(t)
	_, err := s.GetSBOMRecord(t.Context(), "nonexistent")
	if !errors.Is(err, ports.ErrSBOMNotFound) {
		t.Errorf("expected ErrSBOMNotFound, got %v", err)
	}
}

func TestPutSBOMRecordIdempotent(t *testing.T) {
	s := openTestStore(t)
	rec := makeRecord("sbom-001", "walk-001")

	if err := s.PutSBOMRecord(t.Context(), rec); err != nil {
		t.Fatalf("first PutSBOMRecord: %v", err)
	}
	rec.ContentHash = "updated-hash"
	if err := s.PutSBOMRecord(t.Context(), rec); err != nil {
		t.Fatalf("second PutSBOMRecord: %v", err)
	}

	got, err := s.GetSBOMRecord(t.Context(), "sbom-001")
	if err != nil {
		t.Fatalf("GetSBOMRecord: %v", err)
	}
	if got.ContentHash != "updated-hash" {
		t.Errorf("ContentHash: got %q, want updated-hash", got.ContentHash)
	}
}

func TestListSBOMRecords(t *testing.T) {
	s := openTestStore(t)
	recs := []domain.SBOMRecord{
		makeRecord("sbom-001", "walk-001"),
		makeRecord("sbom-002", "walk-001"),
		makeRecord("sbom-003", "walk-002"),
	}
	for _, r := range recs {
		if err := s.PutSBOMRecord(t.Context(), r); err != nil {
			t.Fatalf("PutSBOMRecord %q: %v", r.ID, err)
		}
	}

	list, err := s.ListSBOMRecords(t.Context(), "walk-001")
	if err != nil {
		t.Fatalf("ListSBOMRecords: %v", err)
	}
	if len(list) != 2 {
		t.Errorf("expected 2 records for walk-001, got %d", len(list))
	}
}

func TestFindSBOMRecordByWalk(t *testing.T) {
	s := openTestStore(t)
	rec := makeRecord("sbom-001", "walk-001")
	if err := s.PutSBOMRecord(t.Context(), rec); err != nil {
		t.Fatalf("PutSBOMRecord: %v", err)
	}

	found, ok, err := s.FindSBOMRecord(t.Context(), "walk-001", domain.CycloneDX16, "0.3.0")
	if err != nil {
		t.Fatalf("FindSBOMRecord: %v", err)
	}
	if !ok {
		t.Fatal("expected record to be found")
	}
	if found.ID != "sbom-001" {
		t.Errorf("ID: got %q, want sbom-001", found.ID)
	}
}

func TestFindSBOMRecordMiss(t *testing.T) {
	s := openTestStore(t)

	_, ok, err := s.FindSBOMRecord(t.Context(), "walk-999", domain.CycloneDX16, "0.3.0")
	if err != nil {
		t.Fatalf("FindSBOMRecord: %v", err)
	}
	if ok {
		t.Error("expected cache miss, got hit")
	}
}

// ListSBOMRecords with an empty walk ID returns every record across all walks.
func TestListSBOMRecordsAllWalks(t *testing.T) {
	s := openTestStore(t)
	for _, r := range []domain.SBOMRecord{
		makeRecord("sbom-001", "walk-001"),
		makeRecord("sbom-002", "walk-002"),
		makeRecord("sbom-003", "walk-003"),
	} {
		if err := s.PutSBOMRecord(t.Context(), r); err != nil {
			t.Fatalf("PutSBOMRecord %q: %v", r.ID, err)
		}
	}
	list, err := s.ListSBOMRecords(t.Context(), "")
	if err != nil {
		t.Fatalf("ListSBOMRecords(\"\"): %v", err)
	}
	if len(list) != 3 {
		t.Errorf("expected 3 records across all walks, got %d", len(list))
	}
}

// A record persisted with no ecosystem set backfills to the Go default rather
// than being rejected on read.
func TestPutSBOMRecordDefaultsEmptyEcosystem(t *testing.T) {
	s := openTestStore(t)
	rec := makeRecord("sbom-empty-eco", "walk-1")
	rec.Ecosystem = ""
	if err := s.PutSBOMRecord(t.Context(), rec); err != nil {
		t.Fatalf("PutSBOMRecord: %v", err)
	}
	got, err := s.GetSBOMRecord(t.Context(), "sbom-empty-eco")
	if err != nil {
		t.Fatalf("GetSBOMRecord: %v", err)
	}
	if got.Ecosystem != domain.EcosystemGo {
		t.Errorf("empty ecosystem must default to %q, got %q", domain.EcosystemGo, got.Ecosystem)
	}
}

// An incomplete-licence flag round-trips through the store.
func TestPutSBOMRecordLicensesIncompleteRoundTrip(t *testing.T) {
	s := openTestStore(t)
	rec := makeRecord("sbom-incomplete", "walk-1")
	rec.LicensesIncomplete = true
	if err := s.PutSBOMRecord(t.Context(), rec); err != nil {
		t.Fatalf("PutSBOMRecord: %v", err)
	}
	got, err := s.GetSBOMRecord(t.Context(), "sbom-incomplete")
	if err != nil {
		t.Fatalf("GetSBOMRecord: %v", err)
	}
	if !got.LicensesIncomplete {
		t.Error("LicensesIncomplete must round-trip as true")
	}
}

// New wires a raw database handle into a usable store.
func TestNewWrapsRawHandle(t *testing.T) {
	db, err := sqlitestore.Open(":memory:", sbomstore.Migrations(), sqlitestore.IntentCreate)
	if err != nil {
		t.Fatalf("sqlitestore.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	s := sbomstore.New(db)
	rec := makeRecord("sbom-raw", "walk-1")
	if err := s.PutSBOMRecord(t.Context(), rec); err != nil {
		t.Fatalf("PutSBOMRecord via New: %v", err)
	}
	if _, err := s.GetSBOMRecord(t.Context(), "sbom-raw"); err != nil {
		t.Fatalf("GetSBOMRecord via New: %v", err)
	}
}

// Open surfaces an error when the database cannot be created at the DSN.
func TestOpenInvalidDSN(t *testing.T) {
	if _, err := sbomstore.Open("/no-such-dir/does/not/exist.db"); err == nil {
		t.Fatal("expected an error opening a store at an unwritable path")
	}
}

// Two documents stamped at ONE instant must list in a fixed order, and it must
// be append order: the one produced later comes first, which is what "most
// recent first" already meant.
//
// The tie is not contrived. A document generated with no --generated-at is
// stamped with the newest licence extraction time among its inputs, so two
// documents built over one licence basis carry the same instant by construction.
// Before the tiebreak this listing returned whichever order the store felt like,
// and a golden recorded over it would have frozen an accident.
//
// Ten repetitions, not two: an undefined order can agree with itself by luck
// across a couple of reads on one connection.
func TestListSBOMRecords_TiedTimestampsOrderByAppend(t *testing.T) {
	s := openTestStore(t)
	tied := time.Date(2026, 2, 17, 8, 15, 0, 0, time.UTC)

	first := makeRecord("sbom-tie-first", "walk-A")
	first.GeneratedAt = tied
	second := makeRecord("sbom-tie-second", "walk-B")
	second.GeneratedAt = tied

	for _, rec := range []domain.SBOMRecord{first, second} {
		if err := s.PutSBOMRecord(t.Context(), rec); err != nil {
			t.Fatalf("PutSBOMRecord %s: %v", rec.ID, err)
		}
	}

	for i := range 10 {
		got, err := s.ListSBOMRecords(t.Context(), "")
		if err != nil {
			t.Fatalf("ListSBOMRecords (read %d): %v", i+1, err)
		}
		if len(got) != 2 {
			t.Fatalf("read %d: want 2 records, got %d", i+1, len(got))
		}
		if got[0].ID != second.ID || got[1].ID != first.ID {
			t.Fatalf("read %d: want the later append first (%s, %s), got (%s, %s)",
				i+1, second.ID, first.ID, got[0].ID, got[1].ID)
		}
	}
}

// The CONTROL for the tie above: where the instants differ, the timestamp still
// decides and append order never overrides it. Without this a tiebreak that had
// swallowed the primary key would pass the test above and be wrong.
func TestListSBOMRecords_DistinctTimestampsStayNewestFirst(t *testing.T) {
	s := openTestStore(t)

	// Appended in the order that makes append order DISAGREE with recency: the
	// older document is written last, so a listing that ignored generated_at
	// would put it first.
	newer := makeRecord("sbom-newer", "walk-A")
	newer.GeneratedAt = time.Date(2026, 2, 17, 8, 15, 0, 0, time.UTC)
	older := makeRecord("sbom-older", "walk-B")
	older.GeneratedAt = time.Date(2026, 2, 3, 11, 30, 0, 0, time.UTC)

	for _, rec := range []domain.SBOMRecord{newer, older} {
		if err := s.PutSBOMRecord(t.Context(), rec); err != nil {
			t.Fatalf("PutSBOMRecord %s: %v", rec.ID, err)
		}
	}

	got, err := s.ListSBOMRecords(t.Context(), "")
	if err != nil {
		t.Fatalf("ListSBOMRecords: %v", err)
	}
	if len(got) != 2 || got[0].ID != newer.ID || got[1].ID != older.ID {
		t.Fatalf("want newest first (%s, %s), got %v", newer.ID, older.ID, idsOf(got))
	}
}

func idsOf(records []domain.SBOMRecord) []string {
	out := make([]string, len(records))
	for i, r := range records {
		out[i] = r.ID
	}
	return out
}
