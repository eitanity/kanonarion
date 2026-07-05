package sqlite_test

import (
	"errors"
	"testing"
	"time"

	sbomstore "github.com/eitanity/kanonarion/internal/sbom/adapters/store/sqlite"
	"github.com/eitanity/kanonarion/internal/sbom/domain"
	"github.com/eitanity/kanonarion/internal/sbom/ports"
	"github.com/eitanity/kanonarion/internal/sqlitestore"
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

func makeRecord(id, walkID string, scanRunID *string) domain.SBOMRecord {
	return domain.SBOMRecord{
		ID:              id,
		Ecosystem:       domain.EcosystemGo,
		WalkID:          walkID,
		WalkScanRunID:   scanRunID,
		Format:          domain.CycloneDX15,
		Content:         []byte(`{"bomFormat":"CycloneDX"}`),
		ContentHash:     "abc123",
		GeneratedAt:     time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		PipelineVersion: "0.3.0",
		Operator:        "test",
	}
}

func TestPutAndGetSBOMRecord(t *testing.T) {
	s := openTestStore(t)
	rec := makeRecord("sbom-001", "walk-001", nil)

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
	if got.WalkScanRunID != nil {
		t.Errorf("WalkScanRunID: got %v, want nil", got.WalkScanRunID)
	}
	if got.ContentHash != rec.ContentHash {
		t.Errorf("ContentHash: got %q, want %q", got.ContentHash, rec.ContentHash)
	}
}

func TestSBOMRecord_EcosystemPresentAfterRoundTrip(t *testing.T) {
	s := openTestStore(t)
	rec := makeRecord("sbom-eco", "walk-eco", nil)
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
	rec := makeRecord("sbom-npm", "walk-npm", nil)
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
	rec := makeRecord("sbom-001", "walk-001", nil)

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
	scanRunID := "scan-001"
	recs := []domain.SBOMRecord{
		makeRecord("sbom-001", "walk-001", nil),
		makeRecord("sbom-002", "walk-001", &scanRunID),
		makeRecord("sbom-003", "walk-002", nil),
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

func TestFindSBOMRecordNilScanRun(t *testing.T) {
	s := openTestStore(t)
	rec := makeRecord("sbom-001", "walk-001", nil)
	if err := s.PutSBOMRecord(t.Context(), rec); err != nil {
		t.Fatalf("PutSBOMRecord: %v", err)
	}

	found, ok, err := s.FindSBOMRecord(t.Context(), "walk-001", nil, domain.CycloneDX15, "0.3.0")
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

func TestFindSBOMRecordWithScanRun(t *testing.T) {
	s := openTestStore(t)
	scanRunID := "scan-001"
	rec := makeRecord("sbom-002", "walk-001", &scanRunID)
	if err := s.PutSBOMRecord(t.Context(), rec); err != nil {
		t.Fatalf("PutSBOMRecord: %v", err)
	}

	found, ok, err := s.FindSBOMRecord(t.Context(), "walk-001", &scanRunID, domain.CycloneDX15, "0.3.0")
	if err != nil {
		t.Fatalf("FindSBOMRecord: %v", err)
	}
	if !ok {
		t.Fatal("expected record to be found")
	}
	if found.ID != "sbom-002" {
		t.Errorf("ID: got %q, want sbom-002", found.ID)
	}
}

func TestFindSBOMRecordMiss(t *testing.T) {
	s := openTestStore(t)

	_, ok, err := s.FindSBOMRecord(t.Context(), "walk-999", nil, domain.CycloneDX15, "0.3.0")
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
		makeRecord("sbom-001", "walk-001", nil),
		makeRecord("sbom-002", "walk-002", nil),
		makeRecord("sbom-003", "walk-003", nil),
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
	rec := makeRecord("sbom-empty-eco", "walk-1", nil)
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
	rec := makeRecord("sbom-incomplete", "walk-1", nil)
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
	db, err := sqlitestore.Open(":memory:", sbomstore.Migrations())
	if err != nil {
		t.Fatalf("sqlitestore.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	s := sbomstore.New(db)
	rec := makeRecord("sbom-raw", "walk-1", nil)
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
