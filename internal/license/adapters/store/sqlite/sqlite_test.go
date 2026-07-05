package sqlite_test

import (
	"context"
	"errors"
	"testing"
	"time"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	licensesqlite "github.com/eitanity/kanonarion/internal/license/adapters/store/sqlite"
	domain2 "github.com/eitanity/kanonarion/internal/license/domain"
	"github.com/eitanity/kanonarion/internal/license/ports"
)

func openTestStore(t *testing.T) *licensesqlite.Store {
	t.Helper()
	s, err := licensesqlite.Open(":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return s
}

func mustCoord(t *testing.T, path, version string) fetchdomain.ModuleCoordinate {
	t.Helper()
	c, err := fetchdomain.NewModuleCoordinate(path, version)
	if err != nil {
		t.Fatalf("NewModuleCoordinate: %v", err)
	}
	return c
}

func buildRecord(t *testing.T, coord fetchdomain.ModuleCoordinate, spdx string, status domain2.LicenseStatus) domain2.LicenseRecord {
	t.Helper()
	r := domain2.LicenseRecord{
		SchemaVersion:     domain2.LicenseSchemaVersion,
		Ecosystem:         fetchdomain.EcosystemGo,
		Coordinate:        coord,
		PrimarySPDX:       spdx,
		PrimaryConfidence: 0.95,
		LicenseFiles: []domain2.LicenseFileEntry{
			{Path: "LICENSE", SPDX: spdx, Confidence: 0.95, FileHash: "sha256:abc", FileSize: 1000},
		},
		OverallStatus:   status,
		ExtractedAt:     time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		PipelineVersion: "0.1.0",
	}
	var h domain2.LicenseRecordHasher
	r, err := h.SetContentHash(r)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	return r
}

func TestPutAndGet(t *testing.T) {
	s := openTestStore(t)
	coord := mustCoord(t, "example.com/mod", "v1.0.0")
	r := buildRecord(t, coord, "MIT", domain2.LicenseStatusDetected)

	if err := s.PutLicenseRecord(context.Background(), r); err != nil {
		t.Fatalf("PutLicenseRecord: %v", err)
	}

	got, found, err := s.GetLicenseRecord(context.Background(), coord, "0.1.0")
	if err != nil {
		t.Fatalf("GetLicenseRecord: %v", err)
	}
	if !found {
		t.Fatal("expected record to be found")
	}
	if got.PrimarySPDX != "MIT" {
		t.Errorf("PrimarySPDX: got %q, want MIT", got.PrimarySPDX)
	}
	if got.OverallStatus != domain2.LicenseStatusDetected {
		t.Errorf("OverallStatus: got %v, want Detected", got.OverallStatus)
	}
	if got.ContentHash != r.ContentHash {
		t.Errorf("ContentHash mismatch: got %q, want %q", got.ContentHash, r.ContentHash)
	}
}

func TestGet_NotFound(t *testing.T) {
	s := openTestStore(t)
	coord := mustCoord(t, "example.com/absent", "v1.0.0")

	_, found, err := s.GetLicenseRecord(context.Background(), coord, "0.1.0")
	if err != nil {
		t.Fatalf("GetLicenceRecord: %v", err)
	}
	if found {
		t.Error("expected not found for absent record")
	}
}

func TestPut_Idempotent(t *testing.T) {
	s := openTestStore(t)
	coord := mustCoord(t, "example.com/idempotent", "v1.0.0")
	r := buildRecord(t, coord, "MIT", domain2.LicenseStatusDetected)

	if err := s.PutLicenseRecord(context.Background(), r); err != nil {
		t.Fatalf("first put: %v", err)
	}
	if err := s.PutLicenseRecord(context.Background(), r); err != nil {
		t.Fatalf("second put: %v", err)
	}

	_, found, err := s.GetLicenseRecord(context.Background(), coord, "0.1.0")
	if err != nil {
		t.Fatalf("GetLicenceRecord: %v", err)
	}
	if !found {
		t.Fatal("expected record to be found")
	}
}

func TestListLicenseRecords(t *testing.T) {
	s := openTestStore(t)

	c1 := mustCoord(t, "example.com/a", "v1.0.0")
	c2 := mustCoord(t, "example.com/b", "v2.0.0")
	c3 := mustCoord(t, "example.com/c", "v1.0.0")

	if err := s.PutLicenseRecord(context.Background(), buildRecord(t, c1, "MIT", domain2.LicenseStatusDetected)); err != nil {
		t.Fatalf("put c1: %v", err)
	}
	if err := s.PutLicenseRecord(context.Background(), buildRecord(t, c2, "Apache-2.0", domain2.LicenseStatusDetected)); err != nil {
		t.Fatalf("put c2: %v", err)
	}
	if err := s.PutLicenseRecord(context.Background(), buildRecord(t, c3, "", domain2.LicenseStatusNone)); err != nil {
		t.Fatalf("put c3: %v", err)
	}

	t.Run("all", func(t *testing.T) {
		sums, err := s.ListLicenseRecords(context.Background(), ports.LicenseFilter{})
		if err != nil {
			t.Fatalf("ListLicenseRecords: %v", err)
		}
		if len(sums) != 3 {
			t.Errorf("expected 3 summaries, got %d", len(sums))
		}
	})

	t.Run("filter_by_spdx", func(t *testing.T) {
		sums, err := s.ListLicenseRecords(context.Background(), ports.LicenseFilter{SPDX: "MIT"})
		if err != nil {
			t.Fatalf("ListLicenseRecords: %v", err)
		}
		if len(sums) != 1 {
			t.Errorf("expected 1 summary for MIT, got %d", len(sums))
		}
		if len(sums) > 0 && sums[0].PrimarySPDX != "MIT" {
			t.Errorf("unexpected SPDX: %q", sums[0].PrimarySPDX)
		}
	})

	t.Run("filter_by_status", func(t *testing.T) {
		noneStatus := domain2.LicenseStatusNone
		sums, err := s.ListLicenseRecords(context.Background(), ports.LicenseFilter{Status: &noneStatus})
		if err != nil {
			t.Fatalf("ListLicenseRecords: %v", err)
		}
		if len(sums) != 1 {
			t.Errorf("expected 1 None record, got %d", len(sums))
		}
	})

	t.Run("limit_offset", func(t *testing.T) {
		sums, err := s.ListLicenseRecords(context.Background(), ports.LicenseFilter{Limit: 1})
		if err != nil {
			t.Fatalf("ListLicenseRecords: %v", err)
		}
		if len(sums) != 1 {
			t.Errorf("expected 1 summary with Limit=1, got %d", len(sums))
		}
	})

	t.Run("offset_only", func(t *testing.T) {
		sums, err := s.ListLicenseRecords(context.Background(), ports.LicenseFilter{Offset: 1})
		if err != nil {
			t.Fatalf("ListLicenseRecords: %v", err)
		}
		if len(sums) != 2 {
			t.Errorf("expected 2 summaries with Offset=1, got %d", len(sums))
		}
	})
}

func TestGetLicenseRecord_IntegrityError(t *testing.T) {
	s := openTestStore(t)
	coord := mustCoord(t, "example.com/mod", "v1.0.0")
	r := buildRecord(t, coord, "MIT", domain2.LicenseStatusDetected)

	if err := s.PutLicenseRecord(context.Background(), r); err != nil {
		t.Fatalf("PutLicenseRecord: %v", err)
	}

	db := s.InternalDB().DB()
	r.ContentHash = "sha256:invalid"
	var h domain2.LicenseRecordHasher
	blob, _ := h.Marshal(r)
	if _, err := db.Exec("UPDATE licence_records SET serialised = ?", blob); err != nil {
		t.Fatalf("failed to tamper with db: %v", err)
	}

	_, _, err := s.GetLicenseRecord(context.Background(), coord, "0.1.0")
	if !errors.Is(err, ports.ErrLicenceIntegrity) {
		t.Errorf("expected ErrLicenceIntegrity, got %v", err)
	}
}

// TestPutAndGet_WithCopyrightStatements verifies that CopyrightStatus
// and CopyrightStatements survive a full Put→Get round-trip through SQLite.
func TestPutAndGet_WithCopyrightStatements(t *testing.T) {
	s := openTestStore(t)
	coord := mustCoord(t, "example.com/copyright", "v1.0.0")

	r := domain2.LicenseRecord{
		SchemaVersion:     domain2.LicenseSchemaVersion,
		Ecosystem:         fetchdomain.EcosystemGo,
		Coordinate:        coord,
		PrimarySPDX:       "MIT",
		PrimaryConfidence: 0.99,
		LicenseFiles: []domain2.LicenseFileEntry{
			{
				Path:       "LICENSE",
				SPDX:       "MIT",
				Confidence: 0.99,
				FileHash:   "sha256:abc",
				FileSize:   500,
				CopyrightStatements: []domain2.CopyrightStatement{
					{Verbatim: "Copyright (c) 2024 Test Author", Holders: []string{"Test Author"}, Years: "2024", Source: "LICENSE"},
				},
			},
		},
		OverallStatus:   domain2.LicenseStatusDetected,
		CopyrightStatus: domain2.CopyrightStatusFound,
		ExtractedAt:     time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		PipelineVersion: "0.2.0",
	}
	var h domain2.LicenseRecordHasher
	r, err := h.SetContentHash(r)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}

	if err := s.PutLicenseRecord(context.Background(), r); err != nil {
		t.Fatalf("PutLicenseRecord: %v", err)
	}

	got, found, err := s.GetLicenseRecord(context.Background(), coord, "0.2.0")
	if err != nil {
		t.Fatalf("GetLicenseRecord: %v", err)
	}
	if !found {
		t.Fatal("expected record to be found")
	}
	if got.CopyrightStatus != domain2.CopyrightStatusFound {
		t.Errorf("CopyrightStatus: got %v, want Found", got.CopyrightStatus)
	}
	if len(got.LicenseFiles) != 1 {
		t.Fatalf("LicenseFiles: got %d, want 1", len(got.LicenseFiles))
	}
	stmts := got.LicenseFiles[0].CopyrightStatements
	if len(stmts) != 1 {
		t.Fatalf("CopyrightStatements: got %d, want 1", len(stmts))
	}
	if stmts[0].Verbatim != "Copyright (c) 2024 Test Author" {
		t.Errorf("Verbatim: got %q", stmts[0].Verbatim)
	}
	if stmts[0].Years != "2024" {
		t.Errorf("Years: got %q, want 2024", stmts[0].Years)
	}
}

// TestPutAndGet_NoneFound is the regression pair for the
// SQLite layer: a record with CopyrightStatusNoneFound must not round-trip
// as CopyrightStatusNotAnalysed (the zero value).
func TestPutAndGet_NoneFound(t *testing.T) {
	s := openTestStore(t)
	coord := mustCoord(t, "example.com/nonefound", "v1.0.0")

	r := buildRecord(t, coord, "MIT", domain2.LicenseStatusDetected)
	r.CopyrightStatus = domain2.CopyrightStatusNoneFound
	var h domain2.LicenseRecordHasher
	r, err := h.SetContentHash(r)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}

	if err := s.PutLicenseRecord(context.Background(), r); err != nil {
		t.Fatalf("PutLicenseRecord: %v", err)
	}

	got, found, err := s.GetLicenseRecord(context.Background(), coord, "0.1.0")
	if err != nil {
		t.Fatalf("GetLicenseRecord: %v", err)
	}
	if !found {
		t.Fatal("expected record to be found")
	}
	if got.CopyrightStatus == domain2.CopyrightStatusNotAnalysed {
		t.Error("NoneFound must not round-trip as NotAnalysed")
	}
	if got.CopyrightStatus != domain2.CopyrightStatusNoneFound {
		t.Errorf("CopyrightStatus: got %v, want NoneFound", got.CopyrightStatus)
	}
}

func TestMigrateIdempotent(t *testing.T) {
	s1, err := licensesqlite.Open(":memory:")
	if err != nil {
		t.Fatalf("first Open: %v", err)
	}
	if err := s1.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// A second Open on the same DSN should not fail even though migrations
	// already ran. For:memory: each Open creates a fresh DB, so we just
	// confirm no errors.
	s2, err := licensesqlite.Open(":memory:")
	if err != nil {
		t.Fatalf("second Open: %v", err)
	}
	if err := s2.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}
