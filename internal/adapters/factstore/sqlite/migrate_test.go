package sqlite_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"

	"github.com/eitanity/kanonarion/internal/adapters/factstore/sqlite"
)

func TestOpen_FileDB(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	s, err := sqlite.Open(dbPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() {
		if err := s.Close(); err != nil {
			t.Errorf("s.Close: %v", err)
		}
	}()

	// Verify the schema is usable.
	r := sampleRecord("github.com/test/pkg", "v1.0.0", "0.1.0")
	if err := s.PutFetchRecord(context.Background(), r); err != nil {
		t.Fatalf("PutFetchRecord: %v", err)
	}
}

func TestOpen_ReopenMigration(t *testing.T) {
	// Opening the same DB twice should not fail on the already-run migration.
	dbPath := filepath.Join(t.TempDir(), "reopen.db")
	s1, err := sqlite.Open(dbPath)
	if err != nil {
		t.Fatalf("first Open: %v", err)
	}
	if err := s1.Close(); err != nil {
		t.Fatalf("s1.Close: %v", err)
	}

	s2, err := sqlite.Open(dbPath)
	if err != nil {
		t.Fatalf("second Open: %v", err)
	}
	defer func() {
		if err := s2.Close(); err != nil {
			t.Errorf("s2.Close: %v", err)
		}
	}()

	// Should be functional.
	r := sampleRecord("example.com/x", "v1.0.0", "0.1.0")
	if err := s2.PutFetchRecord(context.Background(), r); err != nil {
		t.Fatalf("PutFetchRecord: %v", err)
	}
}

func TestGetFetchRecord_MultiplePipelineVersions(t *testing.T) {
	s := openMemStore(t)
	ctx := context.Background()

	r1 := sampleRecord("example.com/m", "v1.0.0", "0.1.0")
	r2 := sampleRecord("example.com/m", "v1.0.0", "0.2.0")
	// r2 has a different pipeline version so its content hash differs automatically.

	if err := s.PutFetchRecord(ctx, r1); err != nil {
		t.Fatal(err)
	}
	if err := s.PutFetchRecord(ctx, r2); err != nil {
		t.Fatal(err)
	}

	coord := coordinate.ModuleCoordinate{Path: "example.com/m", Version: "v1.0.0"}

	got1, ok1, _ := s.GetFetchRecord(ctx, coord, "0.1.0")
	got2, ok2, _ := s.GetFetchRecord(ctx, coord, "0.2.0")

	if !ok1 || !ok2 {
		t.Fatalf("expected both records; ok1=%v ok2=%v", ok1, ok2)
	}
	if got1.PipelineVersion != "0.1.0" || got2.PipelineVersion != "0.2.0" {
		t.Errorf("pipeline versions wrong: %q %q", got1.PipelineVersion, got2.PipelineVersion)
	}
}
