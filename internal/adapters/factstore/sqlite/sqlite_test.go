package sqlite_test

import (
	"context"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/adapters/factstore/sqlite"
	domain2 "github.com/eitanity/kanonarion/internal/fetch/domain"
)

func openMemStore(t *testing.T) *sqlite.Store {
	t.Helper()
	s, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Errorf("s.Close: %v", err)
		}
	})
	return s
}

func sampleRecord(path, version, pipelineVersion string) domain2.FactRecord {
	r := domain2.FactRecord{
		SchemaVersion:      domain2.SchemaVersion,
		ModulePath:         path,
		ModuleVersion:      version,
		PipelineVersion:    pipelineVersion,
		ModuleHash:         "h1:abc==",
		GoModHash:          "h1:def==",
		GitURL:             "https://github.com/foo/bar",
		GitRef:             "refs/tags/" + version,
		GitCommitHash:      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		VerificationStatus: "Verified",
		VerificationDetail: "",
		FetchedAt:          time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		ContentLocation:    "sha256:deadbeef",
	}
	var h domain2.CanonicalHasher
	r, _ = h.SetContentHash(r)
	return r
}

func TestPutGetFetchRecord(t *testing.T) {
	s := openMemStore(t)
	ctx := context.Background()

	r := sampleRecord("github.com/foo/bar", "v1.0.0", "0.1.0")
	if err := s.PutFetchRecord(ctx, r); err != nil {
		t.Fatalf("Put: %v", err)
	}

	got, ok, err := s.GetFetchRecord(ctx, domain2.ModuleCoordinate{Path: r.ModulePath, Version: r.ModuleVersion}, r.PipelineVersion)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !ok {
		t.Fatal("record not found")
	}
	if got.ModulePath != r.ModulePath || got.ModuleVersion != r.ModuleVersion {
		t.Errorf("got %+v, want path=%s ver=%s", got, r.ModulePath, r.ModuleVersion)
	}
	if got.FetchedAt != r.FetchedAt {
		t.Errorf("FetchedAt mismatch: %v vs %v", got.FetchedAt, r.FetchedAt)
	}
}

func TestGetFetchRecord_NotFound(t *testing.T) {
	s := openMemStore(t)
	ctx := context.Background()

	_, ok, err := s.GetFetchRecord(ctx, domain2.ModuleCoordinate{Path: "x", Version: "v1.0.0"}, "0.1.0")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if ok {
		t.Error("expected not found")
	}
}

func TestPutFetchRecord_Idempotent(t *testing.T) {
	s := openMemStore(t)
	ctx := context.Background()

	r := sampleRecord("github.com/foo/bar", "v1.0.0", "0.1.0")
	if err := s.PutFetchRecord(ctx, r); err != nil {
		t.Fatalf("first Put: %v", err)
	}

	// Update a field and recompute content hash for a valid second write.
	r.VerificationDetail = "updated"
	var h domain2.CanonicalHasher
	r, _ = h.SetContentHash(r)

	if err := s.PutFetchRecord(ctx, r); err != nil {
		t.Fatalf("second Put: %v", err)
	}

	got, ok, err := s.GetFetchRecord(ctx, domain2.ModuleCoordinate{Path: r.ModulePath, Version: r.ModuleVersion}, r.PipelineVersion)
	if err != nil || !ok {
		t.Fatalf("Get: err=%v ok=%v", err, ok)
	}
	if got.VerificationDetail != "updated" {
		t.Errorf("expected updated detail, got %q", got.VerificationDetail)
	}
	if got.ContentHash != r.ContentHash {
		t.Errorf("ContentHash mismatch: %q vs %q", got.ContentHash, r.ContentHash)
	}
}

func TestGetFetchRecord_IntegrityError(t *testing.T) {
	s := openMemStore(t)
	ctx := context.Background()

	r := sampleRecord("github.com/foo/bar", "v1.0.0", "0.1.0")
	if err := s.PutFetchRecord(ctx, r); err != nil {
		t.Fatal(err)
	}

	// Tamper with content_hash in DB
	db := s.InternalDB().DB()
	if _, err := db.Exec("UPDATE fetch_records SET content_hash = 'sha256:tampered'"); err != nil {
		t.Fatal(err)
	}

	_, ok, err := s.GetFetchRecord(ctx, domain2.ModuleCoordinate{Path: r.ModulePath, Version: r.ModuleVersion}, r.PipelineVersion)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Error("expected GetFetchRecord to return ok=false due to tampered hash")
	}
}

func TestGetFetchRecord_Retracted(t *testing.T) {
	s := openMemStore(t)
	ctx := context.Background()

	r := sampleRecord("github.com/foo/bar", "v1.0.0", "0.1.0")
	r.Retracted = true
	var h domain2.CanonicalHasher
	r, _ = h.SetContentHash(r)

	if err := s.PutFetchRecord(ctx, r); err != nil {
		t.Fatal(err)
	}

	got, ok, err := s.GetFetchRecord(ctx, domain2.ModuleCoordinate{Path: r.ModulePath, Version: r.ModuleVersion}, r.PipelineVersion)
	if err != nil || !ok {
		t.Fatalf("Get: err=%v ok=%v", err, ok)
	}
	if !got.Retracted {
		t.Error("expected Retracted=true")
	}
}
