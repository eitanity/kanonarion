package sqlite_test

import (
	"context"
	"errors"
	"testing"
	"time"

	godebugstore "github.com/eitanity/kanonarion/internal/godebug/adapters/store/sqlite"
	"github.com/eitanity/kanonarion/internal/godebug/domain"
	"github.com/eitanity/kanonarion/internal/sqlitestore"
)

func openTestStore(t *testing.T) *godebugstore.Store {
	t.Helper()
	db, err := sqlitestore.Open(":memory:", godebugstore.Migrations())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return godebugstore.New(db)
}

func mkRecord(project string) domain.Record {
	settings := []domain.Setting{
		{Name: "tlsrsakex", Value: "1", Source: "go.mod", Line: 2,
			Tier: domain.TierRed, PolicyOutcome: "warn", PolicyBlocking: true},
	}
	domain.Sort(settings)
	return domain.Record{
		Ecosystem:         domain.EcosystemGo,
		ProjectModulePath: project,
		Settings:          settings,
		TaxonomyVersion:   domain.TaxonomyVersion(),
		ExtractedAt:       time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		SchemaVersion:     domain.GoDebugSchemaVersion,
		PipelineVersion:   domain.PipelineVersion,
		ContentHash:       "sha256:test",
	}
}

func TestGoDebugRecord_EcosystemPresentAfterRoundTrip(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	if err := store.PutGoDebugRecord(ctx, mkRecord("example.com/eco")); err != nil {
		t.Fatalf("PutGoDebugRecord: %v", err)
	}
	got, found, err := store.GetGoDebugRecord(ctx, "example.com/eco")
	if err != nil || !found {
		t.Fatalf("GetGoDebugRecord: err=%v found=%t", err, found)
	}
	if got.Ecosystem != domain.EcosystemGo {
		t.Errorf("Ecosystem after round-trip = %q, want %q", got.Ecosystem, domain.EcosystemGo)
	}
}

func TestGoDebugRecord_RejectsForeignEcosystem(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	rec := mkRecord("example.com/npm")
	rec.Ecosystem = "npm"
	if err := store.PutGoDebugRecord(ctx, rec); err != nil {
		t.Fatalf("PutGoDebugRecord: %v", err)
	}
	if _, _, err := store.GetGoDebugRecord(ctx, "example.com/npm"); !errors.Is(err, domain.ErrUnsupportedEcosystem) {
		t.Errorf("expected ErrUnsupportedEcosystem, got %v", err)
	}
}

// TestStore_PutAndGetRoundTrip: every field must survive a serialise/
// deserialise cycle through SQLite (mirroring the fips store test).
func TestStore_PutAndGetRoundTrip(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()

	rec := mkRecord("example.com/proj")
	if err := store.PutGoDebugRecord(ctx, rec); err != nil {
		t.Fatalf("PutGoDebugRecord: %v", err)
	}
	got, found, err := store.GetGoDebugRecord(ctx, "example.com/proj")
	if err != nil || !found {
		t.Fatalf("GetGoDebugRecord: err=%v found=%t", err, found)
	}
	if got.ContentHash != rec.ContentHash {
		t.Errorf("content hash differs: %q vs %q", got.ContentHash, rec.ContentHash)
	}
	if len(got.Settings) != len(rec.Settings) {
		t.Fatalf("settings count differs: %d vs %d", len(got.Settings), len(rec.Settings))
	}
	if got.Settings[0].Name != "tlsrsakex" {
		t.Errorf("setting name lost: %q", got.Settings[0].Name)
	}
}

// TestStore_PutIdempotent: re-putting under the same (project, fingerprint)
// replaces rather than duplicates.
func TestStore_PutIdempotent(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()

	rec := mkRecord("example.com/proj")
	if err := store.PutGoDebugRecord(ctx, rec); err != nil {
		t.Fatal(err)
	}
	rec.ContentHash = "sha256:updated"
	if err := store.PutGoDebugRecord(ctx, rec); err != nil {
		t.Fatal(err)
	}
	got, found, err := store.GetGoDebugRecord(ctx, "example.com/proj")
	if err != nil || !found {
		t.Fatalf("GetGoDebugRecord: %v %t", err, found)
	}
	if got.ContentHash != "sha256:updated" {
		t.Errorf("idempotent put did not overwrite: %q", got.ContentHash)
	}
}

// TestStore_GetMissingIsNotError: a project never scanned returns found=false
// with nil error — the "not analysed" state.
func TestStore_GetMissingIsNotError(t *testing.T) {
	store := openTestStore(t)
	_, found, err := store.GetGoDebugRecord(context.Background(), "example.com/never-scanned")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if found {
		t.Error("missing record must read found=false")
	}
}
