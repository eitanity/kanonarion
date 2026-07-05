package sqlite_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/sqlitestore"
	vendorstore "github.com/eitanity/kanonarion/internal/vendortree/adapters/store/sqlite"
	"github.com/eitanity/kanonarion/internal/vendortree/domain"
)

func openTestStore(t *testing.T) *vendorstore.Store {
	t.Helper()
	db, err := sqlitestore.Open(":memory:", vendorstore.Migrations())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return vendorstore.New(db)
}

func mkRecord(project string) domain.Record {
	return domain.Record{
		Ecosystem:         domain.EcosystemGo,
		ProjectModulePath: project,
		VendorDir:         "vendor",
		OverallStatus:     "clean",
		ExtractedAt:       time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		SchemaVersion:     domain.VendorSchemaVersion,
		PipelineVersion:   domain.PipelineVersion,
		ContentHash:       "sha256:test",
	}
}

func TestVendorRecord_EcosystemPresentAfterRoundTrip(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	if err := store.PutVendorRecord(ctx, mkRecord("example.com/eco")); err != nil {
		t.Fatalf("PutVendorRecord: %v", err)
	}
	got, found, err := store.GetVendorRecord(ctx, "example.com/eco")
	if err != nil || !found {
		t.Fatalf("GetVendorRecord: err=%v found=%t", err, found)
	}
	if got.Ecosystem != domain.EcosystemGo {
		t.Errorf("Ecosystem after round-trip = %q, want %q", got.Ecosystem, domain.EcosystemGo)
	}
}

func TestVendorRecord_RejectsForeignEcosystem(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	rec := mkRecord("example.com/npm")
	rec.Ecosystem = "npm"
	if err := store.PutVendorRecord(ctx, rec); err != nil {
		t.Fatalf("PutVendorRecord: %v", err)
	}
	if _, _, err := store.GetVendorRecord(ctx, "example.com/npm"); !errors.Is(err, domain.ErrUnsupportedEcosystem) {
		t.Errorf("expected ErrUnsupportedEcosystem, got %v", err)
	}
}
