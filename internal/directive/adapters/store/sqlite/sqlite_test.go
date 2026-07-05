package sqlite_test

import (
	"context"
	"errors"
	"testing"
	"time"

	directivesqlite "github.com/eitanity/kanonarion/internal/directive/adapters/store/sqlite"
	"github.com/eitanity/kanonarion/internal/directive/domain"
	"github.com/eitanity/kanonarion/internal/sqlitestore"
)

func openTestStore(t *testing.T) (*directivesqlite.Store, sqlitestore.DB) {
	t.Helper()
	db, err := sqlitestore.Open(":memory:", directivesqlite.Migrations())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return directivesqlite.New(db), db
}

func mkRecord(t *testing.T, id, project string, completed time.Time) domain.Record {
	t.Helper()
	ds := []domain.Directive{
		{Kind: domain.KindReplace, Source: "go.mod", Line: 7,
			OldPath: "example.com/foo", NewPath: "example.com/fork", NewVersion: "v1",
			Applied: true, Class: domain.RiskHigh},
	}
	domain.Sort(ds)
	return domain.Record{
		ID:                id,
		Ecosystem:         domain.EcosystemGo,
		ProjectModulePath: project,
		Directives:        ds,
		StartedAt:         completed.Add(-time.Second),
		CompletedAt:       completed,
		ExtractedAt:       completed,
		SchemaVersion:     domain.DirectiveSchemaVersion,
		PipelineVersion:   domain.PipelineVersion,
		ContentHash:       domain.Hash(ds),
	}
}

func TestDirectiveRecord_EcosystemPresentAfterRoundTrip(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()
	rec := mkRecord(t, "01ECO", "example.com/proj", time.Now().UTC())
	if err := store.PutDirectiveRecord(ctx, rec); err != nil {
		t.Fatalf("PutDirectiveRecord: %v", err)
	}
	got, found, err := store.GetScanByID(ctx, "01ECO")
	if err != nil {
		t.Fatalf("GetScanByID: %v", err)
	}
	if !found {
		t.Fatal("expected to find the scan")
	}
	if got.Ecosystem != domain.EcosystemGo {
		t.Errorf("Ecosystem after round-trip = %q, want %q", got.Ecosystem, domain.EcosystemGo)
	}
}

func TestDirectiveRecord_RejectsForeignEcosystem(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()
	rec := mkRecord(t, "01NPM", "example.com/proj", time.Now().UTC())
	rec.Ecosystem = "npm"
	if err := store.PutDirectiveRecord(ctx, rec); err != nil {
		t.Fatalf("PutDirectiveRecord: %v", err)
	}
	if _, _, err := store.GetScanByID(ctx, "01NPM"); !errors.Is(err, domain.ErrUnsupportedEcosystem) {
		t.Errorf("expected ErrUnsupportedEcosystem, got %v", err)
	}
}

// PutDirectiveRecord persists a new row per scan ID; subsequent reads
// round-trip every field. Idempotent on (scan_id) — a re-put with the same ID
// replaces the row rather than inserting a duplicate.
func TestStore_PutAndGetRoundTrip(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()

	rec := mkRecord(t, "01A", "example.com/proj", time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	if err := store.PutDirectiveRecord(ctx, rec); err != nil {
		t.Fatalf("PutDirectiveRecord: %v", err)
	}

	got, found, err := store.GetScanByID(ctx, "01A")
	if err != nil || !found {
		t.Fatalf("GetScanByID: found=%t err=%v", found, err)
	}
	if got.ID != "01A" || got.ProjectModulePath != "example.com/proj" {
		t.Errorf("round-trip mismatch: %+v", got)
	}
	if got.ContentHash != rec.ContentHash {
		t.Errorf("ContentHash drift: got %q want %q", got.ContentHash, rec.ContentHash)
	}
	if got.CompletedAt.IsZero() {
		t.Errorf("CompletedAt zero after round-trip")
	}

	// Re-put same ID is an upsert, not an error or duplicate.
	if err := store.PutDirectiveRecord(ctx, rec); err != nil {
		t.Fatalf("PutDirectiveRecord (upsert): %v", err)
	}
	scans, err := store.ListScans(ctx, "example.com/proj", 0)
	if err != nil {
		t.Fatalf("ListScans: %v", err)
	}
	if len(scans) != 1 {
		t.Errorf("re-put created %d rows, want 1 (upsert)", len(scans))
	}
}

// ListScans returns scans newest-first and honours limit.
func TestStore_ListScansOrderAndLimit(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	// Persist three scans with strictly-increasing completed_at so the
	// ordering assertion does not rely on tie-breaks.
	for i, id := range []string{"01A", "01B", "01C"} {
		if err := store.PutDirectiveRecord(ctx, mkRecord(t, id, "example.com/proj", base.Add(time.Duration(i)*time.Hour))); err != nil {
			t.Fatalf("PutDirectiveRecord: %v", err)
		}
	}

	all, err := store.ListScans(ctx, "example.com/proj", 0)
	if err != nil {
		t.Fatalf("ListScans: %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("ListScans returned %d, want 3", len(all))
	}
	if all[0].ID != "01C" || all[1].ID != "01B" || all[2].ID != "01A" {
		t.Errorf("ListScans not newest-first: %v", []string{all[0].ID, all[1].ID, all[2].ID})
	}

	limited, err := store.ListScans(ctx, "example.com/proj", 2)
	if err != nil {
		t.Fatalf("ListScans (limit): %v", err)
	}
	if len(limited) != 2 {
		t.Errorf("limit=2 returned %d rows", len(limited))
	}

	// GetDirectiveRecord (latest) consistent with ListScans[0].
	latest, found, err := store.GetDirectiveRecord(ctx, "example.com/proj")
	if err != nil || !found {
		t.Fatalf("GetDirectiveRecord: found=%t err=%v", found, err)
	}
	if latest.ID != "01C" {
		t.Errorf("GetDirectiveRecord latest = %s, want 01C", latest.ID)
	}
}

// missing IDs and unknown projects return found=false (no error).
func TestStore_MissingReturnsNotFound(t *testing.T) {
	store, _ := openTestStore(t)
	ctx := context.Background()

	if _, found, err := store.GetScanByID(ctx, "NOPE"); err != nil || found {
		t.Errorf("GetScanByID NOPE: found=%t err=%v", found, err)
	}
	if _, found, err := store.GetDirectiveRecord(ctx, "example.com/never-scanned"); err != nil || found {
		t.Errorf("GetDirectiveRecord unscanned: found=%t err=%v", found, err)
	}
	scans, err := store.ListScans(ctx, "example.com/never-scanned", 0)
	if err != nil {
		t.Fatalf("ListScans: %v", err)
	}
	if len(scans) != 0 {
		t.Errorf("ListScans for unscanned project returned %d rows", len(scans))
	}
}

// migration v3 renames any pre- row whose synthetic ID still
// embeds the redundant 'sha256:' prefix (an artefact of the original v2 SQL)
// to the clean 'legacy-<8 hex>' form. The migration is idempotent.
func TestStore_MigrationRenamesUglyPreIDs(t *testing.T) {
	store, db := openTestStore(t)
	ctx := context.Background()

	// Simulate a row produced by the original v2 form. We use the public Put
	// API to seed a record, then patch the scan_id in-place to mimic the ugly
	// form that older installs persisted. The cleanup pass in this test then
	// verifies v3's rename SQL when re-applied.
	rec := mkRecord(t, "to-be-renamed", "example.com/proj", time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	if err := store.PutDirectiveRecord(ctx, rec); err != nil {
		t.Fatalf("PutDirectiveRecord: %v", err)
	}
	const uglyID = "legacy-sha256:e3b0c442"
	if _, err := db.DB().ExecContext(ctx, `UPDATE directive_scans SET scan_id = ? WHERE scan_id = ?`, uglyID, "to-be-renamed"); err != nil {
		t.Fatalf("seeding ugly ID: %v", err)
	}

	// Apply the v3 rename SQL again (it is idempotent — the rename clause
	// guards on the 'sha256:' substring).
	const renameSQL = `
        UPDATE directive_scans
        SET scan_id = 'legacy-' || substr(content_hash, 8, 8)
        WHERE scan_id LIKE 'legacy-sha256:%'`
	if _, err := db.DB().ExecContext(ctx, renameSQL); err != nil {
		t.Fatalf("running v3 rename: %v", err)
	}

	// The ugly ID must be gone; the clean form must hold the same row.
	if _, found, err := store.GetScanByID(ctx, uglyID); err != nil || found {
		t.Errorf("ugly ID still present after rename: found=%t err=%v", found, err)
	}
	clean := "legacy-" + rec.ContentHash[len("sha256:"):][:8]
	if _, found, err := store.GetScanByID(ctx, clean); err != nil || !found {
		t.Errorf("clean ID %q not present: found=%t err=%v", clean, found, err)
	}

	// Re-running the rename SQL on a store with no ugly rows is a no-op.
	if _, err := db.DB().ExecContext(ctx, renameSQL); err != nil {
		t.Fatalf("idempotency: %v", err)
	}
}
