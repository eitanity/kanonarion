package sqlite_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/adapters/recordseal"
	"github.com/eitanity/kanonarion/internal/adapters/sqlitestore"
	"github.com/eitanity/kanonarion/internal/stdlib/adapters/store/sqlite"
	"github.com/eitanity/kanonarion/internal/stdlib/domain"
	"github.com/eitanity/kanonarion/internal/stdlib/ports"
)

// respellAcquiredAt rewrites f's stored row as a build writing acquired_at at
// sub-second precision would have: the stored values hash to their seal, and
// this build, which re-renders the time at second precision, cannot reproduce
// it. It returns the seal the row is filed under.
func respellAcquiredAt(t *testing.T, db sqlitestore.DB, f domain.Facts) string {
	t.Helper()
	unsealed := f
	unsealed.ContentHash = ""
	raw, err := domain.FactsHasher{}.Marshal(unsealed)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	stored := f.AcquiredAt.UTC().Format(time.RFC3339)
	respelt := f.AcquiredAt.UTC().Format("2006-01-02T15:04:05") + ".5Z"
	from := []byte(`"acquired_at":"` + stored + `"`)
	if bytes.Count(raw, from) != 1 {
		t.Fatalf("fixture has %d acquired_at fields, want 1", bytes.Count(raw, from))
	}
	sum := sha256.Sum256(bytes.Replace(raw, from, []byte(`"acquired_at":"`+respelt+`"`), 1))
	seal := "sha256:" + hex.EncodeToString(sum[:])
	if _, err := db.DB().Exec(`UPDATE stdlib_facts SET acquired_at = ?, content_hash = ? WHERE content_hash = ?`,
		respelt, seal, f.ContentHash); err != nil {
		t.Fatalf("installing the respelt row: %v", err)
	}
	return seal
}

func openFactsStore(t *testing.T) (*sqlite.Store, sqlitestore.DB) {
	t.Helper()
	db, err := sqlitestore.Open(":memory:", sqlite.Migrations(), sqlitestore.IntentCreate)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return sqlite.New(db), db
}

func measuredAt(at time.Time, spdx string) domain.Facts {
	f := sampleFacts()
	f.ContentHash = ""
	f.AcquiredAt = at
	f.LicenseSPDX = spdx
	return sealed(f)
}

// A measurement this build cannot reproduce is set aside and named, the list
// keeps the others and composition serves them; with every row set aside the
// answer is NothingServable. Neither is ErrFactsIntegrity.
func TestListFactsFor_DriftedMeasurementSetAside(t *testing.T) {
	store, db := openFactsStore(t)
	ctx := context.Background()
	var reported []recordseal.SetAsideRow
	store.ReportSetAside(func(rows []recordseal.SetAsideRow) { reported = append(reported, rows...) })

	older := measuredAt(time.Unix(1_700_000_000, 0).UTC(), "BSD-3-Clause")
	newer := measuredAt(time.Unix(1_700_000_100, 0).UTC(), "MIT")
	for _, f := range []domain.Facts{older, newer} {
		if err := store.Put(ctx, f); err != nil {
			t.Fatalf("put: %v", err)
		}
	}
	seal := respellAcquiredAt(t, db, newer)

	got, err := store.ListFactsFor(ctx, "go1.26.4")
	if err != nil || len(got) != 1 || got[0].ContentHash != older.ContentHash {
		t.Fatalf("ListFactsFor = %d rows, %v; want only the readable measurement", len(got), err)
	}
	if len(reported) != 1 || reported[0].ContentHash != seal || reported[0].ID != "go1.26.4" ||
		!errors.Is(reported[0].Reason, recordseal.ErrGenerationDrift) {
		t.Errorf("reported = %+v, want the measurement named by %s", reported, seal)
	}
	if composed, ok, err := store.Get(ctx, "go1.26.4"); err != nil || !ok || composed.LicenseSPDX != "BSD-3-Clause" {
		t.Errorf("Get = %+v, %v, %v; want the readable measurement served", composed, ok, err)
	}

	respellAcquiredAt(t, db, older)
	_, _, err = store.Get(ctx, "go1.26.4")
	var none *recordseal.NothingServable
	if !errors.As(err, &none) || errors.Is(err, ports.ErrFactsIntegrity) || len(none.Aside.Rows) != 2 {
		t.Errorf("every row set aside: Get = %v, want *recordseal.NothingServable naming both", err)
	}
}

// Tamper control: a value altered after sealing hashes to nothing and is still
// ErrFactsIntegrity, ending the read.
func TestListFactsFor_AlteredMeasurementIsStillIntegrity(t *testing.T) {
	store, db := openFactsStore(t)
	ctx := context.Background()
	f := measuredAt(time.Unix(1_700_000_000, 0).UTC(), "BSD-3-Clause")
	if err := store.Put(ctx, f); err != nil {
		t.Fatalf("put: %v", err)
	}
	if _, err := db.DB().Exec(`UPDATE stdlib_facts SET license_spdx = 'BSD-3-Clausf'`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ListFactsFor(ctx, "go1.26.4"); !errors.Is(err, ports.ErrFactsIntegrity) {
		t.Errorf("ListFactsFor = %v, want ErrFactsIntegrity", err)
	}
}
