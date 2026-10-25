package sqlite_test

import (
	"context"
	"path/filepath"
	"testing"

	sqlite2 "github.com/eitanity/kanonarion/internal/adapters/factstore/sqlite"
)

func TestAuditingStore_PutError_ClosedDB(t *testing.T) {
	dir := t.TempDir()
	inner, err := sqlite2.Open(filepath.Join(dir, "facts.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	store := sqlite2.NewAuditingStore(inner, filepath.Join(dir, "audit.jsonl"))

	// Close the DB so PutFetchRecord fails.
	if cerr := store.Close(); cerr != nil {
		t.Fatalf("Close: %v", cerr)
	}

	r := sampleRecord(t, "example.com/m", "v1.0.0", "0.1.0")
	err = store.PutFetchRecord(context.Background(), mustSeal(t, r))
	if err == nil {
		t.Error("expected error after Close")
	}
}
