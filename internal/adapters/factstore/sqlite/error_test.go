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
	store, err := sqlite2.NewAuditingStore(inner, filepath.Join(dir, "audit.jsonl"))
	if err != nil {
		t.Fatalf("NewAuditingStore: %v", err)
	}

	// Close the DB so PutFetchRecord fails.
	if err := store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	r := sampleRecord("example.com/m", "v1.0.0", "0.1.0")
	err = store.PutFetchRecord(context.Background(), r)
	if err == nil {
		t.Error("expected error after Close")
	}
}
