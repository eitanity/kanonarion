package sqlite_test

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/eitanity/kanonarion/internal/adapters/factstore/sqlite"
	"github.com/eitanity/kanonarion/internal/coordinate"
	domain2 "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/fetch/fetchtest"
)

// TestAcquisitionModeRoundTripsThroughTheStore guards the column added with the
// field: dropped from the INSERT or the SELECT, a record read back would claim no
// mode, the strength guard's log would say "unrecorded" for every existing
// record, and nothing would tell a reader which blob store resolves the handle.
func TestAcquisitionModeRoundTripsThroughTheStore(t *testing.T) {
	s := openMemStore(t)
	ctx := context.Background()

	for _, mode := range []domain2.AcquisitionMode{
		domain2.AcquisitionProxy, domain2.AcquisitionModcache, domain2.AcquisitionLocal,
	} {
		r := sampleRecord(t, "github.com/foo/"+string(mode), "v1.0.0", "0.4.0", fetchtest.AcquisitionMode(mode))
		if err := s.PutFetchRecord(ctx, mustSeal(t, r)); err != nil {
			t.Fatalf("Put(%s): %v", mode, err)
		}
		got, ok, err := s.GetFetchRecord(ctx,
			coordinate.ModuleCoordinate{Path: r.ModulePath, Version: r.ModuleVersion}, r.PipelineVersion)
		if err != nil || !ok {
			// Rehydrate verifies the content hash on read, so a field dropped
			// between write and read surfaces here as an integrity error.
			t.Fatalf("Get(%s): ok=%v err=%v", mode, ok, err)
		}
		if got.AcquisitionMode != string(mode) {
			t.Errorf("AcquisitionMode = %q, want %q", got.AcquisitionMode, mode)
		}
	}
}

// TestPreFieldRecordStillReadsBack is the migration guard at the storage layer: a
// record persisted before the column existed defaults to the empty string, which must
// survive the round trip and keep verifying its content hash — the read path treats a
// hash mismatch as absent, so a regression here silently invalidates the store.
func TestPreFieldRecordStillReadsBack(t *testing.T) {
	s := openMemStore(t)
	ctx := context.Background()

	r := sampleRecord(t, "github.com/foo/legacy", "v1.0.0", "0.4.0")
	if r.AcquisitionMode != "" {
		t.Fatalf("fixture is not a pre-field record: mode = %q", r.AcquisitionMode)
	}
	if err := s.PutFetchRecord(ctx, mustSeal(t, r)); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, ok, err := s.GetFetchRecord(ctx,
		coordinate.ModuleCoordinate{Path: r.ModulePath, Version: r.ModuleVersion}, r.PipelineVersion)
	if err != nil || !ok {
		t.Fatalf("a record without an acquisition mode failed to read back: ok=%v err=%v", ok, err)
	}
	if got.AcquisitionMode != "" {
		t.Errorf("AcquisitionMode = %q, want empty", got.AcquisitionMode)
	}
}

// TestAuditEntryNamesTheAcquisitionMode closes the provenance gap in audit.jsonl:
// before it, a fact_record_written entry could not say which mode wrote the
// record, so a run that replaced a network-verified record with a module-cache
// one was indistinguishable in the log from an ordinary re-measurement.
func TestAuditEntryNamesTheAcquisitionMode(t *testing.T) {
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.jsonl")
	inner, err := sqlite.Open(filepath.Join(dir, "facts.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	store, err := sqlite.NewAuditingStore(inner, auditPath)
	if err != nil {
		t.Fatalf("NewAuditingStore: %v", err)
	}
	defer func() {
		if cerr := store.Close(); cerr != nil {
			t.Errorf("store.Close: %v", cerr)
		}
	}()

	r := sampleRecord(t, "github.com/foo/bar", "v2.0.0", "0.4.0", fetchtest.AcquisitionMode(domain2.AcquisitionModcache))
	if err := store.PutFetchRecord(context.Background(), mustSeal(t, r)); err != nil {
		t.Fatalf("PutFetchRecord: %v", err)
	}

	f, err := os.Open(auditPath) //nolint:gosec // test-owned temp path
	if err != nil {
		t.Fatalf("opening audit log: %v", err)
	}
	defer func() {
		if cerr := f.Close(); cerr != nil {
			t.Errorf("f.Close: %v", cerr)
		}
	}()
	scanner := bufio.NewScanner(f)
	if !scanner.Scan() {
		t.Fatal("audit log empty")
	}
	var entry map[string]any
	if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
		t.Fatalf("parsing audit entry: %v", err)
	}
	if got := entry["acquisition_mode"]; got != string(domain2.AcquisitionModcache) {
		t.Errorf("audit entry acquisition_mode = %v, want %q", got, domain2.AcquisitionModcache)
	}
}

// TestAuditEntryOmitsAnUnrecordedMode keeps the field additive: a record with no
// mode must produce exactly the entry a pre-field build produced, so existing
// JSONL consumers see no new key appear from nowhere.
func TestAuditEntryOmitsAnUnrecordedMode(t *testing.T) {
	dir := t.TempDir()
	auditPath := filepath.Join(dir, "audit.jsonl")
	inner, err := sqlite.Open(filepath.Join(dir, "facts.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	store, err := sqlite.NewAuditingStore(inner, auditPath)
	if err != nil {
		t.Fatalf("NewAuditingStore: %v", err)
	}
	defer func() {
		if cerr := store.Close(); cerr != nil {
			t.Errorf("store.Close: %v", cerr)
		}
	}()

	if err := store.PutFetchRecord(context.Background(), mustSeal(t, sampleRecord(t, "github.com/foo/bar", "v2.0.0", "0.4.0"))); err != nil {
		t.Fatalf("PutFetchRecord: %v", err)
	}

	data, err := os.ReadFile(auditPath) //nolint:gosec // test-owned temp path
	if err != nil {
		t.Fatalf("reading audit log: %v", err)
	}
	var entry map[string]any
	if err := json.Unmarshal([]byte(firstLine(string(data))), &entry); err != nil {
		t.Fatalf("parsing audit entry: %v", err)
	}
	if _, present := entry["acquisition_mode"]; present {
		t.Errorf("audit entry carries acquisition_mode for a record that has none: %s", data)
	}
}

func firstLine(s string) string {
	for i, c := range s {
		if c == '\n' {
			return s[:i]
		}
	}
	return s
}
