package sqlite_test

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	sqlite2 "github.com/eitanity/kanonarion/internal/adapters/factstore/sqlite"
	"github.com/eitanity/kanonarion/internal/audit"
	domain2 "github.com/eitanity/kanonarion/internal/fetch/domain"
)

func TestAuditingStore_AttestationDelegates(t *testing.T) {
	dir := t.TempDir()
	inner, err := sqlite2.Open(filepath.Join(dir, "facts.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	store, err := sqlite2.NewAuditingStore(inner, filepath.Join(dir, "audit.jsonl"))
	if err != nil {
		t.Fatalf("NewAuditingStore: %v", err)
	}
	defer func() {
		if err := store.Close(); err != nil {
			t.Errorf("store.Close: %v", err)
		}
	}()

	ctx := context.Background()
	att := sampleAttestation("github.com/foo/bar", "v2.0.0", "0.1.0", domain2.SubjectBlob, "abcd")
	if err := store.PutAttestation(ctx, att); err != nil {
		t.Fatalf("PutAttestation: %v", err)
	}
	got, err := store.ListAttestations(ctx, att.Coordinate, "0.1.0")
	if err != nil {
		t.Fatalf("ListAttestations: %v", err)
	}
	if len(got) != 1 || got[0].SubjectDigest != "abcd" {
		t.Fatalf("delegation failed: got %+v", got)
	}
}

func TestAuditingStore_RecordsOnPut(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "facts.db")
	auditPath := filepath.Join(dir, "audit.jsonl")

	inner, err := sqlite2.Open(dbPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	store, err := sqlite2.NewAuditingStore(inner, auditPath)
	if err != nil {
		t.Fatalf("NewAuditingStore: %v", err)
	}
	defer func() {
		if err := store.Close(); err != nil {
			t.Errorf("store.Close: %v", err)
		}
	}()

	r := sampleRecord("github.com/foo/bar", "v2.0.0", "0.1.0")
	if err := store.PutFetchRecord(context.Background(), r); err != nil {
		t.Fatalf("PutFetchRecord: %v", err)
	}

	// Audit file should have one JSONL line.
	f, err := os.Open(auditPath) //nolint:gosec
	if err != nil {
		t.Fatalf("opening audit log: %v", err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			t.Errorf("f.Close: %v", err)
		}
	}()

	scanner := bufio.NewScanner(f)
	if !scanner.Scan() {
		t.Fatal("audit log empty")
	}
	var entry map[string]string
	if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
		t.Fatalf("parsing audit entry: %v", err)
	}
	if entry["module_path"] != "github.com/foo/bar" {
		t.Errorf("module_path = %q", entry["module_path"])
	}
	if entry["content_hash"] != r.ContentHash {
		t.Errorf("content_hash = %q, want %q", entry["content_hash"], r.ContentHash)
	}
	// fact entries gain event_type additively without losing the
	// historical flat layout, so existing JSONL consumers keep working.
	if entry["event_type"] != string(audit.EventFactRecordWritten) {
		t.Errorf("event_type = %q, want %q", entry["event_type"], audit.EventFactRecordWritten)
	}
}

// TestAuditLog_RecordEvent_GenericEnvelope is the regression: a new
// event type must be writable through the generic envelope with no schema
// migration, and an unrecognised type must be rejected before it reaches disk.
func TestAuditLog_RecordEvent_GenericEnvelope(t *testing.T) {
	auditPath := filepath.Join(t.TempDir(), "audit.jsonl")
	log, err := sqlite2.NewAuditLog(auditPath)
	if err != nil {
		t.Fatalf("NewAuditLog: %v", err)
	}

	if err := log.RecordEvent(audit.Event{
		Type:    audit.EventReplaceDirectiveObserved,
		Payload: map[string]any{"target": "../local/fork", "classification": "highest"},
	}); err != nil {
		t.Fatalf("RecordEvent: %v", err)
	}
	if err := log.RecordEvent(audit.Event{Type: audit.EventType("not_a_real_event")}); err == nil {
		t.Fatal("RecordEvent accepted an unknown event type")
	}

	data, err := os.ReadFile(auditPath) //nolint:gosec
	if err != nil {
		t.Fatalf("reading audit log: %v", err)
	}
	var env struct {
		EventType string         `json:"event_type"`
		Timestamp string         `json:"timestamp"`
		Payload   map[string]any `json:"payload"`
	}
	if err := json.Unmarshal(bytesFirstLine(data), &env); err != nil {
		t.Fatalf("parsing envelope: %v", err)
	}
	if env.EventType != string(audit.EventReplaceDirectiveObserved) {
		t.Errorf("event_type = %q", env.EventType)
	}
	if env.Timestamp == "" {
		t.Error("timestamp not set by the adapter")
	}
	if env.Payload["classification"] != "highest" {
		t.Errorf("payload not round-tripped: %v", env.Payload)
	}
}

func bytesFirstLine(b []byte) []byte {
	for i, c := range b {
		if c == '\n' {
			return b[:i]
		}
	}
	return b
}

func TestAuditingStore_GetDelegates(t *testing.T) {
	dir := t.TempDir()
	inner, err := sqlite2.Open(filepath.Join(dir, "facts.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	store, err := sqlite2.NewAuditingStore(inner, filepath.Join(dir, "audit.jsonl"))
	if err != nil {
		t.Fatalf("NewAuditingStore: %v", err)
	}
	defer func() {
		if err := store.Close(); err != nil {
			t.Errorf("store.Close: %v", err)
		}
	}()

	ctx := context.Background()
	r := sampleRecord("example.com/m", "v1.0.0", "0.1.0")
	if err := store.PutFetchRecord(ctx, r); err != nil {
		t.Fatalf("PutFetchRecord: %v", err)
	}

	got, ok, err := store.GetFetchRecord(ctx, r.Coordinate(), r.PipelineVersion)
	if err != nil || !ok {
		t.Fatalf("GetFetchRecord: err=%v ok=%v", err, ok)
	}
	if got.ModulePath != r.ModulePath {
		t.Errorf("ModulePath = %q", got.ModulePath)
	}
}
