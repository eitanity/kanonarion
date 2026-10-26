package sqlite_test

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	sqlite2 "code.eitanity.com/kanonarion/internal/adapters/factstore/sqlite"
	"code.eitanity.com/kanonarion/internal/audit"
	domain2 "code.eitanity.com/kanonarion/internal/fetch/domain"
)

func TestAuditingStore_AttestationDelegates(t *testing.T) {
	dir := t.TempDir()
	inner, err := sqlite2.Open(filepath.Join(dir, "facts.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	store := sqlite2.NewAuditingStore(inner, filepath.Join(dir, "audit.jsonl"))
	defer func() {
		if cerr := store.Close(); cerr != nil {
			t.Errorf("store.Close: %v", cerr)
		}
	}()

	ctx := context.Background()
	att := sampleAttestation("github.com/foo/bar", "v2.0.0", "0.1.0", domain2.SubjectBlob, "abcd")
	if perr := store.PutAttestation(ctx, att); perr != nil {
		t.Fatalf("PutAttestation: %v", perr)
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
	store := sqlite2.NewAuditingStore(inner, auditPath)
	defer func() {
		if cerr := store.Close(); cerr != nil {
			t.Errorf("store.Close: %v", cerr)
		}
	}()

	r := sampleRecord(t, "github.com/foo/bar", "v2.0.0", "0.1.0")
	if perr := store.PutFetchRecord(context.Background(), mustSeal(t, r)); perr != nil {
		t.Fatalf("PutFetchRecord: %v", perr)
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
	log := sqlite2.NewAuditLog(auditPath)

	if rerr := log.RecordEvent(audit.Event{
		Type:    audit.EventReplaceDirectiveObserved,
		Payload: map[string]any{"target": "../local/fork", "classification": "highest"},
	}); rerr != nil {
		t.Fatalf("RecordEvent: %v", rerr)
	}
	if rerr := log.RecordEvent(audit.Event{Type: audit.EventType("not_a_real_event")}); rerr == nil {
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
	store := sqlite2.NewAuditingStore(inner, filepath.Join(dir, "audit.jsonl"))
	defer func() {
		if cerr := store.Close(); cerr != nil {
			t.Errorf("store.Close: %v", cerr)
		}
	}()

	ctx := context.Background()
	r := sampleRecord(t, "example.com/m", "v1.0.0", "0.1.0")
	if perr := store.PutFetchRecord(ctx, mustSeal(t, r)); perr != nil {
		t.Fatalf("PutFetchRecord: %v", perr)
	}

	got, ok, err := store.GetFetchRecord(ctx, r.Coordinate(), r.PipelineVersion)
	if err != nil || !ok {
		t.Fatalf("GetFetchRecord: err=%v ok=%v", err, ok)
	}
	if got.ModulePath != r.ModulePath {
		t.Errorf("ModulePath = %q", got.ModulePath)
	}
}

// The log exists only once something is recorded: constructing it is what a
// read or a refused open does, and neither may leave a file behind.
func TestAuditLog_FirstEntryCreatesTheFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store", "audit.jsonl")
	log := sqlite2.NewAuditLog(path)
	if _, serr := os.Stat(filepath.Dir(path)); !os.IsNotExist(serr) {
		t.Fatalf("NewAuditLog touched the disk: stat %s = %v", filepath.Dir(path), serr)
	}
	for range 2 {
		if rerr := log.RecordEvent(audit.Event{Type: audit.EventReplaceDirectiveObserved}); rerr != nil {
			t.Fatalf("RecordEvent: %v", rerr)
		}
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("the first entry did not create the log: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("audit log mode = %o, want 600", mode)
	}
	if lines := len(bytesLines(t, path)); lines != 2 {
		t.Errorf("audit log holds %d lines, want 2", lines)
	}
}

// TestAuditLog_UncreatableLogFailsTheFirstEntry: the creation error the
// constructor used to return now reaches the write that needed the file.
func TestAuditLog_UncreatableLogFailsTheFirstEntry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	if err := os.Mkdir(path, 0o750); err != nil {
		t.Fatal(err)
	}
	log := sqlite2.NewAuditLog(path)
	if rerr := log.RecordEvent(audit.Event{Type: audit.EventReplaceDirectiveObserved}); rerr == nil {
		t.Fatal("RecordEvent succeeded with a directory where the log belongs")
	}
}

func bytesLines(t *testing.T, path string) []string {
	t.Helper()
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		out = append(out, sc.Text())
	}
	return out
}

// Ensure creates the log at once, with the mode the first entry would give it,
// and is idempotent.
func TestAuditLog_EnsureCreatesTheFileNow(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store", "audit.jsonl")
	log := sqlite2.NewAuditLog(path)
	for range 2 {
		if err := log.Ensure(); err != nil {
			t.Fatalf("Ensure: %v", err)
		}
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Ensure did not create the log: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 || info.Size() != 0 {
		t.Errorf("audit log mode %o size %d, want an empty 0600 file", mode, info.Size())
	}
}
