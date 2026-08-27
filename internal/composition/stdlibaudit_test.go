package composition_test

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/eitanity/kanonarion/internal/adapters/clock"
	fetchsqlite "github.com/eitanity/kanonarion/internal/adapters/factstore/sqlite"
	"github.com/eitanity/kanonarion/internal/composition"
	"github.com/eitanity/kanonarion/internal/sqlitestore"
)

// auditLines returns every audit envelope under storeRoot whose event_type
// matches want. An absent log is no lines: a run that appended nothing leaves
// no file.
func auditLines(t *testing.T, storeRoot, want string) []map[string]any {
	t.Helper()
	f, err := os.Open(filepath.Clean(filepath.Join(storeRoot, "audit.jsonl")))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatalf("opening audit log: %v", err)
	}
	defer func() { _ = f.Close() }()

	var out []map[string]any
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		if len(sc.Bytes()) == 0 {
			continue
		}
		var line map[string]any
		if err := json.Unmarshal(sc.Bytes(), &line); err != nil {
			t.Fatalf("decoding audit line %q: %v", sc.Text(), err)
		}
		if line["event_type"] == want {
			out = append(out, line)
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("reading audit log: %v", err)
	}
	return out
}

// TestOfflineStdlibAcquirer_WiresTheAssuranceLog drives the offline custody
// route through the shared composition helper — the same call the CLI container
// makes for a --from-modcache run — and reads the event back out of the real
// JSONL log rather than a fake sink. It is the wiring guard: the emission itself
// is covered by the acquirer's own tests, and what could still silently regress
// is a composition root handing the acquirer no sink.
//
// The online (go.dev/dl) route has no hermetic equivalent — establishing custody
// there means downloading a release tarball — so it is covered by unit tests
// over a fake acquisition instead. It does not need a second wiring guard: audit
// is wired INSIDE NewStdlibAcquirer, and both composition roots build their
// online acquirer through that one constructor, so neither can be the quieter
// one by construction.
func TestOfflineStdlibAcquirer_WiresTheAssuranceLog(t *testing.T) {
	storeRoot := t.TempDir()
	handle, err := sqlitestore.Open(filepath.Join(storeRoot, "mirror.db"), composition.Migrations(), sqlitestore.IntentCreate)
	if err != nil {
		t.Fatalf("opening store: %v", err)
	}
	defer func() { _ = handle.Close() }()

	factStore, err := fetchsqlite.NewAuditingStore(
		fetchsqlite.New(handle), filepath.Join(storeRoot, "audit.jsonl"))
	if err != nil {
		t.Fatalf("creating auditing fetch store: %v", err)
	}

	acquirer := composition.NewOfflineStdlibAcquirer(
		handle, "", clock.System{}, factStore,
		slog.New(slog.NewTextHandler(io.Discard, nil)))

	ctx := context.Background()
	// Forced, so the measurement is written rather than served: the event says a
	// record was persisted. The version is irrelevant to the offline route's
	// anchor — it digests this machine's $GOROOT/src whatever the coordinate says.
	facts, _, err := acquirer.AcquireStdlib(ctx, "go1.26.4", true, true)
	if err != nil {
		t.Fatalf("AcquireStdlib: %v (offline custody needs a probeable local toolchain)", err)
	}

	events := auditLines(t, storeRoot, "stdlib_custody_recorded")
	if len(events) != 1 {
		t.Fatalf("assurance log holds %d stdlib_custody_recorded events, want exactly 1", len(events))
	}
	payload, ok := events[0]["payload"].(map[string]any)
	if !ok {
		t.Fatalf("event carries no payload object: %v", events[0])
	}
	if got := payload["acquisition_route"]; got != "local-toolchain" {
		t.Errorf("payload acquisition_route = %v, want %q", got, "local-toolchain")
	}
	if got := payload["go_version"]; got != "go1.26.4" {
		t.Errorf("payload go_version = %v, want %q", got, "go1.26.4")
	}
	if payload["content_hash"] == "" || payload["content_hash"] == nil {
		t.Error("payload names no content hash, so the log cannot reach the record it witnesses")
	}
	if facts.VerificationStatus != "VerifiedLocalToolchain" {
		t.Errorf("acquired status = %q, want VerifiedLocalToolchain", facts.VerificationStatus)
	}

	// CONTROL for the count above: re-serving the stored measurement is not a
	// write, and appends nothing.
	if _, _, err := acquirer.AcquireStdlib(ctx, "go1.26.4", false, true); err != nil {
		t.Fatalf("AcquireStdlib (cached): %v", err)
	}
	if got := len(auditLines(t, storeRoot, "stdlib_custody_recorded")); got != 1 {
		t.Errorf("assurance log holds %d events after a cache hit, want the original 1", got)
	}
}
