package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/adapters/blobcodec"
	"github.com/eitanity/kanonarion/internal/adapters/recordseal"
	"github.com/eitanity/kanonarion/internal/adapters/sqlitestore"
	cgsqlite "github.com/eitanity/kanonarion/internal/callgraph/adapters/store/sqlite"
	cgdomain "github.com/eitanity/kanonarion/internal/callgraph/domain"
)

// A call graph generation written in a canonical shape this build cannot
// reproduce is set aside and named, through the real store and Run, so the
// wiring from store to stderr, document and exit code is what is under test.

// driftedCallGraphStore lays down generations of prefCoord at the given hours,
// rewrites the newest the way a build with one more top-level field would have
// written it, and returns the store root and that generation's seal. mutate, if
// set, then alters the rewritten row's stored bytes.
func driftedCallGraphStore(t *testing.T, hours int, mutate func([]byte) []byte) (string, string) {
	t.Helper()
	root := t.TempDir()
	db, err := sqlitestore.Open(filepath.Join(root, "mirror.db"), nil, sqlitestore.IntentCreate)
	if err != nil {
		t.Fatalf("opening the store: %v", err)
	}
	defer func() { _ = db.Close() }()
	if err := sqlitestore.Apply(db, allMigrations()); err != nil {
		t.Fatalf("migrating the store: %v", err)
	}
	store := cgsqlite.New(db)
	ctx := context.Background()
	var newest cgdomain.CallGraphRecord
	for i := range hours {
		newest = prefRecord(t, prefSpec{at: time.Date(2026, 9, 15, 12+i, 0, 0, 0, time.UTC)})
		if perr := store.PutCallGraphRecord(ctx, newest); perr != nil {
			t.Fatalf("PutCallGraphRecord: %v", perr)
		}
	}

	widen := func(b []byte) []byte {
		return append([]byte(`{"retired_field":"a shape this build never had",`), b[1:]...)
	}
	var h cgdomain.CallGraphRecordHasher
	unsealed := newest
	unsealed.ContentHash = ""
	full, err := h.Marshal(unsealed)
	if err != nil {
		t.Fatalf("marshalling: %v", err)
	}
	sum := sha256.Sum256(widen(full))
	seal := "sha256:" + hex.EncodeToString(sum[:])
	stored := newest
	stored.ContentHash, stored.Edges = seal, nil
	blob, err := h.Marshal(stored)
	if err != nil {
		t.Fatalf("marshalling: %v", err)
	}
	blob = widen(blob)
	if mutate != nil {
		blob = mutate(blob)
	}
	if _, err := db.DB().ExecContext(ctx,
		`UPDATE callgraph_records SET serialised = ?, content_hash = ? WHERE content_hash = ?`,
		blobcodec.Encode(blob), seal, newest.ContentHash); err != nil {
		t.Fatalf("installing the drifted row: %v", err)
	}
	if _, err := db.DB().ExecContext(ctx,
		`UPDATE callgraph_edges SET record_content_hash = ? WHERE record_content_hash = ?`,
		seal, newest.ContentHash); err != nil {
		t.Fatalf("re-keying the drifted row's edges: %v", err)
	}
	return root, seal
}

func runCallGraphShowCLI(root string, extra ...string) (string, string, error) {
	var stdout, stderr bytes.Buffer
	args := append([]string{"callgraph-show", prefCoord.String(), "--store-root", root}, extra...)
	err := Run(args, &stdout, &stderr)
	return stdout.String(), stderr.String(), err
}

// TestCallGraphShow_DriftedGenerationNamedOnStderr: the text read serves the
// rest and states the set-aside generation on stderr, once.
func TestCallGraphShow_DriftedGenerationNamedOnStderr(t *testing.T) {
	root, seal := driftedCallGraphStore(t, 3, nil)

	stdout, stderr, err := runCallGraphShowCLI(root)
	if err != nil {
		t.Fatalf("callgraph-show = %v, want the composed record served", err)
	}
	if strings.Contains(stdout, seal) {
		t.Errorf("stdout carries the set-aside generation as an answer:\n%s", stdout)
	}
	if strings.Count(stderr, seal) != 1 || !strings.Contains(stderr, recordseal.SetAsideRemedy) ||
		!strings.Contains(stderr, "set aside call graph record") {
		t.Errorf("stderr does not name %s once with the remedy:\n%s", seal, stderr)
	}
}

// TestCallGraphShow_DriftedGenerationInTheDocument: under --json the set-aside
// generation is inside the document and not on stderr.
func TestCallGraphShow_DriftedGenerationInTheDocument(t *testing.T) {
	root, seal := driftedCallGraphStore(t, 3, nil)

	stdout, stderr, err := runCallGraphShowCLI(root, "--json")
	if err != nil {
		t.Fatalf("callgraph-show --json = %v", err)
	}
	var doc struct {
		ContentHash string `json:"content_hash"`
		SetAside    []struct {
			Coordinate      string `json:"coordinate"`
			PipelineVersion string `json:"pipeline_version"`
			ContentHash     string `json:"content_hash"`
			Reason          string `json:"reason"`
		} `json:"set_aside"`
	}
	if jerr := json.Unmarshal([]byte(stdout), &doc); jerr != nil {
		t.Fatalf("decoding the document: %v\n%s", jerr, stdout)
	}
	if len(doc.SetAside) != 1 || doc.SetAside[0].ContentHash != seal || doc.SetAside[0].Reason != recordseal.SetAsideRemedy ||
		doc.SetAside[0].Coordinate != prefCoord.String() {
		t.Errorf("set_aside = %+v, want the drifted generation %s", doc.SetAside, seal)
	}
	if doc.ContentHash == seal || doc.ContentHash == "" {
		t.Errorf("served %q, want a readable generation", doc.ContentHash)
	}
	if strings.Contains(stderr, seal) {
		t.Errorf("stderr repeats what the document carries:\n%s", stderr)
	}
}

// TestCallGraphShow_EveryGenerationDriftedExitsNotFound: nothing this build can
// serve is exit 4 with the statement, never exit 10.
func TestCallGraphShow_EveryGenerationDriftedExitsNotFound(t *testing.T) {
	root, seal := driftedCallGraphStore(t, 1, nil)

	_, stderr, err := runCallGraphShowCLI(root)
	if code := ExitCodeForError(err); code != ExitNotFound {
		t.Fatalf("exit %d (%v), want %d", code, err, ExitNotFound)
	}
	for _, want := range []string{"that this build can serve", seal, recordseal.SetAsideRemedy} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal %q does not state %q", err, want)
		}
	}
	if strings.Contains(err.Error(), "integrity check failed") || strings.Contains(stderr, seal) {
		t.Errorf("refusal reads as tampering or names the generation twice:\n%v\n%s", err, stderr)
	}
}

// TestCallGraphShow_AlteredGenerationStillExitsIntegrity is the control: one
// byte flipped in the stored bytes is exit 10 with the integrity wording.
func TestCallGraphShow_AlteredGenerationStillExitsIntegrity(t *testing.T) {
	flip := func(b []byte) []byte {
		at := bytes.Index(b, []byte("a shape this build never had"))
		b[at] = 'A'
		return b
	}
	root, seal := driftedCallGraphStore(t, 3, flip)

	_, stderr, err := runCallGraphShowCLI(root)
	if code := ExitCodeForError(err); code != ExitIntegrity {
		t.Fatalf("exit %d (%v), want %d", code, err, ExitIntegrity)
	}
	if !strings.Contains(err.Error(), "call graph record integrity check failed") ||
		strings.Contains(err.Error(), recordseal.SetAsideRemedy) || strings.Contains(stderr, seal) {
		t.Errorf("altered generation excused as drift:\n%v\n%s", err, stderr)
	}
}
