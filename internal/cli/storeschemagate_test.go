package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/adapters/sqlitestore"
	"github.com/eitanity/kanonarion/internal/composition/storage"
	sqlitestorage "github.com/eitanity/kanonarion/internal/composition/storage/sqlite"
	"github.com/eitanity/kanonarion/internal/config/domain"
)

// allMigrations returns every migration the binary knows about, for fixtures
// that build a store by hand.
func allMigrations() []sqlitestore.Migration {
	return sqlitestorage.Migrations()
}

// seedStoreWithUnknownMigration builds a real store in a temp dir, brings it fully
// up to date, and then records one migration this binary does not know — which is
// exactly what a newer build leaves behind. It returns the store root.
//
// The extra row is what makes the fixture a measurement rather than a mock. The
// real failure was not detectable at open: schema_migrations is keyed on (module,
// version), so a store from a newer build reports every migration this binary
// knows as applied and opens without complaint. Only the unrecognised rows say
// the tables have a shape this binary was not built for.
func seedStoreWithUnknownMigration(t *testing.T, unknownModule string, unknownVersion int) string {
	t.Helper()
	root := t.TempDir()
	dbPath := filepath.Join(root, "mirror.db")

	handle, err := sqlitestore.Open(dbPath, allMigrations(), sqlitestore.IntentCreate)
	if err != nil {
		t.Fatalf("seeding store: %v", err)
	}
	if _, err := handle.DB().Exec(
		`INSERT INTO schema_migrations (module, version, applied_at) VALUES (?, ?, ?)`,
		unknownModule, unknownVersion, time.Now().UTC().Format(time.RFC3339),
	); err != nil {
		_ = handle.Close()
		t.Fatalf("recording an unknown migration: %v", err)
	}
	if err := handle.Close(); err != nil {
		t.Fatalf("closing seeded store: %v", err)
	}
	return root
}

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

// The gate itself. A binary that finds migrations it does not know in the store
// must not operate on it: every write it attempts meets tables shaped by a later
// build, and those failures were logged per statement while the command ran to
// completion and printed a summary over nothing.
func TestStoreSchemaGate_RefusesAnOlderBinaryAgainstANewerStore(t *testing.T) {
	root := seedStoreWithUnknownMigration(t, "vuln", 9999)

	ctr, cleanup, err := NewContainer(root, "", "", false, domain.DefaultConfig(), quietLogger())
	if cleanup != nil {
		t.Error("a refused container must hand back no cleanup function: there is nothing for the caller to close")
		_ = cleanup() //nolint:errcheck // the failure is reported above; this only releases it
	}
	if err == nil {
		t.Fatal("NewContainer opened a store carrying migrations this binary does not know; every write against it would fail and be reported as a completed run")
	}
	if ctr != nil {
		t.Error("a refused container must be nil, so no caller can proceed to write through it")
	}

	// The refusal is a precondition failure — the store is intact and a current
	// binary reads it fine — so it must not be reported as a store-integrity
	// failure, and must not fall through to the catch-all by accident.
	// Asserted through ExitCodeFromError, which reports whether a code was found,
	// NOT through ExitCodeForError alone: ExitConfig is also that function's
	// fallback, so "== ExitConfig" holds for any error whatsoever and could not
	// tell a carried decision from an accident. What needs proving is that the
	// carrier is on the chain and survives being joined with the Close error.
	code, carried := ExitCodeFromError(err)
	if !carried {
		t.Error("the refusal carries no exit code, so it reaches the process only via the catch-all: the classification is an accident, not a decision")
	}
	if carried && code != ExitConfig {
		t.Errorf("carried exit code = %d, want ExitConfig (%d): the store is not corrupt, this binary is stale", code, ExitConfig)
	}
	if got := ExitCodeForError(err); got != ExitConfig {
		t.Errorf("ExitCodeForError = %d, want ExitConfig (%d)", got, ExitConfig)
	}

	// Shaped like the config and policy schema gates: what is newer than what, and
	// the remedy. An operator who cannot act on the message has been told nothing.
	for _, want := range []string{"newer than supported", "vuln@v9999", "upgrade kanonarion", "store info"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal missing %q: %v", want, err)
		}
	}
}

// The other half of the same gate, and the half that makes the first half
// meaningful: an operator diagnosing the refusal must be able to run the command
// the refusal names. `store info` opens with no migrations and applies none, so it
// answers for a store this binary will not operate on.
//
// Asserted against the SAME fixture as the refusal, not a separate healthy store.
// Two stores would let both assertions hold while the gate was in fact too broad
// or too narrow — this pairing is what pins the boundary between them.
func TestStoreSchemaGate_StoreInfoStillReadsANewerStore(t *testing.T) {
	root := seedStoreWithUnknownMigration(t, "vuln", 9999)

	if _, _, err := NewContainer(root, "", "", false, domain.DefaultConfig(), quietLogger()); err == nil {
		t.Fatal("fixture is not a refused store, so this proves nothing about the read path surviving the gate")
	}

	var buf bytes.Buffer
	if err := runStoreInfo(root, true, &buf, os.Stderr); err != nil {
		t.Fatalf("store info must still read a store the operating path refuses; an operator who cannot inspect it cannot act on the refusal: %v", err)
	}

	var got storeInfoResult
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("decoding store info output: %v", err)
	}
	if got.Status != "newer" {
		t.Errorf("status = %q, want %q: the inspection command must name the same condition the gate refused on", got.Status, "newer")
	}
	if len(got.Unknown) != 1 || got.Unknown[0] != "vuln@v9999" {
		t.Errorf("unknown = %v, want exactly [vuln@v9999]: the report must identify which migrations this binary does not know", got.Unknown)
	}
}

// The gate must fire on unrecognised migrations and on nothing else. A store this
// binary knows every migration of — whether already up to date or not yet
// migrated — is one it is entitled to write to, and a gate that refused those
// would take the tool out of service on every ordinary upgrade.
func TestStoreSchemaGate_DoesNotRefuseAStoreThisBinaryKnows(t *testing.T) {
	for _, tc := range []struct {
		name string
		seed func(t *testing.T) string
	}{
		{
			// The ordinary case: nothing to migrate, nothing unknown.
			name: "a store already at this binary's schema",
			seed: func(t *testing.T) string {
				t.Helper()
				root := t.TempDir()
				handle, err := sqlitestore.Open(filepath.Join(root, "mirror.db"), allMigrations(), sqlitestore.IntentCreate)
				if err != nil {
					t.Fatalf("seeding store: %v", err)
				}
				if err := handle.Close(); err != nil {
					t.Fatalf("closing seeded store: %v", err)
				}
				return root
			},
		},
		{
			// A store BEHIND this binary — the normal upgrade — must migrate, not
			// refuse. "applied != expected" is a different question from "applied
			// something unknown", and conflating them is the way this gate would go
			// too broad.
			name: "a store behind this binary's schema",
			seed: func(t *testing.T) string {
				t.Helper()
				root := t.TempDir()
				handle, err := sqlitestore.Open(filepath.Join(root, "mirror.db"), nil, sqlitestore.IntentCreate)
				if err != nil {
					t.Fatalf("seeding store: %v", err)
				}
				if err := handle.Close(); err != nil {
					t.Fatalf("closing seeded store: %v", err)
				}
				return root
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := tc.seed(t)
			_, cleanup, err := NewContainer(root, "", "", false, domain.DefaultConfig(), quietLogger())
			if err != nil {
				t.Fatalf("the gate refused a store this binary knows every migration of: %v", err)
			}
			if cerr := cleanup(); cerr != nil {
				t.Fatalf("cleanup: %v", cerr)
			}

			// And it really was brought up to date, so "did not refuse" is not being
			// confused with "did not migrate either".
			st, err := sqlitestorage.Inspect(storage.Request{StoreRoot: root})
			if err != nil {
				t.Fatalf("reopening store: %v", err)
			}
			defer func() { _ = st.Close() }() //nolint:errcheck // a read-only inspection
			report, err := st.Schema.SchemaState(context.Background())
			if err != nil {
				t.Fatalf("SchemaState: %v", err)
			}
			if state := schemaStateOf(report); state.status() != "ok" {
				t.Errorf("status after NewContainer = %q, want %q: the container must still apply the migrations it knows", state.status(), "ok")
			}
		})
	}
}

// fetch writes, so it takes the operating path's refusal: same text, same exit
// code, and nothing written to the newer store.
func TestStoreSchemaGate_FetchRefusesANewerStoreAndWritesNothing(t *testing.T) {
	root := seedStoreWithUnknownMigration(t, "vuln", 9999)
	// A proxy the fetch would use, so the refusal is the store's and not a
	// GOPROXY=off refusal; nothing is fetched before the store is admitted.
	t.Setenv("GOPROXY", "https://proxy.golang.org")
	before := entries(t, root)

	var stdout, stderr bytes.Buffer
	err := Run([]string{"fetch", "example.com/mod@v1.0.0", "--store-root", root}, &stdout, &stderr)
	if err == nil {
		t.Fatal("fetch wrote into a store carrying a migration this binary does not know")
	}
	if code, carried := ExitCodeFromError(err); !carried || code != ExitConfig {
		t.Errorf("exit code = (%d, carried %v), want ExitConfig carried", code, carried)
	}
	if !strings.Contains(err.Error(), newerStoreError(filepath.Join(root, "mirror.db"), storeSchemaState{unknown: []string{"vuln@v9999"}}).Error()) {
		t.Errorf("refusal = %v, want the container's refusal text", err)
	}
	if after := entries(t, root); strings.Join(after, " ") != strings.Join(before, " ") {
		t.Errorf("root holds %v after the refusal, want %v", after, before)
	}
	handle, err := sqlitestore.Open(filepath.Join(root, "mirror.db"), nil, sqlitestore.IntentRead)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = handle.Close() }() //nolint:errcheck // a read of the fixture
	var n int
	if err := handle.DB().QueryRow(`SELECT count(*) FROM fetch_records`).Scan(&n); err != nil || n != 0 {
		t.Errorf("fetch_records = (%d, %v), want 0 rows", n, err)
	}
}
