package cli

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/config/domain"
	"github.com/eitanity/kanonarion/internal/sqlitestore"
)

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
	storeRoot := t.TempDir()
	dbPath := filepath.Join(storeRoot, "mirror.db")

	handle, err := sqlitestore.Open(dbPath, allMigrations())
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
	return storeRoot
}

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

// The gate itself. A binary that finds migrations it does not know in the store
// must not operate on it: every write it attempts meets tables shaped by a later
// build, and those failures were logged per statement while the command ran to
// completion and printed a summary over nothing.
func TestStoreSchemaGate_RefusesAnOlderBinaryAgainstANewerStore(t *testing.T) {
	storeRoot := seedStoreWithUnknownMigration(t, "vuln", 9999)

	ctr, cleanup, err := NewContainer(storeRoot, "", "", false, domain.DefaultConfig(), quietLogger())
	if cleanup != nil {
		t.Error("a refused container must hand back no cleanup function: there is nothing for the caller to close")
		_ = cleanup()
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
	if code := ExitCodeForError(err); code != ExitConfig {
		t.Errorf("exit code = %d, want ExitConfig (%d): the store is not corrupt, this binary is stale", code, ExitConfig)
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
	storeRoot := seedStoreWithUnknownMigration(t, "vuln", 9999)

	if _, _, err := NewContainer(storeRoot, "", "", false, domain.DefaultConfig(), quietLogger()); err == nil {
		t.Fatal("fixture is not a refused store, so this proves nothing about the read path surviving the gate")
	}

	var buf bytes.Buffer
	if err := runStoreInfo(storeRoot, true, &buf, os.Stderr); err != nil {
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
				storeRoot := t.TempDir()
				handle, err := sqlitestore.Open(filepath.Join(storeRoot, "mirror.db"), allMigrations())
				if err != nil {
					t.Fatalf("seeding store: %v", err)
				}
				if err := handle.Close(); err != nil {
					t.Fatalf("closing seeded store: %v", err)
				}
				return storeRoot
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
				storeRoot := t.TempDir()
				handle, err := sqlitestore.Open(filepath.Join(storeRoot, "mirror.db"), nil)
				if err != nil {
					t.Fatalf("seeding store: %v", err)
				}
				if err := handle.Close(); err != nil {
					t.Fatalf("closing seeded store: %v", err)
				}
				return storeRoot
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			storeRoot := tc.seed(t)
			_, cleanup, err := NewContainer(storeRoot, "", "", false, domain.DefaultConfig(), quietLogger())
			if err != nil {
				t.Fatalf("the gate refused a store this binary knows every migration of: %v", err)
			}
			if err := cleanup(); err != nil {
				t.Fatalf("cleanup: %v", err)
			}

			// And it really was brought up to date, so "did not refuse" is not being
			// confused with "did not migrate either".
			handle, err := sqlitestore.Open(filepath.Join(storeRoot, "mirror.db"), nil)
			if err != nil {
				t.Fatalf("reopening store: %v", err)
			}
			defer func() { _ = handle.Close() }()
			state, err := readStoreSchemaState(handle)
			if err != nil {
				t.Fatalf("readStoreSchemaState: %v", err)
			}
			if state.status() != "ok" {
				t.Errorf("status after NewContainer = %q, want %q: the container must still apply the migrations it knows", state.status(), "ok")
			}
		})
	}
}
