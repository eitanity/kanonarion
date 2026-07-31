package composition_test

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/composition"
	"github.com/eitanity/kanonarion/internal/sqlitestore"
)

// seedStoreWithUnknownMigration brings a temp store fully up to date and then
// records one migration this build does not know, which is what a newer build
// leaves behind.
func seedStoreWithUnknownMigration(t *testing.T) string {
	t.Helper()
	storeRoot := t.TempDir()

	handle, err := sqlitestore.Open(filepath.Join(storeRoot, "mirror.db"), composition.Migrations())
	if err != nil {
		t.Fatalf("seeding store: %v", err)
	}
	if _, err := handle.DB().Exec(
		`INSERT INTO schema_migrations (module, version, applied_at) VALUES (?, ?, ?)`,
		"vuln", 9999, time.Now().UTC().Format(time.RFC3339),
	); err != nil {
		_ = handle.Close()
		t.Fatalf("recording an unknown migration: %v", err)
	}
	if err := handle.Close(); err != nil {
		t.Fatalf("closing seeded store: %v", err)
	}
	return storeRoot
}

// The driver surface writes — fetch, walk, extract, ingest — so it owes the same
// refusal the CLI's operating path gives. Without this the public façade was the
// one way left to reach a newer store with an older build and have every write
// fail per statement behind a successful open.
func TestNewDriver_RefusesAStoreWrittenByANewerBuild(t *testing.T) {
	storeRoot := seedStoreWithUnknownMigration(t)

	drv, cleanup, err := composition.NewDriver(storeRoot)
	if cleanup != nil {
		t.Error("a refused driver must hand back no cleanup function")
		_ = cleanup()
	}
	if err == nil {
		t.Fatal("NewDriver opened a store carrying migrations this build does not know; every write through it would fail while the caller saw a successful open")
	}
	if drv != nil {
		t.Error("a refused driver must be nil, so no caller can proceed to write through it")
	}
	if !errors.Is(err, composition.ErrStoreSchemaNewer) {
		t.Errorf("the sentinel must survive wrapping so a consumer can tell 'upgrade the binary' from a corrupt or unreachable store, got: %v", err)
	}
	for _, want := range []string{"vuln@v9999", "upgrade kanonarion"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal missing %q: %v", want, err)
		}
	}
}

// The read surface must stay open against the same store. An operator who cannot
// query a store the write path refuses cannot find out why it was refused, which
// is the same reason `kanonarion store info` is exempt from the CLI's gate.
func TestNewQueries_StillOpensAStoreTheDriverRefuses(t *testing.T) {
	storeRoot := seedStoreWithUnknownMigration(t)

	if _, _, err := composition.NewDriver(storeRoot); err == nil {
		t.Fatal("fixture is not a refused store, so this proves nothing about the read surface surviving the gate")
	}

	q, cleanup, err := composition.NewQueries(storeRoot)
	if err != nil {
		t.Fatalf("the read-only query surface must still open a store the driver refuses: %v", err)
	}
	if q == nil {
		t.Error("NewQueries returned no error and no queries")
	}
	if err := cleanup(); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
}

// The gate fires on unrecognised migrations and nothing else: a store this build
// knows every migration of must still be opened and brought up to date, or every
// ordinary upgrade would refuse.
func TestNewDriver_DoesNotRefuseAStoreThisBuildKnows(t *testing.T) {
	storeRoot := t.TempDir()

	drv, cleanup, err := composition.NewDriver(storeRoot)
	if err != nil {
		t.Fatalf("the gate refused a store this build knows every migration of: %v", err)
	}
	if drv == nil {
		t.Error("NewDriver returned no error and no driver")
	}
	if err := cleanup(); err != nil {
		t.Fatalf("cleanup: %v", err)
	}

	// And it really migrated, so "did not refuse" is not being read as "did not
	// apply anything either".
	handle, err := sqlitestore.Open(filepath.Join(storeRoot, "mirror.db"), nil)
	if err != nil {
		t.Fatalf("reopening store: %v", err)
	}
	defer func() { _ = handle.Close() }()
	state, err := sqlitestore.ReadMigrationState(handle, composition.Migrations())
	if err != nil {
		t.Fatalf("ReadMigrationState: %v", err)
	}
	if len(state.Unknown) != 0 {
		t.Errorf("unknown = %v, want none", state.Unknown)
	}
	if state.Applied != len(composition.Migrations()) {
		t.Errorf("applied = %d, want %d: the driver must still apply the migrations it knows",
			state.Applied, len(composition.Migrations()))
	}
}
