package sqlite_test

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	fetchsqlite "github.com/eitanity/kanonarion/internal/adapters/factstore/sqlite"
	"github.com/eitanity/kanonarion/internal/adapters/recordseal"
	"github.com/eitanity/kanonarion/internal/adapters/sqlitestore"
	"github.com/eitanity/kanonarion/internal/audit"
	"github.com/eitanity/kanonarion/internal/composition/storage"
	sqlitestorage "github.com/eitanity/kanonarion/internal/composition/storage/sqlite"
)

func open(t *testing.T, req storage.Request) *storage.Storage {
	t.Helper()
	st, err := sqlitestorage.Open(req)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() {
		if err := st.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return st
}

// seedUnknownMigration leaves the store a newer build would: fully migrated,
// plus one migration row this build does not know.
func seedUnknownMigration(t *testing.T, root string) {
	t.Helper()
	db, err := sqlitestore.Open(filepath.Join(root, "mirror.db"), sqlitestorage.Migrations(), sqlitestore.IntentCreate)
	if err != nil {
		t.Fatalf("seeding: %v", err)
	}
	defer func() { _ = db.Close() }()
	if _, err := db.DB().Exec(`INSERT INTO schema_migrations (module, version, applied_at) VALUES (?, ?, ?)`,
		"vuln", 9999, time.Now().UTC().Format(time.RFC3339)); err != nil {
		t.Fatalf("recording an unknown migration: %v", err)
	}
}

func TestOpen_ReadIntentRefusesAnAbsentRootAndCreatesNothing(t *testing.T) {
	root := filepath.Join(t.TempDir(), "absent")
	st, err := sqlitestorage.Open(storage.Request{StoreRoot: root, Intent: storage.IntentRead})
	if st != nil || err == nil {
		t.Fatalf("Open = (%v, %v), want a refusal", st, err)
	}
	if want := "opening database: database directory does not exist: " + root; err.Error() != want {
		t.Errorf("error = %q, want the text the read root has always returned, %q", err, want)
	}
	if !errors.Is(err, sqlitestore.ErrDirMissing) {
		t.Errorf("error does not match sqlitestore.ErrDirMissing: %v", err)
	}
	if _, serr := os.Stat(root); !os.IsNotExist(serr) {
		t.Errorf("stat %s = %v, want not-exist: a read must create nothing", root, serr)
	}
}

func TestOpen_CreateIntentCreatesTheStore(t *testing.T) {
	root := filepath.Join(t.TempDir(), "new")
	st := open(t, storage.Request{StoreRoot: root, Intent: storage.IntentCreate})
	if _, err := os.Stat(filepath.Join(root, "mirror.db")); err != nil {
		t.Errorf("stat mirror.db: %v", err)
	}
	// A writable open creates the ledger before any event is recorded.
	if info, err := os.Stat(filepath.Join(root, "audit.jsonl")); err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("stat audit.jsonl = (%v, %v), want a 0600 file", info, err)
	}
	if err := st.Validate(); err != nil {
		t.Errorf("Validate: %v", err)
	}
	if err := st.Writable(context.Background()); err != nil {
		t.Errorf("Writable on a store this build created: %v", err)
	}
	state, err := st.Schema.SchemaState(context.Background())
	if err != nil {
		t.Fatalf("SchemaState: %v", err)
	}
	if n := len(sqlitestorage.Migrations()); state.Applied != n || state.Expected != n || len(state.Unknown) != 0 {
		t.Errorf("SchemaState = %+v, want %d applied of %d and none unknown", state, n, n)
	}
	if st.Signer == nil {
		t.Error("Signer is nil, want the no-op signer")
	}
}

func TestOpen_StoreWithUnknownMigrationOpensAndRefusesWrites(t *testing.T) {
	for _, intent := range []storage.Intent{storage.IntentRead, storage.IntentCreate} {
		root := t.TempDir()
		seedUnknownMigration(t, root)
		st := open(t, storage.Request{StoreRoot: root, Intent: intent})

		err := st.Writable(context.Background())
		if !errors.Is(err, storage.ErrStoreSchemaNewer) {
			t.Fatalf("intent %d: Writable = %v, want ErrStoreSchemaNewer", intent, err)
		}
		want := storage.ErrStoreSchemaNewer.Error() + ": " + filepath.Join(root, "mirror.db") +
			" carries 1 migration(s) this build does not know (vuln@v9999); upgrade kanonarion"
		if err.Error() != want {
			t.Errorf("intent %d: Writable = %q, want %q", intent, err, want)
		}
		state, serr := st.Schema.SchemaState(context.Background())
		if serr != nil {
			t.Fatalf("SchemaState: %v", serr)
		}
		if len(state.Unknown) != 1 || state.Unknown[0] != "vuln@v9999" {
			t.Errorf("intent %d: Unknown = %v, want [vuln@v9999]", intent, state.Unknown)
		}
	}
}

func TestOpen_FactsAttestationsAndAuditAreOneValue(t *testing.T) {
	st := open(t, storage.Request{StoreRoot: t.TempDir(), Intent: storage.IntentCreate})
	auditing, ok := st.Facts.(*fetchsqlite.AuditingStore)
	if !ok {
		t.Fatalf("Facts is %T, want *fetchsqlite.AuditingStore", st.Facts)
	}
	if st.Attestations != any(auditing) || st.Audit != any(auditing) {
		t.Errorf("Attestations %p and Audit %p are not the fact store %p", st.Attestations, st.Audit, auditing)
	}
}

// Every store that reports set-aside records holds the reporter the request
// carried. The field is unexported, so it is read by reflection and compared
// by code pointer: a nil, or the default logger, would not match.
func TestOpen_EveryReportingStoreReceivesTheReporter(t *testing.T) {
	var reporter recordseal.Reporter = func([]recordseal.SetAsideRow) {}
	st := open(t, storage.Request{StoreRoot: t.TempDir(), Intent: storage.IntentCreate, SetAside: reporter})

	stores := map[string]reflect.Value{
		"Facts":       reflect.ValueOf(st.Facts).Elem().FieldByName("inner"),
		"Walks":       reflect.ValueOf(st.Walks),
		"Licenses":    reflect.ValueOf(st.Licenses),
		"CallGraphs":  reflect.ValueOf(st.CallGraphs),
		"Examples":    reflect.ValueOf(st.Examples),
		"Extractions": reflect.ValueOf(st.Extractions),
		"Stdlib":      reflect.ValueOf(st.Stdlib),
	}
	want := reflect.ValueOf(reporter).Pointer()
	for name, s := range stores {
		f := s.Elem().FieldByName("setAside")
		if !f.IsValid() {
			t.Errorf("%s (%s) has no setAside field", name, s.Type())
			continue
		}
		if f.IsNil() || f.Pointer() != want {
			t.Errorf("%s (%s) does not hold the request's reporter", name, s.Type())
		}
	}
}

func TestOpen_CreateIntentReportsAnUncreatableRoot(t *testing.T) {
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := sqlitestorage.Open(storage.Request{StoreRoot: filepath.Join(file, "root"), Intent: storage.IntentCreate})
	if err == nil || !strings.HasPrefix(err.Error(), "creating store root ") {
		t.Fatalf("Open = %v, want a store-root refusal", err)
	}
}

func TestOpen_ReportsAnUnreadableMigrationTable(t *testing.T) {
	root := t.TempDir()
	db, err := sqlitestore.Open(filepath.Join(root, "mirror.db"), nil, sqlitestore.IntentCreate)
	if err != nil {
		t.Fatal(err)
	}
	// A schema_migrations without the columns this build reads.
	if _, err := db.DB().Exec(`DROP TABLE schema_migrations; CREATE TABLE schema_migrations (x TEXT)`); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	if _, err := sqlitestorage.Open(storage.Request{StoreRoot: root, Intent: storage.IntentRead}); err == nil {
		t.Fatal("Open succeeded over an unreadable schema_migrations")
	}
}

func TestOpen_ReportsAFailedMigration(t *testing.T) {
	root := t.TempDir()
	db, err := sqlitestore.Open(filepath.Join(root, "mirror.db"), nil, sqlitestore.IntentCreate)
	if err != nil {
		t.Fatal(err)
	}
	// A view where the first migration creates a table.
	if _, eerr := db.DB().Exec(`CREATE VIEW fetch_records AS SELECT 1 AS x`); eerr != nil {
		t.Fatal(eerr)
	}
	_ = db.Close()
	_, err = sqlitestorage.Open(storage.Request{StoreRoot: root, Intent: storage.IntentCreate})
	if err == nil || !strings.HasPrefix(err.Error(), "opening database: ") {
		t.Fatalf("Open = %v, want a migration failure", err)
	}
}

func TestOpen_WritableReportsAnUnreadableSchema(t *testing.T) {
	st, err := sqlitestorage.Open(storage.Request{StoreRoot: t.TempDir(), Intent: storage.IntentCreate})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	if err := st.Writable(context.Background()); err == nil || errors.Is(err, storage.ErrStoreSchemaNewer) {
		t.Fatalf("Writable on a closed store = %v, want a read failure that is not the newer-schema refusal", err)
	}
}

func auditLogExists(t *testing.T, root string) bool {
	t.Helper()
	_, err := os.Stat(filepath.Join(root, "audit.jsonl"))
	if err != nil && !os.IsNotExist(err) {
		t.Fatalf("stat audit.jsonl: %v", err)
	}
	return err == nil
}

// A read opens a store without creating its ledger; the first event recorded
// through it still does.
func TestOpen_ReadIntentCreatesNoAuditLogUntilAnEvent(t *testing.T) {
	root := t.TempDir()
	db, err := sqlitestore.Open(filepath.Join(root, "mirror.db"), sqlitestorage.Migrations(), sqlitestore.IntentCreate)
	if err != nil {
		t.Fatal(err)
	}
	_ = db.Close()

	st := open(t, storage.Request{StoreRoot: root, Intent: storage.IntentRead})
	if auditLogExists(t, root) {
		t.Fatal("a read open created audit.jsonl")
	}
	if err := st.Audit.RecordEvent(audit.Event{Type: audit.EventReplaceDirectiveObserved}); err != nil {
		t.Fatalf("RecordEvent: %v", err)
	}
	if !auditLogExists(t, root) {
		t.Error("the first event through a read-opened store did not create audit.jsonl")
	}
}

func TestOpen_CreateIntentOnANewerStoreCreatesNoAuditLog(t *testing.T) {
	root := t.TempDir()
	seedUnknownMigration(t, root)
	_ = open(t, storage.Request{StoreRoot: root, Intent: storage.IntentCreate})
	if auditLogExists(t, root) {
		t.Error("a writable open of a store this build must refuse created audit.jsonl")
	}
}

func TestOpen_ReportsAnUncreatableAuditLog(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "audit.jsonl"), 0o750); err != nil {
		t.Fatal(err)
	}
	_, err := sqlitestorage.Open(storage.Request{StoreRoot: root, Intent: storage.IntentCreate})
	if err == nil || !strings.HasPrefix(err.Error(), "creating audit log: ") {
		t.Fatalf("Open = %v, want an audit-log failure", err)
	}
}

// A read open that finds no mirror.db creates one, so it creates the ledger
// beside it; a read open of a store that already exists creates none.
func TestOpen_ReadIntentOnAnEmptyDirectoryCreatesTheStoreAndItsLedger(t *testing.T) {
	root := t.TempDir()
	_ = open(t, storage.Request{StoreRoot: root, Intent: storage.IntentRead})
	if _, err := os.Stat(filepath.Join(root, "mirror.db")); err != nil {
		t.Fatalf("stat mirror.db: %v", err)
	}
	info, err := os.Stat(filepath.Join(root, "audit.jsonl"))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("stat audit.jsonl = (%v, %v), want a 0600 file", info, err)
	}
}

func TestExists_ReadsOnlyTheDatabaseFile(t *testing.T) {
	root := t.TempDir()
	if sqlitestorage.Exists(root) {
		t.Error("Exists on an empty directory = true")
	}
	if got, want := sqlitestorage.DatabasePath(root), filepath.Join(root, "mirror.db"); got != want {
		t.Errorf("DatabasePath = %q, want %q", got, want)
	}
	_ = open(t, storage.Request{StoreRoot: root, Intent: storage.IntentCreate})
	if !sqlitestorage.Exists(root) {
		t.Error("Exists after a create = false")
	}
}

// entries lists root, so a test can say an open wrote nothing.
func entries(t *testing.T, root string) []string {
	t.Helper()
	des, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, de := range des {
		names = append(names, de.Name())
	}
	return names
}

// An inspection reports a store behind this build as it is, and leaves it so.
func TestOpen_InspectIntentReportsAStoreAsFoundAndWritesNothing(t *testing.T) {
	root := t.TempDir()
	db, err := sqlitestore.Open(filepath.Join(root, "mirror.db"), nil, sqlitestore.IntentCreate)
	if err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	before := entries(t, root)

	for range 2 {
		st, err := sqlitestorage.Open(storage.Request{StoreRoot: root, Intent: storage.IntentInspect})
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		state, err := st.Schema.SchemaState(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if state.Applied != 0 || state.Expected != len(sqlitestorage.Migrations()) {
			t.Errorf("SchemaState = %+v, want nothing applied of %d", state, len(sqlitestorage.Migrations()))
		}
		if err := st.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if after := entries(t, root); !reflect.DeepEqual(after, before) {
		t.Errorf("root holds %v after two inspections, want %v as before", after, before)
	}
}

// The blob maintenance the CLI container ran at every open runs at every open
// that may write, read intent included, and never on a store this build refuses.
func TestOpen_RunsBlobMaintenanceUnlessTheStoreIsRefused(t *testing.T) {
	root := t.TempDir()
	_ = open(t, storage.Request{StoreRoot: root, Intent: storage.IntentRead})
	if _, err := os.Stat(filepath.Join(root, ".blobs-adopted")); err != nil {
		t.Errorf("a read open left no adoption marker: %v", err)
	}

	newer := t.TempDir()
	seedUnknownMigration(t, newer)
	_ = open(t, storage.Request{StoreRoot: newer, Intent: storage.IntentRead})
	if _, err := os.Stat(filepath.Join(newer, ".blobs-adopted")); !os.IsNotExist(err) {
		t.Errorf("an open of a newer store ran the adoption pass: %v", err)
	}
}

func TestOpen_LogsAFailedAdoptionAndStillOpens(t *testing.T) {
	root := t.TempDir()
	// A marker that cannot be written: a link into a directory that is not there.
	if err := os.Symlink(filepath.Join(root, "missing", "marker"), filepath.Join(root, ".blobs-adopted")); err != nil {
		t.Fatal(err)
	}
	var buf strings.Builder
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	_ = open(t, storage.Request{StoreRoot: root, Intent: storage.IntentCreate, Logger: logger})
	if !strings.Contains(buf.String(), `level=WARN msg="could not re-address existing blobs by artefact identity"`) {
		t.Errorf("log = %q, want the adoption failure logged", buf.String())
	}
}

func TestLayout_TheBackendNamesItsFiles(t *testing.T) {
	root := t.TempDir()
	if got, want := sqlitestorage.BlobsDir(root), filepath.Join(root, "blobs"); got != want {
		t.Errorf("BlobsDir = %q, want %q", got, want)
	}
	if got, want := sqlitestorage.LedgerPath(root), fetchsqlite.AuditLogPath(root); got != want {
		t.Errorf("LedgerPath = %q, want the reader's own %q", got, want)
	}
	st := open(t, storage.Request{StoreRoot: root, Intent: storage.IntentCreate})
	state, err := st.Schema.SchemaState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if state.Location != sqlitestorage.DatabasePath(root) {
		t.Errorf("SchemaState.Location = %q, want the database path %q", state.Location, sqlitestorage.DatabasePath(root))
	}
}
