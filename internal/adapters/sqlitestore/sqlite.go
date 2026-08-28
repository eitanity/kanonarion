package sqlitestore

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	_ "modernc.org/sqlite" // register the sqlite3 driver
)

// Migration represents a single schema migration for a specific module.
type Migration struct {
	Module  string
	Version int
	// SQL may be empty, which makes the migration a no-op. That exists for a
	// withdrawn migration whose version number must be retained: schema_migrations
	// is keyed on (module, version), so a store that already applied one cannot
	// have it renumbered or removed.
	SQL string
	// Fn is an optional Go step run inside the SAME transaction as SQL, after it.
	// It exists for back-fills SQLite cannot express — decoding a compressed blob
	// to populate a column denormalised from it is the case that brought it back.
	//
	// It has been added and removed before. It must only ever exist ALONGSIDE a
	// caller: a hook in a struct with nothing using it is the defect this project
	// treats as its own class, and that is why the previous one was deleted when
	// its single caller was withdrawn. If the last user of Fn is ever removed,
	// remove Fn with it.
	//
	// It takes no context deliberately. An earlier version manufactured a
	// context.Background() inside migrate, which made contextcheck flag every
	// Open call site.
	Fn func(tx *sql.Tx) error
}

// DB is a shared SQLite interface that handles opening the database,
// setting up connection pools, and running migrations.
type DB interface {
	DB() *sql.DB
	Close() error
}

// FakeDB is a mock implementation of DB for testing.
type FakeDB struct {
	SqlDB *sql.DB
}

func (f *FakeDB) DB() *sql.DB { return f.SqlDB }

func (f *FakeDB) Close() error {
	if f.SqlDB != nil {
		if err := f.SqlDB.Close(); err != nil {
			return fmt.Errorf("closing sqlite: %w", err)
		}
	}
	return nil
}

var _ DB = (*FakeDB)(nil)

type db struct {
	sqlDB *sql.DB
}

func (d *db) DB() *sql.DB {
	return d.sqlDB
}

func (d *db) Close() error {
	if d.sqlDB == nil {
		return nil
	}
	if err := d.sqlDB.Close(); err != nil {
		return fmt.Errorf("closing sqlite: %w", err)
	}
	return nil
}

// Intent says whether Open may bring the database's containing directory into
// existence. It is a parameter rather than a default because a caller that
// creates a store and a caller that reads one want opposite things from the
// same call, and the one that reads has no way to say so if Open always
// creates: a mistyped path then becomes a new, empty, entirely truthful store.
//
// The zero value is IntentRead. A caller that says nothing gets the refusal.
type Intent int

const (
	// IntentRead opens a database whose directory must already exist. A
	// missing directory is refused, not created.
	IntentRead Intent = iota
	// IntentCreate creates the directory if it is absent, for a caller that is
	// about to write records into it.
	IntentCreate
)

// ErrDirMissing is the refusal from an IntentRead open whose directory is not
// there. It is a sentinel so a caller can tell "nothing has been recorded here
// yet" from a corrupt or unreadable store and name its own remedy.
var ErrDirMissing = errors.New("database directory does not exist")

// Open opens the SQLite database at dsn and runs migrations.
//
// intent decides what happens when the containing directory is absent:
// IntentCreate makes it, IntentRead refuses with ErrDirMissing. Only the
// directory is at issue — SQLite creates the file itself either way.
//
// Use ":memory:" for tests; intent is not consulted for an in-memory DSN.
func Open(dsn string, migrations []Migration, intent Intent) (DB, error) {
	if dsn != ":memory:" && !strings.HasPrefix(dsn, "file::memory:") {
		dir := filepath.Dir(dsn)
		if intent == IntentCreate {
			if err := os.MkdirAll(dir, 0750); err != nil {
				return nil, fmt.Errorf("creating directory for sqlite: %w", err)
			}
		} else if _, err := os.Stat(dir); err != nil {
			if os.IsNotExist(err) {
				return nil, fmt.Errorf("%w: %s", ErrDirMissing, dir)
			}
			return nil, fmt.Errorf("checking directory for sqlite: %w", err)
		}
	}

	sqlDB, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("opening sqlite at %s: %w", dsn, err)
	}
	sqlDB.SetMaxOpenConns(1)

	for _, pragma := range []string{
		// First: bound cross-process lock waits. The store is a single-writer
		// SQLite file shared by every kanonarion invocation; without this a
		// command blocked behind another's write transaction waits forever
		// with no feedback. 10s is long enough for normal short transactions
		// and short enough to fail fast (clear "database is locked") under
		// real contention. Set before migrate so startup DDL is covered too.
		`PRAGMA busy_timeout = 10000`,
		`PRAGMA journal_mode = WAL`,
		`PRAGMA synchronous = NORMAL`,
		`PRAGMA cache_size = -65536`,
		`PRAGMA mmap_size = 268435456`,
		`PRAGMA temp_store = MEMORY`,
	} {
		if _, err := sqlDB.Exec(pragma); err != nil {
			cerr := sqlDB.Close()
			return nil, fmt.Errorf("setting pragma %q: %w", pragma, errors.Join(err, cerr))
		}
	}

	if err := migrate(sqlDB, migrations); err != nil {
		cerr := sqlDB.Close()
		return nil, fmt.Errorf("migrating schema: %w", errors.Join(err, cerr))
	}

	return &db{sqlDB: sqlDB}, nil
}

// New returns a DB interface from an already open *sql.DB.
func New(dbHandle DB) DB {
	return dbHandle
}

// MigrationKey renders a migration's identity the way schema_migrations keys it.
// It is the wire form every report and refusal names a migration by.
func MigrationKey(module string, version int) string {
	return fmt.Sprintf("%s@v%d", module, version)
}

// MigrationState is what schema_migrations says about a given set of known
// migrations: how many are applied in total, and which applied ones are not in
// the known set.
type MigrationState struct {
	// Applied is the total number of rows in schema_migrations, which is the
	// store's schema version.
	Applied int
	// Unknown names the applied migrations absent from the known set, sorted. A
	// non-empty Unknown means the store was written by a newer build: it is the
	// only reliable signal of that, because schema_migrations is keyed on (module,
	// version), so every migration the current binary knows still reads as applied
	// and the open succeeds regardless.
	Unknown []string
}

// ReadMigrationState reads schema_migrations from an open handle and compares it
// against the migrations the caller knows.
//
// It lives here, beside migrate, because there is more than one place that opens
// the store to write to it and they must not each carry their own copy of this
// comparison — a second copy could drift into disagreeing with the command an
// operator runs to diagnose the refusal.
//
// The handle must have been opened WITHOUT migrations, or the comparison would be
// against a table the same call had just written to. It takes no context: it runs
// while the store is being opened, before any request context exists, and reads
// one bounded local table.
func ReadMigrationState(handle DB, known []Migration) (MigrationState, error) {
	rows, err := handle.DB().Query(
		`SELECT module, version FROM schema_migrations ORDER BY module, version`)
	if err != nil {
		return MigrationState{}, fmt.Errorf("querying schema_migrations: %w", err)
	}
	defer func() { _ = rows.Close() }()

	knownKeys := make(map[string]struct{}, len(known))
	for _, m := range known {
		knownKeys[MigrationKey(m.Module, m.Version)] = struct{}{}
	}

	applied := 0
	var unknown []string
	for rows.Next() {
		var module string
		var version int
		if err := rows.Scan(&module, &version); err != nil {
			return MigrationState{}, fmt.Errorf("scanning schema_migrations: %w", err)
		}
		applied++
		key := MigrationKey(module, version)
		if _, ok := knownKeys[key]; !ok {
			unknown = append(unknown, key)
		}
	}
	if err := rows.Err(); err != nil {
		return MigrationState{}, fmt.Errorf("reading schema_migrations: %w", err)
	}
	sort.Strings(unknown)

	return MigrationState{Applied: applied, Unknown: unknown}, nil
}

// Apply runs migrations against an already open handle.
//
// It exists so a caller can interpose between opening the store and writing to
// it. Open(dsn, migrations) does both in one step, which leaves no point at which
// the applied migrations can be read and judged before the first DDL is executed
// — and that judgement is what stops a binary from operating on a store built by
// a newer one. A caller that needs it opens with nil migrations, inspects, then
// calls this.
func Apply(handle DB, migrations []Migration) error {
	if err := migrate(handle.DB(), migrations); err != nil {
		return fmt.Errorf("migrating schema: %w", err)
	}
	return nil
}

func migrate(db *sql.DB, migrations []Migration) error {
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (
        module     TEXT NOT NULL,
        version    INTEGER NOT NULL,
        applied_at TEXT NOT NULL,
        PRIMARY KEY (module, version)
    )`); err != nil {
		return fmt.Errorf("creating migrations table: %w", err)
	}

	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS _store_meta (
        key   TEXT PRIMARY KEY,
        value TEXT NOT NULL
    )`); err != nil {
		return fmt.Errorf("creating _store_meta table: %w", err)
	}

	for _, m := range migrations {
		var exists bool
		err := db.QueryRow(`SELECT 1 FROM schema_migrations WHERE module = ? AND version = ?`, m.Module, m.Version).Scan(&exists)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("checking migration %s v%d: %w", m.Module, m.Version, err)
		}
		if exists {
			continue
		}

		tx, err := db.Begin()
		if err != nil {
			return fmt.Errorf("beginning migration transaction: %w", err)
		}
		if strings.TrimSpace(m.SQL) != "" {
			if _, err := tx.Exec(m.SQL); err != nil {
				rerr := tx.Rollback()
				return fmt.Errorf("migration %s v%d: %w", m.Module, m.Version, errors.Join(err, rerr))
			}
		}
		if m.Fn != nil {
			// Inside the same transaction, so a back-fill that fails leaves the
			// schema change it accompanies rolled back too — a half-applied
			// migration is a store whose columns disagree with its rows.
			if err := m.Fn(tx); err != nil {
				rerr := tx.Rollback()
				return fmt.Errorf("migration %s v%d go step: %w", m.Module, m.Version, errors.Join(err, rerr))
			}
		}
		if _, err := tx.Exec(
			`INSERT INTO schema_migrations (module, version, applied_at) VALUES (?, ?, ?)`,
			m.Module, m.Version, time.Now().UTC().Format(time.RFC3339),
		); err != nil {
			rerr := tx.Rollback()
			return fmt.Errorf("recording migration %s v%d: %w", m.Module, m.Version, errors.Join(err, rerr))
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("committing migration %s v%d: %w", m.Module, m.Version, err)
		}
	}

	if _, err := db.Exec(`INSERT OR REPLACE INTO _store_meta (key, value)
        SELECT 'schema_version', CAST(COUNT(*) AS TEXT) FROM schema_migrations`); err != nil {
		return fmt.Errorf("updating schema_version in _store_meta: %w", err)
	}

	return nil
}
