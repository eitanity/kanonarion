package sqlite_test

import (
	"database/sql"
	"path/filepath"
	"strings"
	"testing"

	"code.eitanity.com/kanonarion/internal/adapters/sqlitestore"
	"code.eitanity.com/kanonarion/internal/composition/storage"
	sqlitestorage "code.eitanity.com/kanonarion/internal/composition/storage/sqlite"
	ifacesqlite "code.eitanity.com/kanonarion/internal/iface/adapters/store/sqlite"
)

// findSymbolQuery is the interface-symbol read whose plan stale statistics turn
// into a scan of a whole index.
const findSymbolQuery = `SELECT record_content_hash FROM interface_symbols
WHERE symbol_name = ? AND pipeline_version = ?
ORDER BY module_path, module_version, package_path`

// seedPreStatisticsStore leaves the store a build before the statistics
// migration did: every other migration applied. With stale is true it also
// holds statistics claiming interface_symbols has one row.
func seedPreStatisticsStore(t *testing.T, root string, stale bool) {
	t.Helper()
	all := sqlitestorage.Migrations()
	db, err := sqlitestore.Open(filepath.Join(root, "mirror.db"), all[:len(all)-1], sqlitestore.IntentCreate)
	if err != nil {
		t.Fatalf("seeding: %v", err)
	}
	defer func() { _ = db.Close() }()
	if !stale {
		return
	}
	for _, q := range []string{
		`ANALYZE sqlite_schema`,
		`INSERT INTO sqlite_stat1 (tbl, idx, stat) VALUES
		    ('interface_symbols', 'interface_symbols_name_pipeline_idx', '1 1 1'),
		    ('interface_symbols', 'interface_symbols_lookup_idx', '1 1 1 1'),
		    ('interface_symbols', 'sqlite_autoindex_interface_symbols_1', '1 1 1 1 1 1')`,
		`INSERT INTO sqlite_stat4 (tbl, idx, neq, nlt, ndlt, sample) VALUES
		    ('interface_symbols', 'interface_symbols_name_pipeline_idx', '1 1 1', '0 0 0', '0 0 0', x'00')`,
		`ANALYZE sqlite_schema`, // loads the rows just written, for the control below
	} {
		if _, err := db.DB().Exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	if plan := queryPlan(t, db.DB(), findSymbolQuery); !strings.Contains(plan, "SCAN interface_symbols") {
		t.Fatalf("control: the seeded statistics should scan interface_symbols, plan %q", plan)
	}
}

func TestOpen_StatisticsMigrationDeletesEveryStatistic(t *testing.T) {
	root := t.TempDir()
	seedPreStatisticsStore(t, root, true)

	st := open(t, storage.Request{StoreRoot: root, Intent: storage.IntentRead})
	db := storeDB(t, st)

	for _, table := range []string{"sqlite_stat1", "sqlite_stat4"} {
		var n int
		if err := db.QueryRow(`SELECT count(*) FROM ` + table).Scan(&n); err != nil {
			t.Fatalf("counting %s: %v", table, err)
		}
		if n != 0 {
			t.Errorf("%s holds %d rows after the migration, want 0", table, n)
		}
	}
	// The migrating connection loaded the statistics before deleting them, so
	// it plans on the built-in estimates only if it reloaded them.
	if plan := queryPlan(t, db, findSymbolQuery); !strings.Contains(plan, "SEARCH interface_symbols USING INDEX interface_symbols_name_pipeline_idx") {
		t.Errorf("the migrating connection still plans on the deleted statistics: %q", plan)
	}
	var recorded int
	if err := db.QueryRow(`SELECT count(*) FROM schema_migrations WHERE module = 'store' AND version = 1`).Scan(&recorded); err != nil {
		t.Fatalf("reading schema_migrations: %v", err)
	}
	if recorded != 1 {
		t.Errorf("store@v1 recorded %d times, want 1", recorded)
	}
}

func TestOpen_StatisticsMigrationNeedsNoStatisticsTable(t *testing.T) {
	root := t.TempDir()
	seedPreStatisticsStore(t, root, false)
	st := open(t, storage.Request{StoreRoot: root, Intent: storage.IntentRead})
	state, err := st.Schema.SchemaState(t.Context())
	if err != nil {
		t.Fatalf("SchemaState: %v", err)
	}
	if n := len(sqlitestorage.Migrations()); state.Applied != n {
		t.Errorf("applied %d migrations, want %d", state.Applied, n)
	}
}

func TestOpen_StatisticsMigrationRunsOnce(t *testing.T) {
	root := t.TempDir()
	seedPreStatisticsStore(t, root, true)
	st := open(t, storage.Request{StoreRoot: root, Intent: storage.IntentRead})
	db := storeDB(t, st)
	if _, err := db.Exec(`INSERT INTO sqlite_stat1 (tbl, idx, stat) VALUES ('interface_symbols', 'interface_symbols_lookup_idx', '7 7 7 7')`); err != nil {
		t.Fatalf("writing a statistic: %v", err)
	}

	// A second open finds the migration recorded and leaves the row alone.
	again := open(t, storage.Request{StoreRoot: root, Intent: storage.IntentRead})
	againDB := storeDB(t, again)
	var n int
	if err := againDB.QueryRow(`SELECT count(*) FROM sqlite_stat1`).Scan(&n); err != nil {
		t.Fatalf("counting sqlite_stat1: %v", err)
	}
	if n != 1 {
		t.Errorf("sqlite_stat1 holds %d rows after a second open, want the 1 written since", n)
	}
	if err := againDB.QueryRow(`SELECT count(*) FROM schema_migrations WHERE module = 'store'`).Scan(&n); err != nil {
		t.Fatalf("reading schema_migrations: %v", err)
	}
	if n != 1 {
		t.Errorf("store migrations recorded %d times, want 1", n)
	}
}

// storeDB is the one connection every store of st shares.
func storeDB(t *testing.T, st *storage.Storage) *sql.DB {
	t.Helper()
	ifaces, ok := st.Interfaces.(*ifacesqlite.Store)
	if !ok {
		t.Fatalf("Interfaces is %T, want the SQLite interface store", st.Interfaces)
	}
	return ifaces.InternalDB().DB()
}

// queryPlan is EXPLAIN QUERY PLAN's detail lines for q, joined by "; ", with
// every placeholder bound to NULL.
func queryPlan(t *testing.T, db *sql.DB, q string) string {
	t.Helper()
	rows, err := db.Query(`EXPLAIN QUERY PLAN `+q, make([]any, strings.Count(q, "?"))...)
	if err != nil {
		t.Fatalf("EXPLAIN QUERY PLAN: %v", err)
	}
	defer func() { _ = rows.Close() }()
	var lines []string
	for rows.Next() {
		var id, parent, notUsed int
		var detail string
		if err := rows.Scan(&id, &parent, &notUsed, &detail); err != nil {
			t.Fatalf("scanning plan: %v", err)
		}
		lines = append(lines, detail)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterating plan: %v", err)
	}
	return strings.Join(lines, "; ")
}
