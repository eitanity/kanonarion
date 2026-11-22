package sqlite_test

import (
	"context"
	"database/sql"
	"path/filepath"
	"slices"
	"testing"

	"code.eitanity.com/kanonarion/internal/coordinate/coordinatetest"
	"code.eitanity.com/kanonarion/internal/iface/adapters/store/sqlite"
)

// A write's cost must not depend on the size of the rest of the store, so a
// record write never refreshes the planner's statistics, however stale they are.
func TestPutInterfaceRecord_LeavesStatisticsAlone(t *testing.T) {
	ctx := context.Background()
	dsn := filepath.Join(t.TempDir(), "mirror.db")

	// Statistics with an index missing from them are the stalest SQLite knows:
	// PRAGMA optimize re-analyses such a table on every call.
	s, err := sqlite.Open(dsn)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err = s.PutInterfaceRecord(ctx, makeRecord(t)); err != nil {
		t.Fatalf("PutInterfaceRecord: %v", err)
	}
	db := s.InternalDB().DB()
	for _, q := range []string{`ANALYZE`, `DELETE FROM sqlite_stat1 WHERE tbl = 'interface_symbols'`} {
		if _, err = db.ExecContext(ctx, q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	if err = s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Reopened, so the connection loads the stale statistics.
	s, err = sqlite.Open(dsn)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	db = s.InternalDB().DB()
	before := statistics(t, db)

	other := makeRecord(t)
	other.Coordinate = coordinatetest.MustNew("example.com/other", "v1.0.0")
	if err := s.PutInterfaceRecord(ctx, resealInterface(t, other)); err != nil {
		t.Fatalf("PutInterfaceRecord: %v", err)
	}
	if after := statistics(t, db); !slices.Equal(after, before) {
		t.Errorf("the write rewrote sqlite_stat1:\nbefore %q\nafter  %q", before, after)
	}

	// Control: the statistics are stale enough that an optimize does rewrite them.
	if _, err := db.ExecContext(ctx, `PRAGMA optimize`); err != nil {
		t.Fatalf("PRAGMA optimize: %v", err)
	}
	if slices.Equal(statistics(t, db), before) {
		t.Fatal("control: PRAGMA optimize left the statistics alone, so the assertion above proves nothing")
	}
}

// statistics is every sqlite_stat1 row, in a stable order.
func statistics(t *testing.T, db *sql.DB) []string {
	t.Helper()
	rows, err := db.Query(`SELECT tbl || '|' || COALESCE(idx, '') || '|' || stat FROM sqlite_stat1 ORDER BY tbl, idx`)
	if err != nil {
		t.Fatalf("reading sqlite_stat1: %v", err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var row string
		if err := rows.Scan(&row); err != nil {
			t.Fatalf("scanning sqlite_stat1: %v", err)
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterating sqlite_stat1: %v", err)
	}
	return out
}
