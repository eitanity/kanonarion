package sqlite_test

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/adapters/sqlitestore"
	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/vuln/adapters/store/sqlite"
	"github.com/eitanity/kanonarion/internal/vuln/domain"
	"github.com/eitanity/kanonarion/internal/vuln/ports"
)

// storedRunRows is every stored byte of one run: its header row and its
// membership rows, each rendered column by column.
type storedRunRows struct {
	header  []string
	members []string
}

func readRunRows(t *testing.T, db *sql.DB, id string) storedRunRows {
	t.Helper()
	var out storedRunRows
	out.header = queryRows(t, db, `SELECT * FROM walk_scan_runs WHERE id = ?`, id)
	out.members = queryRows(t, db,
		`SELECT * FROM walk_scan_run_modules WHERE walk_scan_run_id = ? ORDER BY module_path, module_version`, id)
	return out
}

func queryRows(t *testing.T, db *sql.DB, q, id string) []string {
	t.Helper()
	rows, err := db.Query(q, id)
	if err != nil {
		t.Fatalf("query %q: %v", q, err)
	}
	defer func() { _ = rows.Close() }()
	cols, err := rows.Columns()
	if err != nil {
		t.Fatalf("columns: %v", err)
	}
	var out []string
	for rows.Next() {
		vals := make([]sql.RawBytes, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			t.Fatalf("scan: %v", err)
		}
		parts := make([]string, len(vals))
		for i, v := range vals {
			parts[i] = cols[i] + "=" + string(v)
		}
		out = append(out, strings.Join(parts, "\x1f"))
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}
	return out
}

// A second put under a held id is refused and changes nothing: the header was
// once updated in place while the membership rows kept the first scan's hashes,
// which left one run naming two scans.
func TestPutWalkScanRun_RefusesHeldIDAndLeavesFirstRunUnchanged(t *testing.T) {
	ctx := t.Context()
	db, err := sqlitestore.Open(":memory:", sqlite.Migrations(), sqlitestore.IntentCreate)
	if err != nil {
		t.Fatalf("opening in-memory db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	store := sqlite.New(db)

	snapshot := snap("osv", "v1")
	a, b := coord("example.com/a", "v1.0.0"), coord("example.com/b", "v1.0.0")
	first := scanRun(t, "vscan-walk-1-1", "walk-1", snapshot, a, b)
	if err := store.PutWalkScanRun(ctx, first); err != nil {
		t.Fatalf("PutWalkScanRun(first): %v", err)
	}
	before := readRunRows(t, db.DB(), first.ID)
	if len(before.header) != 1 || len(before.members) != 2 {
		t.Fatalf("control: first run stored %d header and %d membership rows, want 1 and 2",
			len(before.header), len(before.members))
	}

	// Same id, different scan: other hashes, another start, another verdict.
	second := first
	second.PerModuleResults = map[coordinate.ModuleCoordinate]string{a: "hash-second-a"}
	second.StartedAt = first.StartedAt.Add(500 * time.Millisecond)
	second.OverallStatus = domain.WalkStatusAllClean
	second.ContentHash = ""
	second = sealRun(t, second)

	err = store.PutWalkScanRun(ctx, second)
	if !errors.Is(err, ports.ErrWalkScanRunExists) {
		t.Fatalf("PutWalkScanRun(second, same id) error = %v, want ErrWalkScanRunExists", err)
	}
	if !strings.Contains(err.Error(), first.ID) {
		t.Errorf("refusal %q does not name the run id %s", err, first.ID)
	}

	after := readRunRows(t, db.DB(), first.ID)
	if !reflect.DeepEqual(before, after) {
		t.Errorf("first run changed by the refused put:\nbefore %q\nafter  %q", before, after)
	}
	got, found, err := store.GetWalkScanRun(ctx, first.ID)
	if err != nil || !found {
		t.Fatalf("GetWalkScanRun = (%v, %v), want the first run", found, err)
	}
	if got.ContentHash != first.ContentHash {
		t.Errorf("stored run seal = %s, want the first run's %s", got.ContentHash, first.ContentHash)
	}
}

// A put that lost the write lock is retried, and the retry must not meet the
// duplicate refusal: the attempt that lost rolled back and left no row.
func TestPutWalkScanRun_RetryAfterLockContentionIsNotADuplicate(t *testing.T) {
	ctx := t.Context()
	path := filepath.Join(t.TempDir(), "store.db")
	db, err := sqlitestore.Open(path, sqlite.Migrations(), sqlitestore.IntentCreate)
	if err != nil {
		t.Fatalf("opening store: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	// The store's one connection gives up on the lock in milliseconds, so the
	// contention reaches RetryOnBusy instead of SQLite's own wait.
	if _, err := db.DB().ExecContext(ctx, `PRAGMA busy_timeout = 50`); err != nil {
		t.Fatalf("lowering busy_timeout: %v", err)
	}
	store := sqlite.New(db)

	holder, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("opening contender: %v", err)
	}
	t.Cleanup(func() { _ = holder.Close() })
	holder.SetMaxOpenConns(1)

	var held, done sync.WaitGroup
	held.Add(1)
	done.Add(1)
	go func() {
		defer done.Done()
		tx, err := holder.BeginTx(context.Background(), nil)
		if err != nil {
			held.Done()
			t.Errorf("begin holder tx: %v", err)
			return
		}
		if _, err := tx.Exec(`CREATE TABLE lock_holder (v TEXT)`); err != nil {
			held.Done()
			_ = tx.Rollback() //nolint:errcheck // releasing the lock is the point; there is no write to keep
			t.Errorf("holder write: %v", err)
			return
		}
		held.Done()
		time.Sleep(400 * time.Millisecond)
		_ = tx.Rollback() //nolint:errcheck // releasing the lock is the point; there is no write to keep
	}()
	held.Wait()

	sqlitestore.ResetRetries()
	run := scanRun(t, "vscan-walk-1-1", "walk-1", snap("osv", "v1"),
		coord("example.com/a", "v1.0.0"), coord("example.com/b", "v1.0.0"))
	putErr := store.PutWalkScanRun(ctx, run)
	done.Wait()
	if putErr != nil {
		t.Fatalf("PutWalkScanRun after contention: %v", putErr)
	}
	if got := sqlitestore.Retries(); got == 0 {
		t.Fatal("control: the put met no contention, so no retry was exercised")
	}
	rows := readRunRows(t, db.DB(), run.ID)
	if len(rows.header) != 1 || len(rows.members) != 2 {
		t.Errorf("retried put stored %d header and %d membership rows, want 1 and 2",
			len(rows.header), len(rows.members))
	}
}
