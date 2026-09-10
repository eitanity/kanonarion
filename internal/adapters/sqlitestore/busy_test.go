package sqlitestore

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// openContender opens a second connection to the same file with a short
// busy_timeout, so a lost lock is reported in milliseconds rather than after the
// production wait. The wait is not what is under test; the recovery is.
func openContender(t *testing.T, dsn string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("open %s: %v", dsn, err)
	}
	t.Cleanup(func() { _ = db.Close() })
	db.SetMaxOpenConns(1)
	for _, pragma := range []string{`PRAGMA busy_timeout = 50`, `PRAGMA journal_mode = WAL`} {
		if _, err := db.Exec(pragma); err != nil {
			t.Fatalf("pragma %q: %v", pragma, err)
		}
	}
	return db
}

// contendedStore returns two handles on one file, and the table both write to.
func contendedStore(t *testing.T) (writer, holder *sql.DB) {
	t.Helper()
	dsn := filepath.Join(t.TempDir(), "contended.db")
	writer = openContender(t, dsn)
	if _, err := writer.Exec(`CREATE TABLE rows (id INTEGER PRIMARY KEY, v TEXT)`); err != nil {
		t.Fatalf("create table: %v", err)
	}
	return writer, openContender(t, dsn)
}

// holdWriteLock takes the store's single write lock for d and returns once it is
// genuinely held, so the caller's write is guaranteed to meet it.
//
// Contention cannot be scheduled, so it is constructed: BEGIN IMMEDIATE is the
// statement that acquires the write lock, and holding it is exactly the state a
// sibling call-graph child puts the store in while it persists a record.
func holdWriteLock(t *testing.T, holder *sql.DB, d time.Duration) *sync.WaitGroup {
	t.Helper()
	var held sync.WaitGroup
	var done sync.WaitGroup
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
		if _, err := tx.Exec(`INSERT INTO rows (v) VALUES ('holder')`); err != nil {
			held.Done()
			_ = tx.Rollback()
			t.Errorf("holder write: %v", err)
			return
		}
		held.Done()
		time.Sleep(d)
		if err := tx.Commit(); err != nil {
			t.Errorf("holder commit: %v", err)
		}
	}()
	held.Wait()
	return &done
}

// TestRetryOnBusy_RetriesAndSucceeds is the ticket's own acceptance: the write
// must SUCCEED after retrying, and the test must assert that the retry happened
// rather than that the write eventually worked — a write that never contended
// would pass the second check and prove nothing.
func TestRetryOnBusy_RetriesAndSucceeds(t *testing.T) {
	writer, holder := contendedStore(t)
	ResetRetries()

	done := holdWriteLock(t, holder, 400*time.Millisecond)

	err := RetryOnBusy(t.Context(), "contended row", func(ctx context.Context) error {
		_, execErr := writer.ExecContext(ctx, `INSERT INTO rows (v) VALUES ('writer')`)
		return execErr //nolint:wrapcheck // the classifier reads the driver's own error
	})
	done.Wait()

	if err != nil {
		t.Fatalf("a write that lost the lock must be retried, not abandoned: %v", err)
	}
	if got := Retries(); got == 0 {
		t.Fatal("the write succeeded without ever retrying; the contention this test constructs did not happen, " +
			"so it proves nothing about recovery")
	}

	var n int
	if err := writer.QueryRow(`SELECT count(*) FROM rows WHERE v = 'writer'`).Scan(&n); err != nil {
		t.Fatalf("counting: %v", err)
	}
	if n != 1 {
		t.Errorf("rows written = %d, want 1", n)
	}
}

// TestRetryOnBusy_UncontendedWriteShowsNoRetry is the control that must not
// change: the ordinary path takes no wait and reports none, so the presence of a
// contention line in a run's output means something.
func TestRetryOnBusy_UncontendedWriteShowsNoRetry(t *testing.T) {
	writer, _ := contendedStore(t)
	ResetRetries()

	if err := RetryOnBusy(t.Context(), "uncontended row", func(ctx context.Context) error {
		_, execErr := writer.ExecContext(ctx, `INSERT INTO rows (v) VALUES ('alone')`)
		return execErr //nolint:wrapcheck // as above
	}); err != nil {
		t.Fatalf("uncontended write failed: %v", err)
	}
	if got := Retries(); got != 0 {
		t.Errorf("Retries() = %d on an uncontended write, want 0", got)
	}
	if notice := ContentionNotice(Retries()); notice != "" {
		t.Errorf("an uncontended run reported %q; it must say nothing", notice)
	}
}

// TestRetryOnBusy_ExhaustedBudgetNamesContention pins the other end. A write that
// genuinely cannot take the lock still fails — the budget is bounded — and what
// it fails WITH names lock contention, so the gap it leaves is filed against this
// host rather than against the record it was carrying.
//
// The budget is exhausted by replaying a REAL busy error rather than by holding
// the lock for the whole of it: the classification is what is under test, and a
// test that slept out the full schedule would take twenty-five seconds to assert
// something it can assert in none.
func TestRetryOnBusy_ExhaustedBudgetNamesContention(t *testing.T) {
	busy := realBusyError(t)
	ResetRetries()

	attempts := 0
	err := RetryOnBusy(t.Context(), "doomed row", func(context.Context) error {
		attempts++
		return busy
	})
	if !errors.Is(err, ErrLockContended) {
		t.Fatalf("err = %v, want ErrLockContended", err)
	}
	if attempts != busyAttempts {
		t.Errorf("attempts = %d, want the whole budget of %d", attempts, busyAttempts)
	}
	if got := Retries(); got != int64(busyAttempts-1) {
		t.Errorf("Retries() = %d, want %d: every wait is a retry the run should be told about",
			got, busyAttempts-1)
	}
	if !strings.Contains(err.Error(), ContentionMarker) {
		t.Errorf("the message a child hands its parent must carry the marker, got %q", err)
	}
	if !strings.Contains(err.Error(), "doomed row") {
		t.Errorf("the refusal must name what was at stake, got %q", err)
	}
	ResetRetries()
}

// realBusyError produces the driver's own SQLITE_BUSY by losing a real lock, so
// what the budget test replays is the error the store actually raises rather
// than one a test invented.
func realBusyError(t *testing.T) error {
	t.Helper()
	writer, holder := contendedStore(t)
	done := holdWriteLock(t, holder, 200*time.Millisecond)
	_, err := writer.Exec(`INSERT INTO rows (v) VALUES ('writer')`)
	done.Wait()
	if !IsBusy(err) {
		t.Fatalf("could not construct a real busy error, got %v", err)
	}
	return err //nolint:wrapcheck // the classifier reads the driver's own error
}

// TestIsBusy_AsksTheDriverNotTheMessage keeps the classification structural. A
// message-matching check stops retrying the day the driver rewords itself, and
// nothing would say so.
func TestIsBusy_AsksTheDriverNotTheMessage(t *testing.T) {
	writer, holder := contendedStore(t)
	done := holdWriteLock(t, holder, 200*time.Millisecond)
	_, err := writer.Exec(`INSERT INTO rows (v) VALUES ('writer')`)
	done.Wait()
	if err == nil {
		t.Fatal("expected the contended write to be refused")
	}
	if !IsBusy(err) {
		t.Errorf("IsBusy(%v) = false; the driver's own busy code must be recognised", err)
	}
	if IsBusy(errors.New("database is locked")) {
		t.Error("a plain error whose text says 'database is locked' is not the driver saying so")
	}
	if IsBusy(nil) {
		t.Error("IsBusy(nil) must be false")
	}
}

// TestContentionNotice_RoundTripsBetweenProcesses pins the one line a child uses
// to tell its parent what it waited for. Most of a run's writes are made by
// children, so a parent that reported only its own would say "none" for a run
// that waited repeatedly.
func TestContentionNotice_RoundTripsBetweenProcesses(t *testing.T) {
	notice := ContentionNotice(7)
	if notice == "" {
		t.Fatal("a run that retried must say so")
	}
	stderr := "some diagnostic\n" + notice + "trailing\n"
	if got := ContentionNoticeIn(stderr); got != 7 {
		t.Errorf("ContentionNoticeIn = %d, want 7", got)
	}
	if got := ContentionNoticeIn("nothing here"); got != 0 {
		t.Errorf("ContentionNoticeIn of unrelated stderr = %d, want 0", got)
	}
	if got := ContentionNoticeIn(contentionNoticePrefix + "not-a-number\n"); got != 0 {
		t.Errorf("ContentionNoticeIn of a malformed line = %d, want 0", got)
	}
}

// TestAddRetries_FoldsAChildsCountIn covers the fold and its refusal to take a
// negative, which would let one bad parse hide real contention.
func TestAddRetries_FoldsAChildsCountIn(t *testing.T) {
	ResetRetries()
	AddRetries(3)
	AddRetries(0)
	AddRetries(-5)
	if got := Retries(); got != 3 {
		t.Errorf("Retries() = %d, want 3", got)
	}
	ResetRetries()
}
