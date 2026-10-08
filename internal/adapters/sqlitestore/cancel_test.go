package sqlitestore_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/eitanity/kanonarion/internal/adapters/sqlitestore"
)

// A write made under a cancelled context reaches nothing: the store refuses it
// before the statement runs, through the driver this store opens. A cancelled
// run's failure records depend on it, because they are built after the
// cancellation and written with it.
func TestStoreRefusesAWriteUnderACancelledContext(t *testing.T) {
	handle, err := sqlitestore.Open(filepath.Join(t.TempDir(), "mirror.db"), []sqlitestore.Migration{{
		Module: "cancel", Version: 1, SQL: "CREATE TABLE records (status TEXT)",
	}}, sqlitestore.IntentCreate)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = handle.Close() })
	db := handle.DB()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	if _, err := db.ExecContext(ctx, "INSERT INTO records (status) VALUES ('ScanFailed')"); !errors.Is(err, context.Canceled) {
		t.Errorf("ExecContext under a cancelled context: err = %v, want the cancellation", err)
	}
	if _, err := db.BeginTx(ctx, nil); !errors.Is(err, context.Canceled) {
		t.Errorf("BeginTx under a cancelled context: err = %v, want the cancellation", err)
	}
	err = sqlitestore.RetryOnBusy(ctx, "test write", func(ctx context.Context) error {
		_, xerr := db.ExecContext(ctx, "INSERT INTO records (status) VALUES ('ScanFailed')")
		return xerr //nolint:wrapcheck // the test reads the driver's own error
	})
	if !errors.Is(err, context.Canceled) {
		t.Errorf("RetryOnBusy under a cancelled context: err = %v, want the cancellation", err)
	}

	var n int
	if err := db.QueryRowContext(t.Context(), "SELECT COUNT(*) FROM records").Scan(&n); err != nil {
		t.Fatalf("counting: %v", err)
	}
	if n != 0 {
		t.Errorf("%d rows written under a cancelled context, want none", n)
	}
	if _, err := db.ExecContext(t.Context(), "INSERT INTO records (status) VALUES ('Clean')"); err != nil {
		t.Errorf("a write under a live context failed: %v", err)
	}
}
