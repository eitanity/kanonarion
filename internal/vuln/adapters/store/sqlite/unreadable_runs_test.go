package sqlite_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/adapters/recordseal"
	"github.com/eitanity/kanonarion/internal/sqlitestore"
	"github.com/eitanity/kanonarion/internal/vuln/adapters/store/sqlite"
	"github.com/eitanity/kanonarion/internal/vuln/domain"
	"github.com/eitanity/kanonarion/internal/vuln/ports"
)

// One stored run that does not verify used to make the whole table unlistable,
// which took away the command an operator would use to find it. These tests pin
// the replacement contract at the seam both listings share: every run that
// verifies comes back, the ones that do not are named, and a store with no
// faults is untouched by any of it.

// storeRun writes a sealed run through the production path.
func storeRun(t *testing.T, store *sqlite.Store, id, walkID string) domain.WalkScanRun {
	t.Helper()
	run := sealRun(t, domain.WalkScanRun{
		ID:              id,
		WalkID:          walkID,
		Snapshot:        snap("govulndb", "v2024-01-01"),
		StartedAt:       time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		CompletedAt:     time.Date(2024, 1, 1, 0, 1, 0, 0, time.UTC),
		PipelineVersion: "v1",
	})
	if err := store.PutWalkScanRun(context.Background(), run); err != nil {
		t.Fatalf("PutWalkScanRun(%s): %v", id, err)
	}
	return run
}

// driftBlob renders run the way a DIFFERENT canonical shape would have: an
// extra top-level field this build knows nothing about, sealed over the bytes
// as they stand.
//
// That is what the drifted rows in a real store are — written by a release
// whose struct had fields this one does not, or lacked fields this one has. The
// bytes hash to the seal they carry, so nothing has been altered; today's
// struct simply cannot reproduce them, because unmarshalling drops the field
// and marshalling never puts it back.
func driftBlob(t *testing.T, run domain.WalkScanRun) []byte {
	t.Helper()
	blob, err := domain.WalkScanRunHasher{}.Marshal(run)
	if err != nil {
		t.Fatalf("marshalling run: %v", err)
	}
	// Splice the unknown field in after the opening brace, leaving the rest of
	// the bytes exactly as the encoder emitted them.
	widened := append([]byte(`{"retired_field":"a shape this build never had",`), blob[1:]...)

	// Seal it: content_hash blanked, everything else byte-for-byte, bare hex —
	// the recipe this domain has always used.
	stamped := []byte(`"content_hash":"` + run.ContentHash + `"`)
	if bytes.Count(widened, stamped) != 1 {
		t.Fatalf("fixture has %d occurrences of the top-level seal, want exactly 1",
			bytes.Count(widened, stamped))
	}
	blanked := bytes.Replace(widened, stamped, []byte(`"content_hash":""`), 1)
	sum := sha256.Sum256(blanked)
	sealed := hex.EncodeToString(sum[:])
	out := bytes.Replace(widened, stamped, []byte(`"content_hash":"`+sealed+`"`), 1)

	consistent, err := recordseal.SelfConsistent(out, sealed)
	if err != nil || !consistent {
		t.Fatalf("drift fixture is not self-consistent (consistent=%v, err=%v); it would be "+
			"indistinguishable from altered bytes and would prove nothing", consistent, err)
	}
	return out
}

// TestListWalkScanRuns_ReportsUnreadableRowsAndKeepsTheRest is the regression:
// the good rows survive a bad one, the bad one is named rather than dropped,
// and the failure still answers to the integrity sentinel so a consuming
// command's fail-closed branch is unchanged.
func TestListWalkScanRuns_ReportsUnreadableRowsAndKeepsTheRest(t *testing.T) {
	ctx := t.Context()
	db, err := sqlitestore.Open(":memory:", sqlite.Migrations(), sqlitestore.IntentCreate)
	if err != nil {
		t.Fatalf("opening in-memory db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	store := sqlite.New(db)

	good := storeRun(t, store, "vscan-walk-1-good", "walk-1")
	bad := storeRun(t, store, "vscan-walk-1-bad", "walk-1")

	if _, err := db.DB().ExecContext(ctx,
		`UPDATE walk_scan_runs SET serialised = ? WHERE id = ?`,
		driftBlob(t, bad), bad.ID); err != nil {
		t.Fatalf("installing drifted row: %v", err)
	}

	for _, tc := range []struct {
		name string
		list func() ([]domain.WalkScanRun, error)
	}{
		{"ListAllWalkScanRuns", func() ([]domain.WalkScanRun, error) { return store.ListAllWalkScanRuns(ctx) }},
		{"ListWalkScanRuns", func() ([]domain.WalkScanRun, error) { return store.ListWalkScanRuns(ctx, "walk-1") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runs, err := tc.list()

			if len(runs) != 1 || runs[0].ID != good.ID {
				t.Fatalf("runs = %v, want only the verifiable run %s", ids(runs), good.ID)
			}

			var unreadable *ports.UnreadableRuns
			if !errors.As(err, &unreadable) {
				t.Fatalf("error = %v, want *ports.UnreadableRuns", err)
			}
			if len(unreadable.Runs) != 1 {
				t.Fatalf("unreadable = %v, want exactly the one bad row", unreadable.Runs)
			}
			// Naming the row is the point: a caller told only that something is
			// wrong cannot go and look at it.
			if unreadable.Runs[0].ID != bad.ID {
				t.Errorf("unreadable run ID = %q, want %q", unreadable.Runs[0].ID, bad.ID)
			}
			// A generation this build no longer seals must not be reported in the
			// words reserved for altered bytes.
			if !errors.Is(unreadable.Runs[0].Reason, recordseal.ErrGenerationDrift) {
				t.Errorf("reason = %v, want it to classify as generation drift", unreadable.Runs[0].Reason)
			}
			// Consuming commands match this sentinel and must keep failing closed.
			if !errors.Is(err, ports.ErrVulnIntegrity) {
				t.Errorf("errors.Is(err, ErrVulnIntegrity) = false; consuming callers would stop failing closed")
			}
		})
	}
}

// TestListWalkScanRuns_CleanStoreIsUnchanged is the negative direction: with no
// faults the listings answer exactly as they did before, error and all.
func TestListWalkScanRuns_CleanStoreIsUnchanged(t *testing.T) {
	ctx := t.Context()
	store := newTestStore(t)

	a := storeRun(t, store, "vscan-walk-1-a", "walk-1")
	b := storeRun(t, store, "vscan-walk-2-b", "walk-2")

	all, err := store.ListAllWalkScanRuns(ctx)
	if err != nil {
		t.Fatalf("ListAllWalkScanRuns() on a clean store = %v, want nil", err)
	}
	if len(all) != 2 {
		t.Errorf("ListAllWalkScanRuns() = %v, want both runs", ids(all))
	}

	for _, want := range []domain.WalkScanRun{a, b} {
		forWalk, err := store.ListWalkScanRuns(ctx, want.WalkID)
		if err != nil {
			t.Fatalf("ListWalkScanRuns(%s) on a clean store = %v, want nil", want.WalkID, err)
		}
		if len(forWalk) != 1 || forWalk[0].ID != want.ID {
			t.Errorf("ListWalkScanRuns(%s) = %v, want only %s", want.WalkID, ids(forWalk), want.ID)
		}
	}
}

// TestListWalkScanRuns_UnparseableRowIsStillReported covers the row that will
// not even say what it is. It has no id to name, and it is reported anyway:
// "there is a row here I cannot read" is an answer, and dropping it because it
// will not introduce itself would be the silent omission this change exists to
// prevent.
func TestListWalkScanRuns_UnparseableRowIsStillReported(t *testing.T) {
	ctx := t.Context()
	db, err := sqlitestore.Open(":memory:", sqlite.Migrations(), sqlitestore.IntentCreate)
	if err != nil {
		t.Fatalf("opening in-memory db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	store := sqlite.New(db)

	good := storeRun(t, store, "vscan-walk-1-good", "walk-1")
	bad := storeRun(t, store, "vscan-walk-1-bad", "walk-1")
	if _, err := db.DB().ExecContext(ctx,
		`UPDATE walk_scan_runs SET serialised = ? WHERE id = ?`,
		[]byte("not json at all"), bad.ID); err != nil {
		t.Fatalf("installing unparseable row: %v", err)
	}

	runs, err := store.ListAllWalkScanRuns(ctx)
	if len(runs) != 1 || runs[0].ID != good.ID {
		t.Fatalf("runs = %v, want only the verifiable run %s", ids(runs), good.ID)
	}
	var unreadable *ports.UnreadableRuns
	if !errors.As(err, &unreadable) {
		t.Fatalf("error = %v, want *ports.UnreadableRuns", err)
	}
	if len(unreadable.Runs) != 1 || unreadable.Runs[0].ID != "" {
		t.Fatalf("unreadable = %v, want one row with no recoverable id", unreadable.Runs)
	}
	// Bytes that cannot be examined are not claimed to be merely old.
	if errors.Is(unreadable.Runs[0].Reason, recordseal.ErrGenerationDrift) {
		t.Error("an unparseable row was reported as generation drift; absence of evidence is not evidence")
	}
}

// TestGetWalkScanRun_ReportsUnreadableRowAsSuchPins the single-row read on the
// same terms as the listings: an inspection command must be able to tell an
// unreadable row from a missing one, and a consuming caller must still classify
// it exactly as it did before.
func TestGetWalkScanRun_ReportsUnreadableRowAsSuch(t *testing.T) {
	ctx := t.Context()
	db, err := sqlitestore.Open(":memory:", sqlite.Migrations(), sqlitestore.IntentCreate)
	if err != nil {
		t.Fatalf("opening in-memory db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	store := sqlite.New(db)

	bad := storeRun(t, store, "vscan-walk-1-bad", "walk-1")
	if _, err := db.DB().ExecContext(ctx,
		`UPDATE walk_scan_runs SET serialised = ? WHERE id = ?`,
		driftBlob(t, bad), bad.ID); err != nil {
		t.Fatalf("installing drifted row: %v", err)
	}

	_, found, err := store.GetWalkScanRun(ctx, bad.ID)
	if found {
		t.Error("an unverifiable run was handed to the caller")
	}
	var unreadable *ports.UnreadableRuns
	if !errors.As(err, &unreadable) {
		t.Fatalf("error = %v, want *ports.UnreadableRuns", err)
	}
	if len(unreadable.Runs) != 1 || unreadable.Runs[0].ID != bad.ID {
		t.Errorf("unreadable = %v, want the one row named", unreadable.Runs)
	}
	if !errors.Is(unreadable.Runs[0].Reason, recordseal.ErrGenerationDrift) {
		t.Errorf("reason = %v, want generation drift", unreadable.Runs[0].Reason)
	}
	// Consuming readers of this method — the SBOM generator and vuln-scan-diff —
	// match the sentinel and must keep failing closed.
	if !errors.Is(err, ports.ErrVulnIntegrity) {
		t.Error("errors.Is(err, ErrVulnIntegrity) = false; consumers would stop failing closed")
	}

	// Absence is still absence, not an unreadable row.
	_, found, err = store.GetWalkScanRun(ctx, "vscan-absent")
	if found || err != nil {
		t.Errorf("GetWalkScanRun(absent) = (found %v, %v), want (false, nil)", found, err)
	}
}

func ids(runs []domain.WalkScanRun) []string {
	out := make([]string, 0, len(runs))
	for _, r := range runs {
		out = append(out, r.ID)
	}
	return out
}
