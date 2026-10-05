package sqlite_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/adapters/recordseal"
	"github.com/eitanity/kanonarion/internal/adapters/sqlitestore"
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

// tamperBlob is run's stored bytes with one byte of its walk id flipped and the
// seal left alone: the bytes no longer hash to the seal they carry.
func tamperBlob(t *testing.T, run domain.WalkScanRun) []byte {
	t.Helper()
	blob, err := domain.WalkScanRunHasher{}.Marshal(run)
	if err != nil {
		t.Fatalf("marshalling run: %v", err)
	}
	from := []byte(`"walk_id":"` + run.WalkID + `"`)
	if bytes.Count(blob, from) != 1 {
		t.Fatalf("fixture has %d walk ids, want exactly 1", bytes.Count(blob, from))
	}
	to := append([]byte(nil), from...)
	to[len(to)-2] ^= 0x01
	return bytes.Replace(blob, from, to, 1)
}

// TestListWalkScanRuns_SetsDriftedRunAsideAndKeepsTheRest is the regression: a
// run this build cannot reproduce is set aside and named by its seal, the good
// rows survive it, and nothing reports it as tampering — a consuming command no
// longer fails closed on it.
func TestListWalkScanRuns_SetsDriftedRunAsideAndKeepsTheRest(t *testing.T) {
	ctx := t.Context()
	db, err := sqlitestore.Open(":memory:", sqlite.Migrations(), sqlitestore.IntentCreate)
	if err != nil {
		t.Fatalf("opening in-memory db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	store := sqlite.New(db)

	good := storeRun(t, store, "vscan-walk-1-good", "walk-1")
	bad := storeRun(t, store, "vscan-walk-1-bad", "walk-1")
	drifted := driftBlob(t, bad)
	if _, err := db.DB().ExecContext(ctx,
		`UPDATE walk_scan_runs SET serialised = ? WHERE id = ?`, drifted, bad.ID); err != nil {
		t.Fatalf("installing drifted row: %v", err)
	}
	var head struct {
		ContentHash string `json:"content_hash"`
	}
	if err := json.Unmarshal(drifted, &head); err != nil {
		t.Fatal(err)
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
			var aside *recordseal.SetAside
			if !errors.As(err, &aside) || len(aside.Rows) != 1 {
				t.Fatalf("error = %v, want one *recordseal.SetAside row", err)
			}
			row := aside.Rows[0]
			if row.ID != bad.ID || row.Kind != ports.SetAsideKindRun || row.ContentHash != head.ContentHash {
				t.Errorf("set aside = %+v, want run %s named by %s", row, bad.ID, head.ContentHash)
			}
			if errors.Is(err, ports.ErrVulnIntegrity) {
				t.Error("a drifted run was reported as an integrity failure")
			}
		})
	}

	// Tamper control: one altered run makes the listing an integrity failure,
	// the drifted run included so a survey still lists them all.
	altered := storeRun(t, store, "vscan-walk-1-altered", "walk-1")
	if _, err := db.DB().ExecContext(ctx,
		`UPDATE walk_scan_runs SET serialised = ? WHERE id = ?`, tamperBlob(t, altered), altered.ID); err != nil {
		t.Fatalf("installing altered row: %v", err)
	}
	runs, err := store.ListWalkScanRuns(ctx, "walk-1")
	var unreadable *ports.UnreadableRows
	if !errors.As(err, &unreadable) || !errors.Is(err, ports.ErrVulnIntegrity) || len(unreadable.Rows) != 2 {
		t.Fatalf("error = %v, want *ports.UnreadableRows naming both rows and ErrVulnIntegrity", err)
	}
	if len(runs) != 1 || runs[0].ID != good.ID {
		t.Errorf("runs = %v, want only %s", ids(runs), good.ID)
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
	var unreadable *ports.UnreadableRows
	if !errors.As(err, &unreadable) {
		t.Fatalf("error = %v, want *ports.UnreadableRows", err)
	}
	if len(unreadable.Rows) != 1 || unreadable.Rows[0].ID != "" {
		t.Fatalf("unreadable = %v, want one row with no recoverable id", unreadable.Rows)
	}
	// Bytes that cannot be examined are not claimed to be merely old.
	if errors.Is(unreadable.Rows[0].Reason, recordseal.ErrGenerationDrift) {
		t.Error("an unparseable row was reported as generation drift; absence of evidence is not evidence")
	}
}

// TestGetWalkScanRun_DriftIsNothingServableAndTamperIsIntegrity pins the
// single-row read: a run this build cannot reproduce has no other generation to
// serve, so the answer is NothingServable naming its seal, never the integrity
// sentinel; an altered run is still an unreadable row that fails closed.
func TestGetWalkScanRun_DriftIsNothingServableAndTamperIsIntegrity(t *testing.T) {
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
	var none *recordseal.NothingServable
	if !errors.As(err, &none) || len(none.Aside.Rows) != 1 || none.Aside.Rows[0].ID != bad.ID {
		t.Fatalf("error = %v, want *recordseal.NothingServable naming %s", err, bad.ID)
	}
	if !errors.Is(err, recordseal.ErrGenerationDrift) || errors.Is(err, ports.ErrVulnIntegrity) {
		t.Errorf("error = %v, want drift and not the integrity sentinel", err)
	}

	altered := storeRun(t, store, "vscan-walk-1-altered", "walk-1")
	if _, err := db.DB().ExecContext(ctx,
		`UPDATE walk_scan_runs SET serialised = ? WHERE id = ?`, tamperBlob(t, altered), altered.ID); err != nil {
		t.Fatalf("installing altered row: %v", err)
	}
	_, _, err = store.GetWalkScanRun(ctx, altered.ID)
	var unreadable *ports.UnreadableRows
	if !errors.As(err, &unreadable) || !errors.Is(err, ports.ErrVulnIntegrity) {
		t.Errorf("altered run: error = %v, want *ports.UnreadableRows and ErrVulnIntegrity", err)
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
