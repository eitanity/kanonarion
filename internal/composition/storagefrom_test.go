package composition_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"code.eitanity.com/kanonarion/internal/composition"
	"code.eitanity.com/kanonarion/internal/composition/storage"
	sqlitestorage "code.eitanity.com/kanonarion/internal/composition/storage/sqlite"
	walkports "code.eitanity.com/kanonarion/internal/walk/ports"
)

// oneWalkStore is a walk store that is not SQLite: it holds one walk and
// answers presence for any id.
type oneWalkStore struct {
	walkports.WalkStore
	summary walkports.WalkSummary
}

func (s oneWalkStore) ListWalks(context.Context, walkports.WalkFilter) ([]walkports.WalkSummary, error) {
	return []walkports.WalkSummary{s.summary}, nil
}

func (oneWalkStore) PresentWalks(_ context.Context, ids []string) (map[string]bool, error) {
	out := make(map[string]bool, len(ids))
	for _, id := range ids {
		out[id] = true
	}
	return out, nil
}

// sqliteStorage opens the SQLite backend on a temp root and counts closes.
func sqliteStorage(t *testing.T) (*storage.Storage, *int) {
	t.Helper()
	st, err := sqlitestorage.Open(storage.Request{StoreRoot: t.TempDir(), Intent: storage.IntentCreate})
	if err != nil {
		t.Fatalf("opening the SQLite backend: %v", err)
	}
	closes := new(int)
	inner := st.Close
	st.Close = func() error { *closes++; return inner() }
	return st, closes
}

func TestNewQueriesFrom_ReadsThroughTheSuppliedWalkStore(t *testing.T) {
	st, _ := sqliteStorage(t)
	st.Walks = oneWalkStore{summary: walkports.WalkSummary{ID: "walk-from-another-backend"}}

	q, cleanup, err := composition.NewQueriesFrom(st)
	if err != nil {
		t.Fatalf("NewQueriesFrom: %v", err)
	}
	defer func() {
		if cerr := cleanup(); cerr != nil {
			t.Errorf("cleanup: %v", cerr)
		}
	}()
	walks, err := q.Walks.ListWalks(context.Background(), walkports.WalkFilter{})
	if err != nil {
		t.Fatalf("ListWalks: %v", err)
	}
	if len(walks) != 1 || walks[0].ID != "walk-from-another-backend" {
		t.Errorf("ListWalks = %+v, want the one walk the supplied store holds", walks)
	}
}

func TestNewQueriesFrom_RefusesAnIncompleteValueAndClosesIt(t *testing.T) {
	st, closes := sqliteStorage(t)
	st.Walks = nil
	if _, cleanup, err := composition.NewQueriesFrom(st); err == nil || cleanup != nil || err.Error() != "storage: Walks is unset" {
		t.Fatalf("NewQueriesFrom = (cleanup %v, %v), want the Validate refusal and no cleanup", cleanup != nil, err)
	}
	if *closes != 1 {
		t.Errorf("Close called %d times, want 1", *closes)
	}
}

func TestNewDriverFrom_ReturnsTheWritableRefusalAndClosesOnce(t *testing.T) {
	st, closes := sqliteStorage(t)
	refusal := fmt.Errorf("%w: test store", composition.ErrStoreSchemaNewer)
	st.Writable = func(context.Context) error { return refusal }

	drv, cleanup, err := composition.NewDriverFrom(st, t.TempDir())
	if !errors.Is(err, composition.ErrStoreSchemaNewer) || !errors.Is(err, refusal) {
		t.Fatalf("NewDriverFrom = %v, want the Writable refusal", err)
	}
	if drv != nil || cleanup != nil {
		t.Error("a refused driver must hand back no driver and no cleanup")
	}
	if *closes != 1 {
		t.Errorf("Close called %d times, want exactly 1", *closes)
	}
}

func TestNewDriverFrom_BuildsWithANilSigner(t *testing.T) {
	st, closes := sqliteStorage(t)
	st.Signer = nil

	drv, cleanup, err := composition.NewDriverFrom(st, t.TempDir())
	if err != nil {
		t.Fatalf("NewDriverFrom with a nil Signer: %v", err)
	}
	if drv == nil || drv.FetchServe == nil || drv.LocalWalkExtract == nil || drv.ValidateIngest == nil {
		t.Fatalf("NewDriverFrom built an incomplete driver: %+v", drv)
	}
	if cerr := cleanup(); cerr != nil {
		t.Fatalf("cleanup: %v", cerr)
	}
	if *closes != 1 {
		t.Errorf("Close called %d times, want 1", *closes)
	}
}

func TestNewDriverFrom_RefusesAnEmptyStoreRoot(t *testing.T) {
	st, closes := sqliteStorage(t)
	_, _, err := composition.NewDriverFrom(st, "")
	if err == nil || !strings.Contains(err.Error(), "empty store root") {
		t.Fatalf("NewDriverFrom = %v, want the empty-root refusal", err)
	}
	if *closes != 1 {
		t.Errorf("Close called %d times, want 1", *closes)
	}
}

func TestNewDriverFrom_RefusesAnIncompleteValue(t *testing.T) {
	st, closes := sqliteStorage(t)
	st.Facts = nil
	if _, _, err := composition.NewDriverFrom(st, t.TempDir()); err == nil || err.Error() != "storage: Facts is unset" {
		t.Fatalf("NewDriverFrom = %v, want the Validate refusal", err)
	}
	if *closes != 1 {
		t.Errorf("Close called %d times, want 1", *closes)
	}
}

// Reading a store, or being refused one, must not create its assurance log;
// only a writable open does.
func TestNewQueries_LeavesNoAuditLog(t *testing.T) {
	root := t.TempDir()
	seed, cleanup, err := composition.NewDriver(root)
	if err != nil {
		t.Fatalf("seeding a store: %v", err)
	}
	_ = seed
	if cerr := cleanup(); cerr != nil {
		t.Fatal(cerr)
	}
	// A store whose ledger is missing, so the read is the only candidate.
	if rerr := os.Remove(filepath.Join(root, "audit.jsonl")); rerr != nil {
		t.Fatalf("removing the seeded ledger: %v", rerr)
	}

	_, cleanup, err = composition.NewQueries(root)
	if err != nil {
		t.Fatalf("NewQueries: %v", err)
	}
	if cerr := cleanup(); cerr != nil {
		t.Fatal(cerr)
	}
	assertNoAuditLog(t, root, "NewQueries")
}

func TestNewDriver_RefusalLeavesNoAuditLog(t *testing.T) {
	root := seedStoreWithUnknownMigration(t)
	assertNoAuditLog(t, root, "the seeded store")
	if _, _, err := composition.NewDriver(root); !errors.Is(err, composition.ErrStoreSchemaNewer) {
		t.Fatalf("NewDriver = %v, want the newer-schema refusal", err)
	}
	assertNoAuditLog(t, root, "a refused NewDriver")
}

func assertNoAuditLog(t *testing.T, root, after string) {
	t.Helper()
	if _, err := os.Stat(filepath.Join(root, "audit.jsonl")); !os.IsNotExist(err) {
		t.Errorf("after %s, stat audit.jsonl = %v, want not-exist", after, err)
	}
}
