package composition_test

import (
	"bytes"
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/adapters/blobcodec"
	"github.com/eitanity/kanonarion/internal/composition"
	"github.com/eitanity/kanonarion/internal/driver"
)

// One tree analysed from two checkouts is one walk: the root carries no
// directory, so the identity matches and the second run reuses the first walk,
// and neither absolute directory reaches the sealed walk or the fetch ledger.
func TestLocalWalkExtract_AnalyseLocalRoot_TwoCheckoutsAreOneWalk(t *testing.T) {
	storeRoot := t.TempDir()
	const source = "// Package proj is the project root.\npackage proj\n"
	dirs := []string{writeProject(t, source), writeProject(t, source)}

	drv, cleanup, err := composition.NewDriver(storeRoot)
	if err != nil {
		t.Fatalf("NewDriver: %v", err)
	}
	var ids, identities []string
	for _, dir := range dirs {
		res, rerr := drv.LocalWalkExtract.Run(context.Background(), driver.LocalWalkExtractRequest{
			Dir:              dir,
			Stages:           []string{"license"},
			AnalyseLocalRoot: true,
		})
		if rerr != nil {
			t.Fatalf("Run %s: %v", dir, rerr)
		}
		ids = append(ids, res.Walk.ID)
		identities = append(identities, res.Walk.IdentityHash)
	}
	mustClose(t, cleanup)

	if identities[0] == "" || identities[0] != identities[1] {
		t.Errorf("identity hashes = %q, want one non-empty identity for both checkouts", identities)
	}
	if ids[0] != ids[1] {
		t.Errorf("walk ids = %q, want the second checkout to reuse the first walk", ids)
	}

	sealed, details := readSealedWalksAndFetchDetails(t, filepath.Join(storeRoot, "mirror.db"))
	if len(sealed) != 1 {
		t.Errorf("stored walks = %d, want 1", len(sealed))
	}
	if len(details) == 0 {
		t.Fatal("no fetch record for the analysed root")
	}
	for _, dir := range dirs {
		for _, raw := range sealed {
			if bytes.Contains(raw, []byte(dir)) {
				t.Errorf("sealed walk carries the checkout directory %s", dir)
			}
		}
		for _, d := range details {
			if strings.Contains(d, dir) {
				t.Errorf("fetch_records verification_detail %q carries the checkout directory", d)
			}
		}
	}
}

// readSealedWalksAndFetchDetails returns every stored walk's decoded sealed
// bytes and every fetch_records verification_detail.
func readSealedWalksAndFetchDetails(t *testing.T, dbPath string) ([][]byte, []string) {
	t.Helper()
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("opening the store: %v", err)
	}
	defer func() {
		if cerr := db.Close(); cerr != nil {
			t.Errorf("closing the store: %v", cerr)
		}
	}()
	var sealed [][]byte
	for _, blob := range queryColumn[[]byte](t, db, `SELECT serialised FROM walks`) {
		raw, derr := blobcodec.Decode(blob)
		if derr != nil {
			t.Fatalf("decoding walk: %v", derr)
		}
		sealed = append(sealed, raw)
	}
	return sealed, queryColumn[string](t, db, `SELECT verification_detail FROM fetch_records`)
}

// queryColumn reads the single column q selects.
func queryColumn[T any](t *testing.T, db *sql.DB, q string) []T {
	t.Helper()
	rows, err := db.Query(q)
	if err != nil {
		t.Fatalf("%s: %v", q, err)
	}
	defer func() {
		if cerr := rows.Close(); cerr != nil {
			t.Errorf("closing rows: %v", cerr)
		}
	}()
	var out []T
	for rows.Next() {
		var v T
		if serr := rows.Scan(&v); serr != nil {
			t.Fatalf("%s: scanning: %v", q, serr)
		}
		out = append(out, v)
	}
	if rerr := rows.Err(); rerr != nil {
		t.Fatalf("%s: %v", q, rerr)
	}
	return out
}
