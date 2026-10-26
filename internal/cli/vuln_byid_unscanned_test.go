package cli

import (
	"context"
	"path/filepath"
	"testing"

	"code.eitanity.com/kanonarion/internal/adapters/sqlitestore"
	"code.eitanity.com/kanonarion/internal/coordinate"
)

// A walk the store holds but never scanned is an absent record: vuln-by-id and
// its --timeline exit 4 with the one sentence vuln-show prints, unwrapped.
func TestVulnByID_AWalkNeverScannedIsNotFound(t *testing.T) {
	fixture, treeDir, host := upgradeStoreHost(t)
	ctx := context.Background()
	db, err := sqlitestore.Open(filepath.Join(fixture, "mirror.db"), nil, sqlitestore.IntentCreate)
	if err != nil {
		t.Fatal(err)
	}
	if aerr := sqlitestore.Apply(db, allMigrations()); aerr != nil {
		t.Fatal(aerr)
	}
	root, err := coordinate.NewLocalCoordinate(jsonDocRootPath)
	if err != nil {
		t.Fatal(err)
	}
	seedProjectWalk(t, ctx, db, root, host, treeDir, seedWalkSpec{walkID: seedNewWalkID, toolchain: host.toolchain, at: jsonDocAt})
	_ = db.Close()

	want := "no vulnerability scan run for walk " + seedNewWalkID + " — run: kanonarion vuln-scan " + seedNewWalkID
	for _, args := range [][]string{
		{"vuln-by-id", jsonDocFindingID, "--walk-id", seedNewWalkID},
		{"vuln-by-id", jsonDocFindingID, "--walk-id", seedNewWalkID, "--json"},
		{"vuln-by-id", jsonDocFindingID, "--walk-id", seedNewWalkID, "--timeline"},
	} {
		_, _, err := runAside(append(args, "--store-root", fixture)...)
		if code := ExitCodeForError(err); code != ExitNotFound {
			t.Errorf("%v: exit %d (%v), want %d", args, code, err, ExitNotFound)
			continue
		}
		if got := err.Error(); got != want && got != "execute root command: "+want {
			t.Errorf("%v: message %q, want the sentence once: %q", args, got, want)
		}
	}
}
