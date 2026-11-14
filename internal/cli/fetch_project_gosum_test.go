package cli

import (
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"

	_ "modernc.org/sqlite"
)

// pubRecord reads the stored verification status of the fixture's public
// module, and how many fetch records the store holds.
func (fx *privateFixture) pubRecord(t *testing.T) (status string, records int) {
	t.Helper()
	if _, err := os.Stat(filepath.Join(fx.store, "mirror.db")); err != nil {
		return "", 0
	}
	db, err := sql.Open("sqlite", filepath.Join(fx.store, "mirror.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	if err := db.QueryRow(`SELECT count(*) FROM fetch_records`).Scan(&records); err != nil {
		t.Fatal(err)
	}
	_ = db.QueryRow(`SELECT verification_status FROM fetch_records WHERE module_path = 'example.org/pub'`).Scan(&status) //nolint:errcheck // no row leaves status empty
	return status, records
}

// TestFetchGoMod_ProjectGoSumAnchorsEveryModule: with the checksum database
// switched off, a fetch naming --gomod verifies a public module against that
// project's go.sum, as audit does; without --gomod nothing anchors it, even
// run inside the project.
func TestFetchGoMod_ProjectGoSumAnchorsEveryModule(t *testing.T) {
	fx := buildPrivateFixture(t)
	t.Setenv("GOSUMDB", "off")
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"fetch", "--gomod", "./go.mod", "--skip-vcs-verify"}, "VerifiedByGoSum"},
		{[]string{"fetch", "example.org/pub@v1.0.0", "--gomod", "./go.mod", "--skip-vcs-verify"}, "VerifiedByGoSum"},
		{[]string{"fetch", "example.org/pub@v1.0.0", "--skip-vcs-verify"}, "UnverifiedNoSumDB"},
	} {
		run := fx.run(t, fx.project, tc.args...)
		if status, _ := fx.pubRecord(t); run.exit != ExitOK || status != tc.want {
			t.Errorf("%v: exit %d, example.org/pub = %q; want exit 0 and %s\nstderr:\n%s", tc.args, run.exit, status, tc.want, run.stderr)
		}
	}
}

// TestFetchGoMod_GoSumMismatchWritesNoRecord: a go.sum line that disagrees
// with the fetched bytes is the hard failure audit gives, and nothing is
// recorded for the module. The scope fetch meets the go command's own refusal
// first, while it lists the scope.
func TestFetchGoMod_GoSumMismatchWritesNoRecord(t *testing.T) {
	fx := buildPrivateFixture(t)
	t.Setenv("GOSUMDB", "off")
	goSum := filepath.Join(fx.project, "go.sum")
	body, err := os.ReadFile(goSum) // #nosec G304 -- a path under this test's temp dir
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, l := range strings.Split(string(body), "\n") {
		if f := strings.Fields(l); len(f) == 3 && f[0] == "example.org/pub" && f[1] == "v1.0.0" {
			l = f[0] + " " + f[1] + " h1:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="
		}
		lines = append(lines, l)
	}
	writePrivateFixtureFile(t, goSum, strings.Join(lines, "\n"))
	for _, args := range [][]string{
		{"fetch", "--gomod", "./go.mod", "--skip-vcs-verify"},
		{"fetch", "example.org/pub@v1.0.0", "--gomod", "./go.mod", "--skip-vcs-verify"},
	} {
		run := fx.run(t, fx.project, args...)
		status, _ := fx.pubRecord(t)
		if run.exit == ExitOK || status != "" || !strings.Contains(run.stderr, "go.sum") {
			t.Errorf("%v: exit %d, example.org/pub = %q; want a go.sum failure and no record\nstderr:\n%s", args, run.exit, status, run.stderr)
		}
	}
}

// TestInvalidGOSUMDB_RefusedBeforeAnyRecord: a GOSUMDB the go command refuses
// stops fetch and the container's commands at exit 20, naming the value,
// with no record written.
func TestInvalidGOSUMDB_RefusedBeforeAnyRecord(t *testing.T) {
	fx := buildPrivateFixture(t)
	t.Setenv("GOSUMDB", "a b c")
	for _, args := range [][]string{
		{"fetch", "example.org/pub@v1.0.0"},
		{"fetch", "--gomod", "./go.mod"},
		{"audit", "--gomod", "./go.mod"},
	} {
		run := fx.run(t, fx.project, args...)
		if _, records := fx.pubRecord(t); run.exit != ExitConfig || records != 0 ||
			!strings.Contains(run.stderr, `invalid GOSUMDB "a b c"`) {
			t.Errorf("%v: exit %d, %d fetch records; want exit 20 naming GOSUMDB and none\nstderr:\n%s", args, run.exit, records, run.stderr)
		}
	}
}
