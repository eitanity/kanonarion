package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
)

// The .info use derives carries the version's own time as the go command writes
// it, or no Time at all when the record holds none; never the fetch time. An
// Origin field the record does not hold is left out, as the go command does.
func TestWriteDerivedModCacheFiles_VersionTime(t *testing.T) {
	const tagged = `"Origin":{"VCS":"git","URL":"https://go.googlesource.com/text","Hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","Ref":"refs/tags/v0.42.0"}}`
	// A pseudo-version has no ref, and the go command leaves the key out.
	const pseudo = `"Origin":{"VCS":"git","URL":"https://go.googlesource.com/text","Hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}`
	cases := []struct {
		name, version, ref string
		versionTime        fetchdomain.VersionTime
		want               string
	}{
		{"tagged with time", "v0.42.0", "refs/tags/v0.42.0", "2026-09-08T16:29:55Z",
			`{"Version":"v0.42.0","Time":"2026-09-08T16:29:55Z",` + tagged},
		{"tagged without time", "v0.42.0", "refs/tags/v0.42.0", "",
			`{"Version":"v0.42.0",` + tagged},
		{"pseudo-version with time", "v0.0.0-20260908162955-aaaaaaaaaaaa", "", "2026-09-08T16:29:55.5Z",
			`{"Version":"v0.0.0-20260908162955-aaaaaaaaaaaa","Time":"2026-09-08T16:29:55.5Z",` + pseudo},
		{"pseudo-version without time", "v0.0.0-20260908162955-aaaaaaaaaaaa", "", "",
			`{"Version":"v0.0.0-20260908162955-aaaaaaaaaaaa",` + pseudo},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			root, err := os.OpenRoot(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = root.Close() }()
			rec := fetchdomain.CompositeRecord{
				FactRecord: fetchdomain.FactRecord{
					GitURL: "https://go.googlesource.com/text", GitRef: tc.ref,
					GitCommitHash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", GitSubdir: fetchdomain.RepoRoot,
					VersionTime: tc.versionTime,
				},
				FirstFetchedAt: time.Date(2026, 9, 20, 21, 11, 10, 0, time.UTC),
			}
			coord := coordinatetest.MustNew("golang.org/x/text", tc.version)
			if err = writeDerivedModCacheFiles(root, rec, coord, "."); err != nil {
				t.Fatalf("writeDerivedModCacheFiles: %v", err)
			}
			got, err := os.ReadFile(filepath.Join(dir, tc.version+".info"))
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tc.want {
				t.Errorf(".info =\n%s\nwant\n%s", got, tc.want)
			}
		})
	}
}

// A recorded version time that is not a time is refused before anything is
// written, rather than left out as if unknown.
func TestWriteDerivedModCacheFiles_UnparseableVersionTimeIsRefused(t *testing.T) {
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	rec := fetchdomain.CompositeRecord{FactRecord: fetchdomain.FactRecord{VersionTime: "yesterday"}}
	err = writeDerivedModCacheFiles(root, rec, coordinatetest.MustNew("golang.org/x/text", "v0.42.0"), ".")
	if err == nil || !strings.Contains(err.Error(), "golang.org/x/text@v0.42.0") {
		t.Fatalf("writeDerivedModCacheFiles = %v, want a refusal naming the module", err)
	}
	if _, serr := os.Stat(filepath.Join(dir, "v0.42.0.info")); !os.IsNotExist(serr) {
		t.Errorf(".info was written for a record whose time does not parse: %v", serr)
	}
}

// A record with no git provenance writes no empty URL, Hash or Ref.
func TestWriteDerivedModCacheFiles_OriginLeavesOutWhatTheRecordDoesNotHold(t *testing.T) {
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	err = writeDerivedModCacheFiles(root, fetchdomain.CompositeRecord{}, coordinatetest.MustNew("example.com/m", "v1.0.0"), ".")
	if err != nil {
		t.Fatalf("writeDerivedModCacheFiles: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "v1.0.0.info"))
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"Version":"v1.0.0","Origin":{"VCS":"git"}}`; string(got) != want {
		t.Errorf(".info = %s, want %s", got, want)
	}
}
