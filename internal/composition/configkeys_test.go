package composition_test

import (
	"os"
	"path/filepath"
	"testing"

	"code.eitanity.com/kanonarion/internal/composition"
)

// The library entry point refuses a misspelt key as the CLI does, naming the
// file, and loads the SQLite backend's own section.
func TestNewQueries_RefusesAnUnknownConfigKey(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "config.yaml")
	if err := os.WriteFile(path, []byte("version: \"3\"\nlicence_policy: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, err := composition.NewQueries(root)
	want := `loading store configuration: unknown key "licence_policy" in ` + path + ` (did you mean "license_policy"?)`
	if err == nil || err.Error() != want {
		t.Fatalf("err = %v\nwant %s", err, want)
	}

	if werr := os.WriteFile(path, []byte("version: \"3\"\nsqlite:\n  # nothing set\n"), 0o600); werr != nil {
		t.Fatal(werr)
	}
	if got := composition.BackendSections(); len(got) != 1 || got[0] != "sqlite" {
		t.Fatalf("BackendSections = %v, want [sqlite]", got)
	}
	_, cleanup, err := composition.NewQueries(root)
	if err != nil {
		t.Fatalf("sqlite section refused: %v", err)
	}
	if err := cleanup(); err != nil {
		t.Fatal(err)
	}
}
