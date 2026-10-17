package tinycgo

import (
	"os"
	"path/filepath"
	"testing"
)

// linkTargets makes root/targets hold testdata/<dir>'s definitions.
func linkTargets(t *testing.T, root, dir string) {
	t.Helper()
	abs, err := filepath.Abs(filepath.Join("testdata", dir))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(abs, filepath.Join(root, "targets")); err != nil {
		t.Fatal(err)
	}
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}
