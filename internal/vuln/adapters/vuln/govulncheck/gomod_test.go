package govulncheck

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A published multi-module member's own filesystem replace (the otel/trace
// shape: `replace <sibling> => ../`) is dropped so the scan resolves the
// sibling from the module cache instead of a path absent from the zip.
func TestNeutraliseLocalReplaces_DropsFilesystemReplaces(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "go.mod")
	src := `module example.com/otel/trace

go 1.24

require example.com/otel v1.41.0

replace example.com/otel => ../

replace example.com/otel/metric => ../metric
`
	// Extracted go.mod entries are read-only; the helper must handle that.
	if err := os.WriteFile(path, []byte(src), 0o444); err != nil { // #nosec G306 -- read-only on purpose to exercise the chmod path
		t.Fatalf("write go.mod: %v", err)
	}

	changed, err := neutraliseLocalReplaces(path)
	if err != nil {
		t.Fatalf("neutraliseLocalReplaces: %v", err)
	}
	if !changed {
		t.Fatal("changed = false, want true (filesystem replaces present)")
	}

	out, err := os.ReadFile(path) // #nosec G304 -- test-owned temp path
	if err != nil {
		t.Fatalf("read go.mod: %v", err)
	}
	got := string(out)
	if strings.Contains(got, "replace") {
		t.Errorf("go.mod still contains a replace directive after neutralising:\n%s", got)
	}
	// The require must survive so the sibling resolves normally from the cache.
	if !strings.Contains(got, "require example.com/otel v1.41.0") {
		t.Errorf("require directive was lost:\n%s", got)
	}
}

// A module-to-module (versioned) replace names a resolvable coordinate and must
// be preserved — only filesystem replaces are development artefacts.
func TestNeutraliseLocalReplaces_KeepsVersionedReplaces(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "go.mod")
	src := `module example.com/app

go 1.24

require example.com/dep v1.0.0

replace example.com/dep => example.com/fork v1.2.0
`
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}

	changed, err := neutraliseLocalReplaces(path)
	if err != nil {
		t.Fatalf("neutraliseLocalReplaces: %v", err)
	}
	if changed {
		t.Fatal("changed = true, want false (only a versioned replace present)")
	}
	out, err := os.ReadFile(path) // #nosec G304 -- test-owned temp path
	if err != nil {
		t.Fatalf("read go.mod: %v", err)
	}
	if !strings.Contains(string(out), "example.com/fork v1.2.0") {
		t.Errorf("versioned replace was dropped:\n%s", string(out))
	}
}

// A go.mod with no replace directives is left untouched.
func TestNeutraliseLocalReplaces_NoReplaces(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "go.mod")
	if err := os.WriteFile(path, []byte("module example.com/app\n\ngo 1.24\n"), 0o600); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}
	changed, err := neutraliseLocalReplaces(path)
	if err != nil {
		t.Fatalf("neutraliseLocalReplaces: %v", err)
	}
	if changed {
		t.Error("changed = true, want false (no replaces)")
	}
}
