package domain_test

import (
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/local/domain"
)

// -- SortModules --

func TestSortModules_SortsByPath(t *testing.T) {
	mods := []domain.ImportedModule{
		{Path: "github.com/z/z"},
		{Path: "github.com/a/a"},
		{Path: "github.com/m/m"},
	}
	domain.SortModules(mods)
	want := []string{"github.com/a/a", "github.com/m/m", "github.com/z/z"}
	for i, m := range mods {
		if m.Path != want[i] {
			t.Errorf("mods[%d].Path = %q, want %q", i, m.Path, want[i])
		}
	}
}

func TestSortModules_Empty(t *testing.T) {
	domain.SortModules(nil)
	domain.SortModules([]domain.ImportedModule{})
}

func TestSortModules_SingleElement(t *testing.T) {
	mods := []domain.ImportedModule{{Path: "github.com/foo/bar"}}
	domain.SortModules(mods)
	if mods[0].Path != "github.com/foo/bar" {
		t.Errorf("unexpected path: %q", mods[0].Path)
	}
}

// -- SnapshotModulePath --

func TestSnapshotModulePath_ReturnsModulePath(t *testing.T) {
	snap := domain.NewSnapshot(map[string][]byte{
		"/ws/go.mod": []byte("module github.com/example/app\n\ngo 1.21\n"),
	})
	got, err := domain.SnapshotModulePath(snap)
	if err != nil {
		t.Fatalf("SnapshotModulePath: %v", err)
	}
	if got != "github.com/example/app" {
		t.Errorf("module path = %q, want github.com/example/app", got)
	}
}

func TestSnapshotModulePath_NoGoMod_Error(t *testing.T) {
	snap := domain.NewSnapshot(map[string][]byte{
		"/ws/main.go": []byte("package main"),
	})
	_, err := domain.SnapshotModulePath(snap)
	if err == nil {
		t.Fatal("expected error for snapshot without go.mod")
	}
}

func TestSnapshotModulePath_EmptySnapshot_Error(t *testing.T) {
	snap := domain.NewSnapshot(map[string][]byte{})
	_, err := domain.SnapshotModulePath(snap)
	if err == nil {
		t.Fatal("expected error for empty snapshot")
	}
}

func TestSnapshotModulePath_IgnoresNonGoMod(t *testing.T) {
	snap := domain.NewSnapshot(map[string][]byte{
		"/ws/go.sum":  []byte("hash data"),
		"/ws/main.go": []byte("package main"),
		"/ws/go.mod":  []byte("module example.com/myapp\n\ngo 1.22\n"),
	})
	got, err := domain.SnapshotModulePath(snap)
	if err != nil {
		t.Fatalf("SnapshotModulePath: %v", err)
	}
	if got != "example.com/myapp" {
		t.Errorf("module path = %q, want example.com/myapp", got)
	}
}

func TestSnapshotModulePath_ModuleWithInlineComment(t *testing.T) {
	snap := domain.NewSnapshot(map[string][]byte{
		"/ws/go.mod": []byte("module example.com/app // some comment\n"),
	})
	got, err := domain.SnapshotModulePath(snap)
	if err != nil {
		t.Fatalf("SnapshotModulePath: %v", err)
	}
	if got != "example.com/app" {
		t.Errorf("module path = %q, want example.com/app (comment should be stripped)", got)
	}
}

func TestSnapshotModulePath_GoModWithoutModuleDirective_Error(t *testing.T) {
	snap := domain.NewSnapshot(map[string][]byte{
		"/ws/go.mod": []byte("go 1.21\n"),
	})
	_, err := domain.SnapshotModulePath(snap)
	if err == nil {
		t.Fatal("expected error when go.mod has no module directive")
	}
}

func TestSnapshotModulePath_NestedGoMod(t *testing.T) {
	// go.mod can live in a subdirectory — SnapshotModulePath searches by basename.
	snap := domain.NewSnapshot(map[string][]byte{
		"/ws/sub/go.mod": []byte("module example.com/sub\n"),
	})
	got, err := domain.SnapshotModulePath(snap)
	if err != nil {
		t.Fatalf("SnapshotModulePath: %v", err)
	}
	if got != "example.com/sub" {
		t.Errorf("module path = %q, want example.com/sub", got)
	}
}

func TestSnapshotModulePath_PrefersRootGoModOverNested(t *testing.T) {
	// Regression: a workspace containing nested fixture go.mod files (e.g. the
	// kanonarion repo's own test/fixtures/) must resolve to the workspace
	// root's go.mod, not a deeper one picked by map-iteration order.
	snap := domain.NewSnapshot(map[string][]byte{
		"/ws/go.mod": []byte("module github.com/eitanity/kanonarion\n"),
		"/ws/test/fixtures/supplychain/fips/dep/go.mod":     []byte("module example.com/supplychain/fips/md5-in-dep\n"),
		"/ws/test/fixtures/supplychain/license/dep/go.mod":  []byte("module example.com/supplychain/license/conflict\n"),
		"/ws/test/fixtures/supplychain/vendored/app/go.mod": []byte("module example.com/supplychain/vendored\n"),
	})
	for i := 0; i < 50; i++ {
		// Loop to defeat map-iteration randomisation even on the off-chance
		// the buggy implementation happens to pick the root on the first try.
		got, err := domain.SnapshotModulePath(snap)
		if err != nil {
			t.Fatalf("iter %d: SnapshotModulePath: %v", i, err)
		}
		if got != "github.com/eitanity/kanonarion" {
			t.Fatalf("iter %d: module path = %q, want github.com/eitanity/kanonarion (root go.mod)", i, got)
		}
	}
}

func TestSnapshotModulePath_PrefersShortestPathTieBrokenLexicographically(t *testing.T) {
	// When two go.mods sit at the same depth, the lexicographically smaller
	// path wins — deterministic regardless of map iteration order.
	snap := domain.NewSnapshot(map[string][]byte{
		"/ws/zzz/go.mod": []byte("module example.com/zzz\n"),
		"/ws/aaa/go.mod": []byte("module example.com/aaa\n"),
	})
	got, err := domain.SnapshotModulePath(snap)
	if err != nil {
		t.Fatalf("SnapshotModulePath: %v", err)
	}
	if got != "example.com/aaa" {
		t.Errorf("module path = %q, want example.com/aaa (lexicographically smaller)", got)
	}
}

func TestSnapshotModulePath_ModulePathPreservedExactly(t *testing.T) {
	path := "github.com/eitanity/kanonarion"
	snap := domain.NewSnapshot(map[string][]byte{
		"/ws/go.mod": []byte("module " + path + "\n"),
	})
	got, err := domain.SnapshotModulePath(snap)
	if err != nil {
		t.Fatalf("SnapshotModulePath: %v", err)
	}
	if got != path {
		t.Errorf("module path = %q, want %q", got, path)
	}
}

func TestSnapshotModulePath_LeadingWhitespaceInModuleLine(t *testing.T) {
	snap := domain.NewSnapshot(map[string][]byte{
		"/ws/go.mod": []byte("  module   example.com/spaces  \n"),
	})
	got, err := domain.SnapshotModulePath(snap)
	if err != nil {
		t.Fatalf("SnapshotModulePath: %v", err)
	}
	if strings.Contains(got, " ") {
		t.Errorf("module path %q contains whitespace, expected trimmed", got)
	}
}
