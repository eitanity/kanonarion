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
	for i := range 50 {
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

// -- test scope --

func TestImportedModule_TestOnly_SymbolsDecideWhenMeasured(t *testing.T) {
	cases := map[string]struct {
		mod  domain.ImportedModule
		want bool
	}{
		"every symbol from a test file": {
			mod: domain.ImportedModule{
				ImportedPackages: []string{"example.com/dep"},
				UsedSymbols:      []string{"example.com/dep.A", "example.com/dep.B"},
				TestOnlyPackages: []string{"example.com/dep"},
				TestOnlySymbols:  []string{"example.com/dep.A", "example.com/dep.B"},
			},
			want: true,
		},
		"one symbol from production": {
			mod: domain.ImportedModule{
				ImportedPackages: []string{"example.com/dep"},
				UsedSymbols:      []string{"example.com/dep.A", "example.com/dep.B"},
				TestOnlySymbols:  []string{"example.com/dep.B"},
			},
			want: false,
		},
		"import level, every package from a test file": {
			mod: domain.ImportedModule{
				ImportedPackages: []string{"example.com/dep"},
				TestOnlyPackages: []string{"example.com/dep"},
			},
			want: true,
		},
		"import level, package imported by production": {
			mod:  domain.ImportedModule{ImportedPackages: []string{"example.com/dep"}},
			want: false,
		},
		// The zero value claims nothing was measured, so it must not claim the
		// module is test-only either.
		"zero value": {mod: domain.ImportedModule{}, want: false},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got := tc.mod.TestOnly(); got != tc.want {
				t.Errorf("TestOnly() = %v, want %v", got, tc.want)
			}
		})
	}
}

// ExcludeTestScope must subtract, never re-measure: what survives has to be a
// subset of what went in, and a module with nothing left goes.
func TestExcludeTestScope_SubtractsAndDropsEmptied(t *testing.T) {
	in := []domain.ImportedModule{
		{
			Path:             "example.com/mixed",
			ImportedPackages: []string{"example.com/mixed/a", "example.com/mixed/b"},
			UsedSymbols:      []string{"example.com/mixed/a.Prod", "example.com/mixed/b.OnlyTest"},
			TestOnlyPackages: []string{"example.com/mixed/b"},
			TestOnlySymbols:  []string{"example.com/mixed/b.OnlyTest"},
		},
		{
			Path:             "example.com/testonly",
			ImportedPackages: []string{"example.com/testonly"},
			UsedSymbols:      []string{"example.com/testonly.Helper"},
			TestOnlyPackages: []string{"example.com/testonly"},
			TestOnlySymbols:  []string{"example.com/testonly.Helper"},
		},
		{
			Path:             "example.com/prod",
			ImportedPackages: []string{"example.com/prod"},
			UsedSymbols:      []string{"example.com/prod.Run"},
		},
	}

	got := domain.ExcludeTestScope(in)

	if len(got) != 2 {
		t.Fatalf("modules = %d, want 2 (the test-only module is dropped): %v", len(got), got)
	}
	if got[0].Path != "example.com/mixed" || got[1].Path != "example.com/prod" {
		t.Fatalf("surviving modules = %q, %q", got[0].Path, got[1].Path)
	}
	if len(got[0].ImportedPackages) != 1 || got[0].ImportedPackages[0] != "example.com/mixed/a" {
		t.Errorf("ImportedPackages = %v, want only the production package", got[0].ImportedPackages)
	}
	if len(got[0].UsedSymbols) != 1 || got[0].UsedSymbols[0] != "example.com/mixed/a.Prod" {
		t.Errorf("UsedSymbols = %v, want only the production symbol", got[0].UsedSymbols)
	}
	if got[0].TestOnly() || got[1].TestOnly() {
		t.Error("a narrowed answer still reports a module as test-only")
	}
	// The input is an argument, not a workspace: narrowing must not edit it.
	if len(in[0].ImportedPackages) != 2 {
		t.Errorf("input was modified: %v", in[0].ImportedPackages)
	}
}

func TestExcludeTestScope_NoTestScopeIsIdentity(t *testing.T) {
	in := []domain.ImportedModule{{
		Path:             "example.com/prod",
		ImportedPackages: []string{"example.com/prod"},
		UsedSymbols:      []string{"example.com/prod.Run"},
	}}
	got := domain.ExcludeTestScope(in)
	if len(got) != 1 || len(got[0].ImportedPackages) != 1 || len(got[0].UsedSymbols) != 1 {
		t.Errorf("ExcludeTestScope changed an answer with no test scope: %v", got)
	}
}
