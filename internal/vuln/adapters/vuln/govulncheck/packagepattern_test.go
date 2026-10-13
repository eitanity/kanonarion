package govulncheck

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
)

// writeTree writes files (slash paths relative to root) with the given bodies.
func writeTree(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for rel, body := range files {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
}

func importing(pkg, path string) string {
	return "package " + pkg + "\n\nimport _ \"" + path + "\"\n"
}

// A pre-modules zip with code where "./..." does not reach: only the module's
// own packages contribute requires. This is the shape that gave
// github.com/go-chi/chi@v3.3.4+incompatible requires from _examples/.
func TestCollectImports_ReadsOnlyWhatThePackagePatternMatches(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"chi.go":                    importing("chi", "example.com/kept"),
		"sub/sub.go":                importing("sub", "example.com/kept/sub"),
		"_examples/main.go":         importing("main", "example.com/underscore-dir"),
		".hidden/h.go":              importing("h", "example.com/dot-dir"),
		"testdata/td.go":            importing("td", "example.com/testdata"),
		"vendor/example.com/v/v.go": importing("v", "example.com/vendored"),
		"_helper.go":                importing("chi", "example.com/underscore-file"),
		"sub/.dot.go":               importing("sub", "example.com/dot-file"),
		"nested/go.mod":             "module example.com/nested\n",
		"nested/n.go":               importing("nested", "example.com/nested-module"),
	})
	got, skipped := collectImports(root)
	want := []string{"example.com/kept", "example.com/kept/sub"}
	if !slices.Equal(got, want) || len(skipped) != 0 {
		t.Errorf("collectImports = %v (skipped %v), want %v", got, skipped, want)
	}
}

// The scan root itself may carry a name the go tool would ignore below it; it is
// the root, so it is read.
func TestCollectImports_RootIsReadWhateverItsName(t *testing.T) {
	root := filepath.Join(t.TempDir(), "_root@v1.0.0")
	writeTree(t, root, map[string]string{"a.go": importing("a", "example.com/kept")})
	if got, _ := collectImports(root); !slices.Equal(got, []string{"example.com/kept"}) {
		t.Errorf("collectImports = %v, want the root's own import", got)
	}
}

// The binary-mode pick takes the first package "./..." matches. "_examples"
// sorts before every lower-case directory, so it was picked first.
func TestFindFirstGoPackage_SkipsWhatThePackagePatternSkips(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"_examples/main.go": "package main\n",
		".github/x.go":      "package x\n",
		"a_nested/go.mod":   "module example.com/nested\n",
		"a_nested/n.go":     "package nested\n",
		"b/_gen.go":         "package b\n",
		"b/b_test.go":       "package b\n",
		"c/c.go":            "package c\n",
		"testdata/t.go":     "package t\n",
		"vendor/v/v.go":     "package v\n",
	})
	if got := findFirstGoPackage(root); got != "./c" {
		t.Errorf("findFirstGoPackage = %q, want ./c", got)
	}
}

// A pre-modules zip with a go.mod below its root is still a module without one:
// the nested file is a separate module or ignored code, not this module's root.
func TestLocateGoMod_OnlyTheModuleRootCounts(t *testing.T) {
	for name, nested := range map[string]string{
		"underscore dir": "_examples/go.mod",
		"testdata":       "testdata/go.mod",
		"nested module":  "sub/go.mod",
	} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			mod := filepath.Join(root, "github.com", "foo", "bar@v1.0.0+incompatible")
			writeTree(t, mod, map[string]string{"bar.go": "package bar\n", nested: "module x\n"})
			dir, found := locateGoMod(root)
			if found || dir != mod {
				t.Errorf("locateGoMod = %q, %v; want %q, false", dir, found, mod)
			}
		})
	}
	root := t.TempDir()
	mod := filepath.Join(root, "example.com", "m@v1.0.0")
	writeTree(t, mod, map[string]string{"go.mod": "module example.com/m\n", "zz/go.mod": "module example.com/m/zz\n"})
	if dir, found := locateGoMod(root); !found || dir != mod {
		t.Errorf("locateGoMod = %q, %v; want the root go.mod at %q", dir, found, mod)
	}
}

// A module root holding files and a single directory is the root; the source
// heuristic descended into the directory and wrote go.mod there.
func TestWriteSynthesisedGoMod_SingleDirectoryRootStaysAtThePrefix(t *testing.T) {
	root := t.TempDir()
	mod := filepath.Join(root, "github.com", "davecgh", "go-spew@v1.1.1")
	writeTree(t, mod, map[string]string{"LICENSE": "ISC\n", "spew/spew.go": "package spew\n"})
	dir, _, err := writeSynthesisedGoMod(root, coordinatetest.MustNew("github.com/davecgh/go-spew", "v1.1.1"), "go1.26.5",
		map[coordinate.ModuleCoordinate]struct{}{})
	if err != nil {
		t.Fatalf("writeSynthesisedGoMod: %v", err)
	}
	if dir != mod {
		t.Errorf("go.mod written to %q, want the module root %q", dir, mod)
	}
	if b, rerr := os.ReadFile(filepath.Join(mod, "go.mod")); rerr != nil || !strings.Contains(string(b), "module github.com/davecgh/go-spew") {
		t.Errorf("root go.mod = %q (%v)", b, rerr)
	}
}
