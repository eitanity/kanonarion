package staticcha

import (
	"path/filepath"
	"testing"
)

// TestSourceRoots_ModuleFilesStayModuleRelative pins the rendering the record
// has always used for the analysed module's own files.
func TestSourceRoots_ModuleFilesStayModuleRelative(t *testing.T) {
	module := t.TempDir()
	roots := newSourceRoots(module, t.TempDir())

	if got := roots.rel(filepath.Join(module, "lib", "hooks.go")); got != filepath.Join("lib", "hooks.go") {
		t.Errorf("rel = %q, want the module-relative path", got)
	}
}

// TestSourceRoots_DependencyFilesCarryNoRunDirectory is the regression guard for
// the defect a per-analysis module cache introduces: a node position is inside
// the record's canonical form, so a directory this process invented would make
// every re-analysis of an unchanged module a different measurement, appending a
// generation for ever.
func TestSourceRoots_DependencyFilesCarryNoRunDirectory(t *testing.T) {
	cache := t.TempDir()
	roots := newSourceRoots(t.TempDir(), cache)

	dep := filepath.Join(cache, "github.com", "json-iterator", "go@v1.1.9", "adapter.go")
	want := filepath.Join("github.com", "json-iterator", "go@v1.1.9", "adapter.go")
	if got := roots.rel(dep); got != want {
		t.Errorf("rel = %q, want %q — the module, its version and the file, and nothing about where this run put them", got, want)
	}
}

// TestSourceRoots_TwoRunsAgree states the property the guard above exists for,
// on two caches that differ only in the name this process gave them.
func TestSourceRoots_TwoRunsAgree(t *testing.T) {
	first, second := t.TempDir(), t.TempDir()
	if first == second {
		t.Fatal("the two runs were given one directory; the test cannot distinguish them")
	}
	name := filepath.Join("golang.org", "x", "net@v0.52.0", "http2", "frame.go")

	a := newSourceRoots(t.TempDir(), first).rel(filepath.Join(first, name))
	b := newSourceRoots(t.TempDir(), second).rel(filepath.Join(second, name))
	if a != b {
		t.Errorf("two analyses of one file rendered it as %q and %q", a, b)
	}
}

// TestSourceRoots_NoCacheLeavesThePathAlone holds the behaviour of an analysis
// reading a cache this run did not create — a working tree's, or the operator's
// under --from-modcache — where the path names a real place a reader can open.
func TestSourceRoots_NoCacheLeavesThePathAlone(t *testing.T) {
	roots := newSourceRoots(t.TempDir(), "")

	if got := roots.rel("/home/dev/go/pkg/mod/example.com/dep@v1.0.0/a.go"); got != "home/dev/go/pkg/mod/example.com/dep@v1.0.0/a.go" {
		t.Errorf("rel = %q, want the path as it was before a cache could be materialised", got)
	}
}
