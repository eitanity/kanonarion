package staticcha

import (
	"context"
	"errors"
	"go/token"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/eitanity/kanonarion/internal/callgraph/domain"
)

// TestSourceRoots_ModuleFilesStayModuleRelative pins the rendering the record
// has always used for the analysed module's own files.
func TestSourceRoots_ModuleFilesStayModuleRelative(t *testing.T) {
	module := t.TempDir()
	roots := newSourceRoots(module, t.TempDir(), SourceDirs{})

	got, ok := roots.rel(filepath.Join(module, "lib", "hooks.go"))
	if !ok {
		t.Fatal("the module's own file was given no position")
	}
	if got != filepath.Join("lib", "hooks.go") {
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
	roots := newSourceRoots(t.TempDir(), cache, SourceDirs{})

	dep := filepath.Join(cache, "github.com", "json-iterator", "go@v1.1.9", "adapter.go")
	want := filepath.Join("github.com", "json-iterator", "go@v1.1.9", "adapter.go")
	got, ok := roots.rel(dep)
	if !ok {
		t.Fatal("a dependency's file was given no position")
	}
	if got != want {
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

	a, aok := newSourceRoots(t.TempDir(), first, SourceDirs{}).rel(filepath.Join(first, name))
	b, bok := newSourceRoots(t.TempDir(), second, SourceDirs{}).rel(filepath.Join(second, name))
	if a != b || aok != bok {
		t.Errorf("two analyses of one file rendered it as %q (%t) and %q (%t)", a, aok, b, bok)
	}
}

// TestSourceRoots_TheOperatorsOwnCacheIsSpelledLikeAMaterialisedOne holds that
// the same module read out of the host's cache and out of one this run
// materialised reaches the record as the same bytes. Without it an operator who
// passes --from-modcache records a different measurement from one who does not.
func TestSourceRoots_TheOperatorsOwnCacheIsSpelledLikeAMaterialisedOne(t *testing.T) {
	materialised, hosts := t.TempDir(), t.TempDir()
	name := filepath.Join("github.com", "spf13", "pflag@v1.0.10", "flag.go")

	// The run built its own cache and told the loader about it.
	built, bok := newSourceRoots(t.TempDir(), materialised, SourceDirs{ModuleCache: materialised}).
		rel(filepath.Join(materialised, name))
	// The run named no cache; the toolchain resolved the host's.
	read, rok := newSourceRoots(t.TempDir(), "", SourceDirs{ModuleCache: hosts}).
		rel(filepath.Join(hosts, name))

	if !bok || !rok {
		t.Fatalf("a dependency's file was given no position (%t, %t)", bok, rok)
	}
	if built != read {
		t.Errorf("materialised cache rendered %q, the host's rendered %q — the same analysis run two ways must record the same bytes", built, read)
	}
	if built != name {
		t.Errorf("rel = %q, want %q", built, name)
	}
}

// TestSourceRoots_BuildCacheFilesAreGivenNoPosition is the regression that
// matters most here. A build-cache entry is content-addressed: its path changes
// whenever the entry is rebuilt, so recording it makes a record that changes
// when nothing changed, and a coordinate that can never be composed with its own
// predecessor. It names no file a reader can open either, so there is nothing to
// express it against — it is omitted.
func TestSourceRoots_BuildCacheFilesAreGivenNoPosition(t *testing.T) {
	cache := t.TempDir()
	roots := newSourceRoots(t.TempDir(), t.TempDir(), SourceDirs{BuildCache: cache})

	generated := filepath.Join(cache, "1d", "1d8c3801890dd089be260e5757b29ec0f8523ed63eecaf87ec39a3738a466322-d")
	if got, ok := roots.rel(generated); ok {
		t.Errorf("rel = %q, true — a content-addressed cache entry must be given no position at all", got)
	}
}

// TestSourceRoots_TwoBuildCachesAgree is the check the original acceptance
// missed: GOMODCACHE, $HOME and the working directory were all varied, and none
// of them moves the build-cache path.
func TestSourceRoots_TwoBuildCachesAgree(t *testing.T) {
	first, second := t.TempDir(), t.TempDir()
	if first == second {
		t.Fatal("the two runs were given one directory; the test cannot distinguish them")
	}
	module := t.TempDir()

	// The same generated file, under two caches, at two content addresses —
	// which is what a rebuild produces.
	a, aok := newSourceRoots(module, "", SourceDirs{BuildCache: first}).
		rel(filepath.Join(first, "1d", "1d8c3801890dd089be2-d"))
	b, bok := newSourceRoots(module, "", SourceDirs{BuildCache: second}).
		rel(filepath.Join(second, "e4", "e4ebf6b181cdd8137d6-d"))

	if a != b || aok != bok {
		t.Errorf("two build caches rendered one generated file as %q (%t) and %q (%t)", a, aok, b, bok)
	}
}

// TestSourceRoots_StdlibIsExpressedAgainstGOROOT holds the standard library's
// spelling: src/fmt/print.go names the file without naming the host that
// installed the toolchain.
func TestSourceRoots_StdlibIsExpressedAgainstGOROOT(t *testing.T) {
	goroot := t.TempDir()
	roots := newSourceRoots(t.TempDir(), t.TempDir(), SourceDirs{GOROOT: goroot})

	want := filepath.Join("src", "fmt", "print.go")
	got, ok := roots.rel(filepath.Join(goroot, want))
	if !ok {
		t.Fatal("a standard library file was given no position")
	}
	if got != want {
		t.Errorf("rel = %q, want %q", got, want)
	}
}

// TestSourceRoots_GOROOTInsideTheModuleCacheIsStillGOROOT pins the ordering. A
// toolchain fetched as a module lives inside GOMODCACHE, and spelling its files
// against the cache would write the toolchain version into every stdlib position
// — a second thing that moves between two runs, on an axis the record already
// states for itself.
func TestSourceRoots_GOROOTInsideTheModuleCacheIsStillGOROOT(t *testing.T) {
	cache := t.TempDir()
	goroot := filepath.Join(cache, "golang.org", "toolchain@v0.0.1-go1.26.6.linux-amd64")
	roots := newSourceRoots(t.TempDir(), cache, SourceDirs{GOROOT: goroot})

	want := filepath.Join("src", "fmt", "print.go")
	got, ok := roots.rel(filepath.Join(goroot, want))
	if !ok {
		t.Fatal("a standard library file was given no position")
	}
	if got != want {
		t.Errorf("rel = %q, want %q — a toolchain in the module cache is still GOROOT", got, want)
	}
}

// TestSourceRoots_APathNoRootContainsStaysAbsolute holds the other half. The
// leading separator used to be trimmed whatever happened, so `/home/dev/go/pkg/mod/...`
// reached the record as `home/dev/go/pkg/mod/...` and read as repo-relative. A
// path that cannot be made relative must stay visibly absolute: that is what
// makes it obvious it names a place on someone else's host.
func TestSourceRoots_APathNoRootContainsStaysAbsolute(t *testing.T) {
	roots := newSourceRoots(t.TempDir(), "", SourceDirs{})

	abs := string(filepath.Separator) + filepath.Join("home", "dev", "go", "pkg", "mod", "example.com", "dep@v1.0.0", "a.go")
	got, ok := roots.rel(abs)
	if !ok {
		t.Fatal("a path outside every root was given no position; it should be recorded as it stands")
	}
	if got != abs {
		t.Errorf("rel = %q, want %q — a path that cannot be made relative stays visibly absolute", got, abs)
	}
}

// TestSourceRoots_PositionOmitsTheLineWithTheFile states what a node with no
// usable position carries: the zero position, not a line number attached to no
// file. Every reader already handles the zero — `--json` omits both fields and
// the text surfaces print "(position not recorded)" — whereas a bare line would
// have them render ":47".
func TestSourceRoots_PositionOmitsTheLineWithTheFile(t *testing.T) {
	cache := t.TempDir()
	roots := newSourceRoots(t.TempDir(), "", SourceDirs{BuildCache: cache})

	got := roots.position(token.Position{Filename: filepath.Join(cache, "1d", "abc-d"), Line: 47})
	if got != (domain.SourcePosition{}) {
		t.Errorf("position = %+v, want the zero position", got)
	}
}

// TestSourceRoots_RootsAreRecognisedThroughASymlink holds the case
// newSourceRoots already handled for the materialised cache, for every root: the
// loader reports the path it resolved, which on a host whose directory is
// reached through a symlink is not the path the toolchain named.
func TestSourceRoots_RootsAreRecognisedThroughASymlink(t *testing.T) {
	target := t.TempDir()
	link := filepath.Join(t.TempDir(), "cache")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("this host cannot create a symlink: %v", err)
	}

	roots := newSourceRoots(t.TempDir(), "", SourceDirs{BuildCache: link})
	resolved, err := filepath.EvalSymlinks(link)
	if err != nil {
		t.Fatalf("resolving the link: %v", err)
	}
	if _, ok := roots.rel(filepath.Join(resolved, "1d", "abc-d")); ok {
		t.Error("a build-cache file reported under the resolved path was given a position")
	}
}

// TestProbeSourceDirs_AFailedProbeNamesNoDirectory holds the fault seam. A probe
// that fails must leave every root unnamed rather than half-named: a GOROOT
// paired with an unknown build cache would put content-addressed paths back
// inside the seal while looking as though the roots had been resolved.
func TestProbeSourceDirs_AFailedProbeNamesNoDirectory(t *testing.T) {
	restore := sourceDirsProbe
	t.Cleanup(func() { sourceDirsProbe = restore })

	sourceDirsProbe = func(context.Context, string, []string) (SourceDirs, error) {
		return SourceDirs{GOROOT: "/usr/local/go"}, errors.New("no toolchain on PATH")
	}
	a := New("0.1.0", "", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if got := a.probeSourceDirs(context.Background(), t.TempDir(), nil); got != (SourceDirs{}) {
		t.Errorf("probeSourceDirs = %+v, want the zero value when the probe failed", got)
	}
}

// TestProbeSourceDirs_TheProbesAnswerIsUsedAsGiven is the other half of the
// seam: what the toolchain says is what the roots are.
func TestProbeSourceDirs_TheProbesAnswerIsUsedAsGiven(t *testing.T) {
	restore := sourceDirsProbe
	t.Cleanup(func() { sourceDirsProbe = restore })

	want := SourceDirs{GOROOT: "/usr/local/go", BuildCache: "/cache/go-build", ModuleCache: "/go/pkg/mod"}
	sourceDirsProbe = func(context.Context, string, []string) (SourceDirs, error) { return want, nil }
	a := New("0.1.0", "", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if got := a.probeSourceDirs(context.Background(), t.TempDir(), nil); got != want {
		t.Errorf("probeSourceDirs = %+v, want %+v", got, want)
	}
}

// TestSetSourceDirsProbe_NilIsRefused pins that a composition root cannot unwire
// the probe by passing nil, which would silently restore the behaviour this
// whole mechanism exists to prevent.
func TestSetSourceDirsProbe_NilIsRefused(t *testing.T) {
	restore := sourceDirsProbe
	t.Cleanup(func() { sourceDirsProbe = restore })

	installed := func(context.Context, string, []string) (SourceDirs, error) {
		return SourceDirs{GOROOT: "/marker"}, nil
	}
	SetSourceDirsProbe(installed)
	SetSourceDirsProbe(nil)

	got, err := sourceDirsProbe(context.Background(), "", nil)
	if err != nil || got.GOROOT != "/marker" {
		t.Errorf("SetSourceDirsProbe(nil) replaced the installed probe: %+v, %v", got, err)
	}
}
