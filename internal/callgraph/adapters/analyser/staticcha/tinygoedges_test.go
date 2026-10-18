package staticcha_test

import (
	"context"
	"fmt"
	"go/build"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/adapters/goenv"
	"github.com/eitanity/kanonarion/internal/callgraph/adapters/analyser/staticcha"
	"github.com/eitanity/kanonarion/internal/callgraph/domain"
	"github.com/eitanity/kanonarion/internal/coordinate"
)

// edgesFixture is testdata/tinyedges: a fake TINYGOROOT whose runtime,
// runtime/interrupt and internal/task replace Go's in a merged GOROOT, and a
// program that uses them.
func edgesFixture(t *testing.T, version, goos, goarch string) (goenv.TinyGo, string) {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	fx := filepath.Join(filepath.Dir(file), "testdata", "tinyedges")
	root := t.TempDir()
	copyFixture(t, filepath.Join(fx, "root"), root)
	program := t.TempDir()
	copyFixture(t, filepath.Join(fx, "program"), program)

	host := build.Default.GOROOT
	merged := t.TempDir()
	linkEntries(t, host, merged, "src")
	src := filepath.Join(merged, "src")
	mkdir(t, src)
	linkEntries(t, filepath.Join(host, "src"), src, "runtime", "internal")
	internal := filepath.Join(src, "internal")
	mkdir(t, internal)
	linkEntries(t, filepath.Join(host, "src", "internal"), internal)
	for _, p := range []string{"runtime", "internal/task", "fxtime"} {
		symlink(t, filepath.Join(root, "src", p), filepath.Join(src, p))
	}
	f, err := goenv.NewTinyGo("fakeboard", version, "go1.27.2", goos, goarch, "6", merged, root,
		"thumbv6m-unknown-unknown-eabi", []string{"fakeboard", "scheduler.tasks", "tinygo"})
	if err != nil {
		t.Fatalf("NewTinyGo: %v", err)
	}
	return f, program
}

func linkEntries(t *testing.T, from, to string, skip ...string) {
	t.Helper()
	entries, err := os.ReadDir(from)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if !slicesContains(skip, e.Name()) {
			symlink(t, filepath.Join(from, e.Name()), filepath.Join(to, e.Name()))
		}
	}
}

func slicesContains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func symlink(t *testing.T, from, to string) {
	t.Helper()
	if err := os.Symlink(from, to); err != nil {
		t.Fatal(err)
	}
}

func mkdir(t *testing.T, dir string) {
	t.Helper()
	if err := os.Mkdir(dir, 0o750); err != nil {
		t.Fatal(err)
	}
}

// copyFixture copies a fixture tree, a .go.txt file as .go.
func copyFixture(t *testing.T, from, to string) {
	t.Helper()
	err := filepath.WalkDir(from, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(from, path)
		if err != nil {
			return fmt.Errorf("relating %s: %w", path, err)
		}
		dst := filepath.Join(to, strings.TrimSuffix(rel, ".txt"))
		if d.IsDir() {
			return os.MkdirAll(dst, 0o750)
		}
		b, err := os.ReadFile(path) // #nosec G304 G122 -- a checked-in fixture tree
		if err != nil {
			return fmt.Errorf("reading %s: %w", path, err)
		}
		return os.WriteFile(dst, b, 0o600) // #nosec G703 -- under a fresh temp directory
	})
	if err != nil {
		t.Fatalf("copying %s: %v", from, err)
	}
}

func analyseEdgesFixture(t *testing.T, version string) domain.CallGraphRecord {
	t.Helper()
	return analyseEdgesFixtureFor(t, version, "linux", "arm")
}

func analyseEdgesFixtureFor(t *testing.T, version, goos, goarch string) domain.CallGraphRecord {
	t.Helper()
	frame, program := edgesFixture(t, version, goos, goarch)
	coord, err := coordinate.NewModuleCoordinate("example.com/lowerfx", coordinate.LocalVersion)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := staticcha.New("0.0.0-test", "", slog.Default()).WithTinyGo(frame).AnalyseDir(context.Background(), program, coord)
	if err != nil {
		t.Fatalf("AnalyseDir: %v", err)
	}
	return rec
}

func edgeOfKind(rec domain.CallGraphRecord, from, to string, kind domain.EdgeKind) (domain.CallEdge, bool) {
	for _, e := range rec.Edges {
		if e.FromID == from && e.ToID == to && e.Kind == kind {
			return e, true
		}
	}
	return domain.CallEdge{}, false
}

// Under a TinyGo frame the record gains what the compiler and //go:linkname
// supply, and the handlers interrupt.New installs, in all their forms.
func TestAnalyseDir_TinyGoSuppliedEdgesAndHandlers(t *testing.T) {
	rec := analyseEdgesFixture(t, "0.42.0")
	if rec.OverallStatus != domain.CallGraphStatusExtracted {
		t.Fatalf("status = %s: %s", rec.OverallStatus, rec.FailureDetail)
	}
	for _, want := range []struct {
		from, to string
		kind     domain.EdgeKind
	}{
		{"example.com/lowerfx.lookup", "runtime.hashmapStringGet", domain.EdgeKindCompilerInserted},
		{"example.com/lowerfx.main", "internal/task.start", domain.EdgeKindCompilerInserted},
		{"fxtime.Sleep", "runtime.timeSleep", domain.EdgeKindLinkname},
		{"runtime.callMain", "example.com/lowerfx.main", domain.EdgeKindLinkname},
	} {
		e, ok := edgeOfKind(rec, want.from, want.to, want.kind)
		if !ok {
			t.Errorf("no %s edge %s -> %s", want.kind, want.from, want.to)
			continue
		}
		if e.Confidence != domain.ConfidenceDirect || e.CallSite.File == "" || e.CallSite.Line == 0 {
			t.Errorf("%s -> %s = %+v, want Direct at a site", want.from, want.to, e)
		}
	}
	if _, ok := edgeOfKind(rec, "example.com/lowerfx.lookup", "runtime.stringConcat", domain.EdgeKindCompilerInserted); ok {
		t.Error("an edge to a runtime function the construct does not lower to")
	}
	for id, line := range map[string]int{
		"example.com/lowerfx.onIRQ":         24,
		"example.com/lowerfx.(*dev).handle": 25,
		"example.com/lowerfx.main$1":        26,
	} {
		n, ok := nodeByID(rec, id)
		want := domain.InterruptHandler{Kind: domain.HandlerInterruptNew, Site: domain.SourcePosition{File: "main.go", Line: line}}
		if !ok || n.InterruptHandler != want {
			t.Errorf("%s handler = %+v (node %v), want %+v", id, n.InterruptHandler, ok, want)
		}
	}
	assertTinyGoDirectives(t, rec)
}

// assertTinyGoDirectives checks the directives read from TinyGo's packages.
func assertTinyGoDirectives(t *testing.T, rec domain.CallGraphRecord) {
	t.Helper()
	reset, _ := nodeByID(rec, "runtime.main")
	if reset.ExportDirective != (domain.ExportDirective{Kind: domain.ExportC, Name: "Reset_Handler"}) {
		t.Errorf("runtime.main directive = %+v, want TinyGo's //export read", reset.ExportDirective)
	}
	if n, ok := nodeByID(rec, "runtime.wasmEntryCommand"); !ok || !n.ExportDirective.IsZero() {
		t.Errorf("runtime.wasmEntryCommand = %+v (node %v), want a node with no directive outside wasm", n.ExportDirective, ok)
	}
	for _, id := range []string{"runtime.strlen", "runtime.memcmp"} {
		if n, ok := nodeByID(rec, id); ok && !n.ExportDirective.IsZero() {
			t.Errorf("%s directive = %+v, want none on a declaration without a body", id, n.ExportDirective)
		}
	}
}

// A TinyGo release the lowering table does not cover still yields the parse and
// the class-hierarchy edges, Partial, with the release named.
func TestAnalyseDir_AnUnlistedTinyGoVersionIsPartial(t *testing.T) {
	rec := analyseEdgesFixture(t, "0.41.0")
	if rec.OverallStatus != domain.CallGraphStatusPartial || rec.FailureCause != domain.FailureCauseEnvironment {
		t.Fatalf("status = %s, cause %s, want Partial for this run", rec.OverallStatus, rec.FailureCause)
	}
	const want = "compiler-inserted runtime calls and the entry points TinyGo exports by name are not recorded: TinyGo 0.41.0 is outside kanonarion's lowering table, which covers TinyGo 0.42.0"
	if !strings.HasPrefix(rec.FailureDetail, want) {
		t.Errorf("detail = %q, want it to lead with %q", rec.FailureDetail, want)
	}
	for _, e := range rec.Edges {
		if e.Kind == domain.EdgeKindCompilerInserted {
			t.Fatalf("compiler-inserted edge %s -> %s under an unlisted version", e.FromID, e.ToID)
		}
	}
	if _, ok := edgeOfKind(rec, "fxtime.Sleep", "runtime.timeSleep", domain.EdgeKindLinkname); !ok {
		t.Error("linkname edges depend on the source, not the table, and are missing")
	}
	if n, _ := nodeByID(rec, "example.com/lowerfx.onIRQ"); n.InterruptHandler.IsZero() {
		t.Error("handler facts depend on the source, not the table, and are missing")
	}
}

// The standard frame is untouched: maps, goroutines and a linkname in a host
// build add no edge of either TinyGo kind.
func TestAnalyse_TheHostFrameGainsNoTinyGoEdge(t *testing.T) {
	rec := analyseFiles(t, map[string]string{
		"go.mod": "module example.com/cgtestmod\n\ngo 1.21\n",
		"host/host.go": `package host

import _ "unsafe"

//go:linkname nanotime runtime.nanotime
func nanotime() int64

var m = map[string]int{}

func Use(k string) int { go func() {}(); return m[k] + int(nanotime()) }
`,
	})
	for _, e := range rec.Edges {
		if e.Kind == domain.EdgeKindCompilerInserted || e.Kind == domain.EdgeKindLinkname {
			t.Errorf("host frame edge %s -> %s of kind %s", e.FromID, e.ToID, e.Kind)
		}
	}
	for _, n := range rec.Nodes {
		if !n.InterruptHandler.IsZero() {
			t.Errorf("host frame handler on %s", n.ID)
		}
	}
}

// In a wasm build TinyGo exports its runtime's command entry as _start by
// name, so the record carries the directive a source //go:wasmexport would.
func TestAnalyseDir_TheWasmEntryTinyGoExportsByName(t *testing.T) {
	rec := analyseEdgesFixtureFor(t, "0.42.0", "wasip1", "wasm")
	n, ok := nodeByID(rec, "runtime.wasmEntryCommand")
	if want := (domain.ExportDirective{Kind: domain.ExportWasm, Name: "_start"}); !ok || n.ExportDirective != want {
		t.Errorf("runtime.wasmEntryCommand = %+v (node %v), want %+v", n.ExportDirective, ok, want)
	}
	gap := analyseEdgesFixtureFor(t, "0.41.0", "wasip1", "wasm")
	if n, _ := nodeByID(gap, "runtime.wasmEntryCommand"); !n.ExportDirective.IsZero() {
		t.Errorf("an unlisted release carries %+v, want the class left out", n.ExportDirective)
	}
}
