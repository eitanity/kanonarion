package staticcha

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/eitanity/kanonarion/internal/callgraph/domain"
)

// TestDistinctNodePackages_SkipsNamesTheLoaderCannotOpen holds the whole point
// of the filter: the packages handed to packages.Load must be paths the go
// command can list. The graph is built from a test-scoped load, so its nodes
// carry two names go/packages invented — the test binary main "<path>.test" and
// the external test package "<path>_test" — and neither names a directory.
//
// Passing one is not merely useless. Having failed to find a package of that
// name, the go command falls back to resolving the argument as a MODULE, which
// costs a proxy round trip per name. On this repo that was 226 names of 518.
func TestDistinctNodePackages_SkipsNamesTheLoaderCannotOpen(t *testing.T) {
	t.Parallel()

	nodes := []domain.CallNode{
		{Package: "example.com/mod/app"},
		{Package: "example.com/mod/app.test"},
		{Package: "example.com/mod/app_test"},
		{Package: ""},
		// The internal test variant keeps the production import path, so it must
		// survive: it is loaded here as the production package, as it always was.
		{Package: "example.com/mod/app"},
		{Package: "example.com/mod/store"},
	}

	got := distinctNodePackages(nodes)
	slices.Sort(got)
	want := []string{"example.com/mod/app", "example.com/mod/store"}
	if !slices.Equal(got, want) {
		t.Errorf("distinctNodePackages = %v, want %v", got, want)
	}
}

// TestScanBodyFacts_LeavesTheProcessEnvironmentAlone pins the removal of a
// GOGC dance that reached nothing. It snapshotted GOGC, set it, and restored it
// around packages.Load: the child never saw it, because cfg.Env is set from the
// analysis env slice; the parent's GC never moved, because the runtime reads
// GOGC at startup; and the restore wrote GOGC="" whenever the variable was
// unset, which is the normal case, so every subprocess spawned afterwards
// inherited an empty GOGC instead of none.
//
// os.Setenv is process-global, so a load doing this is a hazard to every
// concurrent environment read in the process. The load must leave the
// environment exactly as it found it.
func TestScanBodyFacts_LeavesTheProcessEnvironmentAlone(t *testing.T) {
	dir := t.TempDir()
	write := func(rel, content string) {
		t.Helper()
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatalf("write %s: %v", rel, err)
		}
	}

	const modPath = "example.com/bodyfactsmod"
	write("go.mod", "module "+modPath+"\n\ngo 1.21\n")
	write("app/app.go", "package app\n\nimport \"unsafe\"\n\n"+
		"func Reinterpret(p *int) unsafe.Pointer { return unsafe.Pointer(p) }\n")

	before, beforeSet := os.LookupEnv("GOGC")

	facts := scanBodyFacts(context.Background(), dir, []string{modPath + "/app"}, analysisEnv())

	// The non-zero control: the load has to have actually happened, or the
	// environment assertion below would pass on a load that never ran.
	if got, ok := facts[modPath+"/app.Reinterpret"]; !ok || !got.usesUnsafePointer {
		t.Skipf("go/packages could not load test module (facts=%d); skipping", len(facts))
	}

	after, afterSet := os.LookupEnv("GOGC")
	if beforeSet != afterSet || before != after {
		t.Errorf("scanBodyFacts changed GOGC in the parent process: before set=%v %q, after set=%v %q; "+
			"os.Setenv reaches neither the child (cfg.Env is already set) nor the parent's GC "+
			"(GOGC is read at startup), and leaves GOGC=\"\" behind when it was unset",
			beforeSet, before, afterSet, after)
	}
}
