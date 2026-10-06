package staticcha

import (
	"bytes"
	"context"
	"go/token"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/callgraph/domain"
	"github.com/eitanity/kanonarion/internal/coordinate"
)

// A package load the run's cancellation stopped says nothing about whether the
// module loads with its tests: it is returned, not reported as a test-scope
// exclusion and retried.
func TestLoadAndBuildSSA_LoadStoppedByTheCancellationIsNotATestScopeExclusion(t *testing.T) {
	dir := t.TempDir()
	const modPath = "example.com/cancelmod"
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module "+modPath+"\n\ngo 1.21\n"), 0o600); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "m.go"), []byte("package cancelmod\n"), 0o600); err != nil {
		t.Fatalf("write m.go: %v", err)
	}
	coord, err := coordinate.NewModuleCoordinate(modPath, "v0.0.0")
	if err != nil {
		t.Fatalf("coordinate: %v", err)
	}
	var logs bytes.Buffer
	a := New("0.1.0", "", slog.New(slog.NewTextHandler(&logs, nil)))
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	_, lerr := a.loadAndBuildSSA(ctx, token.NewFileSet(), dir, coord, []string{modPath}, isolatedModuleEnv(), modeModuleZip)
	if lerr == nil {
		t.Fatal("a load under a cancelled context succeeded; the seam this test needs did not fire")
	}
	if strings.Contains(logs.String(), "callgraph_test_scope_excluded") {
		t.Errorf("a stopped load was reported as a test-scope exclusion:\n%s", logs.String())
	}
}

// A load the run's cancellation killed is a Cancelled record, never LoadFailed:
// a LoadFailed record states that the module would not load, and one caused by
// the cancellation could be read as a property of the module.
func TestAnalyseDir_LoadStoppedByTheCancellationIsCancelledNotLoadFailed(t *testing.T) {
	dir := t.TempDir()
	const modPath = "example.com/cancelmod"
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module "+modPath+"\n\ngo 1.21\n"), 0o600); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "m.go"), []byte("package cancelmod\n"), 0o600); err != nil {
		t.Fatalf("write m.go: %v", err)
	}
	coord, err := coordinate.NewModuleCoordinate(modPath, "v0.0.0")
	if err != nil {
		t.Fatalf("coordinate: %v", err)
	}
	a := New("0.1.0", "", slog.New(slog.NewTextHandler(io.Discard, nil)))
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	rec, aerr := a.analyseDir(ctx, dir, coord, domain.SynthesisedGoMod{}, nil, modeModuleZip, "")
	if aerr != nil {
		t.Fatalf("analyseDir: %v", aerr)
	}
	if rec.OverallStatus != domain.CallGraphStatusCancelled {
		t.Errorf("status = %s (%s), want Cancelled", rec.OverallStatus, rec.FailureDetail)
	}

	// The control: a module whose go.mod the go command rejects is still LoadFailed.
	broken := t.TempDir()
	if err := os.WriteFile(filepath.Join(broken, "go.mod"), []byte("module "+modPath+"\n\ngo 1.21\n\nrequire (\n"), 0o600); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}
	if err := os.WriteFile(filepath.Join(broken, "m.go"), []byte("package cancelmod\n"), 0o600); err != nil {
		t.Fatalf("write m.go: %v", err)
	}
	rec, aerr = a.analyseDir(t.Context(), broken, coord, domain.SynthesisedGoMod{}, nil, modeModuleZip, "")
	if aerr != nil {
		t.Fatalf("analyseDir: %v", aerr)
	}
	if rec.OverallStatus != domain.CallGraphStatusLoadFailed {
		t.Errorf("a module that does not load was reported %s, want LoadFailed: %s", rec.OverallStatus, rec.FailureDetail)
	}
}

// A go command the cancellation kills mid-load cannot remove the work directory
// it wrote; the temp root the analysis gave it goes when the analysis returns.
func TestAnalyseDir_KilledLoadLeavesNoTempDir(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	stub := t.TempDir()
	rec := filepath.Join(stub, "tmpdir")
	script := "#!/bin/sh\ncase \"$1\" in\n" +
		"env) for v in \"$@\"; do case $v in GOVERSION) echo go1.26.6;; env) ;; *) echo /nonexistent;; esac; done ;;\n" +
		"version) echo go version go1.26.6 linux/amd64 ;;\n" +
		"*) mkdir -p \"$TMPDIR/go-build-stub\" && echo \"$TMPDIR\" > " + rec + ".part && mv " + rec + ".part " + rec + "; exec sleep 30 ;;\n" +
		"esac\n"
	if err := os.WriteFile(filepath.Join(stub, "go"), []byte(script), 0o700); err != nil { // #nosec G306 -- a test stand-in that must be executable
		t.Fatalf("writing the stand-in go: %v", err)
	}
	t.Setenv("PATH", stub+string(os.PathListSeparator)+os.Getenv("PATH"))
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/cancelmod\n\ngo 1.21\n"), 0o600); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}
	coord, err := coordinate.NewModuleCoordinate("example.com/cancelmod", "v0.0.0")
	if err != nil {
		t.Fatalf("coordinate: %v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go func() {
		for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
			if _, err := os.Stat(rec); err == nil {
				break
			}
		}
		cancel()
	}()

	a := New("0.1.0", "", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if _, aerr := a.analyseDir(ctx, dir, coord, domain.SynthesisedGoMod{}, nil, modeModuleZip, ""); aerr != nil {
		t.Fatalf("analyseDir: %v", aerr)
	}
	b, rerr := os.ReadFile(rec) // #nosec G304 -- this test's own file
	if rerr != nil {
		t.Fatalf("the stand-in load never ran: %v", rerr)
	}
	childTmp := strings.TrimSpace(string(b))
	if filepath.Dir(childTmp) != tmp {
		t.Errorf("the load's TMPDIR is %s, want a directory under %s", childTmp, tmp)
	}
	if _, serr := os.Stat(childTmp); !os.IsNotExist(serr) { // #nosec G703 -- a path this test's own child reported under its temp dir
		t.Errorf("the killed load's temp root %s survived (stat: %v)", childTmp, serr)
	}
}
