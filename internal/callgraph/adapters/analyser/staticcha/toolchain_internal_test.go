package staticcha

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/eitanity/kanonarion/internal/callgraph/domain"
	"github.com/eitanity/kanonarion/internal/coordinate"
)

// analysedDir stands for the directory the loader was pointed at — the extracted
// module or the working tree — which is what the probe is asked about.
const analysedDir = "/tmp/analysed-module"

func quietAnalyser() *Analyser {
	return New("0.0.0-test", "", slog.New(slog.NewTextHandler(io.Discard, nil)))
}

// swapProbe installs a probe outcome for the duration of one test.
func swapProbe(t *testing.T, fn ToolchainProbe) {
	t.Helper()
	old := toolchainProbe
	toolchainProbe = fn
	t.Cleanup(func() { toolchainProbe = old })
}

// TestClassifyLoadFailure_UnusableToolchainIsEnvironment is the reproduction
// that motivated the axis: a PATH whose `go` is a shim with no version behind
// it. The loader's message names the toolchain, not the module, and the record
// must say so rather than filing the run's failure as the module's property.
func TestClassifyLoadFailure_UnusableToolchainIsEnvironment(t *testing.T) {
	swapProbe(t, func(context.Context, string) error {
		return errors.New("exit status 1: mise ERROR No version is set for shim: go")
	})

	got := quietAnalyser().classifyLoadFailure(context.Background(), analysedDir)
	if got != domain.FailureCauseEnvironment {
		t.Errorf("classifyLoadFailure = %q, want %q", got, domain.FailureCauseEnvironment)
	}
}

// TestClassifyLoadFailure_WorkingToolchainIsModule: the toolchain ran, so
// whatever the loader reported was reported about the module.
func TestClassifyLoadFailure_WorkingToolchainIsModule(t *testing.T) {
	swapProbe(t, func(context.Context, string) error { return nil })

	got := quietAnalyser().classifyLoadFailure(context.Background(), analysedDir)
	if got != domain.FailureCauseModule {
		t.Errorf("classifyLoadFailure = %q, want %q", got, domain.FailureCauseModule)
	}
}

// TestClassifyLoadFailure_ProbesTheAnalysedDirectory pins the directory the
// probe is asked about. A toolchain is resolved per directory, so a probe asked
// from anywhere other than the tree the loader read would be answering about a
// different toolchain from the one that failed — and would report it usable,
// filing the run's failure as the module's property and caching it forever.
func TestClassifyLoadFailure_ProbesTheAnalysedDirectory(t *testing.T) {
	var asked string
	swapProbe(t, func(_ context.Context, dir string) error {
		asked = dir
		return nil
	})

	quietAnalyser().classifyLoadFailure(context.Background(), analysedDir)

	if asked != analysedDir {
		t.Errorf("probe was asked about %q, want the analysed directory %q", asked, analysedDir)
	}
}

// TestAnalyseDir_ProbesTheDirectoryItLoaded pins the wiring the two unit tests
// either side of it cannot see: that the directory reaching the probe is the one
// the loader was actually pointed at.
//
// Classifying against any other directory is the whole defect. A toolchain is
// resolved per directory, so a probe asked about the caller's own working
// directory can report a usable toolchain for a load that had none — and the
// run's failure is then filed as the module's property and cached forever. A
// test that only pins classifyLoadFailure's behaviour given a directory passes
// happily while the call sites hand it the empty string.
//
// The load is made to fail by giving the tree a go.mod the toolchain will not
// parse, which is the cheapest way to reach the classification: no synthetic
// toolchain, and no successful analysis to wait for.
func TestAnalyseDir_ProbesTheDirectoryItLoaded(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/analysed\n\ngo 1.21\n\nrequire !!!unparseable\n"), 0o600); err != nil {
		t.Fatalf("writing go.mod: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "a.go"), []byte("package analysed\n"), 0o600); err != nil {
		t.Fatalf("writing a.go: %v", err)
	}

	var asked []string
	swapProbe(t, func(_ context.Context, probed string) error {
		asked = append(asked, probed)
		return nil
	})

	coord, err := coordinate.NewModuleCoordinate("example.com/analysed", coordinate.LocalVersion)
	if err != nil {
		t.Fatalf("coordinate: %v", err)
	}
	rec, err := quietAnalyser().AnalyseDir(context.Background(), dir, coord)
	if err != nil {
		t.Fatalf("AnalyseDir: %v", err)
	}
	if rec.OverallStatus != domain.CallGraphStatusLoadFailed {
		t.Fatalf("the load succeeded (%v), so the classification was never reached", rec.OverallStatus)
	}

	if len(asked) == 0 {
		t.Fatal("the load failed without the toolchain being probed at all")
	}
	for _, probed := range asked {
		if probed != dir {
			t.Errorf("the probe was asked about %q; the loader read %q", probed, dir)
		}
	}
}

// TestClassifyLoadFailure_CancelledIsEnvironmentWithoutProbing pins the order of
// the two checks. A cancelled context makes the probe fail for a reason that
// says nothing about the toolchain, so the cancellation is answered first.
func TestClassifyLoadFailure_CancelledIsEnvironmentWithoutProbing(t *testing.T) {
	probed := false
	swapProbe(t, func(context.Context, string) error {
		probed = true
		return nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if got := quietAnalyser().classifyLoadFailure(ctx, analysedDir); got != domain.FailureCauseEnvironment {
		t.Errorf("classifyLoadFailure on a cancelled context = %q, want %q", got, domain.FailureCauseEnvironment)
	}
	if probed {
		t.Error("the toolchain was probed under a cancelled context; the probe's failure would say nothing about the toolchain")
	}
}

// TestClassifyLoadFailure_UnwiredProbeAssumesUsable pins the zero seam: with no
// probe wired by a composition root, a load failure files as the module's. The
// real environment check lives with the composition root (this is an extraction
// package and must not carry process-spawning capability), and its own control
// test lives beside that implementation.
func TestClassifyLoadFailure_UnwiredProbeAssumesUsable(t *testing.T) {
	swapProbe(t, assumeUsableToolchain)

	if got := quietAnalyser().classifyLoadFailure(context.Background(), analysedDir); got != domain.FailureCauseModule {
		t.Errorf("classifyLoadFailure with the zero seam = %q, want %q", got, domain.FailureCauseModule)
	}
}

// TestSetToolchainProbe_NilIsRefused pins that a composition root cannot unwire
// the seam by passing nil: the previously-installed probe keeps answering.
func TestSetToolchainProbe_NilIsRefused(t *testing.T) {
	sentinel := errors.New("sentinel probe")
	swapProbe(t, func(context.Context, string) error { return sentinel })

	SetToolchainProbe(nil)

	if err := toolchainProbe(context.Background(), analysedDir); !errors.Is(err, sentinel) {
		t.Error("SetToolchainProbe(nil) replaced the installed probe")
	}
}

// TestFailRecordCarriesTheCause pins the field onto the record every failure
// path builds, so no failure this generation writes can be the unattributed
// record the cache gate has to treat as unknown.
func TestFailRecordCarriesTheCause(t *testing.T) {
	coord, err := coordinate.NewModuleCoordinate("example.com/analysed", "v1.0.0")
	if err != nil {
		t.Fatalf("coordinate: %v", err)
	}
	rec := quietAnalyser().failRecord(
		coord,
		domain.CallGraphStatusLoadFailed,
		domain.CompletenessFailed,
		domain.FailureCauseEnvironment,
		"meta load: err: exit status 1",
	)
	if rec.FailureCause != domain.FailureCauseEnvironment {
		t.Errorf("FailureCause = %q, want %q", rec.FailureCause, domain.FailureCauseEnvironment)
	}
	if domain.RecordIsCacheable(rec) {
		t.Error("an environment failure record is cacheable")
	}
}
