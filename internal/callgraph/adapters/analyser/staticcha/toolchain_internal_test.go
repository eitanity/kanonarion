package staticcha

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/eitanity/kanonarion/internal/callgraph/domain"
	"github.com/eitanity/kanonarion/internal/coordinate"
)

func quietAnalyser() *Analyser {
	return New("0.0.0-test", "", slog.New(slog.NewTextHandler(io.Discard, nil)))
}

// swapProbe installs a probe outcome for the duration of one test.
func swapProbe(t *testing.T, fn func(context.Context) error) {
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
	swapProbe(t, func(context.Context) error {
		return errors.New("exit status 1: mise ERROR No version is set for shim: go")
	})

	got := quietAnalyser().classifyLoadFailure(context.Background())
	if got != domain.FailureCauseEnvironment {
		t.Errorf("classifyLoadFailure = %q, want %q", got, domain.FailureCauseEnvironment)
	}
}

// TestClassifyLoadFailure_WorkingToolchainIsModule: the toolchain ran, so
// whatever the loader reported was reported about the module.
func TestClassifyLoadFailure_WorkingToolchainIsModule(t *testing.T) {
	swapProbe(t, func(context.Context) error { return nil })

	got := quietAnalyser().classifyLoadFailure(context.Background())
	if got != domain.FailureCauseModule {
		t.Errorf("classifyLoadFailure = %q, want %q", got, domain.FailureCauseModule)
	}
}

// TestClassifyLoadFailure_CancelledIsEnvironmentWithoutProbing pins the order of
// the two checks. A cancelled context makes the probe fail for a reason that
// says nothing about the toolchain, so the cancellation is answered first.
func TestClassifyLoadFailure_CancelledIsEnvironmentWithoutProbing(t *testing.T) {
	probed := false
	swapProbe(t, func(context.Context) error {
		probed = true
		return nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if got := quietAnalyser().classifyLoadFailure(ctx); got != domain.FailureCauseEnvironment {
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

	if got := quietAnalyser().classifyLoadFailure(context.Background()); got != domain.FailureCauseModule {
		t.Errorf("classifyLoadFailure with the zero seam = %q, want %q", got, domain.FailureCauseModule)
	}
}

// TestSetToolchainProbe_NilIsRefused pins that a composition root cannot unwire
// the seam by passing nil: the previously-installed probe keeps answering.
func TestSetToolchainProbe_NilIsRefused(t *testing.T) {
	sentinel := errors.New("sentinel probe")
	swapProbe(t, func(context.Context) error { return sentinel })

	SetToolchainProbe(nil)

	if err := toolchainProbe(context.Background()); !errors.Is(err, sentinel) {
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
