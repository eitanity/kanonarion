package staticcha

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
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
	swapProbe(t, func(context.Context, string, []string) (string, error) {
		return "", errors.New("exit status 1: mise ERROR No version is set for shim: go")
	})

	got := quietAnalyser().classifyLoadFailure(context.Background(), analysedDir, nil)
	if got != domain.FailureCauseEnvironment {
		t.Errorf("classifyLoadFailure = %q, want %q", got, domain.FailureCauseEnvironment)
	}
}

// TestClassifyLoadFailure_WorkingToolchainIsModule: the toolchain ran, so
// whatever the loader reported was reported about the module.
func TestClassifyLoadFailure_WorkingToolchainIsModule(t *testing.T) {
	swapProbe(t, func(context.Context, string, []string) (string, error) { return "go1.26.6", nil })

	got := quietAnalyser().classifyLoadFailure(context.Background(), analysedDir, nil)
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
	swapProbe(t, func(_ context.Context, dir string, _ []string) (string, error) {
		asked = dir
		return "go1.26.6", nil
	})

	quietAnalyser().classifyLoadFailure(context.Background(), analysedDir, nil)

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
	swapProbe(t, func(_ context.Context, probed string, _ []string) (string, error) {
		asked = append(asked, probed)
		return "go1.26.6", nil
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
	swapProbe(t, func(context.Context, string, []string) (string, error) {
		probed = true
		return "go1.26.6", nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if got := quietAnalyser().classifyLoadFailure(ctx, analysedDir, nil); got != domain.FailureCauseEnvironment {
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

	if got := quietAnalyser().classifyLoadFailure(context.Background(), analysedDir, nil); got != domain.FailureCauseModule {
		t.Errorf("classifyLoadFailure with the zero seam = %q, want %q", got, domain.FailureCauseModule)
	}
}

// TestSetToolchainProbe_NilIsRefused pins that a composition root cannot unwire
// the seam by passing nil: the previously-installed probe keeps answering.
func TestSetToolchainProbe_NilIsRefused(t *testing.T) {
	sentinel := errors.New("sentinel probe")
	swapProbe(t, func(context.Context, string, []string) (string, error) { return "", sentinel })

	SetToolchainProbe(nil)

	if _, err := toolchainProbe(context.Background(), analysedDir, nil); !errors.Is(err, sentinel) {
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

// writeModuleTree writes a go.mod and one source file, whose body carries a call
// so a successful analysis has an edge to show for itself.
func writeModuleTree(t *testing.T, gomod string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(gomod), 0o600); err != nil {
		t.Fatalf("writing go.mod: %v", err)
	}
	src := "package analysed\n\n// F calls g.\nfunc F() int { return g() }\n\nfunc g() int { return 1 }\n"
	if err := os.WriteFile(filepath.Join(dir, "a.go"), []byte(src), 0o600); err != nil {
		t.Fatalf("writing a.go: %v", err)
	}
	return dir
}

func localCoord(t *testing.T) coordinate.ModuleCoordinate {
	t.Helper()
	coord, err := coordinate.NewModuleCoordinate("example.com/analysed", coordinate.LocalVersion)
	if err != nil {
		t.Fatalf("coordinate: %v", err)
	}
	return coord
}

// TestAnalyseDir_ToolchainDirectiveAboveTheRunningOneStillAnalyses covers the
// class the pin recovers outright: the `go` directive is satisfied, only the
// `toolchain` line is not, and that line is advice rather than a requirement.
// go1.99.0 is beyond any host, so the switch is measured declined, not absent.
func TestAnalyseDir_ToolchainDirectiveAboveTheRunningOneStillAnalyses(t *testing.T) {
	dir := writeModuleTree(t, "module example.com/analysed\n\ngo 1.21\n\ntoolchain go1.99.0\n")

	rec, err := quietAnalyser().AnalyseDir(context.Background(), dir, localCoord(t))
	if err != nil {
		t.Fatalf("AnalyseDir: %v", err)
	}
	if rec.OverallStatus == domain.CallGraphStatusLoadFailed {
		t.Fatalf("a module whose go directive this host satisfies failed to load: %s", rec.FailureDetail)
	}
	if rec.NodeCount == 0 {
		t.Errorf("no nodes for a module that loaded; detail: %s", rec.FailureDetail)
	}
}

// TestAnalyseDir_UnsatisfiableGoDirectiveNamesTheVersionGap covers the other
// outcome — a host that genuinely cannot answer — and pins the sentence it
// leaves: the two versions, not a checksum service nobody configured.
//
// The probe answers "usable" because that is what a real probe answers here, so
// the cause has to come from the marker.
func TestAnalyseDir_UnsatisfiableGoDirectiveNamesTheVersionGap(t *testing.T) {
	swapProbe(t, func(context.Context, string, []string) (string, error) { return "go1.26.6", nil })
	dir := writeModuleTree(t, "module example.com/analysed\n\ngo 1.99.0\n")

	rec, err := quietAnalyser().AnalyseDir(context.Background(), dir, localCoord(t))
	if err != nil {
		t.Fatalf("AnalyseDir: %v", err)
	}
	if rec.OverallStatus != domain.CallGraphStatusLoadFailed {
		t.Fatalf("a module requiring go 1.99.0 loaded (%v); the gap was never reached", rec.OverallStatus)
	}
	for _, unwanted := range []string{"GOSUMDB", "checksum database"} {
		if strings.Contains(rec.FailureDetail, unwanted) {
			t.Errorf("failure detail names %q, which is this environment's own setting and not the host's shortfall:\n%s",
				unwanted, rec.FailureDetail)
		}
	}
	for _, want := range []string{"requires go >= 1.99.0", "running go "} {
		if !strings.Contains(rec.FailureDetail, want) {
			t.Errorf("failure detail does not carry %q, so it names neither the gap nor the versions:\n%s",
				want, rec.FailureDetail)
		}
	}
	if rec.FailureCause != domain.FailureCauseEnvironment {
		t.Errorf("FailureCause = %q, want %q: a host one point release behind is not the module's fault, "+
			"and a module fault is cached",
			rec.FailureCause, domain.FailureCauseEnvironment)
	}
	if domain.RecordIsCacheable(rec) {
		t.Error("the host's missing toolchain was recorded as a cacheable property of the module")
	}
}

// TestIsToolchainTooOld_MatchesTheGoCommandsSentence pins the marker against the
// wording the go command emits and against two strings that must not match it.
func TestIsToolchainTooOld_MatchesTheGoCommandsSentence(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		detail string
		want   bool
	}{
		{
			name:   "unpinned",
			detail: "meta load: err: exit status 1: stderr: go: go.mod requires go >= 1.26.6 (running go 1.26.5)\n",
			want:   true,
		},
		{
			name:   "pinned names the setting too",
			detail: "go: go.mod requires go >= 1.26.6 (running go 1.26.5; GOTOOLCHAIN=local)\n",
			want:   true,
		},
		{
			name:   "the message this replaces",
			detail: "go: golang.org/toolchain@v0.0.1-go1.26.6.linux-amd64: verifying module: checksum database disabled by GOSUMDB=off\n",
			want:   false,
		},
		{
			name:   "half the phrase in the module's own prose",
			detail: "./doc.go:3:2: this package requires go >= 1.22 to build",
			want:   false,
		},
	} {
		if got := isToolchainTooOld(tc.detail); got != tc.want {
			t.Errorf("%s: isToolchainTooOld = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestProbeToolchainVersion_AsksWithTheLoadersOwnEnvironment is the
// reproduction the env argument exists for.
//
// Every analysis environment pins GOTOOLCHAIN=local. A probe left to inherit the
// process environment switches to whatever the tree's go directive asks for and
// names a toolchain the loader never ran — measured on a tree whose load failed
// with "requires go >= 1.26.6 (running go 1.26.5)" while the record it wrote said
// go1.26.6. The stamp is only evidence if it is asked the loader's question.
func TestProbeToolchainVersion_AsksWithTheLoadersOwnEnvironment(t *testing.T) {
	var got []string
	swapProbe(t, func(_ context.Context, _ string, env []string) (string, error) {
		got = env
		return "go1.26.5", nil
	})

	want := []string{"GOTOOLCHAIN=local"}
	if v := probeToolchainVersion(context.Background(), analysedDir, want); v != "go1.26.5" {
		t.Errorf("probeToolchainVersion = %q, want the probe's answer go1.26.5", v)
	}
	if len(got) != 1 || got[0] != "GOTOOLCHAIN=local" {
		t.Errorf("the probe was given %v; it must be handed the loader's own environment %v", got, want)
	}
}

// TestProbeToolchainVersion_AFailedProbeRecordsNothing: a record that cannot say
// which toolchain built it says so, and never borrows the reading host's.
func TestProbeToolchainVersion_AFailedProbeRecordsNothing(t *testing.T) {
	swapProbe(t, func(context.Context, string, []string) (string, error) {
		return "go1.26.6", errors.New("no toolchain")
	})

	if v := probeToolchainVersion(context.Background(), analysedDir, nil); v != "" {
		t.Errorf("probeToolchainVersion = %q after a failed probe, want the unrecorded zero value", v)
	}
}
