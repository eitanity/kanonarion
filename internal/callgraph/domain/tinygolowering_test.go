package domain_test

import (
	"errors"
	"runtime"
	"strings"
	"testing"

	"code.eitanity.com/kanonarion/internal/callgraph/domain"
	"code.eitanity.com/kanonarion/internal/coordinate"
)

var wasmFrame = domain.BuildFrame{GOOS: "js", GOARCH: "wasm", TinyGoTarget: "wasm", TinyGoVersion: "0.99.0"}

func gapDetail(found string) string {
	return domain.TinyGoLoweringGap{Found: found, Covered: []string{"0.42.0", "0.43.0", "0.44.0"}}.Clause()
}

// A release no table covers is kanonarion's limit: the remedy names the release
// found and those covered, never the module cache, and re-runs the TinyGo build.
func TestIncompleteGraphRemedy_UncoveredTinyGoRelease(t *testing.T) {
	defer domain.SetTinyGoLoweringReleases([]string{"0.42.0", "0.43.0", "0.44.0"})()
	local, err := coordinate.NewLocalCoordinate("example.com/app")
	if err != nil {
		t.Fatal(err)
	}
	// Unrecorded is what this build files; environment is what 0.16.0 filed
	// before, and such a record reads the same.
	for _, cause := range []domain.FailureCause{domain.FailureCauseUnrecorded, domain.FailureCauseEnvironment} {
		got := domain.IncompleteGraphRemedy(local, cause, gapDetail("0.99.0"), "/work/tree", wasmFrame)
		for _, want := range []string{"TinyGo 0.99.0", "0.42.0, 0.43.0, 0.44.0", "lowering table covers TinyGo 0.99.0",
			"\n  kanonarion local /work/tree --tinygo wasm"} {
			if !strings.Contains(got, want) {
				t.Errorf("cause %s: remedy does not say %q:\n%s", cause, want, got)
			}
		}
		for _, never := range []string{"module cache", domain.ColdModuleCacheRemedy, "Fix the package"} {
			if strings.Contains(got, never) {
				t.Errorf("cause %s: remedy says %q:\n%s", cause, never, got)
			}
		}
	}
	// This binary covers what an older one did not: re-analysing closes it.
	got := domain.IncompleteGraphRemedy(local, domain.FailureCauseUnrecorded, gapDetail("0.44.0"), "/work/tree", wasmFrame)
	if !strings.Contains(got, "this one has one") || strings.Contains(got, "Use a kanonarion") ||
		!strings.HasSuffix(got, "kanonarion local /work/tree --tinygo wasm") {
		t.Errorf("a gap this binary closes:\n%s", got)
	}
}

// The gap's remedy stands beside the remedy for what else the load reported.
func TestIncompleteGraphRemedy_LoweringGapBesideACompileError(t *testing.T) {
	defer domain.SetTinyGoLoweringReleases([]string{"0.42.0"})()
	local, err := coordinate.NewLocalCoordinate("example.com/app")
	if err != nil {
		t.Fatal(err)
	}
	detail := gapDetail("0.99.0") + "; x.go:3:9: undefined: rand.Text"
	got := domain.IncompleteGraphRemedy(local, domain.FailureCauseModule, detail, "/work/tree", wasmFrame)
	if !strings.Contains(got, "TinyGo 0.99.0") || !strings.Contains(got, "Fix the package so it compiles, then re-analyse:\n  kanonarion local /work/tree --tinygo wasm") {
		t.Errorf("remedy:\n%s", got)
	}
}

// A lowering-gap record is never served back, whatever cause the load filed; a
// TinyGo record without one keeps the cause's answer.
func TestRecordIsCacheable_LoweringGapIsNeverServed(t *testing.T) {
	for _, cause := range []domain.FailureCause{domain.FailureCauseUnrecorded, domain.FailureCauseModule} {
		rec := domain.CallGraphRecord{OverallStatus: domain.CallGraphStatusPartial, FailureCause: cause,
			FailureDetail: gapDetail("0.99.0"), Frame: wasmFrame}
		if domain.RecordIsCacheable(rec) {
			t.Errorf("cause %s: a lowering-gap record is cacheable", cause)
		}
	}
	held := domain.CallGraphRecord{OverallStatus: domain.CallGraphStatusPartial, FailureCause: domain.FailureCauseModule,
		FailureDetail: "x.go:3:9: undefined: rand.Text", Frame: wasmFrame}
	if !domain.RecordIsCacheable(held) {
		t.Error("a TinyGo record with no lowering gap is not cacheable")
	}
	if g, ok := domain.ReadTinyGoLoweringGap("x; " + gapDetail("0.45.1")); !ok || g.Found != "0.45.1" || len(g.Covered) != 3 {
		t.Errorf("ReadTinyGoLoweringGap = %+v, %v", g, ok)
	}
}

// local reuses a TinyGo record only from the release on PATH; reads select on
// the frame alone.
func TestWorktreeRecordAnswersFor_TinyGoRelease(t *testing.T) {
	held := domain.CallGraphRecord{AnalysisSource: domain.AnalysisSourceWorktree, AnalysisRoot: "/t",
		WorktreeScanDigest: "d", OverallStatus: domain.CallGraphStatusExtracted, Frame: wasmFrame}
	same := domain.WorktreeIdentity{Root: "/t", ScanDigest: "d", Frame: wasmFrame}
	if !domain.WorktreeRecordAnswersFor(held, same) {
		t.Error("a record of the release on PATH is not reused")
	}
	other := same
	other.Frame.TinyGoVersion = "0.42.0"
	if domain.WorktreeRecordAnswersFor(held, other) {
		t.Error("a record of another TinyGo release is reused")
	}
	if !domain.SameFrame(held.Frame, other.Frame) {
		t.Error("the read selection now separates TinyGo releases")
	}
}

// The TinyGo re-run names the target when it is known.
func TestTinyGoReanalysisInstruction_NamesTheTarget(t *testing.T) {
	local, err := coordinate.NewLocalCoordinate("example.com/app")
	if err != nil {
		t.Fatal(err)
	}
	if got := domain.TinyGoReanalysisInstruction(local, "/work/tree", "wasm"); got != "kanonarion local /work/tree --tinygo wasm" {
		t.Errorf("got %q", got)
	}
	if got := domain.FrameReanalysisInstruction(local, "", wasmFrame, true); got != domain.UnnamedWorkingTreeLead+", so run kanonarion local --force --tinygo wasm from inside it" {
		t.Errorf("got %q", got)
	}
}

// A conflict between TinyGo records re-runs in their frame.
func TestCompose_ConflictRerunKeepsTheTinyGoFrame(t *testing.T) {
	a := composeRecord(t, composeSpec{
		source: domain.AnalysisSourceModuleZip, artefact: "zip:h1:a",
		completeness: domain.CompletenessBuiltWithBodies,
	})
	b := composeRecord(t, composeSpec{
		source: domain.AnalysisSourceModuleZip, artefact: "zip:h1:b",
		completeness: domain.CompletenessBuiltWithBodies,
	})
	a.Frame, b.Frame = wasmFrame, wasmFrame
	_, err := domain.Compose([]domain.CallGraphRecord{a, b}, domain.ComposeRequest{})
	var conflict domain.CallGraphConflict
	if !errors.As(err, &conflict) {
		t.Fatalf("err = %v, want a CallGraphConflict", err)
	}
	lines := conflict.Remedy().Lines
	if last := lines[len(lines)-1]; !strings.HasSuffix(last, " --force --tinygo wasm") {
		t.Errorf("re-analysis line = %q, want the TinyGo frame kept", last)
	}
}

// The remedy does not restate the gap the failure line already names.
func TestIncompleteGraphRemedy_StatesTheGapOnce(t *testing.T) {
	local, err := coordinate.NewLocalCoordinate("example.com/app")
	if err != nil {
		t.Fatal(err)
	}
	got := domain.IncompleteGraphRemedy(local, domain.FailureCauseUnrecorded, gapDetail("0.99.0"), "/work/tree", wasmFrame)
	if strings.Contains(got, "outside kanonarion's lowering table") || strings.Contains(got, "compiler-inserted runtime calls") {
		t.Errorf("the remedy restates the gap:\n%s", got)
	}
}

// Every re-run keeps the flag that selects the record's frame; this host's own
// frame needs none.
func TestFrameReanalysisInstruction_KeepsTheFrameFlag(t *testing.T) {
	local, err := coordinate.NewLocalCoordinate("example.com/app")
	if err != nil {
		t.Fatal(err)
	}
	wasip1 := domain.BuildFrame{GOOS: "wasip1", GOARCH: "wasm"}
	if got := domain.FrameReanalysisInstruction(local, "/t", wasip1, false); got != "kanonarion local /t --target wasip1/wasm" {
		t.Errorf("wasip1/wasm: %q", got)
	}
	host := domain.BuildFrame{GOOS: runtime.GOOS, GOARCH: runtime.GOARCH}
	if got := domain.FrameReanalysisInstruction(local, "/t", host, false); got != "kanonarion local /t" {
		t.Errorf("host: %q", got)
	}
	got := domain.IncompleteGraphRemedy(local, domain.FailureCauseEnvironment, "", "/t", wasip1)
	if !strings.HasSuffix(got, "kanonarion local /t --target wasip1/wasm") {
		t.Errorf("cold-cache remedy under wasip1/wasm:\n%s", got)
	}
}

// An answer read over a gap record is UNRESOLVED naming it, whatever it was.
func TestAnswerWithSinks_TheLoweringGap(t *testing.T) {
	sink := domain.TinyGoLoweringGap{Found: "0.45.0", Covered: []string{"0.44.0"}}.Sink("example.com/app@local")
	for _, v := range []domain.Answer{{Outcome: domain.AnswerResolvedAbsent}, {Outcome: domain.AnswerUnresolved, Sinks: []domain.SoundnessSink{sink}}} {
		got := v.WithSinks(sink)
		if got.Outcome != domain.AnswerUnresolved || len(got.Sinks) != 1 ||
			got.Reason() != "tinygo-lowering-unrecorded at example.com/app@local (TinyGo 0.45.0 ran; the kanonarion that analysed it has lowering tables for TinyGo 0.44.0)" {
			t.Errorf("%+v.WithSinks = %+v %q", v, got, got.Reason())
		}
	}
	if got := (domain.Answer{Outcome: domain.AnswerResolvedAbsent}).WithSinks(); got.Outcome != domain.AnswerResolvedAbsent {
		t.Errorf("no sinks changed the answer: %+v", got)
	}
}
