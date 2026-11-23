package domain_test

import (
	"slices"
	"strings"
	"testing"

	"code.eitanity.com/kanonarion/internal/callgraph/domain"
	"code.eitanity.com/kanonarion/internal/coordinate"
)

const (
	ptrRefusal   = "C.pp_t: struct (unnamed at main.go:9:9) * is a C type this analysis does not translate"
	compileError = "main.go:40:2: undefined: missing"
)

func cgoGapDetail(mixed bool) string {
	return domain.CgoTranslationGapClause("example.com/app", []string{ptrRefusal}, mixed)
}

func localApp(t *testing.T) coordinate.ModuleCoordinate {
	t.Helper()
	local, err := coordinate.NewLocalCoordinate("example.com/app")
	if err != nil {
		t.Fatal(err)
	}
	return local
}

// Every refusal the translation emits that tinygo would not is set aside with
// the errors naming a refused name's identifier; a compile error, an undeclared
// C name and a refused name's prefix are not.
func TestSplitCgoTranslationErrors(t *testing.T) {
	errs := []string{
		"/w/main.go: " + ptrRefusal,
		"/w/main.go:33:10: undefined: _Cgo_pp_t",
		"/w/!cgo.go:1:1: undefined: _Cgo_pp_t",
		`/w/main.go: C.BAD: the macro "__attribute__((unused))" is not a constant this analysis evaluates: unexpected token ILLEGAL`,
		"/w/main.go:20:9: cannot use _Cgo_BAD (untyped) as int value",
		"/w/main.go:6:1: #cgo CFLAGS lines are not read by this analysis",
		"/w/main.go: reading the integer types of the preamble's enums: clang answered 0 of the 2 enum probes",
		"/w/!cgo.go:1:1: internal error: did not find Go type for C type _Cgo_char",
		"/w/main.go: C.pp_t: struct (unnamed at main.go:9:9) * is a C type this analysis does not translate",
		"/w/main.go:34:10: undefined: _Cgo_pp_tx",
		"/w/main.go:35:10: undefined: _Cgo_not_declared",
		compileError,
	}
	refusals, followers, rest := domain.SplitCgoTranslationErrors(errs)
	if len(refusals) != 4 || refusals[0] != ptrRefusal || !strings.HasPrefix(refusals[3], "internal error:") {
		t.Errorf("refusals = %q", refusals)
	}
	if !slices.Equal(followers, []string{errs[1], errs[2]}) {
		t.Errorf("followers = %q", followers)
	}
	// TinyGo refuses a macro that is not a constant too, so it stays the source's.
	if !slices.Equal(rest, append([]string{errs[3], errs[4]}, errs[9:]...)) {
		t.Errorf("rest = %q", rest)
	}
	if r, f, rest := domain.SplitCgoTranslationErrors([]string{compileError}); r != nil || f != nil || len(rest) != 1 {
		t.Errorf("a compile error alone = %q %q %q", r, f, rest)
	}
}

// A package that failed on the gap alone is kanonarion's: the remedy states it
// and sends no one to fix the source.
func TestIncompleteGraphRemedy_CgoTranslationGap(t *testing.T) {
	local := localApp(t)
	got := domain.IncompleteGraphRemedy(local, domain.FailureCauseUnrecorded, cgoGapDetail(false), "/work/tree", wasmFrame)
	for _, want := range []string{"kanonarion's cgo translation, not in the source", "No change to the source is owed",
		"Re-analyse:\n  kanonarion local /work/tree --tinygo wasm"} {
		if !strings.Contains(got, want) {
			t.Errorf("remedy does not say %q:\n%s", want, got)
		}
	}
	for _, never := range []string{"Fix the package", "--force", domain.ColdModuleCacheRemedy} {
		if strings.Contains(got, never) {
			t.Errorf("remedy says %q:\n%s", never, got)
		}
	}
	// A record from before the clause quotes the refusal and filed the module's cause.
	legacy := domain.IncompleteGraphRemedy(local, domain.FailureCauseModule, "/w/main.go: "+ptrRefusal+"; /w/main.go:33:10: undefined: _Cgo_pp_t", "/work/tree", wasmFrame)
	if !strings.Contains(legacy, "kanonarion's cgo translation") || strings.Contains(legacy, "Fix the package") {
		t.Errorf("legacy remedy:\n%s", legacy)
	}
}

// Beside a compile error of the package's own, the gap is stated and the
// compile error keeps its remedy.
func TestIncompleteGraphRemedy_CgoGapBesideACompileError(t *testing.T) {
	detail := cgoGapDetail(true) + "; " + compileError
	got := domain.IncompleteGraphRemedy(localApp(t), domain.FailureCauseModule, detail, "/work/tree", wasmFrame)
	if !strings.Contains(got, "kanonarion's cgo translation") ||
		!strings.Contains(got, "Fix the package so it compiles, then re-analyse:\n  kanonarion local /work/tree --tinygo wasm") {
		t.Errorf("remedy:\n%s", got)
	}
	g, ok := domain.ReadCgoTranslationGap(detail)
	if !ok || len(g.Mixed) != 1 || g.DroppedBy("example.com/app") {
		t.Errorf("ReadCgoTranslationGap = %+v, %v", g, ok)
	}
}

// The remedies with no gap in them are unchanged.
func TestIncompleteGraphRemedy_NoCgoGapControls(t *testing.T) {
	local := localApp(t)
	cold := domain.IncompleteGraphRemedy(local, domain.FailureCauseEnvironment, "could not import x", "/work/tree", domain.BuildFrame{})
	if !strings.Contains(cold, "\n  "+domain.ColdModuleCacheRemedy+"\n  kanonarion local /work/tree") || strings.Contains(cold, "cgo") {
		t.Errorf("cold-cache remedy:\n%s", cold)
	}
	compile := domain.IncompleteGraphRemedy(local, domain.FailureCauseModule, compileError, "/work/tree", domain.BuildFrame{})
	if compile != "  Fix the package so it compiles, then re-analyse:\n  kanonarion local /work/tree" {
		t.Errorf("compile-error remedy:\n%s", compile)
	}
}

// A gap record is never served back, whatever cause it states, and a record
// from before the clause neither; one without a gap keeps the cause's answer.
func TestRecordIsCacheable_CgoTranslationGapIsNeverServed(t *testing.T) {
	for _, detail := range []string{cgoGapDetail(false), cgoGapDetail(true) + "; " + compileError, "/w/main.go: " + ptrRefusal} {
		for _, cause := range []domain.FailureCause{domain.FailureCauseUnrecorded, domain.FailureCauseModule} {
			rec := domain.CallGraphRecord{AnalysisSource: domain.AnalysisSourceWorktree, AnalysisRoot: "/t", WorktreeScanDigest: "d",
				OverallStatus: domain.CallGraphStatusPartial, FailureCause: cause, FailureDetail: detail, Frame: wasmFrame}
			if domain.RecordIsCacheable(rec) {
				t.Errorf("cause %s, %q: cacheable", cause, detail)
			}
			if domain.WorktreeRecordAnswersFor(rec, domain.WorktreeIdentity{Root: "/t", ScanDigest: "d", Frame: wasmFrame}) {
				t.Errorf("cause %s, %q: reused by local", cause, detail)
			}
		}
	}
	held := domain.CallGraphRecord{OverallStatus: domain.CallGraphStatusPartial, FailureCause: domain.FailureCauseModule,
		FailureDetail: compileError, Frame: wasmFrame}
	if !domain.RecordIsCacheable(held) {
		t.Error("a record with no gap is not cacheable")
	}
}

// A package the gap alone dropped is said not to have been analysed; one with
// compile errors of its own still did not typecheck.
func TestDroppedPackageReasonFor_CgoTranslationGap(t *testing.T) {
	if got := domain.DroppedPackageReasonFor("example.com/app", cgoGapDetail(false)); !strings.Contains(got, "cgo translation") {
		t.Errorf("gap alone: %q", got)
	}
	for _, detail := range []string{cgoGapDetail(true), compileError} {
		if got := domain.DroppedPackageReasonFor("example.com/app", detail); got != "did not typecheck" {
			t.Errorf("%q: %q", detail, got)
		}
	}
	long := domain.CgoTranslationGapClause("p", []string{"a", "b", "c", "d", "e"}, false)
	if !strings.HasSuffix(long, ": a; b; c and 2 more") {
		t.Errorf("clause = %q", long)
	}
	if _, ok := domain.ReadCgoTranslationGap(compileError); ok {
		t.Error("a compile error reads as a gap")
	}
}
