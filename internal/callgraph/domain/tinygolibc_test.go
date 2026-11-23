package domain_test

import (
	"strings"
	"testing"

	"code.eitanity.com/kanonarion/internal/callgraph/domain"
)

const (
	libcDir     = "/home/u/.cache/tinygo/wasi-libc-wasm32-unknown-wasi-generic/include"
	libcAbsence = "/w/main.go: TinyGo has not built wasi-libc for target wasip1 on this host: " + libcDir +
		" does not exist, so clang could not read the preamble of example.com/app (/w/main.go:4:10: fatal error: 'stdio.h' file not found)"
	libcRejection = "/w/main.go: clang rejected the preamble, read with TinyGo's wasi-libc headers: /w/main.go:5:10: fatal error: 'nosuchheader.h' file not found"
)

func TestReadTinyGoLibcAbsence(t *testing.T) {
	a, ok := domain.ReadTinyGoLibcAbsence(libcAbsence + "; " + strings.Replace(libcAbsence, "example.com/app", "example.com/app/sub", 1) + "; " + libcAbsence)
	if !ok || a.Libc != "wasi-libc" || a.Target != "wasip1" || a.Dir != libcDir ||
		!a.DroppedBy("example.com/app") || !a.DroppedBy("example.com/app/sub") || len(a.Packages) != 2 || a.DroppedBy("example.com/other") {
		t.Errorf("ReadTinyGoLibcAbsence = %+v, %v", a, ok)
	}
	if _, ok := domain.ReadTinyGoLibcAbsence(libcRejection); ok {
		t.Error("a refusal with the headers in place read as their absence")
	}
}

// The absence's remedy builds the libc and re-runs without --force, since the
// record is never served back; it sends no one to fix the source.
func TestIncompleteGraphRemedy_AnUnbuiltLibc(t *testing.T) {
	got := domain.IncompleteGraphRemedy(localApp(t), domain.FailureCauseEnvironment, libcAbsence, "/w", tinyWasip1)
	want := "  TinyGo has not built wasi-libc for target wasip1 on this host, so clang read the preamble\n" +
		"  without its headers: " + libcDir + " does not exist. The gap is in the environment, not in the source.\n" +
		"  Build any program for the target, which builds that libc, then re-analyse:\n" +
		"  tinygo build -target wasip1 <any main package>\n" +
		"  kanonarion local /w --tinygo wasip1"
	if got != want {
		t.Errorf("remedy =\n%s\nwant\n%s", got, want)
	}
	rec := domain.CallGraphRecord{OverallStatus: domain.CallGraphStatusPartial, FailureCause: domain.FailureCauseEnvironment, FailureDetail: libcAbsence}
	if domain.RecordIsCacheable(rec) {
		t.Error("a record the host's missing libc limited was served")
	}
	if got := domain.DroppedPackageReasonFor("example.com/app", libcAbsence); got !=
		"was not analysed: TinyGo has not built wasi-libc for target wasip1 on this host ("+libcDir+" does not exist)" {
		t.Errorf("dropped reason = %q", got)
	}
	if got := domain.DroppedPackageReasonFor("example.com/other", libcAbsence); got != "did not typecheck" {
		t.Errorf("another package's reason = %q", got)
	}
}

// Control: clang refusing a preamble with the libc's headers in place is the
// module's own error, served from cache and fixed in the source.
func TestIncompleteGraphRemedy_ARejectionWithTheHeadersIsTheModules(t *testing.T) {
	got := domain.IncompleteGraphRemedy(localApp(t), domain.FailureCauseModule, libcRejection, "/w", tinyWasip1)
	if got != "  Fix the package so it compiles, then re-analyse:\n  kanonarion local /w --tinygo wasip1" {
		t.Errorf("remedy = %q", got)
	}
	rec := domain.CallGraphRecord{OverallStatus: domain.CallGraphStatusPartial, FailureCause: domain.FailureCauseModule, FailureDetail: libcRejection}
	if !domain.RecordIsCacheable(rec) {
		t.Error("a module's own compile error was not served")
	}
}

// A 0.16.0 record written before the libc headers were passed quotes clang's
// refusal without naming them: it is re-measured, and its remedy says so.
func TestRecordIsCacheable_APreambleReadWithoutTheLibcIsRemeasured(t *testing.T) {
	legacy := "/w/main.go: clang rejected the preamble: /usr/include/stdio.h:28:10: fatal error: 'bits/libc-header-start.h' file not found"
	rec := domain.CallGraphRecord{OverallStatus: domain.CallGraphStatusPartial, FailureCause: domain.FailureCauseModule, FailureDetail: legacy}
	if domain.RecordIsCacheable(rec) {
		t.Error("a record read without TinyGo's libc headers was served")
	}
	got := domain.IncompleteGraphRemedy(localApp(t), domain.FailureCauseModule, legacy, "/w", tinyWasip1)
	if got != "  A kanonarion that read the preamble without TinyGo's libc headers wrote this record; this one\n"+
		"  passes them. Re-analyse:\n  kanonarion local /w --tinygo wasip1" {
		t.Errorf("remedy = %q", got)
	}
}

// Below full fidelity, the coding caveat prescribes a rebuild only when the
// record states no limit a rebuild cannot clear; other phases are unchanged.
func TestCompletenessCaveatFor_NoRebuildForAStatedLimit(t *testing.T) {
	lowering := domain.TinyGoLoweringGap{Found: "0.45.0", Covered: []string{"0.43.0", "0.44.0"}}.Clause()
	for name, detail := range map[string]string{
		"libc":     libcAbsence,
		"cgo gap":  cgoGapDetail(false),
		"lowering": lowering,
		"limit":    "/src/probe/main.go:1:1: package requires newer Go version go1.27 (application built with go1.26)",
		"legacy":   "/w/main.go: clang rejected the preamble: /w/main.go:4:10: fatal error: 'stdio.h' file not found",
	} {
		got := domain.CompletenessCaveatFor(domain.CompletenessTypeOnly, domain.PhaseCoding, detail)
		if got != "call graph is TYPE_ONLY, not built with bodies, for the reason its record states; answers over this module may be incomplete" {
			t.Errorf("%s: caveat %q", name, got)
		}
	}
	// Control: no stated cause, or a compile error, keeps the rebuild.
	for _, detail := range []string{"", compileError, libcRejection} {
		if got := domain.CompletenessCaveatFor(domain.CompletenessTypeOnly, domain.PhaseCoding, detail); !strings.Contains(got, "go generate") {
			t.Errorf("detail %q: caveat %q, want the rebuild", detail, got)
		}
	}
	if got := domain.CompletenessCaveatFor(domain.CompletenessTypeOnly, domain.PhaseInclusion, libcAbsence); !strings.Contains(got, "untrusted") {
		t.Errorf("inclusion caveat %q", got)
	}
	if got := domain.CompletenessCaveatFor(domain.CompletenessBuiltWithBodies, domain.PhaseCoding, libcAbsence); got != "" {
		t.Errorf("full fidelity caveat %q", got)
	}
}
