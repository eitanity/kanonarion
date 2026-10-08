package domain_test

import (
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/callgraph/domain"
	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
)

// limitDetail is the failure detail a go1.26-built kanonarion recorded over a
// go 1.27 module, as measured.
const limitDetail = "/src/probe/main.go:1:1: package requires newer Go version go1.27 (application built with go1.26); " +
	"-: This application uses version go1.26 of the source-processing packages but runs version go1.27 of 'go list'. " +
	"It may fail to process source files that rely on newer language features. If so, rebuild the application using a newer version of Go."

// The binary was too old to read the source, so the remedy is a newer binary:
// never a fix to source that compiles, and never a warmed cache.
func TestIncompleteGraphRemedy_AnalyserLimitIsNotACompileError(t *testing.T) {
	restore := domain.SetAnalysingGo("go1.26.6")
	defer restore()
	local := coordinatetest.MustNew("example.com/probe", coordinate.LocalVersion)
	published := coordinatetest.MustNew("example.com/dep", "v1.0.0")
	for _, tc := range []struct {
		coord coordinate.ModuleCoordinate
		cause domain.FailureCause
		rerun string
	}{
		{local, domain.FailureCauseEnvironment, "kanonarion local /work/tree"},
		// A record written before the class was classified states Module.
		{local, domain.FailureCauseModule, "kanonarion local /work/tree"},
		{published, domain.FailureCauseModule, "kanonarion callgraph example.com/dep@v1.0.0"},
	} {
		got := domain.IncompleteGraphRemedy(tc.coord, tc.cause, limitDetail, "/work/tree")
		for _, bad := range []string{"Fix the package", "go mod download", "fetched dependency", "--force"} {
			if strings.Contains(got, bad) {
				t.Errorf("%s/%s: remedy says %q:\n%s", tc.coord, tc.cause, bad, got)
			}
		}
		for _, want := range []string{"built with go1.26", "requires go1.27", "kanonarion built with go1.27 or newer", tc.rerun} {
			if !strings.Contains(got, want) {
				t.Errorf("%s/%s: remedy lacks %q:\n%s", tc.coord, tc.cause, want, got)
			}
		}
	}
}

// A binary new enough to read the code was not the one that wrote the record:
// the remedy is to re-analyse with it, not to install it.
func TestIncompleteGraphRemedy_AnalyserLimitThisBinaryClears(t *testing.T) {
	restore := domain.SetAnalysingGo("go1.27.1")
	defer restore()
	coord := coordinatetest.MustNew("example.com/probe", coordinate.LocalVersion)
	got := domain.IncompleteGraphRemedy(coord, domain.FailureCauseModule, limitDetail, "/work/tree")
	if strings.Contains(got, "go install") || strings.Contains(got, "Fix the package") {
		t.Errorf("remedy for a record this binary can re-measure names an install or a source fix:\n%s", got)
	}
	if !strings.Contains(got, "kanonarion local /work/tree") {
		t.Errorf("remedy does not name the re-analysis:\n%s", got)
	}
	if _, binding := domain.AnalyserLimitOf(limitDetail); binding {
		t.Error("a limit this binary clears was reported as binding")
	}
}

// Earlier builds filed the limit as the module's, so the detail is what keeps
// that record from being served to a binary that can read the code.
func TestRecordIsCacheable_AnalyserLimitIsNeverServed(t *testing.T) {
	t.Parallel()
	for _, cause := range []domain.FailureCause{domain.FailureCauseModule, domain.FailureCauseEnvironment} {
		r := makeTestRecord()
		r.OverallStatus = domain.CallGraphStatusPartial
		r.FailureCause = cause
		r.FailureDetail = limitDetail
		if domain.RecordIsCacheable(r) {
			t.Errorf("a %s-cause record of the analyser limit is served as a cache hit", cause)
		}
	}
}

func TestDroppedPackageReason(t *testing.T) {
	t.Parallel()
	if got := domain.DroppedPackageReason(limitDetail); strings.Contains(got, "typecheck") || !strings.Contains(got, "not analysed") {
		t.Errorf("analyser limit reads %q", got)
	}
	if got := domain.DroppedPackageReason("a.go:1:1: undefined: x"); got != "did not typecheck" {
		t.Errorf("compile error reads %q", got)
	}
}
