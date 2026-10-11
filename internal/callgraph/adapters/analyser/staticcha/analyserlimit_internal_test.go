package staticcha

import (
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/callgraph/domain"
)

// The standard library carries no go version, so a go1.26 binary over go1.27's
// sources is told only by go/packages' warning, attached after the type errors.
const stdlibWarning = "-: This application uses version go1.26 of the source-processing packages but runs version " +
	"go1.27 of 'go list'. It may fail to process source files that rely on newer language features. " +
	"If so, rebuild the application using a newer version of Go."

// A Partial graph the binary could not read is this host's limit, read from
// every error rather than the three the detail keeps, and led with.
func TestClassifyIncompleteGraph_AnalyserLimitIsTheEnvironment(t *testing.T) {
	t.Parallel()
	errs := []string{
		"/usr/local/go/src/internal/poll/splice_linux.go:237:21: unknown field rfd in struct literal of type splicePipe",
		"/usr/local/go/src/internal/poll/splice_linux.go:237:34: unknown field wfd in struct literal of type splicePipe",
		"/usr/local/go/src/math/rand/v2/x.go:1:1: undefined: y",
		stdlibWarning,
	}
	rec := domain.CallGraphRecord{OverallStatus: domain.CallGraphStatusPartial, FailureDetail: joinFirst(errs, 3)}
	got := classifyIncompleteGraph(rec, t.TempDir(), nil, errs, nil)
	if got.FailureCause != domain.FailureCauseEnvironment {
		t.Errorf("cause = %q, want %q", got.FailureCause, domain.FailureCauseEnvironment)
	}
	if !strings.HasPrefix(got.FailureDetail, stdlibWarning) {
		t.Errorf("detail does not lead with the limit:\n%s", got.FailureDetail)
	}

	// Already in the kept detail: stated once, not twice.
	refusal := "/p/main.go:1:1: package requires newer Go version go1.27 (application built with go1.26)"
	rec = domain.CallGraphRecord{OverallStatus: domain.CallGraphStatusPartial, FailureDetail: refusal}
	got = classifyIncompleteGraph(rec, t.TempDir(), nil, []string{refusal}, nil)
	if got.FailureCause != domain.FailureCauseEnvironment || strings.Count(got.FailureDetail, refusal) != 1 {
		t.Errorf("cause %q, detail %q", got.FailureCause, got.FailureDetail)
	}

	// The control: a package that does not compile is still the module's.
	rec = domain.CallGraphRecord{OverallStatus: domain.CallGraphStatusPartial, FailureDetail: errs[2]}
	if got := classifyIncompleteGraph(rec, t.TempDir(), nil, errs[2:3], nil); got.FailureCause != domain.FailureCauseModule {
		t.Errorf("a compile error was filed as %q", got.FailureCause)
	}
}
