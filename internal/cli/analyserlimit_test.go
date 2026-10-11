package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"

	cgapp "github.com/eitanity/kanonarion/internal/callgraph/application"
	cgdomain "github.com/eitanity/kanonarion/internal/callgraph/domain"
	cgports "github.com/eitanity/kanonarion/internal/callgraph/ports"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
)

// What a go1.26-built kanonarion recorded over a go 1.27 module, as measured.
const analyserLimitDetail = "/src/probe/main.go:1:1: package requires newer Go version go1.27 (application built with go1.26); " +
	"-: This application uses version go1.26 of the source-processing packages but runs version go1.27 of 'go list'. " +
	"It may fail to process source files that rely on newer language features. If so, rebuild the application using a newer version of Go."

// 20: the remedy is another build of this binary, which no invocation of this
// one runs. Once this binary clears the limit the record is an ordinary Partial.
func TestCallGraphExtractionExit_AnalyserLimitIsConfig(t *testing.T) {
	for _, tc := range []struct {
		built  string
		status cgdomain.CallGraphStatus
		want   int
	}{
		{"go1.26.6", cgdomain.CallGraphStatusPartial, ExitConfig},
		{"go1.26.6", cgdomain.CallGraphStatusLoadFailed, ExitConfig},
		{"go1.27.1", cgdomain.CallGraphStatusPartial, ExitPartial},
	} {
		restore := cgdomain.SetAnalysingGo(tc.built)
		rec := makeCGRecord(t)
		rec.OverallStatus = tc.status
		rec.FailureCause = cgdomain.FailureCauseEnvironment
		rec.FailureDetail = analyserLimitDetail
		err := callGraphExtractionExit(rec)
		restore()
		if got := ExitCodeForError(err); got != tc.want {
			t.Errorf("built %s, %s: exit %d, want %d (%v)", tc.built, tc.status, got, tc.want, err)
		}
		if tc.want == ExitConfig && !strings.Contains(err.Error(), "built with go1.26 and the code requires go1.27") {
			t.Errorf("the refusal does not state the limit: %v", err)
		}
	}
}

// The run that met the limit prints the statement and the remedy, for a graph
// and for no graph at all, and never a fix to the source.
func TestPrintCallGraphSummary_AnalyserLimitRemedy(t *testing.T) {
	restore := cgdomain.SetAnalysingGo("go1.26.6")
	defer restore()
	for _, status := range []cgdomain.CallGraphStatus{cgdomain.CallGraphStatusPartial, cgdomain.CallGraphStatusLoadFailed} {
		rec := makeCGRecord(t)
		rec.Coordinate = coordinatetest.MustNew("example.com/probe", "local")
		rec.OverallStatus = status
		rec.FailureCause = cgdomain.FailureCauseEnvironment
		rec.FailureDetail = analyserLimitDetail
		var buf bytes.Buffer
		if err := printCallGraphSummary(rec, false, false, "/work/tree", &buf, callGraphRunJSON{}); err != nil {
			t.Fatal(err)
		}
		out := buf.String()
		if strings.Contains(out, "Fix the package") {
			t.Errorf("%s: a toolchain limit was reported as a compile error:\n%s", status, out)
		}
		for _, want := range []string{"cannot read this code", "kanonarion built with go1.27 or newer", "kanonarion local /work/tree"} {
			if !strings.Contains(out, want) {
				t.Errorf("%s: output lacks %q:\n%s", status, want, out)
			}
		}
	}
}

// The callers notice says why the package was not analysed, not that it did
// not typecheck.
func TestRunCallers_AnalyserLimitNotice(t *testing.T) {
	restore := cgdomain.SetAnalysingGo("go1.26.6")
	defer restore()
	uc := droppedEdgeStore()
	uc.AddRecord(coordinatetest.MustNew("example.com/dep", "v1.0.0"), cgapp.PipelineVersion,
		cgdomain.CallGraphRecord{
			Completeness:   cgdomain.CompletenessBuiltWithBodies,
			TestScope:      cgdomain.TestScopeAnalysed,
			ReferenceScope: cgdomain.ReferenceScopeAnalysed,
			OverallStatus:  cgdomain.CallGraphStatusPartial,
			FailedPackages: []string{"example.com/dep"},
			FailureCause:   cgdomain.FailureCauseEnvironment,
			FailureDetail:  analyserLimitDetail,
		})
	uc.SetCallers([]cgports.CallEdgeRef{consumerEdge()})
	var buf bytes.Buffer
	if err := runCallers(context.Background(), "example.com/dep.FuncMap", false, uc, &buf, buildScope{}, cgports.EdgeQueryOptions{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	for _, bad := range []string{"did not typecheck", "Fix the package", "fetched dependency"} {
		if strings.Contains(out, bad) {
			t.Errorf("notice says %q:\n%s", bad, out)
		}
	}
	for _, want := range []string{"was not analysed", "built with go1.26 and the code requires go1.27", "kanonarion built with go1.27 or newer"} {
		if !strings.Contains(out, want) {
			t.Errorf("notice lacks %q:\n%s", want, out)
		}
	}
}
