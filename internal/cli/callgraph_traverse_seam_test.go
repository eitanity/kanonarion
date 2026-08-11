package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"

	cgapp "github.com/eitanity/kanonarion/internal/callgraph/application"

	cgdomain "github.com/eitanity/kanonarion/internal/callgraph/domain"
	cgports "github.com/eitanity/kanonarion/internal/callgraph/ports"
	"github.com/eitanity/kanonarion/internal/cli/testfakes"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	"github.com/spf13/cobra"
)

// traverseFake is an analysed module with one production caller and one test
// caller of the same target, over a graph that is Partial and built below full
// fidelity — so every notice, caveat and verdict path renders.
func traverseFake(t *testing.T, partial bool) *testfakes.FakeQueryCallGraph {
	t.Helper()
	rec := builtRecord([]cgdomain.CallNode{
		{ID: "example.com/m.Target", Symbol: "Target"},
		{ID: "example.com/m.Caller", Symbol: "Caller"},
		{ID: "example.com/m_test.TestCaller", Symbol: "TestCaller", IsTest: true},
	}, []cgdomain.CallEdge{
		{FromID: "example.com/m.Caller", ToID: "example.com/m.Target", Confidence: cgdomain.ConfidenceDirect},
	})
	if partial {
		rec.OverallStatus = cgdomain.CallGraphStatusPartial
		rec.FailedPackages = []string{"example.com/m/broken"}
		rec.Completeness = cgdomain.CompletenessTypeOnly
	}
	uc := testfakes.NewFakeQueryCallGraph()
	uc.SetList([]cgports.CallGraphSummary{
		{ModulePath: "example.com/m", ModuleVersion: "v1.0.0", PipelineVersion: cgapp.PipelineVersion},
	})
	uc.AddRecord(coordinatetest.MustNew("example.com/m", "v1.0.0"), cgapp.PipelineVersion, rec)
	uc.SetCallers([]cgports.CallEdgeRef{
		{ModulePath: "example.com/m", ModuleVersion: "v1.0.0", FromID: "example.com/m.Caller", ToID: "example.com/m.Target", Confidence: cgdomain.ConfidenceDirect},
		{ModulePath: "example.com/m", ModuleVersion: "v1.0.0", FromID: "example.com/m_test.TestCaller", ToID: "example.com/m.Target", Confidence: cgdomain.ConfidenceDirect, IsTest: true},
	})
	uc.SetCallees([]cgports.CallEdgeRef{
		{ModulePath: "example.com/m", ModuleVersion: "v1.0.0", FromID: "example.com/m.Caller", ToID: "example.com/m.Target", Confidence: cgdomain.ConfidenceDirect},
	})
	return uc
}

// TestRunCallers_NoticesAndVerdictReportFailedWrites: every line of a callers
// answer — the Partial notice, the completeness caveat, the rows, the verdict —
// has to report a failed write rather than go missing. A dropped notice turns a
// caveated answer into a confident one.
func TestRunCallers_NoticesAndVerdictReportFailedWrites(t *testing.T) {
	uc := traverseFake(t, true)
	assertEveryWriteGuardFires(t, func(w *stallingWriter) error {
		return runCallers(context.Background(), "example.com/m.Target", false, uc, w, buildScope{}, cgports.EdgeQueryOptions{})
	})
}

func TestRunCallees_NoticesAndVerdictReportFailedWrites(t *testing.T) {
	uc := traverseFake(t, true)
	assertEveryWriteGuardFires(t, func(w *stallingWriter) error {
		return runCallees(context.Background(), "example.com/m.Caller", false, uc, w, buildScope{}, cgports.EdgeQueryOptions{})
	})
}

func TestRunCallersTransitive_ReportsFailedWrites(t *testing.T) {
	uc := traverseFake(t, true)
	uc.SetTraverseCallers([]cgports.CallEdgeRef{
		{ModulePath: "example.com/m", ModuleVersion: "v1.0.0", FromID: "example.com/m.Caller", ToID: "example.com/m.Target"},
	}, []string{"example.com/m.Caller"})
	assertEveryWriteGuardFires(t, func(w *stallingWriter) error {
		return runCallersTransitive(context.Background(), "example.com/m.Target", 2, false, uc, w, buildScope{}, cgports.EdgeQueryOptions{})
	})
}

func TestRunCalleesTransitive_ReportsFailedWrites(t *testing.T) {
	uc := traverseFake(t, true)
	uc.SetTraverseCallees([]cgports.CallEdgeRef{
		{ModulePath: "example.com/m", ModuleVersion: "v1.0.0", FromID: "example.com/m.Caller", ToID: "example.com/m.Target"},
	}, []string{"example.com/m.Target"})
	assertEveryWriteGuardFires(t, func(w *stallingWriter) error {
		return runCalleesTransitive(context.Background(), "example.com/m.Caller", 0, false, uc, w, buildScope{}, cgports.EdgeQueryOptions{})
	})
}

// TestPrintTransitiveResult_ReportsFailedWrites covers the renderer directly,
// including the empty case whose single line is the whole answer.
func TestPrintTransitiveResult_ReportsFailedWrites(t *testing.T) {
	edges := []cgports.CallEdgeRef{{ModulePath: "example.com/m", ModuleVersion: "v1.0.0", FromID: "a", ToID: "b"}}
	assertEveryWriteGuardFires(t, func(w *stallingWriter) error {
		return printTransitiveResult("callers", "b", 3, []string{"a"}, edges, false, w)
	})
	assertEveryWriteGuardFires(t, func(w *stallingWriter) error {
		return printTransitiveResult("callers", "b", 0, nil, nil, false, w)
	})
	if err := printTransitiveResult("callers", "b", 0, nil, nil, true, &stallingWriter{}); err == nil {
		t.Error("a failed JSON write was swallowed")
	}
}

// TestPrintTransitiveResult_JSONNeverEncodesNull: an empty node set has to
// serialise as [], because null reads as "not measured" to a consumer.
func TestPrintTransitiveResult_JSONNeverEncodesNull(t *testing.T) {
	var buf bytes.Buffer
	if err := printTransitiveResult("callers", "b", 0, nil, nil, true, &buf); err != nil {
		t.Fatalf("printTransitiveResult: %v", err)
	}
	if strings.Contains(buf.String(), "null") {
		t.Errorf("empty result encoded a null: %s", buf.String())
	}
}

// TestRunCallers_PartialRootIsStatedNotRefused: a root in a package that did not
// typecheck is answered with the gap on the answer. Refusing it withheld edges
// the store held — the callers of a dependency's symbol live in the consumer's
// own graph, which the dependency's build failure does not touch.
func TestRunCallers_PartialRootIsStatedNotRefused(t *testing.T) {
	uc := traverseFake(t, true)
	var buf bytes.Buffer
	if err := runCallers(context.Background(), "example.com/m/broken.Fn", false, uc, &buf, buildScope{}, cgports.EdgeQueryOptions{}); err != nil {
		t.Fatalf("want an answer carrying its gap, got error %v", err)
	}
	if !strings.Contains(buf.String(), "did not typecheck") {
		t.Fatalf("the gap is not stated on the answer: %q", buf.String())
	}
}

// TestNewCallersAndCalleesCmd_RegisterTheTestScopeFlag: the flag has to exist on
// both edge queries, or the production-only view is unavailable on one of them.
func TestNewCallersAndCalleesCmd_RegisterTheTestScopeFlag(t *testing.T) {
	var out, errOut bytes.Buffer
	for _, tc := range []struct {
		name string
		cmd  *cobra.Command
	}{
		{"callers", newCallersCmd(&out, &errOut)},
		{"callees", newCalleesCmd(&out, &errOut)},
		{"implementers", newImplementersCmd(&out, &errOut)},
	} {
		f := tc.cmd.Flags().Lookup(testScopeFlagName)
		if f == nil {
			t.Errorf("%s does not register --%s", tc.name, testScopeFlagName)
			continue
		}
		if f.DefValue != "false" {
			t.Errorf("%s --%s defaults to %q; the test surface must be included unless asked otherwise",
				tc.name, testScopeFlagName, f.DefValue)
		}
	}
}
