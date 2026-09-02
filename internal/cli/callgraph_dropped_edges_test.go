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
	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
)

// droppedEdgeStore is the sprig condition in miniature: a dependency whose own
// package failed to typecheck, so it produced no SSA and no node for the queried
// symbol, alongside a consumer whose graph is complete and DOES record the call
// sites into it.
//
// That pairing is the whole point. The refusal this fixture guards against
// treated the dependency's gap as a property of the symbol and suppressed the
// consumer's measured edges, while interface-diff --used-by answered the same
// question off exactly those edges.
func droppedEdgeStore() *testfakes.FakeQueryCallGraph {
	uc := testfakes.NewFakeQueryCallGraph()
	uc.SetList([]cgports.CallGraphSummary{
		{ModulePath: "example.com/dep", ModuleVersion: "v1.0.0", PipelineVersion: cgapp.PipelineVersion},
		{ModulePath: "example.com/app", ModuleVersion: coordinate.LocalVersion, PipelineVersion: cgapp.PipelineVersion},
	})
	uc.AddRecord(coordinatetest.MustNew("example.com/dep", "v1.0.0"), cgapp.PipelineVersion,
		cgdomain.CallGraphRecord{
			Completeness:   cgdomain.CompletenessBuiltWithBodies,
			TestScope:      cgdomain.TestScopeAnalysed,
			ReferenceScope: cgdomain.ReferenceScopeAnalysed,
			OverallStatus:  cgdomain.CallGraphStatusPartial,
			FailedPackages: []string{"example.com/dep"},
			// The dependency's own sources are what failed, which is what makes the
			// stored record answer the re-run and therefore what makes --force part
			// of the remedy.
			FailureCause: cgdomain.FailureCauseModule,
		})
	uc.AddRecord(coordinatetest.MustNew("example.com/app", coordinate.LocalVersion), cgapp.PipelineVersion,
		builtRecord([]cgdomain.CallNode{{ID: "example.com/app.Handler", Symbol: "Handler"}}, nil))
	return uc
}

func consumerEdge() cgports.CallEdgeRef {
	return cgports.CallEdgeRef{
		FromID:        "example.com/app.Handler",
		ToID:          "example.com/dep.FuncMap",
		ModulePath:    "example.com/app",
		ModuleVersion: coordinate.LocalVersion,
	}
}

// A package whose edges were dropped must not turn a query into a refusal. The
// refusal it replaced exited 20 and printed nothing, so five recorded call sites
// became zero answerable queries on the command named for the job.
func TestRunCallers_DroppedEdgePackageAnswersFromTheConsumersGraph(t *testing.T) {
	uc := droppedEdgeStore()
	uc.SetCallers([]cgports.CallEdgeRef{consumerEdge()})

	var buf bytes.Buffer
	if err := runCallers(context.Background(), "example.com/dep.FuncMap", false, uc, &buf, buildScope{}, cgports.EdgeQueryOptions{}); err != nil {
		t.Fatalf("a query the store can answer was refused: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "example.com/app.Handler") {
		t.Errorf("the consumer's recorded call site is missing from:\n%s", out)
	}
	if !strings.Contains(out, "unmeasured on one side") {
		t.Errorf("the answer does not state what it could not measure:\n%s", out)
	}
	if !strings.Contains(out, `package "example.com/dep" did not typecheck`) {
		t.Errorf("the reason is not named:\n%s", out)
	}
}

// The remedy must be one the reader can act on. A dependency's failed typecheck
// lives in that dependency's own sources: telling the operator to fix a package
// and re-run 'kanonarion local <dir>' names a working tree they do not have.
func TestRunCallers_DroppedEdgeRemedySuitsADependencyCoordinate(t *testing.T) {
	uc := droppedEdgeStore()
	uc.SetCallers([]cgports.CallEdgeRef{consumerEdge()})

	var buf bytes.Buffer
	if err := runCallers(context.Background(), "example.com/dep.FuncMap", false, uc, &buf, buildScope{}, cgports.EdgeQueryOptions{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if strings.Contains(out, "kanonarion local") {
		t.Errorf("a fetched dependency's build failure was blamed on the reader's working tree:\n%s", out)
	}
	if !strings.Contains(out, "not in your tree") {
		t.Errorf("the answer does not say whose failure it is:\n%s", out)
	}
	if !strings.Contains(out, "kanonarion callgraph example.com/dep@v1.0.0 --force") {
		t.Errorf("no command the reader can actually run is named:\n%s", out)
	}
}

// With nothing recorded anywhere, the answer is still not a refusal — and still
// not a confident absence. It is unmeasured, with the dropped package as the
// reason, so the gap reads as a property of the analysis rather than of the
// symbol.
func TestRunCallers_DroppedEdgePackageWithNoEdgesIsUnresolvedNotAbsent(t *testing.T) {
	uc := droppedEdgeStore()

	var buf bytes.Buffer
	if err := runCallers(context.Background(), "example.com/dep.FuncMap", false, uc, &buf, buildScope{}, cgports.EdgeQueryOptions{}); err != nil {
		t.Fatalf("an empty answer was raised as an error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "answer: UNRESOLVED") {
		t.Errorf("expected UNRESOLVED, got:\n%s", out)
	}
	if !strings.Contains(out, string(cgdomain.SinkDroppedPackageEdges)) {
		t.Errorf("the verdict does not name the dropped package as its sink:\n%s", out)
	}
	// "not a node in the analysed call graph … it may be a typo, or
	// unexported/unreachable code" is what the empty-result classifier says, and
	// it is the accusation this condition must never produce: the symbol is
	// missing because its package never compiled.
	if strings.Contains(out, "may be a typo") {
		t.Errorf("the symbol was blamed for its module's build failure:\n%s", out)
	}
}

// The same condition on every edge command, so a fix at one entry point cannot
// leave the others refusing.
func TestDroppedEdgePackage_EveryEdgeCommandAnswers(t *testing.T) {
	cmds := map[string]func(*testfakes.FakeQueryCallGraph, *bytes.Buffer) error{
		"callers": func(uc *testfakes.FakeQueryCallGraph, buf *bytes.Buffer) error {
			return runCallers(context.Background(), "example.com/dep.FuncMap", false, uc, buf, buildScope{}, cgports.EdgeQueryOptions{})
		},
		"callees": func(uc *testfakes.FakeQueryCallGraph, buf *bytes.Buffer) error {
			return runCallees(context.Background(), "example.com/dep.FuncMap", false, uc, buf, buildScope{}, cgports.EdgeQueryOptions{})
		},
		"transitive callers": func(uc *testfakes.FakeQueryCallGraph, buf *bytes.Buffer) error {
			return runCallersTransitive(context.Background(), "example.com/dep.FuncMap", 0, false, uc, buf, buildScope{}, cgports.EdgeQueryOptions{})
		},
		"transitive callees": func(uc *testfakes.FakeQueryCallGraph, buf *bytes.Buffer) error {
			return runCalleesTransitive(context.Background(), "example.com/dep.FuncMap", 0, false, uc, buf, buildScope{}, cgports.EdgeQueryOptions{})
		},
	}
	for name, run := range cmds {
		t.Run(name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := run(droppedEdgeStore(), &buf); err != nil {
				t.Fatalf("%s refused a dropped-edge package: %v", name, err)
			}
			out := buf.String()
			if !strings.Contains(out, "unmeasured on one side") {
				t.Errorf("%s does not state the gap:\n%s", name, out)
			}
			if !strings.Contains(out, "answer: UNRESOLVED") {
				t.Errorf("%s does not downgrade its empty answer:\n%s", name, out)
			}
		})
	}
}

// interface-diff --used-by joins its reach counts against the consumer's stored
// call graph, so a consumer package that never compiled cannot contribute a call
// site to any count it prints. 'callers' states that condition; this section
// used to print a bare "not reached" over the same missing edges, and two
// commands in one binary disagreeing about whether a question is answerable is
// the defect, not the wording.
func TestPrintUsedBySection_DisclosesTheConsumersDroppedPackages(t *testing.T) {
	used := &usedByResult{
		Consumer:        coordinatetest.MustNew("example.com/app", coordinate.LocalVersion),
		WalkID:          "01TESTWALK",
		CallGraphFound:  true,
		DroppedPackages: []string{"example.com/app/internal/broken"},
	}
	var buf bytes.Buffer
	if err := printUsedBySection(used, &buf); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "example.com/app/internal/broken") {
		t.Errorf("the consumer's dropped package is not disclosed:\n%s", out)
	}
	if !strings.Contains(out, "unmeasured, not unreached") {
		t.Errorf("the section does not say what a missing count means here:\n%s", out)
	}
}

// A complete consumer graph must not gain a caveat it has no basis for.
func TestPrintUsedBySection_SaysNothingWhenNoPackageWasDropped(t *testing.T) {
	used := &usedByResult{
		Consumer:       coordinatetest.MustNew("example.com/app", coordinate.LocalVersion),
		WalkID:         "01TESTWALK",
		CallGraphFound: true,
	}
	var buf bytes.Buffer
	if err := printUsedBySection(used, &buf); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(buf.String(), "did not typecheck") {
		t.Errorf("a caveat was invented for a complete graph:\n%s", buf.String())
	}
}

// A gap this host's cold module cache opened is not a compile error, and a
// remedy that says it is sends the reader looking for a fault in sources that
// are fine. The record states which it was, so the notice reads that rather than
// assuming.
func TestRunCallers_DroppedEdgeRemedyNamesTheColdCacheWhenThatIsTheCause(t *testing.T) {
	uc := droppedEdgeStore()
	uc.AddRecord(coordinatetest.MustNew("example.com/dep", "v1.0.0"), cgapp.PipelineVersion,
		cgdomain.CallGraphRecord{
			Completeness:   cgdomain.CompletenessBuiltWithBodies,
			TestScope:      cgdomain.TestScopeAnalysed,
			ReferenceScope: cgdomain.ReferenceScopeAnalysed,
			OverallStatus:  cgdomain.CallGraphStatusPartial,
			FailedPackages: []string{"example.com/dep"},
			FailureCause:   cgdomain.FailureCauseEnvironment,
		})
	uc.SetCallers([]cgports.CallEdgeRef{consumerEdge()})

	var buf bytes.Buffer
	if err := runCallers(context.Background(), "example.com/dep.FuncMap", false, uc, &buf, buildScope{}, cgports.EdgeQueryOptions{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "module cache") {
		t.Errorf("the remedy does not name the cold module cache:\n%s", out)
	}
	if !strings.Contains(out, cgdomain.ColdModuleCacheRemedy) {
		t.Errorf("the one-step way to make the modules available is not named:\n%s", out)
	}
	// The record is not servable, so the plain command re-derives; printing
	// --force here would teach a flag the reader does not need.
	if strings.Contains(out, "--force") {
		t.Errorf("a remedy for an unservable record still names --force:\n%s", out)
	}
}

// The same on a working tree: 'local' is the command, and it needs no flag
// because the record a cold cache produced is not served back.
func TestDroppedEdgeRemedy_LocalColdCacheReanalysesWithoutForce(t *testing.T) {
	coord := coordinatetest.MustNew("example.com/app", coordinate.LocalVersion)
	got := cgdomain.IncompleteGraphRemedy(coord, cgdomain.FailureCauseEnvironment, "", "/work/tree")
	if !strings.Contains(got, cgdomain.ColdModuleCacheRemedy) {
		t.Errorf("the remedy does not warm the cache in one step:\n%s", got)
	}
	if !strings.Contains(got, "kanonarion local /work/tree") {
		t.Errorf("the remedy does not name the run in the tree it was pointed at:\n%s", got)
	}
	if strings.Contains(got, "--force") {
		t.Errorf("a record that is not served back was given a bypass flag:\n%s", got)
	}
	if strings.Contains(got, "Fix the package so it compiles") {
		t.Errorf("a cold cache was reported as a compile error:\n%s", got)
	}
}
