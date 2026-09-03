package cli

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	cgapp "github.com/eitanity/kanonarion/internal/callgraph/application"

	cgdomain "github.com/eitanity/kanonarion/internal/callgraph/domain"
	cgports "github.com/eitanity/kanonarion/internal/callgraph/ports"
	"github.com/eitanity/kanonarion/internal/cli/testfakes"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
)

// stallingWriter accepts n writes and then fails. Every rendering path here
// writes its answer in pieces, and the never-silent rule says each piece has to
// report a failed write rather than drop a line — so the guards are exercised
// one at a time by moving the failure point along.
type stallingWriter struct {
	remaining int
}

func (w *stallingWriter) Write(p []byte) (int, error) {
	if w.remaining <= 0 {
		return 0, errors.New("write failed")
	}
	w.remaining--
	return len(p), nil
}

// assertEveryWriteGuardFires runs render with a writer that fails at each
// successive write, and requires an error every time. A swallowed write error
// would show up as a nil return for some prefix length.
func assertEveryWriteGuardFires(t *testing.T, render func(w *stallingWriter) error) {
	t.Helper()
	// Count the writes a successful render performs.
	counter := &stallingWriter{remaining: 1 << 20}
	if err := render(counter); err != nil {
		t.Fatalf("baseline render failed: %v", err)
	}
	total := (1 << 20) - counter.remaining
	if total == 0 {
		t.Fatal("render performed no writes")
	}
	for i := range total {
		if err := render(&stallingWriter{remaining: i}); err == nil {
			t.Errorf("write %d/%d failed silently", i+1, total)
		}
	}
}

func TestWriteImplementersText_ReportsEveryFailedWrite(t *testing.T) {
	impls := []scopedImplementer{{
		impl: cgdomain.InterfaceImplementation{
			InterfaceID: implPortID, TypeID: implFake, IsTest: true,
			Methods: []cgdomain.ImplementedMethod{{Method: "Put", NodeID: implFake + ".Put"}},
		},
		modulePath: implModule, moduleVersion: "v1.0.0",
	}}
	v := cgdomain.Verdict{Outcome: cgdomain.VerdictResolvedPresent}
	scope := implementersScopeLine(implModule, cgports.EdgeQueryOptions{})

	assertEveryWriteGuardFires(t, func(w *stallingWriter) error {
		return writeImplementersText(w, implPortID, "", false, impls, v, scope, buildScope{}, foreignDrawOfImplementers(impls))
	})
}

func TestWriteImplementersText_ReportsFailedWritesOnEmptyAndUnresolved(t *testing.T) {
	v := cgdomain.Verdict{
		Outcome: cgdomain.VerdictUnresolved,
		Sinks:   []cgdomain.SoundnessSink{{Kind: cgdomain.SinkTestScopeUnmeasured, Site: implPortID}},
	}
	scope := implementersScopeLine(implModule, cgports.EdgeQueryOptions{})
	assertEveryWriteGuardFires(t, func(w *stallingWriter) error {
		return writeImplementersText(w, implPortID, "", false, nil, v, scope, buildScope{}, foreignDraw{})
	})
}

func TestWriteImplementersText_ReportsFailedWritesOnAbsent(t *testing.T) {
	v := cgdomain.Verdict{Outcome: cgdomain.VerdictResolvedAbsent}
	scope := implementersScopeLine(implModule, cgports.EdgeQueryOptions{})
	assertEveryWriteGuardFires(t, func(w *stallingWriter) error {
		return writeImplementersText(w, implPortID, "", false, nil, v, scope, buildScope{}, foreignDraw{})
	})
}

func TestWriteImplementersJSON_ReportsFailedWrite(t *testing.T) {
	err := writeImplementersJSON(&stallingWriter{}, implPortID, "Put", true, nil,
		cgdomain.Verdict{Outcome: cgdomain.VerdictResolvedAbsent}, "scope", implModule, cgports.EdgeQueryOptions{}, foreignDraw{})
	if err == nil {
		t.Fatal("a failed JSON write was swallowed")
	}
}

func TestPrintCallGraphRecord_ReportsEveryFailedWrite(t *testing.T) {
	rec := builtRecord([]cgdomain.CallNode{
		{ID: "example.com/m.Root", Symbol: "Root"},
		{ID: "example.com/m_test.TestRoot", Symbol: "TestRoot", IsTest: true},
		{ID: "fmt.Println", Symbol: "Println", IsExternal: true},
		{ID: "example.com/m.Exported", Symbol: "Exported", IsExportedAPI: true},
	}, []cgdomain.CallEdge{
		{FromID: "example.com/m_test.TestRoot", ToID: "example.com/m.Root", Confidence: cgdomain.ConfidenceDirect},
	})
	rec.NodeCount = len(rec.Nodes)
	rec.EdgeCount = len(rec.Edges)
	rec.FailureDetail = "one package did not load"
	rec.Interfaces = []cgdomain.InterfaceType{{ID: "example.com/m/ports.Store", Methods: []string{"Put"}}}

	assertEveryWriteGuardFires(t, func(w *stallingWriter) error {
		return printCallGraphRecord(rec, 10, 10, w)
	})
}

func TestWriteTestScopeLine_ReportsFailedWriteAndCarriesDetail(t *testing.T) {
	rec := builtRecord([]cgdomain.CallNode{{ID: "example.com/m.Root", Symbol: "Root"}}, nil)
	rec.TestScope = cgdomain.TestScopeExcluded
	rec.TestScopeDetail = "loading the module with test files failed: boom"

	var buf bytes.Buffer
	if err := writeTestScopeLine(&buf, rec); err != nil {
		t.Fatalf("writeTestScopeLine: %v", err)
	}
	if !strings.Contains(buf.String(), "boom") {
		t.Errorf("the recorded reason is not shown: %q", buf.String())
	}
	if err := writeTestScopeLine(&stallingWriter{}, rec); err == nil {
		t.Error("a failed write was swallowed")
	}
}

func TestPrintEdgeRefs_ReportsEveryFailedWrite(t *testing.T) {
	refs := []cgports.CallEdgeRef{
		{ModulePath: implModule, ModuleVersion: "v1.0.0", FromID: "a", ToID: "b", Confidence: cgdomain.ConfidenceDirect, IsTest: true},
	}
	assertEveryWriteGuardFires(t, func(w *stallingWriter) error {
		return printEdgeRefs("callers", "b", refs, false, w)
	})
	assertEveryWriteGuardFires(t, func(w *stallingWriter) error {
		return printEdgeRefs("callers", "b", nil, false, w)
	})
	if err := printEdgeRefs("callers", "b", refs, true, &stallingWriter{}); err == nil {
		t.Error("a failed JSON write was swallowed")
	}
}

// TestCallGraphShow_JSONWriteError covers the encode guard on the record dump.
func TestCallGraphShow_JSONWriteError(t *testing.T) {
	rec := builtRecord([]cgdomain.CallNode{{ID: "example.com/m.Root", Symbol: "Root"}}, nil)
	uc := fakeWithRecord("example.com/m", "v1.0.0", cgapp.PipelineVersion, rec)
	err := runCallGraphShow(context.Background(), "example.com/m@v1.0.0", callGraphShowFlags{nodeFilter: "", limitNodes: 10, limitEdges: 10}, true, uc, &stallingWriter{})
	if err == nil {
		t.Fatal("a failed JSON write was swallowed")
	}
}

// TestCallGraphShow_BadCoordinate refuses an argument that names no module
// rather than querying for one.
func TestCallGraphShow_BadCoordinate(t *testing.T) {
	uc := testfakes.NewFakeQueryCallGraph()
	var buf bytes.Buffer
	err := runCallGraphShow(context.Background(), "not-a-coordinate", callGraphShowFlags{nodeFilter: "", limitNodes: 10, limitEdges: 10}, false, uc, &buf)
	if err == nil || !strings.Contains(err.Error(), "invalid coordinate") {
		t.Fatalf("want an invalid-coordinate error, got %v", err)
	}
}

// TestCallNodeRole_TestBeatsAPI: a test declaration is test scope first. An
// exported helper in a _test.go file is not part of the module's API, and
// labelling it "api" would put it in the wrong bucket for every consumer.
func TestCallNodeRole_TestBeatsAPI(t *testing.T) {
	for _, tc := range []struct {
		node cgdomain.CallNode
		want string
	}{
		{cgdomain.CallNode{IsExternal: true, IsTest: true}, "external"},
		{cgdomain.CallNode{IsTest: true, IsExportedAPI: true}, "test"},
		{cgdomain.CallNode{IsExportedAPI: true}, "api"},
		{cgdomain.CallNode{}, "internal"},
	} {
		if got := callNodeRole(tc.node); got != tc.want {
			t.Errorf("callNodeRole(%+v) = %q, want %q", tc.node, got, tc.want)
		}
	}
}

// TestGatherImplementers_ModuleNeverAnalysed keeps "we never looked" separate
// from "we looked and found none".
func TestGatherImplementers_ModuleNeverAnalysed(t *testing.T) {
	uc := testfakes.NewFakeQueryCallGraph()
	var buf bytes.Buffer
	err := runImplementers(context.Background(), "example.com/never/ports.Store", false, uc, &buf, buildScope{}, cgports.EdgeQueryOptions{})
	if err == nil {
		t.Fatal("expected an error for a module that was never analysed")
	}
	if !strings.Contains(err.Error(), "not in the call-graph store") {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestGatherImplementers_SkipsOtherModulesAndMissingRecords walks the loop
// guards: a summary for a different module, and a summary whose record is gone.
func TestGatherImplementers_SkipsOtherModulesAndMissingRecords(t *testing.T) {
	uc := testfakes.NewFakeQueryCallGraph()
	uc.SetList([]cgports.CallGraphSummary{
		{ModulePath: implModule, ModuleVersion: "v1.0.0", PipelineVersion: implPipeline},
		{ModulePath: implModule, ModuleVersion: "v2.0.0", PipelineVersion: implPipeline}, // no record stored
		{ModulePath: "example.com/other", ModuleVersion: "v1.0.0", PipelineVersion: implPipeline},
	})
	uc.AddRecord(coordinatetest.MustNew(implModule, "v1.0.0"), implPipeline, implRecord())

	var buf bytes.Buffer
	if err := runImplementers(context.Background(), implPortID, false, uc, &buf, buildScope{}, cgports.EdgeQueryOptions{}); err != nil {
		t.Fatalf("runImplementers: %v", err)
	}
	if !strings.Contains(buf.String(), "2 implementers") {
		t.Errorf("unexpected output: %q", buf.String())
	}
}

// TestGatherImplementers_DedupesAcrossVersions: the same declaration analysed at
// two versions is one answer to "what must change", not two.
func TestGatherImplementers_DedupesAcrossVersions(t *testing.T) {
	uc := testfakes.NewFakeQueryCallGraph()
	uc.SetList([]cgports.CallGraphSummary{
		{ModulePath: implModule, ModuleVersion: "v1.0.0", PipelineVersion: implPipeline},
		{ModulePath: implModule, ModuleVersion: "v2.0.0", PipelineVersion: implPipeline},
	})
	uc.AddRecord(coordinatetest.MustNew(implModule, "v1.0.0"), implPipeline, implRecord())
	uc.AddRecord(coordinatetest.MustNew(implModule, "v2.0.0"), implPipeline, implRecord())

	var buf bytes.Buffer
	if err := runImplementers(context.Background(), implPortID, false, uc, &buf, buildScope{}, cgports.EdgeQueryOptions{}); err != nil {
		t.Fatalf("runImplementers: %v", err)
	}
	if !strings.Contains(buf.String(), "2 implementers") {
		t.Errorf("implementations were not deduplicated across versions: %q", buf.String())
	}
}

// TestImplementers_PartialAndBelowFullDowngrade: the two other reasons an empty
// implementer set is not a measurement.
func TestImplementers_PartialAndBelowFullDowngrade(t *testing.T) {
	t.Run("failed package", func(t *testing.T) {
		rec := implRecord()
		rec.Implementations = nil
		rec.OverallStatus = cgdomain.CallGraphStatusPartial
		rec.FailedPackages = []string{"example.com/m/ports"}
		out := runImpl(t, implPortID, false, rec, cgports.EdgeQueryOptions{})
		if !strings.Contains(out, "UNRESOLVED") || !strings.Contains(out, "did not typecheck") {
			t.Errorf("a failed package did not downgrade the verdict: %q", out)
		}
	})
	t.Run("built below full fidelity", func(t *testing.T) {
		rec := implRecord()
		rec.Implementations = nil
		rec.Completeness = cgdomain.CompletenessTypeOnly
		out := runImpl(t, implPortID, false, rec, cgports.EdgeQueryOptions{})
		if !strings.Contains(out, "UNRESOLVED") || !strings.Contains(out, "module completeness") {
			t.Errorf("a below-full module did not downgrade the verdict: %q", out)
		}
	})
}

// TestImplementers_ErrorFromTheStoreIsPropagated: a store failure must surface,
// never read as an empty implementer set.
func TestImplementers_ErrorFromTheStoreIsPropagated(t *testing.T) {
	uc := testfakes.NewFakeQueryCallGraph()
	uc.SetList([]cgports.CallGraphSummary{
		{ModulePath: implModule, ModuleVersion: "v1.0.0", PipelineVersion: implPipeline},
	})
	uc.SetGetErr(errors.New("store exploded"))

	var buf bytes.Buffer
	err := runImplementers(context.Background(), implPortID, false, uc, &buf, buildScope{}, cgports.EdgeQueryOptions{})
	if err == nil || !strings.Contains(err.Error(), "store exploded") {
		t.Fatalf("want the store error, got %v", err)
	}
}

// TestMethodNodeID_MissReturnsEmpty: an implementation that records no node for
// the queried method must not fabricate one.
func TestMethodNodeID_MissReturnsEmpty(t *testing.T) {
	impl := cgdomain.InterfaceImplementation{
		Methods: []cgdomain.ImplementedMethod{{Method: "Put", NodeID: "x.Put"}},
	}
	if got := methodNodeID(impl, "Get"); got != "" {
		t.Errorf("methodNodeID for an unrecorded method = %q, want empty", got)
	}
}

// TestModuleOfScopeLine_FallsBackWhenUnparseable keeps the absent verdict
// readable even if the scope line is not in the expected shape.
func TestModuleOfScopeLine_FallsBackWhenUnparseable(t *testing.T) {
	if got := moduleOfScopeLine(""); got != "the analysed module" {
		t.Errorf("moduleOfScopeLine(\"\") = %q", got)
	}
	if got := moduleOfScopeLine("scope: concrete types declared in example.com/m"); got != "example.com/m" {
		t.Errorf("moduleOfScopeLine without a trailing clause = %q", got)
	}
}

// TestImplementersScopeLine_EmptyModule: with no module resolved there is
// nothing to state, and an invented scope line would be worse than none.
func TestImplementersScopeLine_EmptyModule(t *testing.T) {
	if got := implementersScopeLine("", cgports.EdgeQueryOptions{}); got != "" {
		t.Errorf("scope line for an unresolved module = %q, want empty", got)
	}
}

// TestNewImplementersCmd_RequiresOneArgument: the command refuses a call that
// names no interface rather than guessing one.
func TestNewImplementersCmd_RequiresOneArgument(t *testing.T) {
	var out, errOut bytes.Buffer
	cmd := newImplementersCmd(&out, &errOut)
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)
	cmd.SetArgs(nil)
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected a usage error with no arguments")
	}
	if f := cmd.Flags().Lookup(testScopeFlagName); f == nil {
		t.Errorf("the %s flag is not registered", testScopeFlagName)
	}
}

// TestGatherImplementers_RejectsARecordNamingNoModule guards the coordinate
// reconstruction: a summary that cannot name a module is a corrupt row, and
// answering from it would attribute implementations to nothing.
func TestGatherImplementers_RejectsARecordNamingNoModule(t *testing.T) {
	uc := testfakes.NewFakeQueryCallGraph()
	uc.SetList([]cgports.CallGraphSummary{
		{ModulePath: implModule, ModuleVersion: "", PipelineVersion: implPipeline},
	})
	_, err := gatherImplementers(context.Background(), implPortID, uc, buildScope{})
	if err == nil || !strings.Contains(err.Error(), "names no module") {
		t.Fatalf("want a names-no-module error, got %v", err)
	}
}
