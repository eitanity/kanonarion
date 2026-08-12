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
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
)

// walkWith builds a walk record rooted at target with the given dependency
// coordinates as graph nodes.
func walkWith(id string, target coordinate.ModuleCoordinate, deps ...coordinate.ModuleCoordinate) walkdomain.WalkRecord {
	nodes := make([]walkdomain.GraphNode, 0, len(deps))
	for _, d := range deps {
		nodes = append(nodes, walkdomain.GraphNode{Coordinate: d})
	}
	return walkdomain.WalkRecord{
		ID:     id,
		Target: target,
		Graph:  walkdomain.Graph{Nodes: nodes},
	}
}

// TestWalkModuleSet_PinsOneVersionPerModule is the core of the fix: the version
// set a walk resolved admits the version the build uses and no other.
func TestWalkModuleSet_PinsOneVersionPerModule(t *testing.T) {
	rec := walkWith("w1",
		coordinatetest.MustNew("example.com/app", "v1.0.0"),
		coordinatetest.MustNew("golang.org/x/net", "v0.33.0"),
		coordinatetest.MustNew("golang.org/x/text", "v0.14.0"),
	)

	set := walkModuleSet(rec)
	if !set.IsRestricted() {
		t.Fatal("walkModuleSet returned an unrestricted set")
	}
	if !set.ContainsPathVersion("golang.org/x/net", "v0.33.0") {
		t.Error("the version the build resolved was not admitted")
	}
	for _, v := range []string{"v0.21.0", "v0.55.0", "v0.56.0"} {
		if set.ContainsPathVersion("golang.org/x/net", v) {
			t.Errorf("out-of-build version %s was admitted", v)
		}
	}
	if !set.ContainsPathVersion("example.com/app", "v1.0.0") {
		t.Error("the walk target was not admitted")
	}
}

// TestWalkModuleSet_AdmitsLocalAnalysisVersion covers the main module, which a
// walk records at coordinate.LocalVersion and `kanonarion local` now ingests at
// the same version. Scoping a query to a project's own build must not filter out
// the project's own symbols.
//
// It also pins the negative half: the retired synthetic "v0.0.0" must NOT be
// admitted. Nothing writes call graphs there any more, so admitting it would
// widen every project-scoped query to a coordinate that names a published
// release of the module — a different artefact entirely.
func TestWalkModuleSet_AdmitsLocalAnalysisVersion(t *testing.T) {
	target, err := coordinate.NewLocalCoordinate("example.com/app")
	if err != nil {
		t.Fatalf("NewLocalCoordinate: %v", err)
	}
	set := walkModuleSet(walkWith("w1", target))

	if !set.ContainsPathVersion("example.com/app", coordinate.LocalVersion) {
		t.Error("the walk's own target coordinate was not admitted")
	}
	if set.ContainsPathVersion("example.com/app", "v0.0.0") {
		t.Error("the retired synthetic local-analysis version v0.0.0 is still admitted")
	}
}

func TestBuildScopeFlags_UnsetIsUnrestricted(t *testing.T) {
	var f buildScopeFlags
	sc, err := f.resolve(context.Background(), testfakes.NewFakeQueryWalks())
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if sc.modules.IsRestricted() {
		t.Error("no scope flag set should leave the query unrestricted")
	}
}

func TestBuildScopeFlags_WalkIDAndGoModAreMutuallyExclusive(t *testing.T) {
	f := buildScopeFlags{walkID: "w1", gomodSet: true}
	if _, err := f.resolve(context.Background(), testfakes.NewFakeQueryWalks()); err == nil {
		t.Fatal("expected an error when both --walk-id and --gomod are given")
	}
}

func TestBuildScopeFlags_ResolvesWalkID(t *testing.T) {
	walks := testfakes.NewFakeQueryWalks()
	walks.AddWalk(walkWith("w1",
		coordinatetest.MustNew("example.com/app", "v1.0.0"),
		coordinatetest.MustNew("golang.org/x/net", "v0.33.0"),
	))

	f := buildScopeFlags{walkID: "w1"}
	sc, err := f.resolve(context.Background(), walks)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if !sc.modules.ContainsPathVersion("golang.org/x/net", "v0.33.0") {
		t.Error("resolved scope missing a walk member")
	}
	if !strings.Contains(sc.source, "w1") {
		t.Errorf("scope source = %q, want it to name walk w1", sc.source)
	}
}

func TestBuildScopeFlags_UnknownWalkIDErrors(t *testing.T) {
	f := buildScopeFlags{walkID: "nope"}
	if _, err := f.resolve(context.Background(), testfakes.NewFakeQueryWalks()); err == nil {
		t.Fatal("expected an error for an unknown walk id")
	}
}

// TestRunCallers_ScopeFiltersOutOfBuildVersions is the end-to-end shape of the
// reported defect: three analysed versions of a module, one of them in the
// build, and only that one's caller should be reported.
func TestRunCallers_ScopeFiltersOutOfBuildVersions(t *testing.T) {
	uc := testfakes.NewFakeQueryCallGraph()
	sums := make([]cgports.CallGraphSummary, 0, 3)
	for _, v := range []string{"v0.21.0", "v0.33.0", "v0.55.0"} {
		sums = append(sums, cgports.CallGraphSummary{
			ModulePath: "golang.org/x/net", ModuleVersion: v, PipelineVersion: cgapp.PipelineVersion,
		})
		uc.AddRecord(coordinatetest.MustNew("golang.org/x/net", v), cgapp.PipelineVersion,
			builtRecord([]cgdomain.CallNode{{ID: "golang.org/x/net/idna.normalize", Symbol: "normalize"}}, nil))
	}
	uc.SetList(sums)
	uc.SetCallers([]cgports.CallEdgeRef{
		{ModulePath: "golang.org/x/net", ModuleVersion: "v0.21.0", FromID: "golang.org/x/net/idna.a", ToID: "golang.org/x/net/idna.normalize"},
		{ModulePath: "golang.org/x/net", ModuleVersion: "v0.33.0", FromID: "golang.org/x/net/idna.b", ToID: "golang.org/x/net/idna.normalize"},
		{ModulePath: "golang.org/x/net", ModuleVersion: "v0.55.0", FromID: "golang.org/x/net/idna.c", ToID: "golang.org/x/net/idna.normalize"},
	})

	sc := buildScope{
		modules: coordinate.NewModuleSet([]coordinate.ModuleCoordinate{
			coordinatetest.MustNew("golang.org/x/net", "v0.33.0"),
		}),
		source: `walk "w1"`,
	}

	var buf bytes.Buffer
	if err := runCallers(context.Background(), "golang.org/x/net/idna.normalize", false, uc, &buf, sc, cgports.EdgeQueryOptions{}); err != nil {
		t.Fatalf("runCallers: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "golang.org/x/net/idna.b") {
		t.Errorf("in-build caller missing from output:\n%s", out)
	}
	for _, dead := range []string{"golang.org/x/net/idna.a", "golang.org/x/net/idna.c"} {
		if strings.Contains(out, dead) {
			t.Errorf("out-of-build caller %s leaked into scoped output:\n%s", dead, out)
		}
	}
	if !strings.Contains(out, "notice: results restricted") {
		t.Errorf("scoped output did not say it was filtered:\n%s", out)
	}
}

// TestRunCallers_UnscopedKeepsEveryVersion is the control: without a scope flag
// the command keeps answering across every stored version, so the fix is opt-in.
func TestRunCallers_UnscopedKeepsEveryVersion(t *testing.T) {
	uc := fakeWithRecord("golang.org/x/net", "v0.33.0", cgapp.PipelineVersion,
		builtRecord([]cgdomain.CallNode{{ID: "golang.org/x/net/idna.normalize", Symbol: "normalize"}}, nil))
	uc.SetCallers([]cgports.CallEdgeRef{
		{ModulePath: "golang.org/x/net", ModuleVersion: "v0.21.0", FromID: "golang.org/x/net/idna.a", ToID: "golang.org/x/net/idna.normalize"},
		{ModulePath: "golang.org/x/net", ModuleVersion: "v0.33.0", FromID: "golang.org/x/net/idna.b", ToID: "golang.org/x/net/idna.normalize"},
	})

	var buf bytes.Buffer
	if err := runCallers(context.Background(), "golang.org/x/net/idna.normalize", false, uc, &buf, buildScope{}, cgports.EdgeQueryOptions{}); err != nil {
		t.Fatalf("runCallers: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"golang.org/x/net/idna.a", "golang.org/x/net/idna.b"} {
		if !strings.Contains(out, want) {
			t.Errorf("unscoped output dropped %s:\n%s", want, out)
		}
	}
	if strings.Contains(out, "notice: results restricted") {
		t.Errorf("unscoped query claimed to be filtered:\n%s", out)
	}
}

// TestCheckSymbolInScope_ModuleNotInBuild pins the diagnostic that keeps an
// out-of-build symbol from being answered with a confident empty result.
func TestCheckSymbolInScope_ModuleNotInBuild(t *testing.T) {
	uc := fakeWithRecord("example.com/dep", "v1.0.0", cgapp.PipelineVersion,
		builtRecord([]cgdomain.CallNode{{ID: "example.com/dep.Foo", Symbol: "Foo"}}, nil))

	sc := buildScope{
		modules: coordinate.NewModuleSet([]coordinate.ModuleCoordinate{
			coordinatetest.MustNew("example.com/other", "v1.0.0"),
		}),
		source: `walk "w1"`,
	}

	err := checkSymbolInScope(context.Background(), "example.com/dep.Foo", uc, sc)
	if err == nil {
		t.Fatal("expected an error for a symbol whose module is not in the build")
	}
	if !strings.Contains(err.Error(), "does not contain") || !strings.Contains(err.Error(), "v1.0.0") {
		t.Errorf("diagnostic does not name the build or the analysed versions: %v", err)
	}
}

// TestCheckSymbolInScope_VersionNotAnalysed distinguishes the neighbouring case:
// the build does contain the module, at a version nothing has analysed. That is
// an instruction to analyse, not a claim about reachability.
func TestCheckSymbolInScope_VersionNotAnalysed(t *testing.T) {
	uc := fakeWithRecord("example.com/dep", "v1.0.0", cgapp.PipelineVersion,
		builtRecord([]cgdomain.CallNode{{ID: "example.com/dep.Foo", Symbol: "Foo"}}, nil))

	sc := buildScope{
		modules: coordinate.NewModuleSet([]coordinate.ModuleCoordinate{
			coordinatetest.MustNew("example.com/dep", "v2.0.0"),
		}),
		source: `walk "w1"`,
	}

	err := checkSymbolInScope(context.Background(), "example.com/dep.Foo", uc, sc)
	if err == nil {
		t.Fatal("expected an error for an unanalysed in-build version")
	}
	if !strings.Contains(err.Error(), "v2.0.0") || !strings.Contains(err.Error(), "kanonarion callgraph") {
		t.Errorf("diagnostic does not name the in-build version and the remedy: %v", err)
	}
}

func TestCheckSymbolInScope_UnrestrictedIsSilent(t *testing.T) {
	uc := fakeWithRecord("example.com/dep", "v1.0.0", cgapp.PipelineVersion,
		builtRecord([]cgdomain.CallNode{{ID: "example.com/dep.Foo", Symbol: "Foo"}}, nil))
	if err := checkSymbolInScope(context.Background(), "example.com/dep.Foo", uc, buildScope{}); err != nil {
		t.Errorf("unrestricted scope raised a diagnostic: %v", err)
	}
}
