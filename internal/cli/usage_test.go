package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	cgapp "github.com/eitanity/kanonarion/internal/callgraph/application"
	cgdomain "github.com/eitanity/kanonarion/internal/callgraph/domain"
	cgports "github.com/eitanity/kanonarion/internal/callgraph/ports"
	"github.com/eitanity/kanonarion/internal/cli/testfakes"
	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
)

// The fixture is one project and one dependency, plus a nested major-version
// module of the same dependency: the project's edges reach both, and only the
// longest-match rule tells their symbols apart.
const (
	usageProject = "example.com/app"
	usageModPath = "example.com/mod"
	usageModV3   = "example.com/mod/v3"
)

func usageModCoord() coordinate.ModuleCoordinate {
	return coordinatetest.MustNew(usageModPath, "v1.0.0")
}
func usageModV3Coord() coordinate.ModuleCoordinate {
	return coordinatetest.MustNew(usageModV3, "v3.0.0")
}

func usageProjectCoord(t *testing.T) coordinate.ModuleCoordinate {
	t.Helper()
	c, err := coordinate.NewLocalCoordinate(usageProject)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// usageFixture wires a project walk, the project's own call graph, and the
// dependency's call graph into the seam the command reads.
type usageFixture struct {
	ctr   *Container
	gomod string
	cg    *testfakes.FakeQueryCallGraph
}

type usageFixtureOpts struct {
	// projectNodes and projectEdges are the project's own graph.
	projectNodes []cgdomain.CallNode
	projectEdges []cgdomain.CallEdge
	// projectStatus, projectFailed, projectTestScope and projectRefScope are the
	// axes an empty answer's verdict reads.
	projectStatus    cgdomain.CallGraphStatus
	projectFailed    []string
	projectTestScope cgdomain.TestScope
	projectRefScope  cgdomain.ReferenceScope
	projectMissing   bool
	// moduleNodes and moduleInterfaces are the dependency's own graph, from which
	// the public-API population and the declared interfaces are read.
	moduleNodes      []cgdomain.CallNode
	moduleInterfaces []cgdomain.InterfaceType
	moduleMissing    bool
	// v3Nodes, when non-empty, adds the nested major-version module.
	v3Nodes []cgdomain.CallNode
	// walkModules are the coordinates the walk resolves. Empty means the project
	// and example.com/mod@v1.0.0.
	walkModules []coordinate.ModuleCoordinate
	// dir is the directory the fixture's go.mod is written to. Two fixtures
	// compared against each other must share it: the manifest path is in the
	// scope notice, so two temp directories differ for a reason that is not the
	// answer.
	dir string
}

func newUsageFixture(t *testing.T, o usageFixtureOpts) usageFixture {
	t.Helper()
	project := usageProjectCoord(t)

	modules := o.walkModules
	if modules == nil {
		modules = []coordinate.ModuleCoordinate{usageModCoord()}
	}
	nodes := []walkdomain.GraphNode{{Coordinate: project}}
	for _, m := range modules {
		nodes = append(nodes, walkdomain.GraphNode{Coordinate: m})
	}

	walks := testfakes.NewFakeQueryWalks()
	walks.SetSummaries([]walkports.WalkSummary{{
		ID: "walk-1", Target: project, Scope: walkdomain.WalkScopeCode,
		OverallStatus: walkdomain.WalkSucceeded,
		GOOS:          runtime.GOOS, GOARCH: runtime.GOARCH,
	}})
	walks.AddWalk(walkdomain.WalkRecord{
		ID: "walk-1", Target: project, Scope: walkdomain.WalkScopeCode,
		OverallStatus: walkdomain.WalkSucceeded,
		Graph: walkdomain.Graph{
			Target:   project,
			Nodes:    nodes,
			BuildEnv: walkdomain.BuildEnv{GOOS: runtime.GOOS, GOARCH: runtime.GOARCH},
		},
	})

	status := o.projectStatus
	if status == cgdomain.CallGraphStatusUnknown {
		status = cgdomain.CallGraphStatusExtracted
	}
	testScope := o.projectTestScope
	if testScope == cgdomain.TestScopeUnknown {
		testScope = cgdomain.TestScopeAnalysed
	}
	refScope := o.projectRefScope
	if refScope == cgdomain.ReferenceScopeUnknown {
		refScope = cgdomain.ReferenceScopeAnalysed
	}

	cg := testfakes.NewFakeQueryCallGraph()
	if !o.projectMissing {
		cg.AddRecord(project, cgapp.PipelineVersion, cgdomain.CallGraphRecord{
			Coordinate:     project,
			ContentHash:    "sha256:project",
			Nodes:          o.projectNodes,
			Edges:          o.projectEdges,
			OverallStatus:  status,
			FailedPackages: o.projectFailed,
			TestScope:      testScope,
			ReferenceScope: refScope,
			Completeness:   cgdomain.CompletenessBuiltWithBodies,
		})
	}
	if !o.moduleMissing {
		cg.AddRecord(usageModCoord(), cgapp.PipelineVersion, cgdomain.CallGraphRecord{
			Coordinate: usageModCoord(),
			Nodes:      o.moduleNodes,
			Interfaces: o.moduleInterfaces,
		})
	}
	if len(o.v3Nodes) > 0 {
		cg.AddRecord(usageModV3Coord(), cgapp.PipelineVersion, cgdomain.CallGraphRecord{
			Coordinate: usageModV3Coord(), Nodes: o.v3Nodes,
		})
	}
	// The coordinate listing is what the owning-module resolution reads, so both
	// dependency paths have to be in it or the nesting rule is never exercised.
	cg.SetList([]cgports.CallGraphSummary{
		{ModulePath: usageModPath, ModuleVersion: "v1.0.0", PipelineVersion: cgapp.PipelineVersion},
		{ModulePath: usageModV3, ModuleVersion: "v3.0.0", PipelineVersion: cgapp.PipelineVersion},
	})

	dir := o.dir
	if dir == "" {
		dir = t.TempDir()
	}
	gomod := filepath.Join(dir, "go.mod")
	if err := os.WriteFile(gomod, []byte("module "+usageProject+"\n\ngo 1.24\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return usageFixture{
		ctr:   &Container{QueryWalks: walks, QueryCallGraph: cg},
		gomod: gomod,
		cg:    cg,
	}
}

// usageNodes is the project side of the fixture: one production function, one
// test function, and the dependency symbols they reach.
func usageNodes() []cgdomain.CallNode {
	return []cgdomain.CallNode{
		{ID: "example.com/app/svc.Handle", Module: usageProject, Package: "example.com/app/svc", Symbol: "Handle"},
		{ID: "example.com/app/svc.TestHandle", Module: usageProject, Package: "example.com/app/svc", Symbol: "TestHandle", IsTest: true},
		{ID: "example.com/app/svc.init", Module: usageProject, Package: "example.com/app/svc", Symbol: "init"},
		{ID: usageModPath + ".Encode", Package: usageModPath, Symbol: "Encode", IsExternal: true},
		{ID: usageModPath + ".Decode", Package: usageModPath, Symbol: "Decode", IsExternal: true},
		{ID: usageModPath + ".hidden", Package: usageModPath, Symbol: "hidden", IsExternal: true},
		{ID: usageModPath + ".init", Package: usageModPath, Symbol: "init", IsExternal: true},
	}
}

// usageModuleNodes is the dependency's own graph: two exported functions, one
// unexported, one test declaration, and an SSA wrapper whose ID names no module.
func usageModuleNodes() []cgdomain.CallNode {
	return []cgdomain.CallNode{
		{ID: usageModPath + ".Encode", Module: usageModPath, Package: usageModPath, Symbol: "Encode", IsExportedAPI: true},
		{ID: usageModPath + ".Decode", Module: usageModPath, Package: usageModPath, Symbol: "Decode", IsExportedAPI: true},
		{ID: usageModPath + ".Unused", Module: usageModPath, Package: usageModPath, Symbol: "Unused", IsExportedAPI: true},
		{ID: usageModPath + ".hidden", Module: usageModPath, Package: usageModPath, Symbol: "hidden"},
		{ID: usageModPath + ".TestEncode", Module: usageModPath, Package: usageModPath, Symbol: "TestEncode", IsExportedAPI: true, IsTest: true},
		{ID: "(*" + usageModPath + ".buf).Write", Module: usageModPath, Package: usageModPath, Symbol: "Write", IsExportedAPI: true},
	}
}

// usageDefaultEdges reaches Encode directly from production and from test, and
// fans out to hidden through an unresolved dispatch, and imports the module.
func usageDefaultEdges() []cgdomain.CallEdge {
	return []cgdomain.CallEdge{
		{
			FromID: "example.com/app/svc.Handle", ToID: usageModPath + ".Encode",
			CallSite: cgdomain.SourcePosition{File: "svc/handle.go", Line: 12}, Confidence: cgdomain.ConfidenceDirect,
		},
		{
			FromID: "example.com/app/svc.TestHandle", ToID: usageModPath + ".Encode",
			CallSite: cgdomain.SourcePosition{File: "svc/handle_test.go", Line: 30}, Confidence: cgdomain.ConfidenceDirect,
		},
		{
			FromID: "example.com/app/svc.Handle", ToID: usageModPath + ".hidden",
			CallSite: cgdomain.SourcePosition{File: "svc/handle.go", Line: 20}, Confidence: cgdomain.ConfidenceUnknown,
		},
		{
			FromID: "example.com/app/svc.Handle", ToID: usageModPath + ".Decode",
			CallSite: cgdomain.SourcePosition{File: "svc/handle.go", Line: 20}, Confidence: cgdomain.ConfidenceCHAOverapprox,
		},
		{
			FromID: "example.com/app/svc.init", ToID: usageModPath + ".init",
			Confidence: cgdomain.ConfidenceDirect,
		},
	}
}

func runUsageText(t *testing.T, fx usageFixture, coord coordinate.ModuleCoordinate) (string, error) {
	t.Helper()
	var out bytes.Buffer
	err := usageWith(context.Background(), fx.ctr, coord,
		buildScopeFlags{gomod: fx.gomod, gomodSet: true}, &out, &bytes.Buffer{})
	return out.String(), err
}

func runUsageJSON(t *testing.T, fx usageFixture, coord coordinate.ModuleCoordinate) (map[string]any, []byte, error) {
	t.Helper()
	jsonOut = true
	t.Cleanup(func() { jsonOut = false })
	var out bytes.Buffer
	err := usageWith(context.Background(), fx.ctr, coord,
		buildScopeFlags{gomod: fx.gomod, gomodSet: true}, &out, &bytes.Buffer{})
	var doc map[string]any
	if derr := json.Unmarshal(out.Bytes(), &doc); derr != nil {
		t.Fatalf("stdout is not one JSON document: %v\n%s", derr, out.String())
	}
	return doc, out.Bytes(), err
}

func defaultUsageFixture(t *testing.T) usageFixture {
	t.Helper()
	return newUsageFixture(t, usageFixtureOpts{
		projectNodes: usageNodes(),
		projectEdges: usageDefaultEdges(),
		moduleNodes:  usageModuleNodes(),
	})
}

// ---- the used set -------------------------------------------------------

// Only a Direct edge is use, and each site is reported with the position the
// edge was recorded at, not with the caller's declaration.
func TestUsage_DirectEdgesAreTheUsedSetWithTheirSites(t *testing.T) {
	got, err := runUsageText(t, defaultUsageFixture(t), usageModCoord())
	if err != nil {
		t.Fatalf("want exit 0 for a present answer, got: %v", err)
	}
	for _, want := range []string{
		"Used — reached by a Direct edge from example.com/app own code (1 symbol, 2 sites: 1 production, 1 test):",
		"example.com/mod.Encode — 2 sites (1 production, 1 test)",
		"production svc/handle.go:12  [call]  example.com/app/svc.Handle",
		"test       svc/handle_test.go:30  [call]  example.com/app/svc.TestHandle",
		"answer: RESOLVED-PRESENT",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
}

// The two surfaces are separate counts everywhere they are stated. A merged
// number would scope a migration to the wrong amount of code, and there is no
// field, line or total that carries one.
func TestUsage_ProductionAndTestSitesAreNeverMerged(t *testing.T) {
	doc, _, err := runUsageJSON(t, defaultUsageFixture(t), usageModCoord())
	if err != nil {
		t.Fatalf("want exit 0, got: %v", err)
	}
	if doc["used_production_sites"] != float64(1) || doc["used_test_sites"] != float64(1) {
		t.Fatalf("used site counts are not the two measured axes: %v / %v",
			doc["used_production_sites"], doc["used_test_sites"])
	}
	sym := doc["used"].([]any)[0].(map[string]any)
	if sym["production_sites"] != float64(1) || sym["test_sites"] != float64(1) {
		t.Errorf("per-symbol counts are not split: %v", sym)
	}
	for _, banned := range []string{"used_sites", "used_site_count", "sites_total", "total_sites"} {
		if _, present := doc[banned]; present {
			t.Errorf("the document carries %q: a merged site count is exactly what must not be readable", banned)
		}
	}
	dispatch := doc["unresolved_dispatch"].(map[string]any)
	if dispatch["production_edges"] != float64(2) || dispatch["test_edges"] != float64(0) {
		t.Errorf("the dispatch class merges its surfaces: %v", dispatch)
	}
}

// A reference edge takes the function as a value. It is use of the symbol and it
// is not an invocation, so the site says which it was.
func TestUsage_ReferenceEdgeIsUseAndIsNotACall(t *testing.T) {
	fx := newUsageFixture(t, usageFixtureOpts{
		projectNodes: usageNodes(),
		projectEdges: []cgdomain.CallEdge{{
			FromID: "example.com/app/svc.Handle", ToID: usageModPath + ".Encode",
			CallSite:   cgdomain.SourcePosition{File: "svc/handle.go", Line: 12},
			Confidence: cgdomain.ConfidenceDirect, Kind: cgdomain.EdgeKindReference,
		}},
		moduleNodes: usageModuleNodes(),
	})
	got, err := runUsageText(t, fx, usageModCoord())
	if err != nil {
		t.Fatalf("want exit 0, got: %v", err)
	}
	if !strings.Contains(got, "[reference]") {
		t.Errorf("a value reference is rendered as a call:\n%s", got)
	}
	doc, _, _ := runUsageJSON(t, fx, usageModCoord())
	sym := doc["used"].([]any)[0].(map[string]any)
	if sym["reference_sites"] != float64(1) {
		t.Errorf("reference_sites does not carry the distinction: %v", sym)
	}
}

// ---- the over-approximated class ---------------------------------------

// The whole report turns on this: an edge the analyser could not resolve names
// every type-compatible function in the module, so it is reported as its own
// class, never as use, and never dropped either.
func TestUsage_OverApproximatedEdgesAreItsOwnClassAndNotUse(t *testing.T) {
	got, err := runUsageText(t, defaultUsageFixture(t), usageModCoord())
	if err != nil {
		t.Fatalf("want exit 0, got: %v", err)
	}
	for _, want := range []string{
		"Reached only through unresolved dispatch — not established use (2 symbols, 2 edges from 1 site: 2 production, 0 test):",
		"example.com/mod.hidden — 1 edge",
		"example.com/mod.Decode — 1 edge",
		usageConfidenceNote,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	if strings.Contains(got, "Used — reached by a Direct edge from example.com/app own code (3 symbol") {
		t.Errorf("over-approximated symbols were merged into the used count:\n%s", got)
	}
}

// A machine consumer merging the two arrays would lose the distinction, so the
// class states it as a field rather than only in prose.
func TestUsage_DispatchClassStatesItEstablishesNoUse(t *testing.T) {
	doc, _, _ := runUsageJSON(t, defaultUsageFixture(t), usageModCoord())
	dispatch := doc["unresolved_dispatch"].(map[string]any)
	if dispatch["establishes_use"] != false {
		t.Errorf("establishes_use is not stated false: %v", dispatch["establishes_use"])
	}
	if dispatch["symbol_count"] != float64(2) || dispatch["site_count"] != float64(1) {
		t.Errorf("the fan-out shape is not readable: %v", dispatch)
	}
	if note, _ := dispatch["note"].(string); note != usageConfidenceNote {
		t.Errorf("the class carries no note saying what it is: %q", note)
	}
}

// ---- linkage ------------------------------------------------------------

// An edge into the module's own init says the package imports it. That is
// linkage, and it is in no usage count.
func TestUsage_InitEdgeIsLinkageNotUse(t *testing.T) {
	got, err := runUsageText(t, defaultUsageFixture(t), usageModCoord())
	if err != nil {
		t.Fatalf("want exit 0, got: %v", err)
	}
	if !strings.Contains(got, "Linked but not called (1 package of this project import the module):") {
		t.Errorf("linkage is not reported as an import count:\n%s", got)
	}
	if !strings.Contains(got, "      example.com/app/svc\n") {
		t.Errorf("the importing package is not named:\n%s", got)
	}
	if strings.Contains(got, "example.com/mod.init — ") {
		t.Errorf("the init edge was reported as a used symbol:\n%s", got)
	}
}

// ---- the public API population -----------------------------------------

// The population is the module's own exported declarations, and the two things
// that are not part of it are excluded for stated reasons: a test declaration is
// not API, and an SSA wrapper is an ID no callee could ever match.
func TestUsage_UnreachedIsDrawnFromTheModulesOwnPublicAPI(t *testing.T) {
	doc, _, _ := runUsageJSON(t, defaultUsageFixture(t), usageModCoord())
	if doc["public_api_count"] != float64(3) {
		t.Fatalf("public API population = %v, want 3 (Encode, Decode, Unused)", doc["public_api_count"])
	}
	var got []string
	for _, v := range doc["unreached_public_api"].([]any) {
		got = append(got, v.(string))
	}
	want := []string{usageModPath + ".Decode", usageModPath + ".Unused"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("unreached = %v, want %v", got, want)
	}
}

// A symbol the module's population holds and an unresolved dispatch also names
// is marked where the reader meets it: it is not reached by a Direct edge, and
// it is not a symbol nothing goes near.
func TestUsage_UnreachedNamesTheOnesAnUnresolvedDispatchReaches(t *testing.T) {
	got, _ := runUsageText(t, defaultUsageFixture(t), usageModCoord())
	if !strings.Contains(got, "example.com/mod.Decode  (named by an unresolved dispatch above)") {
		t.Errorf("an unreached symbol the fan-out names is not marked:\n%s", got)
	}
}

// Without the module's own graph the population is unknown, so an empty
// unreached list must not read as a module with no API.
func TestUsage_AbsentModuleGraphMakesUnreachedUnmeasured(t *testing.T) {
	fx := newUsageFixture(t, usageFixtureOpts{
		projectNodes: usageNodes(), projectEdges: usageDefaultEdges(), moduleMissing: true,
	})
	got, _ := runUsageText(t, fx, usageModCoord())
	if !strings.Contains(got, "Unreached — unmeasured: the store holds no call graph for any version of example.com/mod") {
		t.Errorf("an absent module graph is not stated as unmeasured:\n%s", got)
	}
	if !strings.Contains(got, "kanonarion callgraph example.com/mod@v1.0.0") {
		t.Errorf("the remedy that produces the population is not named:\n%s", got)
	}
	doc, _, _ := runUsageJSON(t, fx, usageModCoord())
	if doc["module_call_graph_found"] != false {
		t.Errorf("module_call_graph_found does not state the absence: %v", doc["module_call_graph_found"])
	}
}

// ---- a module nothing enumerated -----------------------------------------

// RESOLVED-ABSENT is a claim about a population, so it needs one. With no
// stored call graph for the module at any version, nothing about it was
// enumerated: a misspelt module path would otherwise return the same clean
// exit-0 absent as a migration that really finished, and the documented
// completion check would be satisfied by a typo.
func TestUsage_ModuleNeverEnumeratedIsUnresolvedNotAbsent(t *testing.T) {
	fx := newUsageFixture(t, usageFixtureOpts{
		projectNodes: usageNodes(), moduleMissing: true,
	})
	got, err := runUsageText(t, fx, usageModCoord())
	var ex *exitError
	if !errors.As(err, &ex) || ex.code != ExitPartial {
		t.Fatalf("a module nothing enumerated must not exit 0: %v", err)
	}
	for _, want := range []string{
		"answer: UNRESOLVED",
		"module-surface-unenumerated at example.com/mod",
		"the store holds no call graph for any version of example.com/mod",
		"kanonarion callgraph example.com/mod@v1.0.0",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	doc, _, _ := runUsageJSON(t, fx, usageModCoord())
	if doc["answer"] != "UNRESOLVED" {
		t.Errorf("answer = %v, want UNRESOLVED", doc["answer"])
	}
	if doc["version_basis"] != "none_stored" {
		t.Errorf("version_basis = %v, want none_stored", doc["version_basis"])
	}
}

// The control the rule must not break: a module the project genuinely migrated
// off still has its stored call graph, so its absence IS a measurement and the
// completion check keeps working.
func TestUsage_EnumerableModuleWithNoEdgesStaysResolvedAbsent(t *testing.T) {
	fx := newUsageFixture(t, usageFixtureOpts{
		projectNodes: usageNodes(), moduleNodes: usageModuleNodes(),
	})
	got, err := runUsageText(t, fx, usageModCoord())
	if err != nil {
		t.Fatalf("an enumerated module with no edges must stay a measured absence: %v", err)
	}
	if !strings.Contains(got, "answer: RESOLVED-ABSENT") {
		t.Errorf("a measured absence was downgraded:\n%s", got)
	}
	doc, _, _ := runUsageJSON(t, fx, usageModCoord())
	if doc["answer"] != "RESOLVED-ABSENT" || doc["module_call_graph_found"] != true {
		t.Errorf("answer=%v graph_found=%v", doc["answer"], doc["module_call_graph_found"])
	}
}

// ---- which version was measured ------------------------------------------

// A version with no stored call graph was not measured, and the verdict must
// not name it as though it had been. The edge join matches a callee by module
// PATH, so it answers whatever version is typed; without this the report
// asserts use of a version that was never released.
func TestUsage_AVersionWithNoGraphIsNeverNamedAsMeasured(t *testing.T) {
	fx := newUsageFixture(t, usageFixtureOpts{
		projectNodes: usageNodes(), projectEdges: usageDefaultEdges(), moduleNodes: usageModuleNodes(),
	})
	asked := coordinatetest.MustNew(usageModPath, "v9.9.9")
	got, err := runUsageText(t, fx, asked)
	if err != nil {
		t.Fatalf("want exit 0 for a present answer, got: %v", err)
	}
	if strings.Contains(got, "of example.com/mod@v9.9.9 at") {
		t.Errorf("the verdict names a version that was never measured:\n%s", got)
	}
	for _, want := range []string{
		"version: example.com/mod@v9.9.9 has no stored call graph",
		"This report measures example.com/mod@v1.0.0",
		"answer: RESOLVED-PRESENT — example.com/app own code reaches 1 symbol of example.com/mod@v1.0.0 " +
			"at 2 sites (1 production, 1 test); the version asked for, v9.9.9, has no stored call graph and was not measured",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	doc, _, _ := runUsageJSON(t, fx, asked)
	if doc["version"] != "v1.0.0" || doc["requested_version"] != "v9.9.9" || doc["version_basis"] != "build_resolved" {
		t.Errorf("the document does not separate the two versions: %v / %v / %v",
			doc["version"], doc["requested_version"], doc["version_basis"])
	}
	// The public API is enumerated from the version actually read, so the
	// unreached population is a measurement rather than an unknown.
	if doc["public_api_count"] != float64(3) {
		t.Errorf("public_api_count = %v, want the measured version's 3", doc["public_api_count"])
	}
}

// When the build resolves no version that has a stored graph either, the
// highest version the store holds answers — and says so.
func TestUsage_HighestStoredVersionAnswersWhenTheBuildOffersNone(t *testing.T) {
	fx := newUsageFixture(t, usageFixtureOpts{
		projectNodes: usageNodes(), projectEdges: usageDefaultEdges(), moduleNodes: usageModuleNodes(),
		walkModules: []coordinate.ModuleCoordinate{coordinatetest.MustNew(usageModPath, "v0.9.0")},
	})
	got, _ := runUsageText(t, fx, coordinatetest.MustNew(usageModPath, "v9.9.9"))
	if !strings.Contains(got, "This report measures example.com/mod@v1.0.0 — the newest version of the module the store holds") {
		t.Errorf("the rule that chose the version is not stated:\n%s", got)
	}
	doc, _, _ := runUsageJSON(t, fx, coordinatetest.MustNew(usageModPath, "v9.9.9"))
	if doc["version_basis"] != "highest_stored" {
		t.Errorf("version_basis = %v, want highest_stored", doc["version_basis"])
	}
}

// The version measured is the version asked for whenever the store holds it,
// whatever the build resolves. Nothing is substituted that need not be.
func TestUsage_AStoredRequestedVersionIsNeverSubstituted(t *testing.T) {
	fx := newUsageFixture(t, usageFixtureOpts{
		projectNodes: usageNodes(), projectEdges: usageDefaultEdges(), moduleNodes: usageModuleNodes(),
		walkModules: []coordinate.ModuleCoordinate{coordinatetest.MustNew(usageModPath, "v0.9.0")},
	})
	doc, _, _ := runUsageJSON(t, fx, usageModCoord())
	if doc["version"] != "v1.0.0" || doc["version_basis"] != "as_requested" {
		t.Errorf("the version asked for was not the one measured: %v / %v", doc["version"], doc["version_basis"])
	}
	if _, present := doc["requested_version"]; present {
		t.Errorf("requested_version is set where nothing was substituted: %v", doc["requested_version"])
	}
}

// ---- nested module paths ------------------------------------------------

// Go module paths nest, so example.com/mod and example.com/mod/v3 are different
// modules whose symbols a prefix test cannot tell apart. Asking about one must
// not attribute the other's symbols to it.
func TestUsage_NestedMajorVersionSymbolsAreNotAttributedToTheParent(t *testing.T) {
	nodes := append(usageNodes(),
		cgdomain.CallNode{ID: usageModV3 + ".Encode", Package: usageModV3, Symbol: "Encode", IsExternal: true})
	edges := append(usageDefaultEdges(), cgdomain.CallEdge{
		FromID: "example.com/app/svc.Handle", ToID: usageModV3 + ".Encode",
		CallSite: cgdomain.SourcePosition{File: "svc/handle.go", Line: 44}, Confidence: cgdomain.ConfidenceDirect,
	})
	fx := newUsageFixture(t, usageFixtureOpts{
		projectNodes: nodes, projectEdges: edges, moduleNodes: usageModuleNodes(),
		v3Nodes: []cgdomain.CallNode{{
			ID: usageModV3 + ".Encode", Module: usageModV3, Package: usageModV3,
			Symbol: "Encode", IsExportedAPI: true,
		}},
		walkModules: []coordinate.ModuleCoordinate{usageModCoord(), usageModV3Coord()},
	})

	got, err := runUsageText(t, fx, usageModCoord())
	if err != nil {
		t.Fatalf("want exit 0, got: %v", err)
	}
	if strings.Contains(got, usageModV3+".Encode") {
		t.Errorf("a nested module's symbol was attributed to its parent:\n%s", got)
	}

	gotV3, err := runUsageText(t, fx, usageModV3Coord())
	if err != nil {
		t.Fatalf("want exit 0, got: %v", err)
	}
	if !strings.Contains(gotV3, "svc/handle.go:44") {
		t.Errorf("the nested module's own site is missing from its own answer:\n%s", gotV3)
	}
	if strings.Contains(gotV3, "svc/handle.go:12") {
		t.Errorf("the parent module's site was attributed to the nested module:\n%s", gotV3)
	}
}

// The same nesting, with the nested module absent from the BUILD — which is the
// shape a migration has: the project still requires v2, the successor v3 is not
// in its go.mod, and every v3 symbol in the graph is a candidate to be filed
// under v2. Drawing the owning-module candidates from the build alone conflates
// the module being left with the module being adopted, which is the one pair a
// migration inventory must never merge.
func TestUsage_NestedModuleOutsideTheBuildIsStillItsOwnOwner(t *testing.T) {
	nodes := append(usageNodes(),
		cgdomain.CallNode{ID: usageModV3 + ".Encode", Package: usageModV3, Symbol: "Encode", IsExternal: true},
		cgdomain.CallNode{ID: usageModV3 + ".Decode", Package: usageModV3, Symbol: "Decode", IsExternal: true},
		cgdomain.CallNode{ID: usageModV3 + ".init", Package: usageModV3, Symbol: "init", IsExternal: true})
	edges := append(usageDefaultEdges(),
		cgdomain.CallEdge{
			FromID: "example.com/app/svc.Handle", ToID: usageModV3 + ".Encode",
			CallSite: cgdomain.SourcePosition{File: "svc/handle.go", Line: 44}, Confidence: cgdomain.ConfidenceDirect,
		},
		cgdomain.CallEdge{
			FromID: "example.com/app/svc.Handle", ToID: usageModV3 + ".Decode",
			CallSite: cgdomain.SourcePosition{File: "svc/handle.go", Line: 45}, Confidence: cgdomain.ConfidenceCHAOverapprox,
		},
		cgdomain.CallEdge{
			FromID: "example.com/app/svc.init", ToID: usageModV3 + ".init", Confidence: cgdomain.ConfidenceDirect,
		})
	fx := newUsageFixture(t, usageFixtureOpts{
		projectNodes: nodes, projectEdges: edges, moduleNodes: usageModuleNodes(),
		v3Nodes: []cgdomain.CallNode{{
			ID: usageModV3 + ".Encode", Module: usageModV3, Package: usageModV3,
			Symbol: "Encode", IsExportedAPI: true,
		}},
		// The build has the parent only; v3 is known from the store's listing.
		walkModules: []coordinate.ModuleCoordinate{usageModCoord()},
	})

	doc, raw, err := runUsageJSON(t, fx, usageModCoord())
	if err != nil {
		t.Fatalf("want exit 0, got: %v", err)
	}
	assertUsageIDsBelongToTheModule(t, doc, raw)
	// The v3 edges must be in no class of the v2 answer, linkage included: the
	// package that imports v3 does not thereby import v2.
	if strings.Contains(string(raw), usageModV3) {
		t.Errorf("a v3 identity appears in the v2 answer:\n%s", raw)
	}
}

// assertUsageIDsBelongToTheModule is the invariant the whole report turns on:
// every symbol it names belongs to the module it was asked about. Linkage is
// held to the mirror-image rule — those are the CONSUMER's packages, not the
// module's — because a linkage list drawn from another module's importers is
// the same conflation wearing a different heading.
func assertUsageIDsBelongToTheModule(t *testing.T, doc map[string]any, raw []byte) {
	t.Helper()
	path, _ := doc["module"].(string)
	owns := func(id string) bool {
		return strings.HasPrefix(id, path+".") || strings.HasPrefix(id, path+"/")
	}
	check := func(heading string, ids []string) {
		for _, id := range ids {
			if !owns(id) {
				t.Errorf("%s names %q, which does not belong to %s:\n%s", heading, id, path, raw)
			}
		}
	}
	check("used", usageJSONSymbolIDs(t, doc["used"]))
	dispatch, _ := doc["unresolved_dispatch"].(map[string]any)
	check("unresolved_dispatch", usageJSONSymbolIDs(t, dispatch["symbols"]))
	check("unreached_public_api", usageJSONStrings(t, doc["unreached_public_api"]))
	for _, pkg := range usageJSONStrings(t, doc["linked_not_called_packages"]) {
		if !strings.HasPrefix(pkg, usageProject) {
			t.Errorf("linked_not_called_packages names %q, which is not this project's:\n%s", pkg, raw)
		}
	}
}

func usageJSONSymbolIDs(t *testing.T, v any) []string {
	t.Helper()
	items, _ := v.([]any)
	out := make([]string, 0, len(items))
	for _, it := range items {
		m, _ := it.(map[string]any)
		id, _ := m["node_id"].(string)
		out = append(out, id)
	}
	return out
}

func usageJSONStrings(t *testing.T, v any) []string {
	t.Helper()
	items, _ := v.([]any)
	out := make([]string, 0, len(items))
	for _, it := range items {
		s, _ := it.(string)
		out = append(out, s)
	}
	return out
}

// ---- the three-valued answer -------------------------------------------

// A zero is an answer only when nothing about the project's analysis leaves room
// for a missing edge, and it states the population it was measured over.
func TestUsage_MeasuredZeroIsResolvedAbsentWithItsScopeAndExitsZero(t *testing.T) {
	fx := newUsageFixture(t, usageFixtureOpts{
		projectNodes: usageNodes(),
		projectEdges: []cgdomain.CallEdge{{
			FromID: "example.com/app/svc.Handle", ToID: "example.com/other.Thing",
			Confidence: cgdomain.ConfidenceDirect,
		}},
		moduleNodes: usageModuleNodes(),
	})
	got, err := runUsageText(t, fx, usageModCoord())
	if err != nil {
		t.Fatalf("a measured zero must exit 0, got: %v", err)
	}
	if !strings.Contains(got, "answer: RESOLVED-ABSENT — no recorded call edge from example.com/app own code "+
		"reaches example.com/mod@v1.0.0, measured over the 1 edge(s) of its stored call graph") {
		t.Errorf("the zero does not state what it was measured over:\n%s", got)
	}
	doc, _, _ := runUsageJSON(t, fx, usageModCoord())
	if doc["answer"] != "RESOLVED-ABSENT" {
		t.Errorf("answer = %v, want RESOLVED-ABSENT", doc["answer"])
	}
}

// An unresolved dispatch into the module is exactly the case in which an empty
// used set is not a measurement: the project does reach the module, and which
// symbol was never established.
func TestUsage_DispatchWithoutADirectEdgeIsUnresolvedAndExitsPartial(t *testing.T) {
	fx := newUsageFixture(t, usageFixtureOpts{
		projectNodes: usageNodes(),
		projectEdges: []cgdomain.CallEdge{{
			FromID: "example.com/app/svc.Handle", ToID: usageModPath + ".hidden",
			CallSite: cgdomain.SourcePosition{File: "svc/handle.go", Line: 20}, Confidence: cgdomain.ConfidenceUnknown,
		}},
		moduleNodes: usageModuleNodes(),
	})
	got, err := runUsageText(t, fx, usageModCoord())
	requireExit(t, err, ExitPartial)
	if !strings.Contains(got, "answer: UNRESOLVED") ||
		!strings.Contains(got, string(cgdomain.SinkUnresolvedEdge)) {
		t.Errorf("the unresolved answer does not name what blocked it:\n%s", got)
	}
	if !strings.Contains(got, "svc/handle.go:20") {
		t.Errorf("the site the graph could not resolve was dropped rather than named:\n%s", got)
	}
}

// The project's own dropped packages, unmeasured axes and completeness each
// stop a zero being a measurement, in the same vocabulary the edge queries use.
func TestUsage_EachUnmeasuredProjectAxisDowngradesTheZero(t *testing.T) {
	for _, tc := range []struct {
		name string
		opts usageFixtureOpts
		sink cgdomain.SinkKind
	}{
		{
			name: "a package that did not typecheck",
			opts: usageFixtureOpts{projectStatus: cgdomain.CallGraphStatusPartial,
				projectFailed: []string{"example.com/app/broken"}},
			sink: cgdomain.SinkDroppedPackageEdges,
		},
		{
			name: "function-value references never extracted",
			opts: usageFixtureOpts{projectRefScope: "unmeasured-sentinel"},
			sink: cgdomain.SinkReferenceScopeUnmeasured,
		},
		{
			name: "test declarations never analysed",
			opts: usageFixtureOpts{projectTestScope: cgdomain.TestScopeExcluded},
			sink: cgdomain.SinkTestScopeUnmeasured,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := tc.opts
			o.projectNodes, o.moduleNodes = usageNodes(), usageModuleNodes()
			got, err := runUsageText(t, newUsageFixture(t, o), usageModCoord())
			requireExit(t, err, ExitPartial)
			if !strings.Contains(got, "answer: UNRESOLVED") || !strings.Contains(got, string(tc.sink)) {
				t.Errorf("the zero was reported as measured despite %s:\n%s", tc.sink, got)
			}
		})
	}
}

// A project with no stored call graph has nothing to measure, so the command
// refuses and names what produces one rather than printing an empty report.
func TestUsage_NoProjectCallGraphIsNotFoundWithARemedy(t *testing.T) {
	fx := newUsageFixture(t, usageFixtureOpts{projectMissing: true, moduleNodes: usageModuleNodes()})
	_, err := runUsageText(t, fx, usageModCoord())
	requireExit(t, err, ExitNotFound)
	if !strings.Contains(err.Error(), "kanonarion local .") {
		t.Errorf("the refusal does not name the command that produces the graph: %v", err)
	}
}

// ---- interface satisfaction --------------------------------------------

// The interfaces a module declares are what a migration has to check by hand,
// because no stored record holds satisfaction across the project/dependency
// boundary. Naming them is what a reader can act on; claiming they are
// unsatisfied would be a measurement nothing took.
func TestUsage_DeclaredInterfacesAreNamedAndSatisfactionIsStatedUnmeasured(t *testing.T) {
	fx := newUsageFixture(t, usageFixtureOpts{
		projectNodes: usageNodes(), projectEdges: usageDefaultEdges(), moduleNodes: usageModuleNodes(),
		moduleInterfaces: []cgdomain.InterfaceType{
			{ID: usageModPath + ".Writer", Package: usageModPath, Name: "Writer", Methods: []string{"Write"}},
			{ID: usageModPath + ".testDouble", Package: usageModPath, Name: "testDouble", IsTest: true},
		},
	})
	got, _ := runUsageText(t, fx, usageModCoord())
	if !strings.Contains(got, "Interfaces declared by the module (1):") ||
		!strings.Contains(got, usageModPath+".Writer") {
		t.Errorf("the module's interfaces are not named:\n%s", got)
	}
	if strings.Contains(got, usageModPath+".testDouble") {
		t.Errorf("a test-only interface is not part of the module's surface:\n%s", got)
	}
	if !strings.Contains(got, usageSatisfactionNote) {
		t.Errorf("satisfaction is not stated as unmeasured:\n%s", got)
	}
	doc, _, _ := runUsageJSON(t, fx, usageModCoord())
	if doc["interface_satisfaction_measured"] != false {
		t.Errorf("interface_satisfaction_measured is not stated: %v", doc["interface_satisfaction_measured"])
	}
}

// With no interface there is nothing to satisfy, so the caveat does not arise.
// A caveat printed where it cannot apply is how a reader learns to skip caveats.
func TestUsage_NoDeclaredInterfaceCarriesNoSatisfactionCaveat(t *testing.T) {
	got, _ := runUsageText(t, defaultUsageFixture(t), usageModCoord())
	if !strings.Contains(got, "Interfaces declared by the module: none") {
		t.Errorf("the empty case is not stated:\n%s", got)
	}
	if strings.Contains(got, usageSatisfactionNote) {
		t.Errorf("a caveat was printed where it cannot apply:\n%s", got)
	}
}

// ---- unmeasured kinds ---------------------------------------------------

// Types, constants and variables have no call-graph node, so their absence from
// every list above is an absence of measurement. It is said where the reader
// meets the numbers and fielded for a machine.
func TestUsage_UnmeasuredKindsAreNamedOnBothSurfaces(t *testing.T) {
	got, _ := runUsageText(t, defaultUsageFixture(t), usageModCoord())
	if !strings.Contains(got, usageUnmeasuredKindsNote+"example.com/mod@v1.0.0") {
		t.Errorf("the unmeasured kinds are not named beside the counts:\n%s", got)
	}
	doc, _, _ := runUsageJSON(t, defaultUsageFixture(t), usageModCoord())
	var kinds []string
	for _, v := range doc["unmeasured_kinds"].([]any) {
		kinds = append(kinds, v.(string))
	}
	if strings.Join(kinds, ",") != "type,const,var" {
		t.Errorf("unmeasured_kinds = %v", kinds)
	}
}

// ---- the build the answer is about --------------------------------------

// The walk names the build; the project's graph is what was analysed. When they
// disagree about which version of the module is present, the reader is told,
// because every count below is then about a version the build does not resolve.
func TestUsage_ModuleAtAnotherVersionInTheBuildIsStated(t *testing.T) {
	fx := newUsageFixture(t, usageFixtureOpts{
		projectNodes: usageNodes(), projectEdges: usageDefaultEdges(), moduleNodes: usageModuleNodes(),
		walkModules: []coordinate.ModuleCoordinate{coordinatetest.MustNew(usageModPath, "v0.9.0")},
	})
	got, _ := runUsageText(t, fx, usageModCoord())
	if !strings.Contains(got, "caveat: the build above resolves example.com/mod to v0.9.0, not the v1.0.0 measured here") {
		t.Errorf("the disagreement between the build and the graph is not stated:\n%s", got)
	}
	doc, _, _ := runUsageJSON(t, fx, usageModCoord())
	if doc["module_in_build"] != false || doc["module_path_in_build"] != true {
		t.Errorf("the two build facts are not separated: %v / %v",
			doc["module_in_build"], doc["module_path_in_build"])
	}
}

// A module the build has not got at all is the question this command exists
// for, so the caveat says it is answering, not apologising — and names the
// sibling command that refuses the same coordinate, so the divergence between
// the two is never something a reader has to discover.
func TestUsage_ModuleOutsideTheBuildIsAnsweredAndSaidToBe(t *testing.T) {
	fx := newUsageFixture(t, usageFixtureOpts{
		projectNodes: usageNodes(), projectEdges: usageDefaultEdges(), moduleNodes: usageModuleNodes(),
		walkModules: []coordinate.ModuleCoordinate{coordinatetest.MustNew("example.com/other", "v1.0.0")},
	})
	got, err := runUsageText(t, fx, usageModCoord())
	if err != nil {
		t.Fatalf("a module outside the build must be answered, not refused: %v", err)
	}
	for _, want := range []string{
		"caveat: the build above does not contain example.com/mod at any version",
		"is the migration question this command exists for",
		"kanonarion callers",
		"answer: RESOLVED-PRESENT",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	doc, _, _ := runUsageJSON(t, fx, usageModCoord())
	if doc["module_in_build"] != false || doc["module_path_in_build"] != false {
		t.Errorf("the two build facts are not both false: %v / %v",
			doc["module_in_build"], doc["module_path_in_build"])
	}
}

// Two builds are two answers, and naming one of them is not the same request as
// naming the other.
func TestUsage_WalkIDAndGoModAreMutuallyExclusive(t *testing.T) {
	err := runUsage(context.Background(), usageModPath+"@v1.0.0",
		buildScopeFlags{walkID: "walk-1", gomod: "./go.mod", gomodSet: true}, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("naming two builds is not refused: %v", err)
	}
}

// A malformed coordinate never reaches the store.
func TestUsage_MalformedCoordinateIsRefused(t *testing.T) {
	err := runUsage(context.Background(), "not-a-coordinate", buildScopeFlags{}, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "invalid coordinate") {
		t.Errorf("a malformed coordinate is not refused: %v", err)
	}
}

// ---- determinism --------------------------------------------------------

// The same query twice is byte-identical, whatever order the record's edges
// arrive in: every list is ordered on a key that covers each of its own fields.
func TestUsage_IsByteIdenticalUnderReorderedEdges(t *testing.T) {
	dir := t.TempDir()
	edges := usageDefaultEdges()
	forward := newUsageFixture(t, usageFixtureOpts{
		projectNodes: usageNodes(), projectEdges: edges, moduleNodes: usageModuleNodes(), dir: dir,
	})
	reversed := make([]cgdomain.CallEdge, len(edges))
	for i := range edges {
		reversed[len(edges)-1-i] = edges[i]
	}
	backward := newUsageFixture(t, usageFixtureOpts{
		projectNodes: usageNodes(), projectEdges: reversed, moduleNodes: usageModuleNodes(), dir: dir,
	})

	a, _ := runUsageText(t, forward, usageModCoord())
	b, _ := runUsageText(t, backward, usageModCoord())
	again, _ := runUsageText(t, forward, usageModCoord())
	if a != b {
		t.Errorf("edge order changed the answer:\n--- forward\n%s\n--- backward\n%s", a, b)
	}
	if a != again {
		t.Errorf("two runs of one query differ:\n%s\n%s", a, again)
	}

	_, rawA, _ := runUsageJSON(t, forward, usageModCoord())
	_, rawB, _ := runUsageJSON(t, backward, usageModCoord())
	if !bytes.Equal(rawA, rawB) {
		t.Errorf("the JSON document is not stable under edge order:\n%s\n%s", rawA, rawB)
	}
}

// ---- the JSON contract --------------------------------------------------

// Every scalar the run measured is present at its zero, and every collection is
// an array at every count, so a consumer can tell a measured zero from a field
// this build does not derive.
func TestUsage_JSONStatesMeasuredZerosAndEmptyArrays(t *testing.T) {
	fx := newUsageFixture(t, usageFixtureOpts{
		projectNodes: usageNodes(), moduleNodes: usageModuleNodes(),
	})
	doc, raw, err := runUsageJSON(t, fx, usageModCoord())
	if err != nil {
		t.Fatalf("want exit 0 for a measured zero, got: %v", err)
	}
	for _, key := range []string{
		"module", "version", "consumer", "walk_id", "walk_frame", "walk_frame_basis",
		"walk_scope", "walk_selection", "scope_size", "module_in_build",
		"module_call_graph_found", "call_graph_content_hash", "call_graph_status",
		"call_graph_node_count", "call_graph_edge_count", "used", "used_symbol_count",
		"used_production_sites", "used_test_sites", "unresolved_dispatch",
		"linked_not_called_packages", "linked_not_called_package_count",
		"unreached_public_api", "public_api_count", "declared_interfaces",
		"interface_satisfaction_measured", "interface_satisfaction_note",
		"unmeasured_kinds", "coverage", "confidence_note", "answer",
	} {
		if _, present := doc[key]; !present {
			t.Errorf("key %q is absent from the document", key)
		}
	}
	for _, want := range []string{
		`"used": []`, `"linked_not_called_packages": []`, `"used_production_sites": 0`,
		`"used_test_sites": 0`, `"public_api_count": 3`,
	} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("want %s in the document:\n%s", want, raw)
		}
	}
}

// The scope notice names the walk, its scope, its frame and the size of the set
// it filtered against, and each of those is readable off the document.
func TestUsage_ScopeNoticeFactsAreAllFielded(t *testing.T) {
	fx := defaultUsageFixture(t)
	got, _ := runUsageText(t, fx, usageModCoord())
	if !strings.Contains(got, "notice: results restricted to the 2 module versions resolved by walk \"walk-1\"") {
		t.Errorf("the scope notice is missing:\n%s", got)
	}
	doc, _, _ := runUsageJSON(t, fx, usageModCoord())
	if doc["scope_size"] != float64(2) || doc["walk_id"] != "walk-1" || doc["walk_scope"] != "code" {
		t.Errorf("the notice's facts are not readable off the document: %v", doc)
	}
}

// ---- the orderings ------------------------------------------------------

// The site ordering has to be total over every field a site carries, or two
// sites that differ only in a field it skips can swap places between runs and
// the answer stops being byte-identical.
func TestUsageSiteLess_IsTotalAndIrreflexive(t *testing.T) {
	base := usageSite{Caller: "c", File: "f", Line: 1, IsTest: false, Kind: usageEdgeKindCall}
	if usageSiteLess(base, base) {
		t.Errorf("the ordering is not irreflexive: a site is ordered before itself")
	}
	variants := []usageSite{base, base, base, base, base}
	variants[1].File = "g"
	variants[2].Line = 2
	variants[3].Caller = "d"
	variants[4].Kind = usageEdgeKindReference
	testVariant := base
	testVariant.IsTest = true
	variants = append(variants, testVariant)

	for i := range variants {
		for j := range variants {
			if i == j {
				continue
			}
			if usageSiteLess(variants[i], variants[j]) == usageSiteLess(variants[j], variants[i]) {
				t.Errorf("sites %d and %d are not ordered against each other: %+v vs %+v",
					i, j, variants[i], variants[j])
			}
		}
	}
	// Production sorts before test, so a reader scanning a symbol's sites meets
	// the shipped surface first.
	if !usageSiteLess(base, testVariant) {
		t.Errorf("a production site does not sort before the test site beside it")
	}
}

// ---- the write path -----------------------------------------------------

// Every section writes to stdout, and a write that fails must come back as an
// error rather than leaving a half-written report reading as a whole one.
func TestUsage_AWriteFailureIsSurfacedFromEverySection(t *testing.T) {
	fx := newUsageFixture(t, usageFixtureOpts{
		projectNodes: usageNodes(), projectEdges: usageDefaultEdges(), moduleNodes: usageModuleNodes(),
		moduleInterfaces: []cgdomain.InterfaceType{{ID: usageModPath + ".Writer", Package: usageModPath, Name: "Writer"}},
	})
	bound, err := bindConsumer(context.Background(), fx.ctr.QueryWalks, fx.ctr.QueryCallGraph,
		consumerSelector{gomod: fx.gomod})
	if err != nil {
		t.Fatal(err)
	}
	report, err := joinUsage(context.Background(), fx.ctr.QueryCallGraph, bound, usageModCoord(), "")
	if err != nil {
		t.Fatal(err)
	}
	// The report is written against a writer that fails after n bytes, for every
	// n the whole report spans, so no section's error path is left unexercised.
	var full bytes.Buffer
	if err := printUsageReport(&full, report); err != nil {
		t.Fatalf("the report does not write cleanly: %v", err)
	}
	for n := 0; n < full.Len(); n++ {
		if err := printUsageReport(&cutoffWriter{limit: n}, report); err == nil {
			t.Fatalf("a write that failed after %d bytes was reported as a complete report", n)
		}
	}
}

// cutoffWriter accepts limit bytes and then fails, so a caller can be cut at
// every point in its output.
type cutoffWriter struct {
	limit   int
	written int
}

func (w *cutoffWriter) Write(p []byte) (int, error) {
	if w.written+len(p) > w.limit {
		return 0, errPipeClosed
	}
	w.written += len(p)
	return len(p), nil
}

var errPipeClosed = errors.New("pipe closed")

// A site the record has no position for is named as such, never rendered as a
// blank location that reads like a file at the root of the tree.
func TestUsage_ASiteWithNoRecordedPositionSaysSo(t *testing.T) {
	fx := newUsageFixture(t, usageFixtureOpts{
		projectNodes: usageNodes(),
		projectEdges: []cgdomain.CallEdge{{
			FromID: "example.com/app/svc.Handle", ToID: usageModPath + ".Encode",
			Confidence: cgdomain.ConfidenceDirect,
		}},
		moduleNodes: usageModuleNodes(),
	})
	got, _ := runUsageText(t, fx, usageModCoord())
	if !strings.Contains(got, "(position not recorded)") {
		t.Errorf("a site with no position is rendered as a blank location:\n%s", got)
	}
}

// The three answers are three renderings, and each of them writes to stdout, so
// each of them has to surface a write failure.
func TestUsage_EveryAnswerSurfacesAWriteFailure(t *testing.T) {
	for _, tc := range []struct {
		name  string
		edges []cgdomain.CallEdge
	}{
		{name: "resolved-absent"},
		{name: "unresolved", edges: []cgdomain.CallEdge{{
			FromID: "example.com/app/svc.Handle", ToID: usageModPath + ".hidden",
			CallSite: cgdomain.SourcePosition{File: "svc/handle.go", Line: 20}, Confidence: cgdomain.ConfidenceUnknown,
		}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fx := newUsageFixture(t, usageFixtureOpts{
				projectNodes: usageNodes(), projectEdges: tc.edges, moduleMissing: true,
			})
			bound, err := bindConsumer(context.Background(), fx.ctr.QueryWalks, fx.ctr.QueryCallGraph,
				consumerSelector{gomod: fx.gomod})
			if err != nil {
				t.Fatal(err)
			}
			report, err := joinUsage(context.Background(), fx.ctr.QueryCallGraph, bound, usageModCoord(), "")
			if err != nil {
				t.Fatal(err)
			}
			var full bytes.Buffer
			if err := printUsageReport(&full, report); err != nil {
				t.Fatalf("the report does not write cleanly: %v", err)
			}
			for n := 0; n < full.Len(); n++ {
				if err := printUsageReport(&cutoffWriter{limit: n}, report); err == nil {
					t.Fatalf("a write that failed after %d bytes was reported as complete", n)
				}
			}
		})
	}
}

// A store that cannot answer is a failure to surface, never an empty report: an
// unreadable ledger and a project that calls nothing are opposite findings.
func TestUsage_StoreFailuresAreSurfacedNotReportedAsEmpty(t *testing.T) {
	fx := defaultUsageFixture(t)
	fx.cg.Err = errPipeClosed
	if _, err := runUsageText(t, fx, usageModCoord()); err == nil {
		t.Errorf("an unreadable call graph store produced a report rather than an error")
	}
}

// A walk id the store does not hold is the not-found class, answered with the
// statement every command that reads a walk by id gives.
func TestUsage_UnknownWalkIDIsNotFound(t *testing.T) {
	fx := defaultUsageFixture(t)
	err := usageWith(context.Background(), fx.ctr, usageModCoord(),
		buildScopeFlags{walkID: "walk-missing"}, &bytes.Buffer{}, &bytes.Buffer{})
	requireExit(t, err, ExitNotFound)
}

// A caller who names a walk chose it, so the document must not report the choice
// as one this command made on their behalf.
func TestUsage_ANamedWalkIsReportedAsPinned(t *testing.T) {
	fx := defaultUsageFixture(t)
	jsonOut = true
	t.Cleanup(func() { jsonOut = false })
	var out bytes.Buffer
	if err := usageWith(context.Background(), fx.ctr, usageModCoord(),
		buildScopeFlags{walkID: "walk-1"}, &out, &bytes.Buffer{}); err != nil {
		t.Fatalf("want exit 0, got: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	sel := doc["walk_selection"].(map[string]any)
	if sel["rule"] != "pinned" || sel["candidates"] != nil {
		t.Errorf("a caller-named walk is reported as a choice this command made: %v", sel)
	}
	if strings.Contains(out.String(), "was not re-resolved for this read") {
		t.Errorf("a manifest nobody named is reported as one this read did not re-resolve:\n%s", out.String())
	}
}

// The command takes exactly one coordinate; anything else is a usage error a
// script can read off the exit code.
func TestUsage_WrongArgumentCountIsAUsageError(t *testing.T) {
	cmd := newUsageCmd(&bytes.Buffer{}, &bytes.Buffer{})
	cmd.SetArgs(nil)
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "invalid arguments") {
		t.Errorf("a bare invocation is not refused: %v", err)
	}
}

// Two sites of one over-approximated class are ordered, deduplicated and
// reported once each, whichever order the edges arrive in.
func TestUsage_DispatchSitesAreDeduplicatedAndOrdered(t *testing.T) {
	fx := newUsageFixture(t, usageFixtureOpts{
		projectNodes: usageNodes(),
		projectEdges: []cgdomain.CallEdge{
			{FromID: "example.com/app/svc.Handle", ToID: usageModPath + ".Decode",
				CallSite: cgdomain.SourcePosition{File: "svc/b.go", Line: 9}, Confidence: cgdomain.ConfidenceUnknown},
			{FromID: "example.com/app/svc.Handle", ToID: usageModPath + ".hidden",
				CallSite: cgdomain.SourcePosition{File: "svc/b.go", Line: 9}, Confidence: cgdomain.ConfidenceUnknown},
			{FromID: "example.com/app/svc.Handle", ToID: usageModPath + ".hidden",
				CallSite: cgdomain.SourcePosition{File: "svc/a.go", Line: 3}, Confidence: cgdomain.ConfidenceVTA},
		},
		moduleNodes: usageModuleNodes(),
	})
	doc, _, err := runUsageJSON(t, fx, usageModCoord())
	requireExit(t, err, ExitPartial)
	dispatch := doc["unresolved_dispatch"].(map[string]any)
	sites := dispatch["sites"].([]any)
	if len(sites) != 2 {
		t.Fatalf("two distinct sites naming three edges = %d rows, want 2", len(sites))
	}
	if sites[0].(map[string]any)["file"] != "svc/a.go" {
		t.Errorf("the sites are not ordered: %v", sites)
	}
	if dispatch["edge_count"] != float64(3) {
		t.Errorf("edge_count = %v, want 3", dispatch["edge_count"])
	}
}

// A project analysed below BUILT_WITH_BODIES has method bodies nothing built,
// so edges out of them are simply absent and a zero cannot be a measurement.
func TestUsage_AProjectBelowFullCompletenessDowngradesTheZero(t *testing.T) {
	fx := newUsageFixture(t, usageFixtureOpts{projectNodes: usageNodes(), moduleNodes: usageModuleNodes()})
	project := usageProjectCoord(t)
	fx.cg.AddRecord(project, cgapp.PipelineVersion, cgdomain.CallGraphRecord{
		Coordinate: project, Nodes: usageNodes(),
		OverallStatus: cgdomain.CallGraphStatusExtracted,
		TestScope:     cgdomain.TestScopeAnalysed, ReferenceScope: cgdomain.ReferenceScopeAnalysed,
		Completeness: cgdomain.CompletenessTypeOnly,
	})
	got, err := runUsageText(t, fx, usageModCoord())
	requireExit(t, err, ExitPartial)
	if !strings.Contains(got, string(cgdomain.SinkTypeOnlyCallee)) {
		t.Errorf("the completeness the project was analysed at is not named as what blocked the zero:\n%s", got)
	}
}

// The disclosure that some of the project's packages did not typecheck is part
// of the report, so it too must surface a write failure rather than vanish.
func TestUsage_TheDroppedPackageDisclosureSurfacesAWriteFailure(t *testing.T) {
	fx := newUsageFixture(t, usageFixtureOpts{
		projectNodes: usageNodes(), projectEdges: usageDefaultEdges(), moduleNodes: usageModuleNodes(),
		projectStatus: cgdomain.CallGraphStatusPartial, projectFailed: []string{"example.com/app/broken"},
	})
	bound, err := bindConsumer(context.Background(), fx.ctr.QueryWalks, fx.ctr.QueryCallGraph,
		consumerSelector{gomod: fx.gomod})
	if err != nil {
		t.Fatal(err)
	}
	report, err := joinUsage(context.Background(), fx.ctr.QueryCallGraph, bound, usageModCoord(), "")
	if err != nil {
		t.Fatal(err)
	}
	var full bytes.Buffer
	if err := printUsageReport(&full, report); err != nil {
		t.Fatalf("the report does not write cleanly: %v", err)
	}
	if !strings.Contains(full.String(), "unmeasured, not unreached") {
		t.Fatalf("the dropped package is not disclosed:\n%s", full.String())
	}
	for n := 0; n < full.Len(); n++ {
		if err := printUsageReport(&cutoffWriter{limit: n}, report); err == nil {
			t.Fatalf("a write that failed after %d bytes was reported as complete", n)
		}
	}
}
