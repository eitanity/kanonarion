package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/cli/testfakes"
	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	vuldomain "github.com/eitanity/kanonarion/internal/vuln/domain"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
)

// The two builds the dependency-frame tests answer in. `consumerWalk` is a
// project that depends on the library; `libraryWalk` is the same library walked
// on its own. Both hold the library, and they resolve different dependency sets
// for it — the consumer build drops the library's test-only dependency and MVS
// raises another version — which is why the section names the build it answered
// in rather than printing a bare count.
const (
	consumerWalkID = "01CONSUMERWALK00000000000"
	libraryWalkID  = "01LIBRARYWALK000000000000"
)

func libCoord(t *testing.T) coordinate.ModuleCoordinate {
	t.Helper()
	return coordinatetest.MustNew("example.com/lib", "v3.3.0")
}

// consumerWalk is a project walk: a local root whose manifest requires the whole
// build list (so the root has an edge to every node) but marks only two of those
// requirements direct, plus the library with one outgoing edge of its own.
func consumerWalk(t *testing.T) walkdomain.WalkRecord {
	t.Helper()
	root, err := coordinate.NewLocalCoordinate("example.com/app")
	if err != nil {
		t.Fatalf("local coordinate: %v", err)
	}
	lib := libCoord(t)
	cast := coordinatetest.MustNew("example.com/cast", "v1.10.0")
	extra := coordinatetest.MustNew("example.com/extra", "v1.0.0")
	g := walkdomain.Graph{
		Target: root,
		Nodes: []walkdomain.GraphNode{
			{Coordinate: root, ResolutionSource: walkdomain.ResolutionLocalMainModule},
			{Coordinate: lib, DirectDependency: true, ResolutionSource: walkdomain.ResolutionMVS},
			{Coordinate: extra, DirectDependency: true, ResolutionSource: walkdomain.ResolutionMVS},
			{Coordinate: cast, ResolutionSource: walkdomain.ResolutionMVS},
		},
		Edges: []walkdomain.GraphEdge{
			{From: root, To: lib, ConstraintVersion: "v3.3.0"},
			{From: root, To: extra, ConstraintVersion: "v1.0.0"},
			{From: root, To: cast, ConstraintVersion: "v1.10.0"},
			{From: lib, To: cast, ConstraintVersion: "v1.7.0"},
		},
		BuildEnv: walkdomain.BuildEnv{GOOS: "linux", GOARCH: "amd64", GoVersion: "go1.26.6"},
	}
	g.Sort()
	return walkdomain.WalkRecord{
		ID: consumerWalkID, Target: root, Scope: walkdomain.WalkScopeCode,
		OverallStatus: walkdomain.WalkSucceeded, Graph: g,
	}
}

// libraryWalk is the same library walked on its own: two direct dependencies,
// one of them the test-only module a consumer build never requires, and the
// declared rather than the MVS-raised version of the shared one.
func libraryWalk(t *testing.T) walkdomain.WalkRecord {
	t.Helper()
	lib := libCoord(t)
	cast := coordinatetest.MustNew("example.com/cast", "v1.7.0")
	spew := coordinatetest.MustNew("example.com/spew", "v1.1.1")
	g := walkdomain.Graph{
		Target: lib,
		Nodes: []walkdomain.GraphNode{
			{Coordinate: lib, ResolutionSource: walkdomain.ResolutionTarget},
			{Coordinate: cast, DirectDependency: true, ResolutionSource: walkdomain.ResolutionMVS},
			{Coordinate: spew, DirectDependency: true, ResolutionSource: walkdomain.ResolutionMVS},
		},
		Edges: []walkdomain.GraphEdge{
			{From: lib, To: cast, ConstraintVersion: "v1.7.0"},
			{From: lib, To: spew, ConstraintVersion: "v1.1.1"},
		},
	}
	g.Sort()
	return walkdomain.WalkRecord{
		ID: libraryWalkID, Target: lib, Scope: walkdomain.WalkScopeCode,
		OverallStatus: walkdomain.WalkSucceeded, Graph: g,
	}
}

// frameStore holds the walks, with summaries in the order the SQL adapter
// returns them.
func frameStore(recs ...walkdomain.WalkRecord) *testfakes.FakeQueryWalks {
	qw := testfakes.NewFakeQueryWalks()
	summaries := make([]walkports.WalkSummary, 0, len(recs))
	for _, rec := range recs {
		qw.AddWalk(rec)
		summaries = append(summaries, walkports.WalkSummary{
			ID: rec.ID, Target: rec.Target, Scope: rec.Scope,
			OverallStatus: rec.OverallStatus,
			GOOS:          rec.Graph.BuildEnv.GOOS, GOARCH: rec.Graph.BuildEnv.GOARCH,
		})
	}
	qw.SetSummaries(summaries)
	return qw
}

func depPaths(d contextDependencies) []string {
	out := make([]string, 0, len(d.Dependencies))
	for _, dep := range d.Dependencies {
		out = append(out, dep.Path+"@"+dep.Version)
	}
	return out
}

// A module a project walk holds had its dependencies reported as never measured,
// one line above the walk that resolved them. The build the rest of the document
// answers in answers this section too.
func TestBuildDependencies_AnswersFromTheDocumentsBasisWalk(t *testing.T) {
	ctx := context.Background()
	consumer, library := consumerWalk(t), libraryWalk(t)
	store := frameStore(consumer, library)

	got := buildDependencies(ctx, libCoord(t), store, resolveBasisWalk(ctx, store, consumer.ID))

	if got.Status == sectionStatusNotRun {
		t.Fatalf("dependencies reported %q for a module the basis walk holds", got.Status)
	}
	if got.WalkID != consumer.ID {
		t.Errorf("answered from walk %q, want the document's basis %q", got.WalkID, consumer.ID)
	}
	if want := string(vuldomain.TargetRootedAt(consumer.Target)); got.Rooting != want {
		t.Errorf("rooting = %q, want %q", got.Rooting, want)
	}
	if want := []string{"example.com/cast@v1.10.0"}; !slices.Equal(depPaths(got), want) {
		t.Errorf("dependencies = %v, want the library's outgoing edges in the consumer build %v", depPaths(got), want)
	}
}

// The frames genuinely disagree, so the section must not answer one frame's
// question with the other's numbers: the same coordinate resolves a different
// dependency set in its own walk (a test-only module, and the declared version)
// from the one a consumer build resolves.
func TestBuildDependencies_EachBasisReportsItsOwnFramesSet(t *testing.T) {
	ctx := context.Background()
	consumer, library := consumerWalk(t), libraryWalk(t)
	store := frameStore(consumer, library)
	lib := libCoord(t)

	inConsumer := buildDependencies(ctx, lib, store, resolveBasisWalk(ctx, store, consumer.ID))
	inLibrary := buildDependencies(ctx, lib, store, resolveBasisWalk(ctx, store, library.ID))

	if inConsumer.Count == inLibrary.Count {
		t.Fatalf("both frames reported %d dependencies; the fixture no longer exercises disagreeing frames", inConsumer.Count)
	}
	if want := []string{"example.com/cast@v1.10.0"}; !slices.Equal(depPaths(inConsumer), want) {
		t.Errorf("consumer frame = %v, want %v", depPaths(inConsumer), want)
	}
	if want := []string{"example.com/cast@v1.7.0", "example.com/spew@v1.1.1"}; !slices.Equal(depPaths(inLibrary), want) {
		t.Errorf("library's own frame = %v, want %v", depPaths(inLibrary), want)
	}
	if inConsumer.WalkID == inLibrary.WalkID {
		t.Errorf("both answers named walk %q; each must name the frame it answered in", inConsumer.WalkID)
	}
}

// GraphNode.DirectDependency is a fact about the walk ROOT's manifest. Read for
// a dependency it reports the root's direct dependencies as that dependency's —
// measured at 76 against the queried module's 4 on a real project walk. The
// fixture's root has two direct-dependency nodes and the queried module has one
// outgoing edge, so reading the flag fails this test.
func TestBuildDependencies_DoesNotReadTheRootsDirectDependencyFlag(t *testing.T) {
	ctx := context.Background()
	consumer := consumerWalk(t)
	store := frameStore(consumer)

	rootDirect := 0
	for _, n := range consumer.Graph.Nodes {
		if n.DirectDependency {
			rootDirect++
		}
	}
	if rootDirect < 2 {
		t.Fatalf("fixture root has %d direct dependencies; it must differ from the queried module's for this test to bite", rootDirect)
	}

	got := buildDependencies(ctx, libCoord(t), store, resolveBasisWalk(ctx, store, consumer.ID))
	if got.Count == rootDirect {
		t.Fatalf("dependencies = %d, which is the walk ROOT's direct-dependency count, not the queried module's", got.Count)
	}
	if got.Count != 1 {
		t.Errorf("dependencies = %d, want the queried module's 1 outgoing edge", got.Count)
	}
}

// The root's own answer is the other half of the same rule. A main module's
// go.mod requires its whole build list, so the root's outgoing edges are that
// list — 127 of 128 nodes on a real project walk — while the flag records the
// requirements the manifest did not mark indirect. Reading edges for the root
// turns "direct dependencies" into the build list.
func TestBuildDependencies_TheRootIsAnsweredByItsManifestNotItsEdges(t *testing.T) {
	ctx := context.Background()
	consumer := consumerWalk(t)
	store := frameStore(consumer)

	rootEdges := 0
	for _, e := range consumer.Graph.Edges {
		if e.From == consumer.Target {
			rootEdges++
		}
	}

	got := buildDependencies(ctx, consumer.Target, store, resolveBasisWalk(ctx, store, consumer.ID))
	if got.Count == rootEdges {
		t.Fatalf("the root reported %d direct dependencies, which is its whole require list, not what it declares directly", got.Count)
	}
	if want := []string{"example.com/extra@v1.0.0", "example.com/lib@v3.3.0"}; !slices.Equal(depPaths(got), want) {
		t.Errorf("root dependencies = %v, want %v", depPaths(got), want)
	}
}

// A build that did not contain the module is not a build that failed to measure
// it. `not run` claims nobody looked, and its remedy is a full walk; here a walk
// was measured and the module was simply not in it.
func TestBuildDependencies_SaysWhenTheBasisWalkDoesNotHoldTheModule(t *testing.T) {
	ctx := context.Background()
	consumer := consumerWalk(t)
	store := frameStore(consumer)
	absent := coordinatetest.MustNew("example.com/absent", "v1.0.0")

	got := buildDependencies(ctx, absent, store, resolveBasisWalk(ctx, store, consumer.ID))

	if got.Status != sectionStatusNotInWalk {
		t.Fatalf("status = %q, want %q", got.Status, sectionStatusNotInWalk)
	}
	if got.WalkID != consumer.ID {
		t.Errorf("walk id = %q, want the basis walk %q named in the answer", got.WalkID, consumer.ID)
	}

	var buf bytes.Buffer
	out := contextOutput{
		Module:       contextModuleInfo{Path: absent.Path(), Version: absent.Version()},
		Dependencies: got,
	}
	if err := printContextSummary(out, &buf); err != nil {
		t.Fatalf("printContextSummary: %v", err)
	}
	line := dependencyLine(t, buf.String())
	if strings.Contains(line, "not run") {
		t.Errorf("rendered %q, which claims nothing measured the module", line)
	}
	if !strings.Contains(line, consumer.ID) {
		t.Errorf("rendered %q, which does not name the walk that did not hold the module", line)
	}
}

// A coordinate whose only walk is its own still answers from that walk, and
// still says so — an isolated coordinate must not become unanswerable. A
// document with no basis walk has no basis line for this choice to contradict.
func TestBuildDependencies_WithNoBasisAnswersFromTheModulesOwnWalk(t *testing.T) {
	ctx := context.Background()
	library := libraryWalk(t)
	store := frameStore(library)

	got := buildDependencies(ctx, libCoord(t), store, basisWalk{})

	if got.Status != walkdomain.WalkSucceeded.String() {
		t.Fatalf("status = %q, want the walk's own %q", got.Status, walkdomain.WalkSucceeded)
	}
	if got.WalkID != library.ID {
		t.Errorf("walk id = %q, want %q", got.WalkID, library.ID)
	}
	if got.Count != 2 {
		t.Errorf("count = %d, want the module's own walk's 2", got.Count)
	}
}

// Control: the reserved case. A module no walk holds still reports not_run with
// the walk remedy, unchanged.
func TestBuildDependencies_AModuleNoWalkHoldsStillReportsNotRun(t *testing.T) {
	ctx := context.Background()
	store := frameStore()
	stranger := coordinatetest.MustNew("example.com/stranger", "v1.0.0")

	got := buildDependencies(ctx, stranger, store, basisWalk{})
	if got.Status != sectionStatusNotRun {
		t.Fatalf("status = %q, want %q", got.Status, sectionStatusNotRun)
	}

	var buf bytes.Buffer
	out := contextOutput{
		Module:       contextModuleInfo{Path: stranger.Path(), Version: stranger.Version()},
		Dependencies: got,
	}
	if err := printContextSummary(out, &buf); err != nil {
		t.Fatalf("printContextSummary: %v", err)
	}
	if line := dependencyLine(t, buf.String()); !strings.Contains(line, "kanonarion walk example.com/stranger@v1.0.0") {
		t.Errorf("rendered %q, want the unchanged walk remedy", line)
	}
}

// A named basis walk that cannot be read is a store fault, not a licence to
// answer in some other build. The section reports the fault.
func TestBuildDependencies_ARefusedBasisWalkIsReportedNotRoutedAround(t *testing.T) {
	ctx := context.Background()
	library := libraryWalk(t)
	store := frameStore(library)

	got := buildDependencies(ctx, libCoord(t), store, resolveBasisWalk(ctx, store, "01MISSINGWALK00000000000"))
	if got.Status != sectionStatusReadError {
		t.Fatalf("status = %q, want %q", got.Status, sectionStatusReadError)
	}
	if got.WalkID == library.ID {
		t.Errorf("answered from walk %q after the document's basis could not be read", got.WalkID)
	}
}

// One document, one frame. The dependency section is resolved from the very
// field the vulnerability section publishes as the document's basis, so the two
// cannot name different builds — in the JSON an agent reads, or in the prose a
// person reads.
func TestContextDocument_DependenciesAndWalkBasisNameOneBuild(t *testing.T) {
	ctx := context.Background()
	consumer, library := consumerWalk(t), libraryWalk(t)
	store := frameStore(consumer, library)
	lib := libCoord(t)

	// What runContext holds after the vulnerability section has answered.
	vulns := contextVulnerabilities{
		Status:         string(vuldomain.StatusClean),
		WalkBasisID:    consumer.ID,
		WalkBasisFrame: string(vuldomain.TargetRootedAt(consumer.Target)),
	}
	out := contextOutput{
		Module:          contextModuleInfo{Path: lib.Path(), Version: lib.Version()},
		Dependencies:    buildDependencies(ctx, lib, store, resolveBasisWalk(ctx, store, vulns.WalkBasisID)),
		Vulnerabilities: vulns,
	}

	if out.Dependencies.WalkID != vulns.WalkBasisID {
		t.Errorf("dependencies answered in walk %q while the document's basis is %q", out.Dependencies.WalkID, vulns.WalkBasisID)
	}
	if out.Dependencies.Rooting != vulns.WalkBasisFrame {
		t.Errorf("dependencies frame %q, walk basis frame %q", out.Dependencies.Rooting, vulns.WalkBasisFrame)
	}

	raw, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var doc struct {
		Dependencies struct {
			WalkID  string `json:"walk_id"`
			Rooting string `json:"rooting"`
		} `json:"dependencies"`
		Vulnerabilities struct {
			WalkBasisID    string `json:"walk_basis_id"`
			WalkBasisFrame string `json:"walk_basis_frame"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if doc.Dependencies.Rooting == "" {
		t.Fatalf("--json carries no frame for the dependency section: %s", raw)
	}
	if doc.Dependencies.WalkID != doc.Vulnerabilities.WalkBasisID ||
		doc.Dependencies.Rooting != doc.Vulnerabilities.WalkBasisFrame {
		t.Errorf("the document reports two frames: dependencies %s/%s, walk basis %s/%s",
			doc.Dependencies.WalkID, doc.Dependencies.Rooting,
			doc.Vulnerabilities.WalkBasisID, doc.Vulnerabilities.WalkBasisFrame)
	}

	var buf bytes.Buffer
	if err := printContextSummary(out, &buf); err != nil {
		t.Fatalf("printContextSummary: %v", err)
	}
	line := dependencyLine(t, buf.String())
	if !strings.Contains(line, consumer.ID) || !strings.Contains(line, vulns.WalkBasisFrame) {
		t.Errorf("dependency line %q names neither the basis walk nor its frame", line)
	}
}

// dependencyLine returns the rendered "Dependencies:" line of a summary.
func dependencyLine(t *testing.T, rendered string) string {
	t.Helper()
	for _, line := range strings.Split(rendered, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "Dependencies:") {
			return line
		}
	}
	t.Fatalf("no Dependencies line in:\n%s", rendered)
	return ""
}
