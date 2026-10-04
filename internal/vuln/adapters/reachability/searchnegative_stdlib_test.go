package reachability_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	callgraphdomain "github.com/eitanity/kanonarion/internal/callgraph/domain"
	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"

	"github.com/eitanity/kanonarion/internal/vuln/adapters/reachability"
	"github.com/eitanity/kanonarion/internal/vuln/domain"
	"github.com/eitanity/kanonarion/internal/vuln/ports"
)

// byCoordinateLoader serves a different graph per coordinate, which is what a
// joined search needs: it loads the build's own graph and the standard
// library's, and the two must not be the same answer.
type byCoordinateLoader struct {
	graphs map[string]ports.CallGraphProjection
	calls  []string
}

func (l *byCoordinateLoader) Load(_ context.Context, coord coordinate.ModuleCoordinate) (ports.CallGraphProjection, error) {
	l.calls = append(l.calls, coord.String())
	proj, ok := l.graphs[coord.String()]
	if !ok {
		return ports.CallGraphProjection{}, ports.ErrCallGraphNotFound
	}
	return proj, nil
}

const (
	consumerModule = "example.com/app"
	linkedPackage  = "encoding/json"
	unlinkedPkg    = "net/url"
)

// consumerGraph is an application that calls one standard-library function and
// records which standard-library packages its build links.
//
// The external leaf is spelled exactly as the standard library's own graph
// spells that function — a call-graph node id is "<package>.<symbol>" on both
// sides — which is the whole mechanism of the join.
func consumerGraph(linked []string) ports.CallGraphProjection {
	return ports.CallGraphProjection{
		Completeness:   "BUILT_WITH_BODIES",
		ArtifactKind:   "Application",
		StdlibPackages: linked,
		AnalysisRoot:   "/srv/app",
		Nodes: []ports.CallGraphNode{
			{ID: consumerModule + ".main", Module: consumerModule, Package: consumerModule, Symbol: "main"},
			{ID: linkedPackage + ".Marshal", Package: linkedPackage, Symbol: "Marshal", IsExternal: true},
		},
		Edges: []ports.CallGraphEdge{{FromID: consumerModule + ".main", ToID: linkedPackage + ".Marshal"}},
	}
}

// stdlibGraph is the standard library's own graph: the function the consumer
// calls, a class-hierarchy over-approximation out of it into a package the
// consumer's build does not link, and the vulnerable symbol in that package.
//
// The over-approximated edge is the case the restriction exists for. CHA
// resolves one indirect call on a func() variable to every func() in the
// program, and the standard library is 23,000 functions, so without the
// restriction a build that links none of net/url reaches net/url.resolvePath.
func stdlibGraph() ports.CallGraphProjection {
	return ports.CallGraphProjection{
		Completeness: "BUILT_WITH_BODIES",
		ArtifactKind: "Library",
		Nodes: []ports.CallGraphNode{
			{ID: linkedPackage + ".Marshal", Module: "stdlib", Package: linkedPackage, Symbol: "Marshal", IsExportedAPI: true},
			{ID: unlinkedPkg + ".Parse", Module: "stdlib", Package: unlinkedPkg, Symbol: "Parse", IsExportedAPI: true},
			{ID: unlinkedPkg + ".resolvePath", Module: "stdlib", Package: unlinkedPkg, Symbol: "resolvePath"},
			// A second Marshal, in the package the advisory below names. Nothing
			// reaches it, while the identically-named one in the linked package is
			// reached from main — which is the pair a package-blind target set
			// collapses into one.
			{ID: unlinkedPkg + ".Marshal", Module: "stdlib", Package: unlinkedPkg, Symbol: "Marshal", IsExportedAPI: true},
			// A shared function SSA synthesises for an interface method. It belongs
			// to no package, so no package list can place it, and dropping it would
			// cut a hop every build makes.
			{ID: "(stdlibErr).Error", Module: "stdlib", Symbol: "Error", IsExternal: true},
			{ID: linkedPackage + ".encodeState", Module: "stdlib", Package: linkedPackage, Symbol: "encodeState"},
		},
		Edges: []ports.CallGraphEdge{
			{FromID: linkedPackage + ".Marshal", ToID: unlinkedPkg + ".Parse"},
			{FromID: unlinkedPkg + ".Parse", ToID: unlinkedPkg + ".resolvePath"},
			{FromID: unlinkedPkg + ".Marshal", ToID: unlinkedPkg + ".resolvePath"},
			{FromID: linkedPackage + ".Marshal", ToID: "(stdlibErr).Error"},
			{FromID: "(stdlibErr).Error", ToID: linkedPackage + ".encodeState"},
		},
	}
}

// stdlibRecord is a standard-library finding measured in the consumer's build,
// which is the only frame a stdlib advisory is ever recorded in.
func stdlibRecord(packages, symbols []string) domain.VulnerabilityRecord {
	rooting := domain.TargetRootedAt(coordinatetest.MustNew(consumerModule, coordinate.LocalVersion))
	return domain.VulnerabilityRecord{
		Coordinate: coordinatetest.MustNew(coordinate.StdlibPath, "v1.26.5"),
		Rooting:    rooting,
		Findings: []domain.VulnerabilityFinding{{
			ID:               "GO-2026-6218",
			AffectedPackages: packages,
			AffectedSymbols:  symbols,
			Reachable: &domain.ReachabilityResult{
				IsReachable: false,
				Confidence:  domain.ConfidenceHigh,
				DerivedBy: domain.ReachabilityDerivation{
					Analyser: domain.AnalyserGovulncheck,
					Fidelity: string(domain.ScanModeSource),
					Rooting:  rooting,
				},
			},
		}},
	}
}

func stdlibLoader(linked []string) *byCoordinateLoader {
	return &byCoordinateLoader{graphs: map[string]ports.CallGraphProjection{
		consumerModule + "@" + coordinate.LocalVersion: consumerGraph(linked),
		coordinate.StdlibPath + "@v1.26.5":             stdlibGraph(),
	}}
}

// TestSearchNegative_StdlibJoinConfirmsWhenThePackageIsNotLinked is the whole
// point of the join: the build does not link net/url, so no edge of the
// standard library's graph into it is a call this binary can make, and the
// negative is confirmed over a graph built with bodies.
func TestSearchNegative_StdlibJoinConfirmsWhenThePackageIsNotLinked(t *testing.T) {
	loader := stdlibLoader([]string{linkedPackage})
	rec := stdlibRecord([]string{unlinkedPkg}, []string{"Parse", "resolvePath"})

	reachability.NewNegativeSearcher(loader).Search(t.Context(), &rec)

	got, reason := domain.NegativeSoundness(rec.Findings[0])
	if got != domain.SoundnessConfirmed {
		t.Fatalf("soundness = %s (%s), want %s", got, reason, domain.SoundnessConfirmed)
	}
	search := rec.Findings[0].NegativeSearch
	if search == nil || search.PathFound {
		t.Fatalf("the search reports a path into a package this build does not link: %+v", search)
	}
	if len(search.GraphsSearched) != 2 {
		t.Fatalf("the answer names %d graphs, want both the build's and the standard library's: %v",
			len(search.GraphsSearched), search.GraphsSearched)
	}
	if !strings.Contains(reason, "stdlib@v1.26.5") || !strings.Contains(reason, consumerModule) {
		t.Errorf("the rung does not name the records it was reached over: %s", reason)
	}
}

// TestSearchNegative_StdlibJoinFollowsLinkedPackages is the other direction,
// and it is what stops the restriction above being a way of confirming
// everything: the same advisory in a package the build DOES link is reached,
// and the rung says the two analysers disagree.
func TestSearchNegative_StdlibJoinFollowsLinkedPackages(t *testing.T) {
	loader := stdlibLoader([]string{linkedPackage, unlinkedPkg})
	rec := stdlibRecord([]string{unlinkedPkg}, []string{"resolvePath"})

	reachability.NewNegativeSearcher(loader).Search(t.Context(), &rec)

	search := rec.Findings[0].NegativeSearch
	if search == nil || !search.PathFound {
		t.Fatalf("the search found no path although every package on it is linked: %+v", search)
	}
	if !search.InRecordedFrame {
		t.Error("a joined graph IS the frame the record was measured in, so a path in it may contradict the record")
	}
	if got, _ := domain.NegativeSoundness(rec.Findings[0]); got != domain.SoundnessDisputed {
		t.Errorf("soundness = %s, want %s", got, domain.SoundnessDisputed)
	}
}

// TestSearchNegative_StdlibJoinScopesSymbolsToTheAdvisorysPackages is the
// precision the standard library forced. "stdlib" is one coordinate spanning
// 362 packages, so an advisory naming Marshal in net/url must not be answered
// by a route to encoding/json's Marshal.
func TestSearchNegative_StdlibJoinScopesSymbolsToTheAdvisorysPackages(t *testing.T) {
	loader := stdlibLoader([]string{linkedPackage, unlinkedPkg})
	rec := stdlibRecord([]string{unlinkedPkg}, []string{"Marshal"})

	reachability.NewNegativeSearcher(loader).Search(t.Context(), &rec)

	search := rec.Findings[0].NegativeSearch
	if search == nil {
		t.Fatal("no search was attached")
	}
	if search.NotSearched != "" {
		t.Fatalf("the search declined, so nothing was scoped: %s", search.NotSearched)
	}
	if search.PathFound {
		t.Errorf("the search reached a same-named symbol in a package the advisory does not name: %s", search.Route)
	}
	// Without the scoping the identically-named symbol in the linked package is
	// reached from main, and the rung reads disputed off a route the advisory is
	// not about.
	if got, reason := domain.NegativeSoundness(rec.Findings[0]); got != domain.SoundnessConfirmed {
		t.Errorf("soundness = %s (%s), want %s", got, reason, domain.SoundnessConfirmed)
	}
}

// TestSearchNegative_StdlibJoinRefusesWithoutTheRecordedClosure is the refusal
// that keeps the restriction honest. A build's graph that does not say which
// standard-library packages it links cannot be joined soundly, and guessing
// would confirm negatives out of code nothing measured.
func TestSearchNegative_StdlibJoinRefusesWithoutTheRecordedClosure(t *testing.T) {
	loader := stdlibLoader(nil)
	rec := stdlibRecord([]string{unlinkedPkg}, []string{"resolvePath"})

	reachability.NewNegativeSearcher(loader).Search(t.Context(), &rec)

	search := rec.Findings[0].NegativeSearch
	if search == nil || search.NotSearched == "" {
		t.Fatalf("the search ran without the build's standard-library closure: %+v", search)
	}
	if !strings.Contains(search.NotSearched, "kanonarion local /srv/app --force") {
		t.Errorf("the refusal does not name the command that records the closure: %s", search.NotSearched)
	}
	if got, _ := domain.NegativeSoundness(rec.Findings[0]); got != domain.SoundnessInferred {
		t.Errorf("soundness = %s, want the recorded derivation's own rung %s", got, domain.SoundnessInferred)
	}
}

// TestSearchNegative_StdlibJoinNamesBothMissingGraphs is the remedy half: a
// store holding neither graph says so once and names both commands, rather
// than sending the reader back a second time for the second graph.
func TestSearchNegative_StdlibJoinNamesBothMissingGraphs(t *testing.T) {
	loader := &byCoordinateLoader{graphs: map[string]ports.CallGraphProjection{}}
	rec := stdlibRecord([]string{unlinkedPkg}, []string{"resolvePath"})

	reachability.NewNegativeSearcher(loader).Search(t.Context(), &rec)

	why := rec.Findings[0].NegativeSearch.NotSearched
	for _, want := range []string{
		consumerModule + "@" + coordinate.LocalVersion,
		"stdlib@v1.26.5",
		"kanonarion callgraph stdlib@v1.26.5",
	} {
		if !strings.Contains(why, want) {
			t.Errorf("the refusal does not mention %q: %s", want, why)
		}
	}
}

// TestSearchNegative_StdlibWithNoFrameSearchesItsOwnGraph: a record that does
// not say which build it was measured in has no consumer graph to continue
// from, so the standard library's own graph is searched and the entry-point
// rooting is what stops it confirming out of a root set made of the vulnerable
// symbols themselves.
func TestSearchNegative_StdlibWithNoFrameSearchesItsOwnGraph(t *testing.T) {
	loader := stdlibLoader([]string{linkedPackage})
	rec := stdlibRecord([]string{unlinkedPkg}, []string{"Parse"})
	rec.Rooting = domain.RootingIsolated

	reachability.NewNegativeSearcher(loader).Search(t.Context(), &rec)

	if got := loader.calls; len(got) != 1 || got[0] != "stdlib@v1.26.5" {
		t.Fatalf("loaded %v, want only the standard library's own graph", got)
	}
	search := rec.Findings[0].NegativeSearch
	if search == nil || !search.PathFound {
		t.Fatalf("net/url.Parse is the standard library's own exported API, so its own graph reaches it: %+v", search)
	}
	if search.InRecordedFrame {
		t.Error("the standard library's own graph is not a graph of the frame, so a path in it contradicts nothing")
	}
}

// TestSearchNegative_StdlibJoinNamesOnlyTheStandardLibraryWhenTheBuildIsHeld:
// the refusal names what is actually missing, so a reader with a project graph
// already in the store is not sent to re-analyse it.
func TestSearchNegative_StdlibJoinNamesOnlyTheStandardLibraryWhenTheBuildIsHeld(t *testing.T) {
	loader := &byCoordinateLoader{graphs: map[string]ports.CallGraphProjection{
		consumerModule + "@" + coordinate.LocalVersion: consumerGraph([]string{linkedPackage}),
	}}
	rec := stdlibRecord([]string{unlinkedPkg}, []string{"resolvePath"})

	reachability.NewNegativeSearcher(loader).Search(t.Context(), &rec)

	why := rec.Findings[0].NegativeSearch.NotSearched
	if strings.Contains(why, consumerModule) {
		t.Errorf("the refusal names a graph the store holds: %s", why)
	}
	if !strings.Contains(why, "extract it with: kanonarion callgraph stdlib@v1.26.5") {
		t.Errorf("the refusal does not name the one command that closes the gap: %s", why)
	}
}

// failingLoader fails every load with a fault that is not "no record held".
type failingLoader struct{ err error }

func (l failingLoader) Load(context.Context, coordinate.ModuleCoordinate) (ports.CallGraphProjection, error) {
	return ports.CallGraphProjection{}, l.err
}

// TestSearchNegative_StdlibJoinReportsAnUnreadableGraphAsItself: a graph that
// exists and will not decode is a different problem from one that was never
// taken, and a remedy for the second does not address the first.
func TestSearchNegative_StdlibJoinReportsAnUnreadableGraphAsItself(t *testing.T) {
	rec := stdlibRecord([]string{unlinkedPkg}, []string{"resolvePath"})

	reachability.NewNegativeSearcher(failingLoader{err: errors.New("blob truncated")}).Search(t.Context(), &rec)

	why := rec.Findings[0].NegativeSearch.NotSearched
	if !strings.Contains(why, "could not be read") || !strings.Contains(why, "blob truncated") {
		t.Errorf("the refusal does not carry the store's own fault: %s", why)
	}
	if strings.Contains(why, "kanonarion callgraph") {
		t.Errorf("the refusal offers an extraction for a graph that is already there: %s", why)
	}
}

// TestSearchNegative_StdlibJoinRefusesAnUnparseableFrame: a record whose frame
// does not name a coordinate has no build to load, and says so rather than
// falling back to the standard library's own graph.
func TestSearchNegative_StdlibJoinRefusesAnUnparseableFrame(t *testing.T) {
	rec := stdlibRecord([]string{unlinkedPkg}, []string{"resolvePath"})
	rec.Rooting = domain.Rooting("target-rooted:not a coordinate")

	reachability.NewNegativeSearcher(stdlibLoader([]string{linkedPackage})).Search(t.Context(), &rec)

	why := rec.Findings[0].NegativeSearch.NotSearched
	if !strings.Contains(why, "is not a coordinate") {
		t.Errorf("the refusal does not say the frame cannot be loaded: %s", why)
	}
}

// TestSearchNegative_StdlibJoinKeepsAPackagelessHop: the shared functions SSA
// synthesises for an interface method belong to no package, so no package list
// can place one. Dropping them would cut a hop every build makes, so they are
// kept and the advisory's symbol behind one is still reached.
func TestSearchNegative_StdlibJoinKeepsAPackagelessHop(t *testing.T) {
	loader := stdlibLoader([]string{linkedPackage})
	rec := stdlibRecord([]string{linkedPackage}, []string{"encodeState"})

	reachability.NewNegativeSearcher(loader).Search(t.Context(), &rec)

	search := rec.Findings[0].NegativeSearch
	if search == nil || search.NotSearched != "" {
		t.Fatalf("the search declined: %+v", search)
	}
	if !search.PathFound {
		t.Error("a hop through a package-less synthetic was dropped, so the symbol behind it reads unreached")
	}
}

// fakeProjectDirs is the walk ledger's record of where a frame's tree is.
type fakeProjectDirs struct {
	dir   string
	found bool
	err   error
	asked []string
}

func (d *fakeProjectDirs) WalkProjectDir(_ context.Context, walkID string) (string, bool, error) {
	d.asked = append(d.asked, walkID)
	return d.dir, d.found, d.err
}

// TestSearchNegative_StdlibJoinNamesTheTreeTheWalkRecorded: a project-rooted
// frame's working tree IS recorded, by the walk the record came from, so the
// refusal names the command that analyses it rather than a sentence saying
// nothing names it.
func TestSearchNegative_StdlibJoinNamesTheTreeTheWalkRecorded(t *testing.T) {
	loader := &byCoordinateLoader{graphs: map[string]ports.CallGraphProjection{
		coordinate.StdlibPath + "@v1.26.5": stdlibGraph(),
	}}
	dirs := &fakeProjectDirs{dir: "/srv/checkouts/app", found: true}
	rec := stdlibRecord([]string{unlinkedPkg}, []string{"resolvePath"})
	rec.WalkID = "01M04P06Y1GJKX225K01M22E4Q"

	reachability.NewNegativeSearcher(loader).WithProjectDirs(dirs).Search(t.Context(), &rec)

	why := rec.Findings[0].NegativeSearch.NotSearched
	if !strings.Contains(why, "extract it with: kanonarion local /srv/checkouts/app") {
		t.Errorf("the refusal does not name the tree the walk recorded: %s", why)
	}
	if strings.Contains(why, callgraphdomain.UnnamedWorkingTreeLead) {
		t.Errorf("the refusal still claims no record names the tree: %s", why)
	}
	if len(dirs.asked) == 0 || dirs.asked[0] != rec.WalkID {
		t.Errorf("the ledger was asked about %v, want the walk the record names", dirs.asked)
	}
}

// TestSearchNegative_StdlibJoinStatesAnUnnamedTreeAsASentence: where nothing
// names the tree, the reason is a SENTENCE of its own. A remedy slot takes a
// command or takes nothing — splicing the sentence into "extract it with: …"
// composes text that reads as an invocation and is not one.
func TestSearchNegative_StdlibJoinStatesAnUnnamedTreeAsASentence(t *testing.T) {
	loader := &byCoordinateLoader{graphs: map[string]ports.CallGraphProjection{
		coordinate.StdlibPath + "@v1.26.5": stdlibGraph(),
	}}
	rec := stdlibRecord([]string{unlinkedPkg}, []string{"resolvePath"})

	// No dir reader wired, and no graph to carry an analysis root.
	reachability.NewNegativeSearcher(loader).Search(t.Context(), &rec)

	why := rec.Findings[0].NegativeSearch.NotSearched
	if strings.Contains(why, "with: "+callgraphdomain.UnnamedWorkingTreeLead) ||
		strings.Contains(why, "with: No stored record") {
		t.Fatalf("a sentence was spliced into a remedy slot: %s", why)
	}
	if !strings.Contains(why, ". No stored record names the working tree, so run kanonarion local from inside it") {
		t.Errorf("the refusal does not state the unnamed tree as its own sentence: %s", why)
	}
}

// TestSearchNegative_StdlibJoinAsksNoLedgerWhenTheGraphNamesTheTree: the graph
// the refusal is about already says which tree it was taken of, and that is a
// stronger answer than the walk's — it is the tree that graph describes.
func TestSearchNegative_StdlibJoinAsksNoLedgerWhenTheGraphNamesTheTree(t *testing.T) {
	loader := stdlibLoader(nil) // a consumer graph that records no closure
	dirs := &fakeProjectDirs{dir: "/somewhere/else", found: true}
	rec := stdlibRecord([]string{unlinkedPkg}, []string{"resolvePath"})
	rec.WalkID = "01M04P06Y1GJKX225K01M22E4Q"

	reachability.NewNegativeSearcher(loader).WithProjectDirs(dirs).Search(t.Context(), &rec)

	why := rec.Findings[0].NegativeSearch.NotSearched
	if !strings.Contains(why, "re-analyse it with: kanonarion local /srv/app --force") {
		t.Errorf("the refusal does not name the tree the graph was taken of: %s", why)
	}
	if len(dirs.asked) != 0 {
		t.Errorf("the walk ledger was consulted although the graph names its own tree: %v", dirs.asked)
	}
}

// TestSearchNegative_StdlibJoinSurvivesALedgerFault: a store that will not
// answer leaves the refusal without a directory, never with a wrong one.
func TestSearchNegative_StdlibJoinSurvivesALedgerFault(t *testing.T) {
	loader := &byCoordinateLoader{graphs: map[string]ports.CallGraphProjection{
		coordinate.StdlibPath + "@v1.26.5": stdlibGraph(),
	}}
	rec := stdlibRecord([]string{unlinkedPkg}, []string{"resolvePath"})
	rec.WalkID = "01M04P06Y1GJKX225K01M22E4Q"

	reachability.NewNegativeSearcher(loader).
		WithProjectDirs(&fakeProjectDirs{err: errors.New("store closed")}).Search(t.Context(), &rec)

	why := rec.Findings[0].NegativeSearch.NotSearched
	if !strings.Contains(why, ". No stored record names the working tree") {
		t.Errorf("a ledger fault did not fall back to the sentence: %s", why)
	}
}
