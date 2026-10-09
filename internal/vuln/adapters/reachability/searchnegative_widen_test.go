package reachability_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"

	"github.com/eitanity/kanonarion/internal/vuln/adapters/reachability"
	"github.com/eitanity/kanonarion/internal/vuln/domain"
	"github.com/eitanity/kanonarion/internal/vuln/ports"
)

const (
	wrapModule = "example.com/wrap"
	wrapCoord  = wrapModule + "@v1.0.0"
	walkID     = "01M04P06Y1GJKX225K01M22E4Q"
)

// fakeWalkModules is the walk ledger's build list.
type fakeWalkModules struct {
	mods  []ports.BuildModule
	found bool
	err   error
}

func (w fakeWalkModules) WalkModules(context.Context, string) ([]ports.BuildModule, bool, error) {
	return w.mods, w.found, w.err
}

func buildList(localReplace bool) fakeWalkModules {
	return fakeWalkModules{found: true, mods: []ports.BuildModule{
		{Coordinate: coordinatetest.MustNew(wrapModule, "v1.0.0"), LocalReplace: localReplace},
		{Coordinate: coordinatetest.MustNew(depModule, depVersion)},
	}}
}

// wrapFrame is a build whose only entry into anything is main calling
// example.com/wrap.callee, a leaf the frame's own graph stops at.
func wrapFrame(callee string) ports.CallGraphProjection {
	return ports.CallGraphProjection{
		Completeness:       "BUILT_WITH_BODIES",
		ArtifactKind:       "Application",
		StdlibPackages:     []string{linkedPackage},
		DependencyPackages: []string{wrapModule, depLanguage, depInternal},
		AnalysisRoot:       "/srv/app",
		Nodes: []ports.CallGraphNode{
			{ID: consumerModule + ".main", Module: consumerModule, Package: consumerModule, Symbol: "main"},
			{ID: wrapModule + "." + callee, Package: wrapModule, Symbol: callee, IsExternal: true},
		},
		Edges: []ports.CallGraphEdge{{FromID: consumerModule + ".main", ToID: wrapModule + "." + callee}},
	}
}

// wrapGraph is example.com/wrap's own graph: Next calls encoding/json.Marshal,
// behind which the standard library reaches encodeState; Accept calls into
// x/text; Hello calls nothing; Tested reaches Marshal only through test code.
func wrapGraph(completeness string) ports.CallGraphProjection {
	return ports.CallGraphProjection{
		Completeness: completeness,
		ArtifactKind: "Library",
		Nodes: []ports.CallGraphNode{
			{ID: wrapModule + ".Next", Module: wrapModule, Package: wrapModule, Symbol: "Next", IsExportedAPI: true},
			{ID: wrapModule + ".Accept", Module: wrapModule, Package: wrapModule, Symbol: "Accept", IsExportedAPI: true},
			{ID: wrapModule + ".Hello", Module: wrapModule, Package: wrapModule, Symbol: "Hello", IsExportedAPI: true},
			{ID: wrapModule + ".Tested", Module: wrapModule, Package: wrapModule, Symbol: "Tested", IsExportedAPI: true},
			{ID: wrapModule + ".helper", Module: wrapModule, Package: wrapModule, Symbol: "helper", IsTest: true},
			{ID: linkedPackage + ".Marshal", Package: linkedPackage, Symbol: "Marshal", IsExternal: true},
			{ID: depLanguage + ".ParseAcceptLanguage", Package: depLanguage, Symbol: "ParseAcceptLanguage", IsExternal: true},
		},
		Edges: []ports.CallGraphEdge{
			{FromID: wrapModule + ".Next", ToID: linkedPackage + ".Marshal"},
			{FromID: wrapModule + ".Accept", ToID: depLanguage + ".ParseAcceptLanguage"},
			{FromID: wrapModule + ".Tested", ToID: wrapModule + ".helper"},
			{FromID: wrapModule + ".helper", ToID: linkedPackage + ".Marshal"},
		},
	}
}

func widenLoader(frame ports.CallGraphProjection, wrap *ports.CallGraphProjection) *byCoordinateLoader {
	graphs := map[string]ports.CallGraphProjection{
		projectCoord:                       frame,
		coordinate.StdlibPath + "@v1.26.5": stdlibGraph(),
		depModule + "@" + depVersion:       dependencyGraph(),
	}
	if wrap != nil {
		graphs[wrapCoord] = *wrap
	}
	return &byCoordinateLoader{graphs: graphs}
}

// searchWidened searches GO-2026-6218 (encodeState, behind Marshal) in the
// frame, with the build list given.
func searchWidened(t *testing.T, loader ports.CallGraphLoader, walk ports.WalkModuleReader) (*domain.NegativeSearch, domain.ReachabilitySoundness, string) {
	t.Helper()
	rec := stdlibRecord([]string{linkedPackage}, []string{"encodeState"})
	rec.WalkID = walkID
	reachability.NewNegativeSearcher(loader).WithWalkModules(walk).Search(t.Context(), &rec)
	got, reason := domain.NegativeSoundness(rec.Findings[0])
	return rec.Findings[0].NegativeSearch, got, reason
}

func ptr(p ports.CallGraphProjection) *ports.CallGraphProjection { return &p }

// TestSearchNegative_WidenedJoinDisputesThroughAHeldDependency: main reaches
// the standard library only through example.com/wrap. With wrap's graph held,
// the join follows the route through it and the negative reads disputed.
// x/text is linked and held but nothing reaches it, so it is not loaded.
func TestSearchNegative_WidenedJoinDisputesThroughAHeldDependency(t *testing.T) {
	s, got, reason := searchWidened(t, widenLoader(wrapFrame("Next"), ptr(wrapGraph("BUILT_WITH_BODIES"))), buildList(false))
	if got != domain.SoundnessDisputed {
		t.Fatalf("soundness = %s (%s), want %s", got, reason, domain.SoundnessDisputed)
	}
	if r := s.Route.String(); !strings.Contains(r, "Next") || !strings.Contains(r, "encodeState") {
		t.Errorf("route = %s, want it through %s.Next", r, wrapModule)
	}
	if len(s.GraphsSearched) != 3 || !strings.Contains(s.GraphsSearched[1], "1 further dependency graph held for this build ("+wrapCoord+")") {
		t.Errorf("graphs searched = %q, want the frame's, wrap's alone and the standard library's", s.GraphsSearched)
	}
}

// TestSearchNegative_WidenedJoinConfirmsPastAnUnrelatedHeldDependency: main
// calls a dependency that calls nothing. Its graph is held, so every reached
// call is joined and the clean search confirms.
func TestSearchNegative_WidenedJoinConfirmsPastAnUnrelatedHeldDependency(t *testing.T) {
	s, got, reason := searchWidened(t, widenLoader(wrapFrame("Hello"), ptr(wrapGraph("BUILT_WITH_BODIES"))), buildList(false))
	if got != domain.SoundnessConfirmed || s.NotJoined != "" {
		t.Errorf("soundness = %s (%s), not_joined %q, want %s and none", got, reason, s.NotJoined, domain.SoundnessConfirmed)
	}
}

// TestSearchNegative_WidenedJoinNamesTheCommandForAnUnheldDependency: the same
// build without wrap's graph cannot see past the call, so the rung stays and
// not_joined names the call and the command that would join it.
func TestSearchNegative_WidenedJoinNamesTheCommandForAnUnheldDependency(t *testing.T) {
	frame := wrapFrame("Hello")
	frame.Nodes = append(frame.Nodes, ports.CallGraphNode{ID: wrapModule + ".init", Package: wrapModule, Symbol: "init", IsExternal: true})
	frame.Edges = append(frame.Edges, ports.CallGraphEdge{FromID: consumerModule + ".main", ToID: wrapModule + ".init"})
	s, got, reason := searchWidened(t, widenLoader(frame, nil), buildList(false))
	if got != domain.SoundnessInferred {
		t.Fatalf("soundness = %s (%s), want %s", got, reason, domain.SoundnessInferred)
	}
	if n := strings.Count(s.NotJoined, "kanonarion callgraph"); n != 1 {
		t.Errorf("two calls into one module name %d commands, want 1: %s", n, s.NotJoined)
	}
	for _, want := range []string{"(" + wrapModule + ".Hello, " + wrapModule + ".init)", "the module that provides them; extract it with: kanonarion callgraph " + wrapCoord} {
		if !strings.Contains(s.NotJoined, want) || !strings.Contains(reason, want) {
			t.Errorf("not_joined and the reason do not both say %q:\n%s\n%s", want, s.NotJoined, reason)
		}
	}
}

// TestSearchNegative_WidenedJoinStatesWhyEachCallWasNotJoined: every way a
// reached call can stay unjoined is named, and none of them confirms.
func TestSearchNegative_WidenedJoinStatesWhyEachCallWasNotJoined(t *testing.T) {
	noDeps := wrapFrame("Hello")
	noDeps.DependencyPackages = nil
	strange := wrapFrame("Hello")
	strange.Nodes[1] = ports.CallGraphNode{ID: "example.org/other.F", Package: "example.org/other", Symbol: "F", IsExternal: true}
	strange.Edges[0].ToID = "example.org/other.F"
	held := ptr(wrapGraph("BUILT_WITH_BODIES"))
	for name, tt := range map[string]struct {
		loader ports.CallGraphLoader
		walk   ports.WalkModuleReader
		want   string
	}{
		"local replace":      {widenLoader(wrapFrame("Hello"), held), buildList(true), wrapCoord + " is replaced by a local directory"},
		"two unheld modules": {twoUnheld(), buildList(false), "the 2 modules that provide them; extract them with: kanonarion callgraph " + wrapCoord + "; kanonarion callgraph " + depModule + "@" + depVersion},
		"held without node":  {widenLoader(wrapFrame("Missing"), held), buildList(false), "the stored call graphs of " + wrapCoord + " (BUILT_WITH_BODIES, 7 nodes) hold no node for those calls; kanonarion callgraph-show"},
		"unreadable":         {wrapFaultLoader{widenLoader(wrapFrame("Hello"), nil)}, buildList(false), "the stored call graph of " + wrapCoord + " could not be read: blob missing"},
		"no module":          {widenLoader(strange, held), buildList(false), "no module of this build's walk provides example.org/other"},
		"no walk reader":     {widenLoader(wrapFrame("Hello"), held), nil, "no walk is named that lists the modules this build selected"},
		"walk not held":      {widenLoader(wrapFrame("Hello"), held), fakeWalkModules{}, "the store holds no walk " + walkID},
		"walk unreadable":    {widenLoader(wrapFrame("Hello"), held), fakeWalkModules{err: errors.New("disk on fire")}, "could not be read: disk on fire"},
		"no closure":         {widenLoader(noDeps, held), buildList(false), "does not record which packages of other modules its build links, so no dependency graph was joined; re-analyse it with: kanonarion local /srv/app --force"},
	} {
		t.Run(name, func(t *testing.T) {
			s, got, reason := searchWidened(t, tt.loader, tt.walk)
			if got != domain.SoundnessInferred {
				t.Errorf("soundness = %s (%s), want %s", got, reason, domain.SoundnessInferred)
			}
			if !strings.Contains(s.NotJoined, tt.want) {
				t.Errorf("not_joined does not say %q: %s", tt.want, s.NotJoined)
			}
		})
	}
}

// twoUnheld is a build calling into two modules, neither of whose graphs is held.
func twoUnheld() *byCoordinateLoader {
	frame := wrapFrame("Hello")
	frame.Nodes = append(frame.Nodes, ports.CallGraphNode{ID: depLanguage + ".Parse", Package: depLanguage, Symbol: "Parse", IsExternal: true})
	frame.Edges = append(frame.Edges, ports.CallGraphEdge{FromID: consumerModule + ".main", ToID: depLanguage + ".Parse"})
	l := widenLoader(frame, nil)
	delete(l.graphs, depModule+"@"+depVersion)
	return l
}

// wrapFaultLoader fails wrap's graph with a fault that is not "no record".
type wrapFaultLoader struct{ inner ports.CallGraphLoader }

func (l wrapFaultLoader) Load(ctx context.Context, coord coordinate.ModuleCoordinate) (ports.CallGraphProjection, error) {
	if coord.String() == wrapCoord {
		return ports.CallGraphProjection{}, errors.New("blob missing")
	}
	return l.inner.Load(ctx, coord) //nolint:wrapcheck // the fake passes the inner loader's error through
}

// TestSearchNegative_WidenedJoinLeavesOutADependencysTests: Tested reaches
// Marshal only through a test helper, which no consuming build compiles.
func TestSearchNegative_WidenedJoinLeavesOutADependencysTests(t *testing.T) {
	if _, got, reason := searchWidened(t, widenLoader(wrapFrame("Tested"), ptr(wrapGraph("BUILT_WITH_BODIES"))), buildList(false)); got != domain.SoundnessConfirmed {
		t.Errorf("a route through test code -> %s (%s), want %s", got, reason, domain.SoundnessConfirmed)
	}
}

// TestSearchNegative_WidenedJoinWeighsOnlyTheGraphsItEnters: a held graph
// below BUILT_WITH_BODIES lowers the rung where the entry points reach into
// it, and not where nothing does.
func TestSearchNegative_WidenedJoinWeighsOnlyTheGraphsItEnters(t *testing.T) {
	typeOnly := ptr(wrapGraph("TYPE_ONLY"))
	if _, got, reason := searchWidened(t, widenLoader(wrapFrame("Hello"), typeOnly), buildList(false)); got != domain.SoundnessUnconfirmed {
		t.Errorf("entered TYPE_ONLY graph -> %s (%s), want %s", got, reason, domain.SoundnessUnconfirmed)
	}
	// Only an unused function calls into wrap: its graph is joined for the
	// whole-graph claim, and no entry point enters it.
	frame := wrapFrame("Hello")
	frame.Nodes = append(frame.Nodes, ports.CallGraphNode{ID: consumerModule + ".unused", Module: consumerModule, Package: consumerModule, Symbol: "unused"})
	frame.Edges[0].FromID = consumerModule + ".unused"
	s, got, reason := searchWidened(t, widenLoader(frame, typeOnly), buildList(false))
	if got != domain.SoundnessConfirmed || len(s.GraphsSearched) != 3 {
		t.Errorf("unentered TYPE_ONLY graph -> %s (%s) over %q, want %s over it", got, reason, s.GraphsSearched, domain.SoundnessConfirmed)
	}
}

// TestSearchNegative_WidenedDependencyJoinFollowsAThirdModule: the project
// reaches x/text only through example.com/wrap. With wrap's graph held, the
// dependency's negative reads disputed along that route, over one shared join.
func TestSearchNegative_WidenedDependencyJoinFollowsAThirdModule(t *testing.T) {
	loader := widenLoader(wrapFrame("Accept"), ptr(wrapGraph("BUILT_WITH_BODIES")))
	searcher := reachability.NewNegativeSearcher(loader).WithWalkModules(buildList(false))

	rec := dependencyRecord(advisoryPackages, advisorySymbols)
	rec.WalkID = walkID
	searcher.Search(t.Context(), &rec)
	if got, reason := domain.NegativeSoundness(rec.Findings[0]); got != domain.SoundnessDisputed {
		t.Fatalf("soundness = %s (%s), want %s", got, reason, domain.SoundnessDisputed)
	}
	if r := rec.Findings[0].NegativeSearch.Route.String(); !strings.Contains(r, "Accept") {
		t.Errorf("route = %s, want it through %s.Accept", r, wrapModule)
	}

	std := stdlibRecord([]string{linkedPackage}, []string{"encodeState"})
	std.WalkID = walkID
	searcher.Search(t.Context(), &std)
	counts := map[string]int{}
	for _, c := range loader.calls {
		counts[c]++
	}
	for c, n := range counts {
		if n != 1 {
			t.Errorf("%s loaded %d times, want once across both searches", c, n)
		}
	}
}
