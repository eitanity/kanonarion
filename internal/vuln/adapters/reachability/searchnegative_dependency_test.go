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

// The shape of the wasip1 and cgo fixtures: a build whose main does nothing,
// an exported function the host calls, and a dependency it calls into.
const (
	depModule    = "golang.org/x/text"
	depVersion   = "v0.3.7"
	depLanguage  = depModule + "/language"
	depInternal  = depModule + "/internal/language"
	depUnlinked  = depModule + "/encoding/japanese"
	projectCoord = consumerModule + "@" + coordinate.LocalVersion
)

// projectGraph is the frame's own graph: the export calls callee, a leaf
// spelled as the dependency's own graph spells it.
func projectGraph(symbol, kind, callee string, closure []string) ports.CallGraphProjection {
	entry := consumerModule + "." + symbol
	return ports.CallGraphProjection{
		Completeness:       "BUILT_WITH_BODIES",
		ArtifactKind:       "Application",
		StdlibPackages:     []string{linkedPackage},
		DependencyPackages: closure,
		AnalysisRoot:       "/srv/app",
		Nodes: []ports.CallGraphNode{
			{ID: consumerModule + ".main", Module: consumerModule, Package: consumerModule, Symbol: "main"},
			{ID: entry, Module: consumerModule, Package: consumerModule, Symbol: symbol, ExportKind: kind, ExportName: exportName(kind, symbol)},
			{ID: depLanguage + "." + callee, Package: depLanguage, Symbol: callee, IsExternal: true},
		},
		Edges: []ports.CallGraphEdge{{FromID: entry, ToID: depLanguage + "." + callee}},
	}
}

func exportName(kind, symbol string) string {
	if kind == "" {
		return ""
	}
	return symbol
}

// linkedClosure is what the fixture's build links of x/text.
var linkedClosure = []string{depInternal, depLanguage}

// dependencyGraph is x/text's own graph. Parse and ParseAcceptLanguage share
// an internal parser; a class-hierarchy edge leads from it into a package the
// build does not link, and only through that package is MatchStrings reached.
func dependencyGraph() ports.CallGraphProjection {
	return ports.CallGraphProjection{
		Completeness: "BUILT_WITH_BODIES",
		ArtifactKind: "Library",
		Nodes: []ports.CallGraphNode{
			{ID: depLanguage + ".Parse", Module: depModule, Package: depLanguage, Symbol: "Parse", IsExportedAPI: true},
			{ID: depLanguage + ".ParseAcceptLanguage", Module: depModule, Package: depLanguage, Symbol: "ParseAcceptLanguage", IsExportedAPI: true},
			{ID: depInternal + ".parse", Module: depModule, Package: depInternal, Symbol: "parse"},
			{ID: depUnlinked + ".decode", Module: depModule, Package: depUnlinked, Symbol: "decode"},
			{ID: depLanguage + ".MatchStrings", Module: depModule, Package: depLanguage, Symbol: "MatchStrings", IsExportedAPI: true},
			{ID: depUnlinked + ".Decoder", Module: depModule, Package: depUnlinked, Symbol: "Decoder", IsExportedAPI: true},
			// The frame owns this id too; the frame's node is kept.
			{ID: consumerModule + ".main", Module: depModule, Package: consumerModule, Symbol: "main", IsExportedAPI: true},
		},
		Edges: []ports.CallGraphEdge{
			{FromID: depLanguage + ".Parse", ToID: depInternal + ".parse"},
			{FromID: depLanguage + ".ParseAcceptLanguage", ToID: depInternal + ".parse"},
			{FromID: depInternal + ".parse", ToID: depUnlinked + ".decode"},
			{FromID: depUnlinked + ".decode", ToID: depLanguage + ".MatchStrings"},
		},
		ReflectiveDispatch: []ports.CallGraphReflectSite{
			{CallerID: depInternal + ".parse", CalleeID: "reflect.Value.Call"},
			{CallerID: depUnlinked + ".decode", CalleeID: "reflect.Value.Call"},
		},
	}
}

// advisoryPackages and advisorySymbols are GO-2022-1059's.
var (
	advisoryPackages = []string{depLanguage}
	advisorySymbols  = []string{"MatchStrings", "ParseAcceptLanguage"}
)

// dependencyRecord is GO-2022-1059 measured in the project's own build.
func dependencyRecord(packages, symbols []string) domain.VulnerabilityRecord {
	rooting := domain.TargetRootedAt(coordinatetest.MustNew(consumerModule, coordinate.LocalVersion))
	return domain.VulnerabilityRecord{
		Coordinate: coordinatetest.MustNew(depModule, depVersion),
		Rooting:    rooting,
		Findings: []domain.VulnerabilityFinding{{
			ID:               "GO-2022-1059",
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

func searchDependency(t *testing.T, loader ports.CallGraphLoader, packages, symbols []string) (*domain.NegativeSearch, domain.ReachabilitySoundness, string) {
	t.Helper()
	rec := dependencyRecord(packages, symbols)
	reachability.NewNegativeSearcher(loader).Search(t.Context(), &rec)
	got, reason := domain.NegativeSoundness(rec.Findings[0])
	return rec.Findings[0].NegativeSearch, got, reason
}

func dependencyLoader(project ports.CallGraphProjection) *byCoordinateLoader {
	return &byCoordinateLoader{graphs: map[string]ports.CallGraphProjection{
		projectCoord:                 project,
		depModule + "@" + depVersion: dependencyGraph(),
	}}
}

// TestSearchNegative_DependencyJoinDisputesFromAnExport: the project's export
// calls the advisory's symbol, which only the joined graph can show, so the
// negative reads disputed with the route rooted at the export and both graphs
// named.
func TestSearchNegative_DependencyJoinDisputesFromAnExport(t *testing.T) {
	for _, tt := range []struct{ symbol, kind string }{
		{symbol: "parse", kind: "wasmexport"},
		{symbol: "goParse", kind: "export"},
	} {
		t.Run(tt.kind, func(t *testing.T) {
			s, got, reason := searchDependency(t,
				dependencyLoader(projectGraph(tt.symbol, tt.kind, "ParseAcceptLanguage", linkedClosure)),
				advisoryPackages, advisorySymbols)
			if got != domain.SoundnessDisputed {
				t.Fatalf("soundness = %s (%s), want %s", got, reason, domain.SoundnessDisputed)
			}
			if len(s.Route) != 2 || s.Route[0].Symbol != tt.symbol || s.Route[1].Symbol != "ParseAcceptLanguage" {
				t.Errorf("route = %s, want %s -> ParseAcceptLanguage", s.Route, tt.symbol)
			}
			if !strings.Contains(reason, tt.symbol) {
				t.Errorf("the rung does not name the export the route starts at: %s", reason)
			}
			if len(s.GraphsSearched) != 2 ||
				!strings.HasPrefix(s.GraphsSearched[0], projectCoord+" ") ||
				!strings.HasPrefix(s.GraphsSearched[1], depModule+"@"+depVersion+" ") ||
				!strings.Contains(s.GraphsSearched[1], "kept only within the 2 packages of other modules this build links") {
				t.Errorf("graphs searched = %q, want the project's and the dependency's", s.GraphsSearched)
			}
			if !s.InRecordedFrame {
				t.Error("a joined graph is the record's own frame")
			}
		})
	}
}

// TestSearchNegative_DependencyJoinConfirmsWithoutTheExport is the control:
// the directive removed, nothing main or init reaches calls the dependency, so
// the search ran and found no path. That is a confirmed negative.
func TestSearchNegative_DependencyJoinConfirmsWithoutTheExport(t *testing.T) {
	s, got, reason := searchDependency(t,
		dependencyLoader(projectGraph("parse", "", "ParseAcceptLanguage", linkedClosure)),
		advisoryPackages, advisorySymbols)
	if got != domain.SoundnessConfirmed {
		t.Fatalf("soundness = %s (%s), want %s", got, reason, domain.SoundnessConfirmed)
	}
	if s.PathFound || len(s.GraphsSearched) != 2 {
		t.Errorf("search = %+v, want no path over both graphs", s)
	}
}

// TestSearchNegative_DependencyJoinKeepsOnlyTheLinkedPackages: an export that
// calls Parse, as the fixtures do, reaches MatchStrings only through a package
// the build does not link, which is a call the binary cannot make. With that
// package in the closure the same route disputes. A symbol only an unlinked
// package holds is said to be outside the build, not absent from the graph.
func TestSearchNegative_DependencyJoinKeepsOnlyTheLinkedPackages(t *testing.T) {
	loader := dependencyLoader(projectGraph("parse", "wasmexport", "Parse", linkedClosure))

	s, got, reason := searchDependency(t, loader, advisoryPackages, advisorySymbols)
	if got != domain.SoundnessConfirmed {
		t.Errorf("a route through an unlinked package -> %s (%s), want %s", got, reason, domain.SoundnessConfirmed)
	}
	if len(s.ReflectiveDispatch) != 1 || strings.HasPrefix(s.ReflectiveDispatch[0].Caller, depUnlinked) {
		t.Errorf("reflective sites = %+v, want only the one in a linked package", s.ReflectiveDispatch)
	}

	linked := dependencyLoader(projectGraph("parse", "wasmexport", "Parse", append([]string{depUnlinked}, linkedClosure...)))
	if _, got, reason := searchDependency(t, linked, advisoryPackages, advisorySymbols); got != domain.SoundnessDisputed {
		t.Errorf("the same route with its package linked -> %s (%s), want %s", got, reason, domain.SoundnessDisputed)
	}

	s, got, _ = searchDependency(t, loader, []string{depUnlinked}, []string{"Decoder"})
	if got != domain.SoundnessInferred || !strings.Contains(s.NotSearched, "links none of the packages of "+depModule+"@"+depVersion) {
		t.Errorf("a symbol only an unlinked package holds -> %s, %q", got, s.NotSearched)
	}

	s, _, _ = searchDependency(t, loader, nil, []string{"NeverExisted"})
	if !strings.Contains(s.NotSearched, "holds none of the symbols the advisory names") {
		t.Errorf("a symbol neither graph holds -> %q", s.NotSearched)
	}
}

// TestSearchNegative_DependencyJoinRefusesAFrameWithoutTheClosure: a frame
// graph that does not record the dependency closure is not joined, and the
// refusal names the re-analysis that records it.
func TestSearchNegative_DependencyJoinRefusesAFrameWithoutTheClosure(t *testing.T) {
	s, got, _ := searchDependency(t,
		dependencyLoader(projectGraph("parse", "wasmexport", "ParseAcceptLanguage", nil)),
		advisoryPackages, advisorySymbols)
	if got != domain.SoundnessInferred {
		t.Errorf("soundness = %s, want the recorded rung %s", got, domain.SoundnessInferred)
	}
	for _, want := range []string{"does not record which packages of other modules", "kanonarion local /srv/app --force"} {
		if !strings.Contains(s.NotSearched, want) {
			t.Errorf("the refusal does not say %q: %s", want, s.NotSearched)
		}
	}
}

// TestSearchNegative_DependencyWithNoProjectGraphKeepsItsOwnSearch: without the
// project's graph the dependency's own graph is searched as before, and the
// answer names the command that analyses the project.
func TestSearchNegative_DependencyWithNoProjectGraphKeepsItsOwnSearch(t *testing.T) {
	loader := &byCoordinateLoader{graphs: map[string]ports.CallGraphProjection{
		depModule + "@" + depVersion: dependencyGraph(),
	}}
	dirs := &fakeProjectDirs{dir: "/srv/checkouts/app", found: true}
	rec := dependencyRecord(advisoryPackages, advisorySymbols)
	rec.WalkID = "01M04P06Y1GJKX225K01M22E4Q"
	reachability.NewNegativeSearcher(loader).WithProjectDirs(dirs).Search(t.Context(), &rec)

	s := rec.Findings[0].NegativeSearch
	if s.InRecordedFrame || !s.PathFound || len(s.GraphsSearched) != 1 {
		t.Errorf("search = %+v, want the dependency's own graph, as before", s)
	}
	if !strings.Contains(s.NotJoined, "analyse it with: kanonarion local /srv/checkouts/app") {
		t.Errorf("the answer does not name the command that analyses the project: %q", s.NotJoined)
	}
	if got, reason := domain.NegativeSoundness(rec.Findings[0]); got != domain.SoundnessInferred ||
		!strings.Contains(reason, "kanonarion local /srv/checkouts/app") {
		t.Errorf("rung = %s (%s), want %s carrying the remedy", got, reason, domain.SoundnessInferred)
	}

	// The same remedy rides on a search that could not be made over that graph.
	rec = dependencyRecord(nil, []string{"NeverExisted"})
	reachability.NewNegativeSearcher(loader).Search(t.Context(), &rec)
	if s := rec.Findings[0].NegativeSearch; s.NotSearched == "" || !strings.Contains(s.NotJoined, "kanonarion local from inside it") {
		t.Errorf("search = %+v, want a refusal carrying the unnamed-tree remedy", s)
	}
}

// TestSearchNegative_DependencyJoinNamesWhatIsMissing: the refusal names every
// graph the join needed and could not get, with the command for each.
func TestSearchNegative_DependencyJoinNamesWhatIsMissing(t *testing.T) {
	for name, tt := range map[string]struct {
		graphs map[string]ports.CallGraphProjection
		want   []string
	}{
		"neither": {
			graphs: map[string]ports.CallGraphProjection{},
			want:   []string{"a dependency's negative", projectCoord, "kanonarion callgraph " + depModule + "@" + depVersion},
		},
		"the dependency": {
			graphs: map[string]ports.CallGraphProjection{projectCoord: projectGraph("parse", "", "ParseAcceptLanguage", linkedClosure)},
			want:   []string{"(the dependency this record is about); extract it with: kanonarion callgraph " + depModule + "@" + depVersion},
		},
	} {
		t.Run(name, func(t *testing.T) {
			s, _, _ := searchDependency(t, &byCoordinateLoader{graphs: tt.graphs}, nil, []string{"parse"})
			for _, want := range tt.want {
				if !strings.Contains(s.NotSearched, want) {
					t.Errorf("the refusal does not say %q: %s", want, s.NotSearched)
				}
			}
		})
	}
}

// TestSearchNegative_DependencyJoinReportsAnUnreadableGraphAsItself: a graph
// that will not load is a different problem from one never taken.
func TestSearchNegative_DependencyJoinReportsAnUnreadableGraphAsItself(t *testing.T) {
	s, _, _ := searchDependency(t, failingLoader{err: errors.New("disk on fire")}, nil, []string{"parse"})
	if !strings.Contains(s.NotSearched, "could not be read: disk on fire") || s.NotJoined != "" {
		t.Errorf("search = %+v, want the read fault itself", s)
	}
}

// TestSearchNegative_DependencyJoinDoesNotCertifyPastAnUnjoinedModule: the
// export reaches the dependency only through a third module whose graph is not
// joined, so a clean joined search proves nothing about that route. The
// dependency's own graph answers instead, as it did before the join.
func TestSearchNegative_DependencyJoinDoesNotCertifyPastAnUnjoinedModule(t *testing.T) {
	project := projectGraph("parse", "wasmexport", "ParseAcceptLanguage", linkedClosure)
	project.Nodes[2] = ports.CallGraphNode{ID: "example.com/wrap.Accept", Package: "example.com/wrap", Symbol: "Accept", IsExternal: true}
	project.Edges = []ports.CallGraphEdge{
		{FromID: consumerModule + ".parse", ToID: "example.com/wrap.Accept"},
		{FromID: consumerModule + ".parse", ToID: linkedPackage + ".Marshal"},
	}
	project.Nodes = append(project.Nodes, ports.CallGraphNode{ID: linkedPackage + ".Marshal", Package: linkedPackage, Symbol: "Marshal", IsExternal: true})

	s, got, reason := searchDependency(t, dependencyLoader(project), advisoryPackages, advisorySymbols)
	if got != domain.SoundnessInferred {
		t.Errorf("soundness = %s (%s), want the recorded rung %s", got, reason, domain.SoundnessInferred)
	}
	if s.InRecordedFrame || len(s.GraphsSearched) != 1 {
		t.Errorf("search = %+v, want the dependency's own graph", s)
	}
	if !strings.Contains(s.NotJoined, "reached 1 call into modules whose call graphs are not joined (example.com/wrap.Accept)") {
		t.Errorf("the answer does not name the call it could not follow: %q", s.NotJoined)
	}
}

// TestFirstN_ElidesALongList: a reason names a few examples, not hundreds.
func TestFirstN_ElidesALongList(t *testing.T) {
	project := projectGraph("parse", "wasmexport", "ParseAcceptLanguage", linkedClosure)
	for _, id := range []string{"a", "b", "c", "d"} {
		project.Nodes = append(project.Nodes, ports.CallGraphNode{ID: "example.com/" + id + ".F", Package: "example.com/" + id, Symbol: "F", IsExternal: true})
		project.Edges = append(project.Edges, ports.CallGraphEdge{FromID: consumerModule + ".parse", ToID: "example.com/" + id + ".F"})
	}
	project.Edges = project.Edges[1:]
	s, _, _ := searchDependency(t, dependencyLoader(project), advisoryPackages, advisorySymbols)
	if !strings.Contains(s.NotJoined, "reached 4 calls into modules whose call graphs are not joined (example.com/a.F, example.com/b.F, example.com/c.F, …)") {
		t.Errorf("the examples were not elided: %q", s.NotJoined)
	}
}

// subjectFailingLoader serves the project's graph and fails the dependency's.
type subjectFailingLoader struct{ project ports.CallGraphProjection }

func (l subjectFailingLoader) Load(_ context.Context, coord coordinate.ModuleCoordinate) (ports.CallGraphProjection, error) {
	if coord.String() == projectCoord {
		return l.project, nil
	}
	return ports.CallGraphProjection{}, errors.New("blob missing")
}

// TestSearchNegative_DependencyJoinNamesTheUnreadableDependency: the fault is
// reported against the graph that has it.
func TestSearchNegative_DependencyJoinNamesTheUnreadableDependency(t *testing.T) {
	s, _, _ := searchDependency(t, subjectFailingLoader{project: projectGraph("parse", "", "ParseAcceptLanguage", linkedClosure)}, nil, []string{"parse"})
	if want := "the stored call graph for " + depModule + "@" + depVersion + " could not be read: blob missing"; s.NotSearched != want {
		t.Errorf("refusal = %q, want %q", s.NotSearched, want)
	}
}

// TestSearchNegative_DependencyRootedAtItselfSearchesItsOwnGraph: a record of
// the module's own scan names no other build, so nothing is joined.
func TestSearchNegative_DependencyRootedAtItselfSearchesItsOwnGraph(t *testing.T) {
	loader := dependencyLoader(projectGraph("parse", "wasmexport", "ParseAcceptLanguage", linkedClosure))
	rec := dependencyRecord(advisoryPackages, advisorySymbols)
	rec.Rooting = domain.TargetRootedAt(coordinatetest.MustNew(depModule, depVersion))
	reachability.NewNegativeSearcher(loader).Search(t.Context(), &rec)
	if got := loader.calls; len(got) != 1 || got[0] != depModule+"@"+depVersion {
		t.Errorf("loaded %v, want only the dependency's own graph", got)
	}
}
