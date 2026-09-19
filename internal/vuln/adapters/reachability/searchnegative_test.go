package reachability_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"

	"github.com/eitanity/kanonarion/internal/vuln/adapters/reachability"
	"github.com/eitanity/kanonarion/internal/vuln/domain"
	"github.com/eitanity/kanonarion/internal/vuln/ports"
)

// countingLoader is a fakeLoader that records how many times it was asked. The
// count is the friction measurement: a read that needs no search must not decode
// a call graph at all.
type countingLoader struct {
	projection ports.CallGraphProjection
	err        error
	calls      int
}

func (l *countingLoader) Load(_ context.Context, _ coordinate.ModuleCoordinate) (ports.CallGraphProjection, error) {
	l.calls++
	return l.projection, l.err
}

const searchedModule = "example.com/mod"

// libraryGraph is a two-node graph of searchedModule: an exported entry point
// that calls nothing, and an unexported vulnerable symbol nothing calls.
func libraryGraph(completeness string, withEdge bool) ports.CallGraphProjection {
	proj := ports.CallGraphProjection{
		Completeness: completeness,
		ArtifactKind: "Library",
		Nodes: []ports.CallGraphNode{
			{ID: "entry", Module: searchedModule, Package: searchedModule, Symbol: "Serve", IsExportedAPI: true},
			{ID: "vuln", Module: searchedModule, Package: searchedModule, Symbol: "vulnerable"},
		},
	}
	if withEdge {
		proj.Edges = []ports.CallGraphEdge{{FromID: "entry", ToID: "vuln"}}
	}
	return proj
}

func searchedRecord(rooting domain.Rooting, symbols []string) domain.VulnerabilityRecord {
	return domain.VulnerabilityRecord{
		Coordinate: coordinatetest.MustNew(searchedModule, "v1.0.0"),
		Rooting:    rooting,
		Findings: []domain.VulnerabilityFinding{{
			ID:              "GO-0000-0000",
			AffectedSymbols: symbols,
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

// TestSearchNegative_CleanSearchConfirms is the headline behaviour: a negative
// stamped from govulncheck's silence, read back with a graph in the store, is
// confirmed by a search that ran over that graph and found nothing.
func TestSearchNegative_CleanSearchConfirms(t *testing.T) {
	loader := &countingLoader{projection: libraryGraph("BUILT_WITH_BODIES", false)}
	rec := searchedRecord(domain.TargetRootedAt(coordinatetest.MustNew(searchedModule, "v1.0.0")), []string{"vulnerable"})

	reachability.NewNegativeSearcher(loader).Search(t.Context(), &rec)

	got, reason := domain.NegativeSoundness(rec.Findings[0])
	if got != domain.SoundnessConfirmed {
		t.Fatalf("soundness = %s (%s), want %s", got, reason, domain.SoundnessConfirmed)
	}
	if rec.Findings[0].Reachable.DerivedBy.Analyser != domain.AnalyserGovulncheck {
		t.Error("the stored derivation was overwritten; the search states its own answer beside it, never on top of it")
	}
}

// TestSearchNegative_PartialGraphIsUnconfirmed asserts the ladder's existing
// rung under the search: a graph with unbuilt bodies leaves call edges absent,
// so a search over one cannot confirm.
func TestSearchNegative_PartialGraphIsUnconfirmed(t *testing.T) {
	for _, completeness := range []string{"METADATA_ONLY", "TYPE_ONLY"} {
		loader := &countingLoader{projection: libraryGraph(completeness, false)}
		rec := searchedRecord(domain.TargetRootedAt(coordinatetest.MustNew(searchedModule, "v1.0.0")), []string{"vulnerable"})

		reachability.NewNegativeSearcher(loader).Search(t.Context(), &rec)

		if got, _ := domain.NegativeSoundness(rec.Findings[0]); got != domain.SoundnessUnconfirmed {
			t.Errorf("a %s graph -> %s, want %s", completeness, got, domain.SoundnessUnconfirmed)
		}
	}
}

// TestSearchNegative_NoGraphStaysInferred is the control this whole change is
// bounded by. An absent graph must never read as a confirmed negative; the
// answer is the one the record already carried, word for word.
func TestSearchNegative_NoGraphStaysInferred(t *testing.T) {
	// The error the real loader returns for a coordinate the store holds no
	// record for, wrapped exactly as it wraps it.
	loader := &countingLoader{err: fmt.Errorf("%w: %s", ports.ErrCallGraphNotFound, searchedModule)}
	rec := searchedRecord(domain.TargetRootedAt(coordinatetest.MustNew(searchedModule, "v1.0.0")), []string{"vulnerable"})
	wantRung, wantReason := domain.NegativeSoundness(rec.Findings[0])

	reachability.NewNegativeSearcher(loader).Search(t.Context(), &rec)

	got, reason := domain.NegativeSoundness(rec.Findings[0])
	// The RUNG is unchanged: a search that could not run concludes nothing, in
	// either direction.
	if got != domain.SoundnessInferred || got != wantRung {
		t.Errorf("with no graph -> %s, want the unchanged %s", got, wantRung)
	}
	// The REASON is not. This test used to require the two to be byte-identical,
	// which pinned the silence as the contract: a coordinate whose graph would not
	// load read exactly like one the search had never been asked about, and the
	// operator was told neither that a search was owed nor what would supply it.
	if reason == wantReason {
		t.Error("a search that could not be made says nothing about itself; the reader cannot tell it from one that ran and came back empty")
	}
	if !strings.HasPrefix(reason, wantReason) {
		t.Errorf("the recorded basis was rewritten rather than extended:\n got %q\nwant prefix %q", reason, wantReason)
	}
	s := rec.Findings[0].NegativeSearch
	if s == nil {
		t.Fatal("no NegativeSearch attached, so --json publishes no key and the skip is invisible to a machine reader")
	}
	if s.NotSearched == "" {
		t.Error("NotSearched is empty on a search that never ran")
	}
	if !strings.Contains(s.NotSearched, "kanonarion callgraph") {
		t.Errorf("the skip names no remedy: %q", s.NotSearched)
	}
}

// TestSearchNegative_EverySkipStatesItself walks the reasons a search can decline
// to run. Each one leaves the recorded rung standing and each one must say so —
// a rung published with nothing beside it is indistinguishable from a coordinate
// nothing ever asked about, which is the failure this ticket exists to close.
func TestSearchNegative_EverySkipStatesItself(t *testing.T) {
	rooted := domain.TargetRootedAt(coordinatetest.MustNew(searchedModule, "v1.0.0"))
	noOwnedNodes := ports.CallGraphProjection{Completeness: "BUILT_WITH_BODIES", ArtifactKind: "Library"}

	for name, tc := range map[string]struct {
		loader *countingLoader
		symbol string
		want   string
	}{
		"no record in the store": {
			loader: &countingLoader{err: ports.ErrCallGraphNotFound},
			symbol: "vulnerable",
			want:   "holds no call graph",
		},
		"the graph owns nothing": {
			loader: &countingLoader{projection: noOwnedNodes},
			symbol: "vulnerable",
			want:   "holds no node this module owns",
		},
		"the graph names none of the advisory's symbols": {
			loader: &countingLoader{projection: libraryGraph("BUILT_WITH_BODIES", false)},
			symbol: "aSymbolThisGraphNeverHeardOf",
			want:   "holds none of the",
		},
	} {
		t.Run(name, func(t *testing.T) {
			rec := searchedRecord(rooted, []string{tc.symbol})
			reachability.NewNegativeSearcher(tc.loader).Search(t.Context(), &rec)

			s := rec.Findings[0].NegativeSearch
			if s == nil {
				t.Fatal("the skip attached nothing, so no surface can publish it")
			}
			if !strings.Contains(s.NotSearched, tc.want) {
				t.Errorf("NotSearched = %q, want it to name %q", s.NotSearched, tc.want)
			}
			rung, reason := domain.NegativeSoundness(rec.Findings[0])
			if rung != domain.SoundnessInferred {
				t.Errorf("rung = %s, want the recorded %s to stand", rung, domain.SoundnessInferred)
			}
			if !strings.Contains(reason, s.NotSearched) {
				t.Errorf("the rung does not carry the reason the search was skipped:\n%s", reason)
			}
		})
	}
}

// TestSearchNegative_PointerReceiverSymbolsAreFound is the matching defect,
// measured on the store before it was fixed: an advisory names a method
// "Renderer.renderAutoLink" and the graph records the receiver as the Go type it
// is declared on, "*Renderer". Compared literally they never meet, so the target
// set came up short and the search looked for less than the advisory named —
// silently, and in the false-negative direction.
//
// Measured over the only two coordinates in a working store holding both a
// negative and a graph: three of three symbols missed on one, four of eight on
// the other.
func TestSearchNegative_PointerReceiverSymbolsAreFound(t *testing.T) {
	graph := ports.CallGraphProjection{
		Completeness: "BUILT_WITH_BODIES",
		ArtifactKind: "Library",
		Nodes: []ports.CallGraphNode{
			{ID: "entry", Module: searchedModule, Package: searchedModule, Symbol: "Serve", IsExportedAPI: true},
			{ID: "ptr", Module: searchedModule, Package: searchedModule, Receiver: "*Renderer", Symbol: "renderLink"},
			{ID: "val", Module: searchedModule, Package: searchedModule, Receiver: "Config", Symbol: "apply"},
		},
	}
	// Every spelling of the same method the two sides use between them.
	for _, advisory := range []string{"Renderer.renderLink", "*Renderer.renderLink", "(*Renderer).renderLink"} {
		t.Run(advisory, func(t *testing.T) {
			rec := searchedRecord(domain.TargetRootedAt(coordinatetest.MustNew(searchedModule, "v1.0.0")), []string{advisory})
			reachability.NewNegativeSearcher(&countingLoader{projection: graph}).Search(t.Context(), &rec)

			s := rec.Findings[0].NegativeSearch
			if s == nil {
				t.Fatal("no search attached at all")
			}
			if s.NotSearched != "" {
				t.Fatalf("the advisory's symbol was not found in a graph that holds it: %s", s.NotSearched)
			}
		})
	}
	// The control: a value receiver still matches, and a method this graph does
	// not hold is still reported as absent rather than matched by accident.
	rec := searchedRecord(domain.TargetRootedAt(coordinatetest.MustNew(searchedModule, "v1.0.0")), []string{"Config.apply"})
	reachability.NewNegativeSearcher(&countingLoader{projection: graph}).Search(t.Context(), &rec)
	if s := rec.Findings[0].NegativeSearch; s == nil || s.NotSearched != "" {
		t.Errorf("a value-receiver method stopped matching: %v", rec.Findings[0].NegativeSearch)
	}
	absent := searchedRecord(domain.TargetRootedAt(coordinatetest.MustNew(searchedModule, "v1.0.0")), []string{"Renderer.notHere"})
	reachability.NewNegativeSearcher(&countingLoader{projection: graph}).Search(t.Context(), &absent)
	if s := absent.Findings[0].NegativeSearch; s == nil || s.NotSearched == "" {
		t.Errorf("a symbol the graph does not hold was matched anyway: %v", absent.Findings[0].NegativeSearch)
	}
}

// TestSearchNegative_SymbolAbsentFromGraphIsNotASearch guards the false-confirm
// this is most exposed to. A graph that holds none of the advisory's symbols did
// not search and come back empty — there was nothing in it to look for — and
// reporting that as a confirmed negative would confirm a mismatch.
func TestSearchNegative_SymbolAbsentFromGraphIsNotASearch(t *testing.T) {
	loader := &countingLoader{projection: libraryGraph("BUILT_WITH_BODIES", false)}
	rec := searchedRecord(domain.TargetRootedAt(coordinatetest.MustNew(searchedModule, "v1.0.0")), []string{"NeverBuilt"})

	reachability.NewNegativeSearcher(loader).Search(t.Context(), &rec)

	if got, _ := domain.NegativeSoundness(rec.Findings[0]); got != domain.SoundnessInferred {
		t.Errorf("a graph naming none of the symbols -> %s, want %s", got, domain.SoundnessInferred)
	}
}

// TestSearchNegative_PathInTheRecordedFrameDisputes is the disagreement case:
// the record says not reachable, the search over the module's own build says
// otherwise, and the reader is told rather than either answer winning silently.
func TestSearchNegative_PathInTheRecordedFrameDisputes(t *testing.T) {
	loader := &countingLoader{projection: libraryGraph("BUILT_WITH_BODIES", true)}
	rec := searchedRecord(domain.TargetRootedAt(coordinatetest.MustNew(searchedModule, "v1.0.0")), []string{"vulnerable"})

	reachability.NewNegativeSearcher(loader).Search(t.Context(), &rec)

	got, reason := domain.NegativeSoundness(rec.Findings[0])
	if got != domain.SoundnessDisputed {
		t.Fatalf("soundness = %s, want %s", got, domain.SoundnessDisputed)
	}
	if !strings.Contains(reason, "vulnerable") {
		t.Errorf("the reason does not carry the path it found: %q", reason)
	}
	if rec.Findings[0].Reachable.IsReachable {
		t.Error("the search flipped a stored verdict")
	}
}

// TestSearchNegative_PathOutsideTheRecordedFrameDoesNotDispute pins the
// asymmetry. A record measured in a consumer's build is not contradicted by a
// path inside the dependency's own graph; the path is stated, not ruled on.
func TestSearchNegative_PathOutsideTheRecordedFrameDoesNotDispute(t *testing.T) {
	loader := &countingLoader{projection: libraryGraph("BUILT_WITH_BODIES", true)}
	rec := searchedRecord("target-rooted:example.com/consumer@local", []string{"vulnerable"})

	reachability.NewNegativeSearcher(loader).Search(t.Context(), &rec)

	got, reason := domain.NegativeSoundness(rec.Findings[0])
	if got != domain.SoundnessInferred {
		t.Errorf("a path found in another frame -> %s, want %s", got, domain.SoundnessInferred)
	}
	if !strings.Contains(reason, "different question") {
		t.Errorf("the path found was not reported at all: %q", reason)
	}
}

// TestSearchNegative_CostsNothingWhenNothingNeedsSearching is the friction
// measurement. A record with no negative the search may speak to must not cost a
// call-graph decode, so an interactive read pays only where it gains something.
func TestSearchNegative_CostsNothingWhenNothingNeedsSearching(t *testing.T) {
	rooted := domain.TargetRootedAt(coordinatetest.MustNew(searchedModule, "v1.0.0"))
	for name, mutate := range map[string]func(*domain.VulnerabilityRecord){
		"a reachable finding": func(r *domain.VulnerabilityRecord) { r.Findings[0].Reachable.IsReachable = true },
		"no reachability answer": func(r *domain.VulnerabilityRecord) {
			r.Findings[0].Reachable = nil
		},
		"an advisory naming no symbols": func(r *domain.VulnerabilityRecord) {
			r.Findings[0].AffectedSymbols = nil
			r.Findings[0].AdvisoryNamesNoSymbols = true
		},
		"a negative that already came from a search": func(r *domain.VulnerabilityRecord) {
			r.Findings[0].Reachable.DerivedBy.Analyser = domain.AnalyserCallGraphBFS
		},
		"no findings at all": func(r *domain.VulnerabilityRecord) { r.Findings = nil },
	} {
		t.Run(name, func(t *testing.T) {
			loader := &countingLoader{projection: libraryGraph("BUILT_WITH_BODIES", false)}
			rec := searchedRecord(rooted, []string{"vulnerable"})
			mutate(&rec)

			reachability.NewNegativeSearcher(loader).Search(t.Context(), &rec)

			if loader.calls != 0 {
				t.Errorf("loaded a call graph %d time(s) for a record with nothing to search", loader.calls)
			}
		})
	}
}

// TestSearchNegative_DecodesEachGraphOnce pins the cost of the path that does
// search: one decode per coordinate, however many findings ask for it.
func TestSearchNegative_DecodesEachGraphOnce(t *testing.T) {
	loader := &countingLoader{projection: libraryGraph("BUILT_WITH_BODIES", false)}
	rec := searchedRecord(domain.TargetRootedAt(coordinatetest.MustNew(searchedModule, "v1.0.0")), []string{"vulnerable"})
	rec.Findings = append(rec.Findings, rec.Findings[0], rec.Findings[0])

	searcher := reachability.NewNegativeSearcher(loader)
	searcher.Search(t.Context(), &rec)
	searcher.Search(t.Context(), &rec)

	if loader.calls != 1 {
		t.Errorf("decoded the call graph %d times, want 1", loader.calls)
	}
}

// applicationGraph is the case the whole ticket turns on: a module that builds a
// command, so the whole-graph rule roots at every function it owns.
//
// It holds a command's main, an exported API function, an unexported vulnerable
// symbol that neither of them reaches, and — optionally — a dispatch target that
// does reach the vulnerable symbol but is entered by nothing the analysis can
// name. The last one is what separates the two claims.
func applicationGraph(completeness string, withDispatchTarget bool) ports.CallGraphProjection {
	proj := ports.CallGraphProjection{
		Completeness: completeness,
		ArtifactKind: "Application",
		Nodes: []ports.CallGraphNode{
			{ID: "main", Module: searchedModule, Package: searchedModule + "/cmd/tool", Symbol: "main"},
			{ID: "entry", Module: searchedModule, Package: searchedModule, Symbol: "Serve", IsExportedAPI: true},
			{ID: "vuln", Module: searchedModule, Package: searchedModule, Symbol: "vulnerable"},
			{ID: "testmain", Module: searchedModule, Package: searchedModule + ".test", Symbol: "main"},
		},
	}
	if withDispatchTarget {
		proj.Nodes = append(proj.Nodes,
			ports.CallGraphNode{ID: "callback", Module: searchedModule, Package: searchedModule, Symbol: "onEvent"})
		proj.Edges = append(proj.Edges, ports.CallGraphEdge{FromID: "callback", ToID: "vuln"})
	}
	return proj
}

// TestSearchNegative_ApplicationRootedNegativeCanBeConfirmed is the headline.
//
// Before this, the search over an application's graph was rooted at every owned
// node, so the vulnerable symbol was itself a root, every search found it in
// zero hops, and the strongest rung of the ladder could not be produced for any
// record anywhere. Measured on a working store at the time: 37 negatives, every
// one inferred, zero confirmed.
func TestSearchNegative_ApplicationRootedNegativeCanBeConfirmed(t *testing.T) {
	loader := &countingLoader{projection: applicationGraph("BUILT_WITH_BODIES", false)}
	rec := searchedRecord(domain.TargetRootedAt(coordinatetest.MustNew(searchedModule, "v1.0.0")), []string{"vulnerable"})

	reachability.NewNegativeSearcher(loader).Search(t.Context(), &rec)

	got, reason := domain.NegativeSoundness(rec.Findings[0])
	if got != domain.SoundnessConfirmed {
		t.Errorf("a clean search over an application-rooted graph -> %s, want %s (%s)", got, domain.SoundnessConfirmed, reason)
	}
	if !strings.Contains(reason, "entry point") {
		t.Errorf("the rung does not name the root set it was made against: %q", reason)
	}
	if !strings.Contains(reason, "Application") {
		t.Errorf("the rung does not name the rooting the graph was classified for: %q", reason)
	}
	if s := rec.Findings[0].NegativeSearch; s == nil || s.EntryPointRoots != 2 {
		t.Errorf("entry-point roots = %v, want the command's main and the exported API", s)
	}
}

// TestSearchNegative_WholeGraphReachIsStatedAndDoesNotDecide is the other half of
// the ticket's decision: the two rootings are different claims, and the one that
// cannot establish an absence does not get to veto one. The route it found is
// still reported — a route this tool found and did not publish is the one
// outcome a reachability surface must not produce.
func TestSearchNegative_WholeGraphReachIsStatedAndDoesNotDecide(t *testing.T) {
	loader := &countingLoader{projection: applicationGraph("BUILT_WITH_BODIES", true)}
	rec := searchedRecord(domain.TargetRootedAt(coordinatetest.MustNew(searchedModule, "v1.0.0")), []string{"vulnerable"})

	reachability.NewNegativeSearcher(loader).Search(t.Context(), &rec)

	s := rec.Findings[0].NegativeSearch
	if s == nil {
		t.Fatal("no search ran")
	}
	if s.PathFound {
		t.Error("a path was found from an entry point, but nothing the analysis can name reaches the symbol")
	}
	if !s.ShippedCodePathFound {
		t.Fatal("the whole-graph search found nothing; this test no longer measures the disagreement")
	}
	got, reason := domain.NegativeSoundness(rec.Findings[0])
	if got != domain.SoundnessConfirmed {
		t.Errorf("soundness = %s, want %s: the whole-graph claim must not decide the rung", got, domain.SoundnessConfirmed)
	}
	if !strings.Contains(reason, "DOES reach") {
		t.Errorf("the whole-graph route was found and not reported: %q", reason)
	}
}

// TestSearchNegative_EntryPointReachIsDisputed is the control on the other side:
// where the vulnerable symbol IS reachable from something a consumer can enter,
// the search contradicts the negative and says so. Nothing here may quietly
// become a confirmed absence.
func TestSearchNegative_EntryPointReachIsDisputed(t *testing.T) {
	graph := applicationGraph("BUILT_WITH_BODIES", false)
	graph.Edges = append(graph.Edges, ports.CallGraphEdge{FromID: "entry", ToID: "vuln"})
	loader := &countingLoader{projection: graph}
	rec := searchedRecord(domain.TargetRootedAt(coordinatetest.MustNew(searchedModule, "v1.0.0")), []string{"vulnerable"})

	reachability.NewNegativeSearcher(loader).Search(t.Context(), &rec)

	got, reason := domain.NegativeSoundness(rec.Findings[0])
	if got != domain.SoundnessDisputed {
		t.Errorf("a path from the exported API -> %s, want %s (%s)", got, domain.SoundnessDisputed, reason)
	}
}

// TestSearchNegative_NoNamedEntryPointConfirmsNothing pins the refusal. A graph
// offering no way in cannot certify an absence: the search starts nowhere, so of
// course it finds nothing, and reading that as evidence is the false negative
// the count exists to prevent.
func TestSearchNegative_NoNamedEntryPointConfirmsNothing(t *testing.T) {
	graph := ports.CallGraphProjection{
		Completeness: "BUILT_WITH_BODIES",
		ArtifactKind: "Application",
		Nodes: []ports.CallGraphNode{
			{ID: "helper", Module: searchedModule, Package: searchedModule, Symbol: "helper"},
			{ID: "vuln", Module: searchedModule, Package: searchedModule, Symbol: "vulnerable"},
		},
	}
	loader := &countingLoader{projection: graph}
	rec := searchedRecord(domain.TargetRootedAt(coordinatetest.MustNew(searchedModule, "v1.0.0")), []string{"vulnerable"})

	reachability.NewNegativeSearcher(loader).Search(t.Context(), &rec)

	if s := rec.Findings[0].NegativeSearch; s == nil || s.EntryPointRoots != 0 {
		t.Fatalf("entry-point roots = %v, want 0; this test no longer measures the refusal", s)
	}
	got, reason := domain.NegativeSoundness(rec.Findings[0])
	if got == domain.SoundnessConfirmed {
		t.Errorf("a search from no entry point at all confirmed a negative: %q", reason)
	}
	if got != domain.SoundnessInferred {
		t.Errorf("soundness = %s, want the recorded rung %s to stand", got, domain.SoundnessInferred)
	}
}

// TestSearchNegative_SyntheticTestMainDoesNotRootTheConfirmingSearch asserts the
// hygiene through the searcher, separately from the main change. The go command
// synthesises this main to run a test binary; rooting at it would let a
// test-only reach contradict a negative about a consumer's build.
func TestSearchNegative_SyntheticTestMainDoesNotRootTheConfirmingSearch(t *testing.T) {
	graph := applicationGraph("BUILT_WITH_BODIES", false)
	graph.Edges = append(graph.Edges, ports.CallGraphEdge{FromID: "testmain", ToID: "vuln"})
	loader := &countingLoader{projection: graph}
	rec := searchedRecord(domain.TargetRootedAt(coordinatetest.MustNew(searchedModule, "v1.0.0")), []string{"vulnerable"})

	reachability.NewNegativeSearcher(loader).Search(t.Context(), &rec)

	s := rec.Findings[0].NegativeSearch
	if s == nil {
		t.Fatal("no search ran")
	}
	if s.PathFound {
		t.Errorf("the synthesised test main rooted the confirming search: %s", s.Route.String())
	}
	if got, reason := domain.NegativeSoundness(rec.Findings[0]); got != domain.SoundnessConfirmed {
		t.Errorf("soundness = %s, want %s (%s)", got, domain.SoundnessConfirmed, reason)
	}
}

// TestSearchNegative_TheGraphsKindReachesTheAnswer is the read-surface half of
// the acceptance at this layer: the dimension that decides the rooting must
// travel with the answer, so a reader can see which rooting produced it.
func TestSearchNegative_TheGraphsKindReachesTheAnswer(t *testing.T) {
	for kind, want := range map[string]string{"Application": "Application", "": "Library", "NotEstablished": "NotEstablished"} {
		graph := applicationGraph("BUILT_WITH_BODIES", false)
		graph.ArtifactKind = kind
		loader := &countingLoader{projection: graph}
		rec := searchedRecord(domain.TargetRootedAt(coordinatetest.MustNew(searchedModule, "v1.0.0")), []string{"vulnerable"})

		reachability.NewNegativeSearcher(loader).Search(t.Context(), &rec)

		s := rec.Findings[0].NegativeSearch
		if s == nil {
			t.Fatalf("kind %q: no search ran", kind)
		}
		if s.ArtifactKind != want {
			t.Errorf("kind %q reached the answer as %q, want %q", kind, s.ArtifactKind, want)
		}
	}
}
