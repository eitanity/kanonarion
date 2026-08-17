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
	loader := &countingLoader{err: errors.New("no call graph record")}
	rec := searchedRecord(domain.TargetRootedAt(coordinatetest.MustNew(searchedModule, "v1.0.0")), []string{"vulnerable"})
	wantRung, wantReason := domain.NegativeSoundness(rec.Findings[0])

	reachability.NewNegativeSearcher(loader).Search(t.Context(), &rec)

	got, reason := domain.NegativeSoundness(rec.Findings[0])
	if got != domain.SoundnessInferred || got != wantRung || reason != wantReason {
		t.Errorf("with no graph -> %s %q, want the unchanged %s %q", got, reason, wantRung, wantReason)
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
