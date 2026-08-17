package reachability

import (
	"context"
	"sync"

	"github.com/eitanity/kanonarion/internal/coordinate"

	"github.com/eitanity/kanonarion/internal/vuln/domain"
	"github.com/eitanity/kanonarion/internal/vuln/ports"
)

// NegativeSearcher runs this package's own call-graph search over the negatives
// a stored record already holds, at READ time.
//
// A negative stamped from another analyser's silence can never be confirmed, and
// rule 4 of domain.NegativeSoundness is right to refuse it: an analyser that
// emits findings for what it reached says nothing by not mentioning a module.
// The search that WOULD answer needs only a coordinate, the symbols the advisory
// named and a stored call graph — all three of which a stored record and the
// call-graph ledger already hold — so it is run here rather than at scan time.
// Nothing is written and no record changes shape; see domain.NegativeSearch.
//
// It uses the same target matching, the same root selection and the same
// traversal as Analyse, so a read-time search and a scan-time one cannot drift
// into different answers.
//
// Cost is one call-graph decode per coordinate that has a negative worth
// searching, memoised for the life of the searcher, and exactly zero for a
// record with none: the graph is loaded only after a finding has asked for it.
type NegativeSearcher struct {
	loader ports.CallGraphLoader

	mu    sync.Mutex
	cache map[coordinate.ModuleCoordinate]*cachedProjection
}

// cachedProjection is one coordinate's loaded graph, or the recorded fact that
// none could be loaded. The negative case is cached too: a coordinate with no
// graph is the common case, and re-asking the store for each of its findings
// would pay the miss over and over.
type cachedProjection struct {
	projection  ports.CallGraphProjection
	entryPoints []string
	loaded      bool
}

// NewNegativeSearcher returns a searcher reading graphs through loader. A nil
// loader disables it: every Search then leaves the record exactly as stored.
func NewNegativeSearcher(loader ports.CallGraphLoader) *NegativeSearcher {
	return &NegativeSearcher{loader: loader, cache: make(map[coordinate.ModuleCoordinate]*cachedProjection)}
}

// Search attaches a domain.NegativeSearch to every finding in rec whose negative
// this search can speak to, leaving every other field untouched.
//
// It is deliberately silent on failure. A graph that cannot be loaded, a graph
// that names none of the advisory's symbols and a graph with no entry points all
// leave the finding as stored, which reads at the rung the recorded derivation
// earns. The one thing that must never happen is an absent or unusable graph
// being reported as a confirmed negative, and leaving the finding alone is what
// guarantees it.
func (s *NegativeSearcher) Search(ctx context.Context, rec *domain.VulnerabilityRecord) {
	if s == nil || s.loader == nil || rec == nil {
		return
	}
	var graph *cachedProjection
	for i := range rec.Findings {
		f := &rec.Findings[i]
		if !searchableNegative(*f) {
			continue
		}
		if graph == nil {
			graph = s.graphFor(ctx, rec.Coordinate)
		}
		if !graph.loaded || len(graph.entryPoints) == 0 {
			return
		}
		targets := buildTargetSet(graph.projection, symbolRefsFor(rec.Coordinate, f.AffectedSymbols))
		if len(targets) == 0 {
			// The graph holds none of the symbols the advisory named. That is not a
			// search that came back empty — there was nothing here to look for — and
			// reporting it as one would confirm a negative out of a mismatch between
			// the graph and the advisory.
			continue
		}
		result := &domain.NegativeSearch{
			Fidelity: graph.projection.Completeness,
			// The stored graph is a graph of the module's own build. It therefore
			// speaks in the record's own frame exactly when that frame is rooted at
			// this very module — the project's own scan of itself — and speaks about
			// a different build when the record was measured inside a consumer's.
			// domain.NegativeSearch.InRecordedFrame says what each case may mean.
			InRecordedFrame: rec.Rooting.IsRootedAtPath(rec.Coordinate.Path()),
		}
		if path := bfsPath(graph.projection, graph.entryPoints, targets); path != nil {
			result.PathFound = true
			result.Route = routeFrom(graph.projection, path)
		}
		f.NegativeSearch = result
	}
}

// searchableNegative reports whether this finding's negative is one the search
// may speak to.
//
// It is narrow on purpose. A reachable finding carries its own route; a negative
// against an advisory that named no symbols is unsearchable at any fidelity and
// must keep saying so; and a negative that ALREADY came from a call-graph search
// is not re-derived, because re-running it would only restate what the record
// says. What is left is the case this exists for: a negative read off an
// analyser's silence.
func searchableNegative(f domain.VulnerabilityFinding) bool {
	return f.Reachable != nil &&
		!f.Reachable.IsReachable &&
		!f.AdvisoryNamesNoSymbols &&
		len(f.AffectedSymbols) > 0 &&
		f.NegativeSearch == nil &&
		f.Reachable.DerivedBy.Analyser == domain.AnalyserGovulncheck
}

// symbolRefsFor scopes the advisory's short symbol names to the record's own
// module, on the same terms as the scan-time conversion: the advisory names
// symbols of the module it is filed against, and an unscoped name would match a
// same-named symbol in any module the graph holds.
func symbolRefsFor(coord coordinate.ModuleCoordinate, symbols []string) []ports.SymbolReference {
	refs := make([]ports.SymbolReference, 0, len(symbols))
	for _, sym := range symbols {
		refs = append(refs, ports.SymbolReference{Module: coord.Path(), Symbol: sym})
	}
	return refs
}

// graphFor loads and memoises the projection for coord, along with the entry
// points selected over it — the selection walks every node, so it is computed
// once per graph rather than once per finding.
func (s *NegativeSearcher) graphFor(ctx context.Context, coord coordinate.ModuleCoordinate) *cachedProjection {
	s.mu.Lock()
	defer s.mu.Unlock()
	if cached, ok := s.cache[coord]; ok {
		return cached
	}
	entry := &cachedProjection{}
	if proj, err := s.loader.Load(ctx, coord); err == nil {
		entry.projection = proj
		entry.entryPoints = collectEntryPoints(proj)
		entry.loaded = true
	}
	s.cache[coord] = entry
	return entry
}
