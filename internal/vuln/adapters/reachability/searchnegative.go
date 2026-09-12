package reachability

import (
	"context"
	"errors"
	"strings"
	"sync"

	"github.com/eitanity/kanonarion/internal/coordinate"

	callgraphdomain "github.com/eitanity/kanonarion/internal/callgraph/domain"

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
// It uses the same target matching and the same traversal as Analyse, so a
// read-time search and a scan-time one cannot drift into different answers. It
// roots TWICE, which is the one place the two deliberately differ: Analyse asks
// what the shipped code can run and roots the whole graph for an application,
// and an absence cannot be certified against a root set the target is a member
// of. The confirming search is therefore rooted at the entry points the
// analysis can name — see callgraphdomain.SelectEntryPointRoots — and the
// whole-graph result is carried beside it rather than dropped.
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
	projection ports.CallGraphProjection
	// shippedRoots is the whole-graph rule Analyse uses — for an application,
	// every owned node. A path from it says the module's shipped code reaches the
	// symbol from somewhere; it cannot say an absence, because the target is
	// itself one of the roots.
	shippedRoots []string
	// entryRoots is what the analysis can name as entered from outside. It is the
	// root set an absence is certified against, and it is empty when the graph
	// offers none — in which case nothing is certified.
	entryRoots []string
	loaded     bool
	// loadErr is why the load failed, kept so the refusal a reader is shown names
	// the cause rather than asserting the commonest one.
	loadErr error
}

// NewNegativeSearcher returns a searcher reading graphs through loader. A nil
// loader disables it: every Search then leaves the record exactly as stored.
func NewNegativeSearcher(loader ports.CallGraphLoader) *NegativeSearcher {
	return &NegativeSearcher{loader: loader, cache: make(map[coordinate.ModuleCoordinate]*cachedProjection)}
}

// Search attaches a domain.NegativeSearch to every finding in rec whose negative
// this search can speak to, leaving every other field untouched.
//
// A search that CANNOT be made attaches one too, carrying the reason and nothing
// else. It used to attach nothing at all, and that silence was the defect: a
// graph that would not load, a graph naming none of the advisory's symbols and a
// graph with no entry point all left the finding looking exactly like a
// coordinate the search had never been asked about. Measured on a working store,
// on the one coordinate holding both a searchable negative and a call graph: the
// answer carried no search, no reason and no remedy, and the rung beside it said
// only that govulncheck had been silent.
//
// What has not changed is what a failure may CONCLUDE, which is nothing. The
// recorded derivation still earns the rung in every one of these cases. The one
// thing that must never happen is an absent or unusable graph being reported as
// a confirmed negative, and a reason field cannot become one.
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
		if !graph.loaded {
			f.NegativeSearch = &domain.NegativeSearch{NotSearched: graph.loadRefusal(rec.Coordinate)}
			continue
		}
		if len(graph.shippedRoots) == 0 {
			f.NegativeSearch = &domain.NegativeSearch{
				ArtifactKind: graph.kind(),
				NotSearched: "the stored call graph for " + rec.Coordinate.String() +
					" holds no node this module owns, so there is nothing in it to traverse from",
			}
			continue
		}
		targets := buildTargetSet(graph.projection, symbolRefsFor(rec.Coordinate, f.AffectedSymbols))
		if len(targets) == 0 {
			// The graph holds none of the symbols the advisory named. That is not a
			// search that came back empty — there was nothing here to look for — and
			// reporting it as one would confirm a negative out of a mismatch between
			// the graph and the advisory. It is now SAID rather than passed over: a
			// mismatch between the two is a fact about this pair of records, and the
			// reader is the only one who can tell whether the advisory names a symbol
			// this version never had or the graph was built without it.
			f.NegativeSearch = &domain.NegativeSearch{
				ArtifactKind: graph.kind(),
				Fidelity:     graph.projection.Completeness,
				NotSearched: "the stored call graph for " + rec.Coordinate.String() +
					" holds none of the symbols the advisory names (" + strings.Join(f.AffectedSymbols, ", ") +
					"), so there was nothing in it to search for",
			}
			continue
		}
		result := &domain.NegativeSearch{
			Fidelity: graph.projection.Completeness,
			// How many entry points the graph offered. Zero is what stops an
			// absence being certified over a graph that named none, and it is
			// carried rather than inferred from an empty route: "searched from
			// nothing and found nothing" and "searched from real entry points and
			// found nothing" are the two answers that must never look alike.
			EntryPointRoots: len(graph.entryRoots),
			// Named, not raw: a library's stored kind is the empty string, and the
			// reason string must not read as though the graph said nothing.
			ArtifactKind: graph.kind(),
			// The stored graph is a graph of the module's own build. It therefore
			// speaks in the record's own frame exactly when that frame is rooted at
			// this very module — the project's own scan of itself — and speaks about
			// a different build when the record was measured inside a consumer's.
			// domain.NegativeSearch.InRecordedFrame says what each case may mean.
			InRecordedFrame: rec.Rooting.IsRootedAtPath(rec.Coordinate.Path()),
		}
		// Two searches over one graph, because they are two claims. The
		// entry-point search is the one that may confirm or contradict the
		// negative; the whole-graph search is what the shipped code does, kept so
		// a route this tool found is never dropped.
		if path := bfsPath(graph.projection, graph.entryRoots, targets); path != nil {
			result.PathFound = true
			result.Route = routeFrom(graph.projection, path)
		}
		if path := bfsPath(graph.projection, graph.shippedRoots, targets); path != nil {
			result.ShippedCodePathFound = true
			result.ShippedCodeRoute = routeFrom(graph.projection, path)
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

// loadRefusal names why the graph could not be loaded, in the terms the reader
// can act on: the store either holds no record for the coordinate — which a
// command fixes — or refused the one it holds, which is a different problem.
func (c *cachedProjection) loadRefusal(coord coordinate.ModuleCoordinate) string {
	if errors.Is(c.loadErr, ports.ErrCallGraphNotFound) {
		return "the store holds no call graph for " + coord.String() +
			", so there was no graph to search; extract one with: kanonarion callgraph " + coord.String()
	}
	if c.loadErr != nil {
		return "the stored call graph for " + coord.String() + " could not be read: " + c.loadErr.Error()
	}
	return "no call graph was loaded for " + coord.String()
}

// kind names the artefact kind of the loaded graph, and "" when none loaded.
func (c *cachedProjection) kind() string {
	if !c.loaded {
		return ""
	}
	return callgraphdomain.ArtifactKind(c.projection.ArtifactKind).String()
}

// graphFor loads and memoises the projection for coord, along with both root
// sets selected over it — each selection walks every node, so they are computed
// once per graph rather than once per finding.
func (s *NegativeSearcher) graphFor(ctx context.Context, coord coordinate.ModuleCoordinate) *cachedProjection {
	s.mu.Lock()
	defer s.mu.Unlock()
	if cached, ok := s.cache[coord]; ok {
		return cached
	}
	entry := &cachedProjection{}
	proj, err := s.loader.Load(ctx, coord)
	if err != nil {
		entry.loadErr = err
	} else {
		entry.projection = proj
		entry.shippedRoots = collectEntryPoints(proj)
		entry.entryRoots = collectNamedEntryPoints(proj)
		entry.loaded = true
	}
	s.cache[coord] = entry
	return entry
}
