package reachability

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
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
	// dirs answers where a frame's working tree is, for the refusal that has to
	// name the command analysing it. Optional: without one a refusal says it
	// cannot name the tree rather than naming the wrong one.
	dirs ports.WalkProjectDirReader

	mu    sync.Mutex
	cache map[graphKey]*cachedProjection
}

// WithProjectDirs gives the searcher the walk ledger's record of where a
// project-rooted frame's tree is, so a refusal about that frame names a command
// instead of a sentence. It returns the receiver for chaining, on the same
// terms as every other optional dependency in this repository.
func (s *NegativeSearcher) WithProjectDirs(r ports.WalkProjectDirReader) *NegativeSearcher {
	if s != nil {
		s.dirs = r
	}
	return s
}

// graphKey identifies one loaded-and-rooted graph. The frame is part of it
// because the standard library's search is a JOIN: the graph searched for
// stdlib@v1.26.5 inside one project is not the graph searched for it inside
// another, and a cache keyed on the coordinate alone would serve the first
// project's build as the second's answer.
type graphKey struct {
	coord coordinate.ModuleCoordinate
	frame string
	// walk is the run the record came from. It is part of the key because the
	// tree a refusal names is read off that walk: two walks of one project at
	// two checkouts are two answers, and a cache that could not tell them apart
	// would name the first project's directory in the second's refusal.
	walk string
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
	// reflectSites is every reflective dispatch site in the graph, each already
	// told whether the entry-point roots reach it. It is computed once per graph
	// beside the root sets, for the same reason they are: the reachable set costs
	// one walk of the graph, and a record can hold many findings.
	reflectSites []domain.ReflectiveDispatchSite
	loaded       bool
	// loadErr is why the load failed, kept so the refusal a reader is shown names
	// the cause rather than asserting the commonest one.
	loadErr error
	// missing is the coordinate the failed load was for. On a joined search two
	// graphs are loaded, so a refusal that named the record's own coordinate
	// would send the reader after the wrong one.
	missing coordinate.ModuleCoordinate
	// searched names the stored records this graph is made of, so an answer says
	// what it was derived from rather than leaving the reader to guess which
	// generation answered.
	searched []string
	// joined says the graph is a consumer's build with the standard library's own
	// graph attached at its external leaves. Such a graph IS the record's frame,
	// which is what lets a path found in it contradict the recorded negative.
	joined bool
	// subject is the coordinate the targets are looked for in — the record's own.
	subject coordinate.ModuleCoordinate
	// analysisRoot is the working tree the missing graph would be taken of, when
	// anything in the store names one. Empty is "not known", never a guess.
	analysisRoot string
	// notSearched is a refusal that is not a load failure: the graphs loaded and
	// the search still could not be made soundly. It is kept apart from loadErr
	// so the reason a reader sees names what actually stopped the search.
	notSearched string
	// notJoined is why a record measured in another build was searched over the
	// coordinate's own graph instead, with the command that lets the join run.
	notJoined string
	// fallback is a joined dependency's own graph. It names a symbol the join
	// dropped as not linked, and it answers where the join cannot certify.
	fallback *cachedProjection
	// unjoinedCalls is every external leaf of the consumer's graph the entry
	// points reach that the join did not replace, outside the standard library:
	// a call into a module whose graph is not held here.
	unjoinedCalls []string
}

// NewNegativeSearcher returns a searcher reading graphs through loader. A nil
// loader disables it: every Search then leaves the record exactly as stored.
func NewNegativeSearcher(loader ports.CallGraphLoader) *NegativeSearcher {
	return &NegativeSearcher{loader: loader, cache: make(map[graphKey]*cachedProjection)}
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
			graph = s.graphForRecord(ctx, rec)
		}
		result := graph.search(rec, *f)
		if graph.fallback != nil && len(graph.unjoinedCalls) > 0 && result.NotSearched == "" && !result.PathFound {
			// The join stops at calls into modules whose graphs it does not hold, so
			// a clean search over it cannot show the symbol is not reached through
			// them. The dependency's own graph is searched instead, as before.
			result = graph.fallback.search(rec, *f)
			result.NotJoined = "the search from the entry points of the build this record was measured in found no path, " +
				"but it reached " + plural(len(graph.unjoinedCalls), "call") + " into modules whose call graphs are not joined (" +
				strings.Join(firstN(graph.unjoinedCalls, 3), ", ") + "), so it cannot show the vulnerable code is not reached " +
				"through them; no command joins them, so the search ran over the own graph of " + rec.Coordinate.String() + " instead"
		}
		f.NegativeSearch = result
	}
}

// search runs the negative search for one finding over this graph, or states
// why it could not be made.
func (c *cachedProjection) search(rec *domain.VulnerabilityRecord, f domain.VulnerabilityFinding) *domain.NegativeSearch {
	if !c.loaded {
		return &domain.NegativeSearch{NotSearched: c.loadRefusal()}
	}
	if len(c.shippedRoots) == 0 {
		return &domain.NegativeSearch{
			ArtifactKind: c.kind(),
			NotSearched: "the stored call graph for " + rec.Coordinate.String() +
				" holds no node this module owns, so there is nothing in it to traverse from",
			NotJoined: c.notJoined,
		}
	}
	refs := symbolRefsFor(rec.Coordinate, f.AffectedPackages, f.AffectedSymbols)
	targets := buildTargetSet(c.projection, refs)
	if len(targets) == 0 && c.fallback != nil && len(buildTargetSet(c.fallback.projection, refs)) > 0 {
		// The dependency's graph holds the symbols, in packages the build does
		// not link. govulncheck's negative stands; the reason is stated.
		return &domain.NegativeSearch{
			ArtifactKind: c.kind(),
			Fidelity:     c.projection.Completeness,
			NotSearched: "the build this record was measured in links none of the packages of " +
				rec.Coordinate.String() + " that hold the symbols the advisory names (" +
				strings.Join(f.AffectedSymbols, ", ") + "), so the joined graph holds nothing to search for",
		}
	}
	if len(targets) == 0 {
		// The graph holds none of the symbols the advisory named. That is not a
		// search that came back empty — there was nothing here to look for — and
		// reporting it as one would confirm a negative out of a mismatch between
		// the graph and the advisory. It is now SAID rather than passed over: a
		// mismatch between the two is a fact about this pair of records, and the
		// reader is the only one who can tell whether the advisory names a symbol
		// this version never had or the graph was built without it.
		return &domain.NegativeSearch{
			ArtifactKind: c.kind(),
			Fidelity:     c.projection.Completeness,
			NotSearched: "the stored call graph for " + rec.Coordinate.String() +
				" holds none of the symbols the advisory names (" + strings.Join(f.AffectedSymbols, ", ") +
				"), so there was nothing in it to search for",
			NotJoined: c.notJoined,
		}
	}
	result := &domain.NegativeSearch{
		Fidelity: c.projection.Completeness,
		// How many entry points the graph offered. Zero is what stops an
		// absence being certified over a graph that named none, and it is
		// carried rather than inferred from an empty route: "searched from
		// nothing and found nothing" and "searched from real entry points and
		// found nothing" are the two answers that must never look alike.
		EntryPointRoots: len(c.entryRoots),
		// Named, not raw: a library's stored kind is the empty string, and the
		// reason string must not read as though the graph said nothing.
		ArtifactKind: c.kind(),
		// The stored graph is a graph of the module's own build. It therefore
		// speaks in the record's own frame exactly when that frame is rooted at
		// this very module — the project's own scan of itself — and speaks about
		// a different build when the record was measured inside a consumer's.
		// domain.NegativeSearch.InRecordedFrame says what each case may mean.
		InRecordedFrame: c.joined || rec.Rooting.IsRootedAtPath(rec.Coordinate.Path()),
		// Which stored records the traversal ran over. A joined search reads two
		// of them, and an answer that named neither would leave the reader
		// unable to check it or to see that the standard library's own graph was
		// what made the rung possible.
		GraphsSearched: c.searched,
		// What the traversal below could NOT follow. It is the same list for
		// every finding over this graph, because it is a property of the graph
		// rather than of the advisory, and it is stated even when empty: empty
		// here means the search looked and found none, which is a different
		// fact from the search never having run.
		ReflectiveDispatch: c.reflectSites,
		NotJoined:          c.notJoined,
	}
	// Two searches over one graph, because they are two claims. The
	// entry-point search is the one that may confirm or contradict the
	// negative; the whole-graph search is what the shipped code does, kept so
	// a route this tool found is never dropped.
	if path := bfsPath(c.projection, c.entryRoots, targets); path != nil {
		result.PathFound = true
		result.Route = routeFrom(c.projection, path)
	}
	if path := bfsPath(c.projection, c.shippedRoots, targets); path != nil {
		result.ShippedCodePathFound = true
		result.ShippedCodeRoute = routeFrom(c.projection, path)
	}
	return result
}

// reflectiveDispatchSites renders the graph's reflective dispatch sites for a
// reader, each told whether the named entry points reach its CALLER.
//
// The reachable set is what separates a site worth reporting from one that only
// makes a negative look weaker. A reflective call in code no entry point reaches
// cannot be on a route into this module, so it qualifies nothing — and on the
// store this was measured against, every site there is is of that kind: two
// calls in a test-harness package, neither reachable from anything the analysis
// can name.
//
// The graph walk is skipped entirely where there are no sites, which is the
// common case. Nothing is computed for a graph with none.
func reflectiveDispatchSites(proj ports.CallGraphProjection, entryRoots []string) []domain.ReflectiveDispatchSite {
	if len(proj.ReflectiveDispatch) == 0 {
		return nil
	}
	reached := reachableFrom(proj, entryRoots)
	sites := make([]domain.ReflectiveDispatchSite, 0, len(proj.ReflectiveDispatch))
	for _, s := range proj.ReflectiveDispatch {
		sites = append(sites, domain.ReflectiveDispatchSite{
			Caller:                  s.CallerID,
			Callee:                  s.CalleeID,
			CallSite:                reflectSitePosition(s),
			ReachableFromEntryPoint: reached[s.CallerID],
		})
	}
	// Sorted on every field that distinguishes two sites, not on the caller
	// alone: two calls from one function to one reflect method differ only in
	// their line, and a sort that cannot tell them apart leaves their order to
	// whatever the store happened to return.
	sort.Slice(sites, func(i, j int) bool {
		a, b := sites[i], sites[j]
		if a.Caller != b.Caller {
			return a.Caller < b.Caller
		}
		if a.Callee != b.Callee {
			return a.Callee < b.Callee
		}
		return a.CallSite < b.CallSite
	})
	return sites
}

// reflectSitePosition renders a site's position the way a hop renders its call
// site: "file:line", the file alone where no line was recorded, and empty where
// the edge carried no position at all.
func reflectSitePosition(s ports.CallGraphReflectSite) string {
	if s.File == "" {
		return ""
	}
	if s.Line == 0 {
		return s.File
	}
	return s.File + ":" + strconv.Itoa(s.Line)
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
// module, and to the PACKAGES the advisory names them in where it names any.
//
// The module scope is the scan-time rule: the advisory names symbols of the
// module it is filed against, and an unscoped name would match a same-named
// symbol in any module the graph holds. The package scope is the same rule one
// level down, and it is what the standard library forced: "stdlib" is one
// coordinate spanning 362 packages, so an advisory about encoding/xml's
// Decoder.Decode matched encoding/json's, encoding/gob's and encoding/asn1's
// too — and a search told to look for all four reported a route to a package
// the advisory is not about.
//
// NARROWING a target set is the direction that makes a negative easier to
// confirm, so it is only legitimate because the advisory itself states the
// packages: a same-named symbol in another package is not the vulnerable
// symbol. Where the finding names none — every record written before the field
// existed — nothing is narrowed and the search behaves exactly as it did.
func symbolRefsFor(coord coordinate.ModuleCoordinate, packages, symbols []string) []ports.SymbolReference {
	if len(packages) == 0 {
		refs := make([]ports.SymbolReference, 0, len(symbols))
		for _, sym := range symbols {
			refs = append(refs, ports.SymbolReference{Module: coord.Path(), Symbol: sym})
		}
		return refs
	}
	refs := make([]ports.SymbolReference, 0, len(symbols)*len(packages))
	for _, sym := range symbols {
		for _, pkg := range packages {
			refs = append(refs, ports.SymbolReference{Module: coord.Path(), Package: pkg, Symbol: sym})
		}
	}
	return refs
}

// loadRefusal names why the graph could not be loaded, in the terms the reader
// can act on: the store either holds no record for the coordinate — which a
// command fixes — or refused the one it holds, which is a different problem.
func (c *cachedProjection) loadRefusal() string {
	if c.notSearched != "" {
		return c.notSearched
	}
	coord := c.missing
	if errors.Is(c.loadErr, ports.ErrCallGraphNotFound) {
		// The remedy comes from the call-graph domain rather than being spelled
		// here, so a coordinate the `callgraph` command cannot take — a working
		// tree, and until this ledger existed the standard library — is told to run
		// the command that does analyse it. A remedy that cannot run costs the
		// reader exactly the round trip it existed to save.
		return "the store holds no call graph for " + coord.String() +
			", so there was no graph to search" +
			remedyClause("extract one with", coord, c.analysisRoot, false)
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
	key := graphKey{coord: coord}
	if cached, ok := s.cache[key]; ok {
		return cached
	}
	entry := &cachedProjection{missing: coord, subject: coord}
	proj, err := s.loader.Load(ctx, coord)
	if err != nil {
		entry.loadErr = err
	} else {
		entry = ownGraph(coord, proj)
	}
	s.cache[key] = entry
	return entry
}

// ownGraph is coord's own stored graph, rooted at its own entry points.
func ownGraph(coord coordinate.ModuleCoordinate, proj ports.CallGraphProjection) *cachedProjection {
	entry := &cachedProjection{missing: coord, subject: coord, projection: proj, loaded: true}
	entry.shippedRoots = collectEntryPoints(proj)
	entry.entryRoots = collectNamedEntryPoints(proj)
	entry.reflectSites = reflectiveDispatchSites(proj, entry.entryRoots)
	entry.searched = []string{graphLabel(coord, proj)}
	return entry
}

// graphForRecord picks the graph a record's negatives are searched over.
//
// A record measured inside another build — the project that depends on this
// coordinate — is searched over that build's own graph joined to this
// coordinate's. The coordinate's graph alone is rooted at its own exported API,
// where almost every symbol an advisory names is a root and is reached in zero
// hops whatever the build does: it answers a question nobody asked. The
// coordinate's own graph is searched only when the record names no other frame.
func (s *NegativeSearcher) graphForRecord(ctx context.Context, rec *domain.VulnerabilityRecord) *cachedProjection {
	target := rec.Rooting.RootTarget()
	if target == "" || (!rec.Coordinate.IsStdlib() && rec.Rooting.IsRootedAtPath(rec.Coordinate.Path())) {
		// No other build is named, so there is nothing to join. The entry-point
		// rooting of the coordinate's own graph is what stops it confirming
		// anything out of a root set made of the vulnerable symbols themselves.
		return s.graphFor(ctx, rec.Coordinate)
	}
	return s.joinedGraphFor(ctx, rec.Coordinate, target, rec.WalkID)
}

// joinRule is what differs between joining the standard library's graph and a
// dependency's: which closure of the frame's build restricts it, and how a
// refusal and an answer name it.
type joinRule struct {
	// negative and subjectGraphs name the join in a refusal's opening clause.
	negative      string
	subjectGraphs string
	// subjectRole says what the missing subject graph is to the build.
	subjectRole string
	// closureNoun names the frame's recorded closure.
	closureNoun string
	closure     func(ports.CallGraphProjection) []string
	// keepUnlinked keeps the subject's nodes outside the closure, reached by no
	// edge. The standard library keeps them so a symbol is still found to exist
	// at that toolchain; a dependency's graph is kept only within the closure.
	keepUnlinked bool
}

// joinRuleFor returns the rule for joining subject's graph to a frame's.
func joinRuleFor(subject coordinate.ModuleCoordinate) joinRule {
	if subject.IsStdlib() {
		return joinRule{
			negative:      "a standard-library negative",
			subjectGraphs: "the standard library's",
			subjectRole:   "the standard library this build links",
			closureNoun:   "standard-library packages",
			closure:       func(p ports.CallGraphProjection) []string { return p.StdlibPackages },
			keepUnlinked:  true,
		}
	}
	return joinRule{
		negative:      "a dependency's negative",
		subjectGraphs: "the dependency's",
		subjectRole:   "the dependency this record is about",
		closureNoun:   "packages of other modules",
		closure:       func(p ports.CallGraphProjection) []string { return p.DependencyPackages },
	}
}

// graphName is how a refusal names the subject's graph.
func (r joinRule) graphName(subject coordinate.ModuleCoordinate) string {
	if r.keepUnlinked {
		return "the standard library's own graph"
	}
	return "the own graph of " + subject.String()
}

// restrictedLabel is graphLabel for the subject's graph as the join uses it:
// an answer that did not say what was left out would overstate what was
// searched.
func (r joinRule) restrictedLabel(coord coordinate.ModuleCoordinate, proj ports.CallGraphProjection, linked int) string {
	how := "traversed only within"
	if !r.keepUnlinked {
		how = "kept only within"
	}
	return fmt.Sprintf("%s (%s, %d nodes, %d edges, %s the %d %s this build links)",
		coord, proj.Completeness, len(proj.Nodes), len(proj.Edges), how, linked, r.closureNoun)
}

// joinedGraphFor loads the frame's own call graph and subject's, and returns
// the one graph that is both.
//
// The join is by node identity and needs nothing else. A call-graph node is
// identified by its package path and symbol — "crypto/tls.(*Conn).Handshake" —
// so the leaf a consumer's graph records where it stops at another module is
// spelled exactly as that module's own graph spells the function. Replacing the
// leaf with the owned node both attaches its outgoing edges and makes it a
// legitimate target: buildTargetSet skips external nodes, so an advisory symbol
// that stayed a leaf could never be searched for.
//
// The ROOTS come from the consumer's graph alone. Rooting the joined graph
// would make every exported function of the subject an entry point, and the
// vulnerable symbol would be reached in zero hops from itself.
func (s *NegativeSearcher) joinedGraphFor(
	ctx context.Context,
	subject coordinate.ModuleCoordinate,
	frameTarget string,
	walkID string,
) *cachedProjection {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := graphKey{coord: subject, frame: frameTarget, walk: walkID}
	if cached, ok := s.cache[key]; ok {
		return cached
	}
	entry := &cachedProjection{subject: subject, missing: subject, joined: true}
	s.cache[key] = entry
	rule := joinRuleFor(subject)

	frameCoord, err := coordinate.ParseModuleCoordinate(frameTarget)
	if err != nil {
		entry.notSearched = "the frame this record was measured in, " + frameTarget +
			", is not a coordinate, so the build it names cannot be loaded: " + err.Error()
		return entry
	}
	consumer, consumerErr := s.loader.Load(ctx, frameCoord)
	own, ownErr := s.loader.Load(ctx, subject)
	// Where the frame's tree is, so a refusal about it names a command. The
	// graph's own analysis root is preferred — it is the tree that graph was
	// taken of — and the walk's recorded directory answers when no graph exists
	// to carry one.
	frameDir := consumer.AnalysisRoot
	if frameDir == "" {
		frameDir = s.projectDir(ctx, walkID)
	}
	if !subject.IsStdlib() && ownErr == nil && errors.Is(consumerErr, ports.ErrCallGraphNotFound) {
		// The project was never analysed, so the dependency's own graph is searched
		// as before, and the answer names the command that lets the join run.
		*entry = *ownGraph(subject, own)
		entry.notJoined = "the build this record was measured in, " + frameCoord.String() +
			", has no stored call graph, so the search ran over " + rule.graphName(subject) +
			" rather than from that build's entry points" +
			remedyClause("to search from them, analyse it with", frameCoord, frameDir, false)
		return entry
	}
	if why := joinLoadRefusal(rule, frameCoord, consumerErr, subject, ownErr, frameDir); why != "" {
		entry.notSearched = why
		return entry
	}
	linked := rule.closure(consumer)
	if len(linked) == 0 {
		// The frame's graph does not say which packages its build links, and
		// without that the join is not sound: a class-hierarchy graph resolves an
		// indirect call to every matching function it holds, so a traversal would
		// walk into packages the binary does not contain. Measured on this store:
		// softmagic-cli, which links none of net/http, net/url or crypto/tls,
		// reached net/url.(*URL).Parse through flag's default usage function.
		// --force, because a graph IS held: without it the re-run is served the very
		// record that cannot be joined.
		entry.notSearched = "the stored call graph of " + frameCoord.String() +
			" does not record which " + rule.closureNoun + " its build links, so " + rule.graphName(subject) +
			" cannot be joined to it without following calls into packages the binary does not contain" +
			remedyClause("re-analyse it with", frameCoord, frameDir, true)
		return entry
	}
	entry.projection = joinProjections(consumer, own, linked, rule.keepUnlinked)
	// Selected over the consumer's graph, never the joined one: see above.
	entry.shippedRoots = collectEntryPoints(consumer)
	entry.entryRoots = collectNamedEntryPoints(consumer)
	entry.reflectSites = reflectiveDispatchSites(entry.projection, entry.entryRoots)
	entry.searched = []string{
		graphLabel(frameCoord, consumer),
		rule.restrictedLabel(subject, own, len(linked)),
	}
	if !rule.keepUnlinked {
		entry.fallback = ownGraph(subject, own)
		entry.unjoinedCalls = unjoinedCalls(entry.projection, entry.entryRoots)
	}
	entry.loaded = true
	return entry
}

// joinProjections attaches subject's graph to a consumer's at the external
// leaves where the consumer's stops, restricted to the packages in linked.
//
// Completeness is the WEAKER of the two, because a path is only as good as its
// worst hop: a negative certified across a joined graph rests on both halves
// having been built with bodies.
//
// The artifact kind is the CONSUMER's, because the kind is what decides rooting
// and the roots are the consumer's.
func joinProjections(consumer, subject ports.CallGraphProjection, linked []string, keepUnlinked bool) ports.CallGraphProjection {
	inClosure := make(map[string]bool, len(linked))
	for _, pkg := range linked {
		inClosure[pkg] = true
	}
	pkgOf := make(map[string]string, len(subject.Nodes))
	for _, n := range subject.Nodes {
		pkgOf[n.ID] = n.Package
	}
	owned := make(map[string]bool, len(consumer.Nodes))
	for _, n := range consumer.Nodes {
		if !n.IsExternal {
			owned[n.ID] = true
		}
	}

	// The subject's own node replaces the consumer's leaf: it carries the module
	// attribution and exported-API axis measured rather than guessed from
	// outside. A node the consumer owns is never replaced.
	byID := make(map[string]bool, len(subject.Nodes))
	nodes := make([]ports.CallGraphNode, 0, len(consumer.Nodes)+len(subject.Nodes))
	for _, n := range subject.Nodes {
		if owned[n.ID] || (!keepUnlinked && !inBuild(inClosure, pkgOf, n.ID)) {
			continue
		}
		byID[n.ID] = true
		nodes = append(nodes, n)
	}
	for _, n := range consumer.Nodes {
		if byID[n.ID] {
			continue
		}
		nodes = append(nodes, n)
	}

	// An edge whose caller or callee sits in a package this build does not link
	// describes a call between functions the binary does not contain. The
	// consumer's own edges are untouched: a build links what it calls.
	edges := make([]ports.CallGraphEdge, 0, len(consumer.Edges)+len(subject.Edges))
	edges = append(edges, consumer.Edges...)
	for _, e := range subject.Edges {
		if !inBuild(inClosure, pkgOf, e.FromID) || !inBuild(inClosure, pkgOf, e.ToID) {
			continue
		}
		edges = append(edges, e)
	}

	var reflect []ports.CallGraphReflectSite
	reflect = append(reflect, consumer.ReflectiveDispatch...)
	for _, site := range subject.ReflectiveDispatch {
		if !inBuild(inClosure, pkgOf, site.CallerID) {
			continue
		}
		reflect = append(reflect, site)
	}

	return ports.CallGraphProjection{
		Nodes: nodes,
		Edges: edges,
		Completeness: string(callgraphdomain.WeakerCompleteness(
			callgraphdomain.CompletenessLevel(consumer.Completeness),
			callgraphdomain.CompletenessLevel(subject.Completeness))),
		Algorithm:          consumer.Algorithm,
		ArtifactKind:       consumer.ArtifactKind,
		ReflectiveDispatch: reflect,
		ServableAsCacheHit: consumer.ServableAsCacheHit && subject.ServableAsCacheHit,
		StdlibPackages:     consumer.StdlibPackages,
		DependencyPackages: consumer.DependencyPackages,
	}
}

// unjoinedCalls lists, sorted, every external node outside the standard
// library that roots reach in the joined graph: a leaf the join did not
// replace, where a route could continue in a module whose graph is not held.
func unjoinedCalls(joined ports.CallGraphProjection, roots []string) []string {
	reached := reachableFrom(joined, roots)
	var out []string
	for _, n := range joined.Nodes {
		if n.IsExternal && reached[n.ID] && n.Package != "" && !callgraphdomain.IsStdlibPackage(n.Package) {
			out = append(out, n.ID)
		}
	}
	sort.Strings(out)
	return out
}

// firstN is at most n leading items of ids, so a reason names examples
// without listing hundreds.
func firstN(ids []string, n int) []string {
	if len(ids) <= n {
		return ids
	}
	return append(append([]string(nil), ids[:n]...), "…")
}

// plural renders a count with its noun.
func plural(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return strconv.Itoa(n) + " " + noun + "s"
}

// inBuild reports whether a subject node belongs to a package this build
// links. A node the subject's graph does not name is one of the consumer's own
// and is always in the build; a node whose package could not be resolved — the
// shared functions SSA synthesises for an interface method — belongs to no
// package and is kept, because excluding it would cut a hop every build makes.
func inBuild(linked map[string]bool, pkgOf map[string]string, id string) bool {
	pkg, known := pkgOf[id]
	if !known || pkg == "" {
		return true
	}
	return linked[pkg]
}

// graphLabel names one stored graph the way an answer cites it: the coordinate
// it is of, and how big and how complete it is. It carries no content hash
// because the projection does not hold one — the label says which graph, and
// callgraph-show is what says which generation.
func graphLabel(coord coordinate.ModuleCoordinate, proj ports.CallGraphProjection) string {
	return fmt.Sprintf("%s (%s, %d nodes, %d edges)",
		coord, proj.Completeness, len(proj.Nodes), len(proj.Edges))
}

// joinLoadRefusal states why a joined search could not be made, naming every
// graph it needed and could not get, and "" when both loaded.
//
// Both halves are named together on purpose: a store that holds neither is the
// ordinary state of one that has analysed neither, so a refusal naming one of
// them costs the reader a second round trip to discover the other.
//
// A load that failed for any other reason is reported as itself: a graph that
// exists and will not decode is a different problem from one that was never
// taken, and a remedy for the second does not address the first.
func joinLoadRefusal(
	rule joinRule,
	frame coordinate.ModuleCoordinate, frameErr error,
	subject coordinate.ModuleCoordinate, subjectErr error,
	frameRoot string,
) string {
	switch {
	case frameErr != nil && !errors.Is(frameErr, ports.ErrCallGraphNotFound):
		return "the stored call graph for " + frame.String() + " could not be read: " + frameErr.Error()
	case subjectErr != nil && !errors.Is(subjectErr, ports.ErrCallGraphNotFound):
		return "the stored call graph for " + subject.String() + " could not be read: " + subjectErr.Error()
	case frameErr == nil && subjectErr == nil:
		return ""
	}
	var missing, remedies []string
	unnamed := ""
	if frameErr != nil {
		missing = append(missing, frame.String()+" (the build this record was measured in)")
		if line, ok := callgraphdomain.ReanalysisCommand(frame, frameRoot, false); ok {
			remedies = append(remedies, line)
		} else {
			// No command can be named for this half, so none is printed for it. The
			// reason is stated as its own sentence rather than inside the remedy,
			// where it would read as the command and is not one.
			unnamed = ". " + unnamedTreeSentence(false)
		}
	}
	if subjectErr != nil {
		missing = append(missing, subject.String()+" ("+rule.subjectRole+")")
		if line, ok := callgraphdomain.ReanalysisCommand(subject, "", false); ok {
			remedies = append(remedies, line)
		}
	}
	why := rule.negative + " is searched by joining the build's own call graph to " + rule.subjectGraphs +
		", and the store holds no call graph for " + strings.Join(missing, " or ")
	if len(remedies) > 0 {
		why += "; extract " + itOrThem(len(remedies)) + " with: " + strings.Join(remedies, "; ")
	}
	return why + unnamed
}

// remedyClause renders ", <lead> with: <command>" for a refusal, and the
// sentence that says why no command can be named where none can.
//
// It is one function because the two outcomes share a slot and must never share
// a shape: a slot takes a command or takes nothing, and a sentence spliced into
// one reads as an invocation the parser would reject.
func remedyClause(lead string, coord coordinate.ModuleCoordinate, dir string, force bool) string {
	if line, ok := callgraphdomain.ReanalysisCommand(coord, dir, force); ok {
		return "; " + lead + ": " + line
	}
	return ". " + unnamedTreeSentence(force)
}

// unnamedTreeSentence states, as a sentence, that no directory can be named and
// what the reader must do from inside the tree. force carries through, because
// a held record answers a re-run that does not ask past it.
func unnamedTreeSentence(force bool) string {
	flags := ""
	if force {
		flags = " --force"
	}
	return capitalise(callgraphdomain.UnnamedWorkingTreeLead) +
		", so run kanonarion local" + flags + " from inside it"
}

// capitalise raises the first letter so a lead written to open a clause can
// open a sentence instead.
func capitalise(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// projectDir asks the walk ledger where the frame's tree is, and answers "" for
// every way it cannot know: no reader wired, no walk named, a walk that records
// no directory, or a store that would not answer. A directory that is not known
// is never guessed.
func (s *NegativeSearcher) projectDir(ctx context.Context, walkID string) string {
	if s.dirs == nil || walkID == "" {
		return ""
	}
	dir, ok, err := s.dirs.WalkProjectDir(ctx, walkID)
	if err != nil || !ok {
		return ""
	}
	return dir
}

// itOrThem renders the pronoun for the remedy count above, so a one-graph
// refusal never reads "extract them with".
func itOrThem(n int) string {
	if n == 1 {
		return "it"
	}
	return "them"
}
