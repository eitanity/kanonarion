package domain

import (
	"container/heap"
	"fmt"
	"slices"
	"sort"
	"strings"

	cgdomain "github.com/eitanity/kanonarion/internal/callgraph/domain"
)

// rankInf is the min-confidence rank of a zero-edge path (a root reached with
// no intervening call). It exceeds every real edge rank so min(rankInf, r) == r.
const rankInf = 1 << 30

// confRank ranks an edge confidence from strongest (Direct) to weakest
// (Unknown). It is the ordering used to pick the most-confident witnessing path
// for a capability and to report that path's weakest edge. The tiers follow the
// resolution vocabulary: a Direct edge names a unique callee; VTA is a
// source-derived refinement of an interface dispatch; Framework is a specific
// model-asserted binding; CHA-overapprox is a coarse over-approximation that may
// include spurious callees; Unknown (including reflect-dispatched edges) is
// unresolved.
func confRank(c cgdomain.EdgeConfidence) int {
	switch c {
	case cgdomain.ConfidenceDirect:
		return 4
	case cgdomain.ConfidenceVTA:
		return 3
	case cgdomain.ConfidenceFramework:
		return 2
	case cgdomain.ConfidenceCHAOverapprox:
		return 1
	default: // ConfidenceUnknown or any unrecognised value
		return 0
	}
}

// confidenceForRank maps a path's weakest rank back to an EdgeConfidence for
// reporting. A zero-edge path (rankInf) is Direct: the capability is used by the
// analysed code itself, not reached through a weaker edge.
func confidenceForRank(rank int) cgdomain.EdgeConfidence {
	switch {
	case rank >= 4:
		return cgdomain.ConfidenceDirect
	case rank == 3:
		return cgdomain.ConfidenceVTA
	case rank == 2:
		return cgdomain.ConfidenceFramework
	case rank == 1:
		return cgdomain.ConfidenceCHAOverapprox
	default:
		return cgdomain.ConfidenceUnknown
	}
}

// CapabilityFinding is one witnessed capability with the evidence for it.
type CapabilityFinding struct {
	// Capability is the witnessed category.
	Capability Capability
	// Path is the witnessing call path from a root to the sink, node IDs in
	// call order. It is never empty; Path[0] is a root and the last element is
	// the sink node.
	Path []string
	// SinkPackage and SinkSymbol identify the classified callee.
	SinkPackage string
	SinkSymbol  string
	// WeakestConfidence is the least-certain edge confidence along Path. It is
	// ConfidenceDirect for a zero-edge path (the root itself is the sink).
	WeakestConfidence cgdomain.EdgeConfidence
	// Basis says what the path established. It is always populated, so a
	// consumer concatenating Findings and Observations can still tell them
	// apart; every entry in Findings carries BasisUse.
	Basis CapabilityBasis
	// Reach is how deliberately the sink is reached, from the sink alone.
	Reach Reach
	// CallerKind is the kind of the last owned function on Path: the one whose
	// own code makes the call, or the sink itself when the module owns it.
	CallerKind CallerKind
	// ClassifiedBy says whether the label came from a rule or a package default.
	ClassifiedBy ClassifiedBy
	// PlumbingOnly is set when every witness of the capability is
	// RUNTIME_PLUMBING. Such a finding is shown, not suppressed, because hiding
	// it would hide the capability.
	PlumbingOnly bool
}

// Suppressed reports whether text hides the finding unless asked: its
// capability is in the suppressed tier.
func (f CapabilityFinding) Suppressed() bool {
	return f.Capability.Tier() == TierSuppressed
}

// CapabilityReport is the result of analysing one call graph.
type CapabilityReport struct {
	// Findings holds one finding per witnessed capability, in tier then
	// capability order. Each finding is the best witness: a direct call over
	// plumbing over an unanalysed body, then the strongest confidence. Every
	// entry is a capability of the analysed module (BasisUse); this is the set
	// Capabilities() and the diff read.
	Findings []CapabilityFinding
	// Observations holds paths that reach a classified node but establish
	// something weaker than a capability of the analysed module — an external
	// package's init (linkage) or a body fact recorded on an external callee.
	// They are reported rather than dropped because silence is the
	// false-negative direction, and only for a capability Findings does not
	// already carry, since a real witness answers the question outright.
	Observations []CapabilityFinding
	// Rows are the witness rows: one per owned caller and classified external
	// callee with basis use, plus each owned node's own body fact. See Rows.
	Rows []WitnessRow
	// SensitiveCalls is the high-signal roll-up over Rows.
	SensitiveCalls []SensitiveCall
	// CollectsAndEgresses names each owned function that itself calls both a
	// collection and an egress member of SensitiveCalls.
	CollectsAndEgresses []CoLocation
	// InitReachesBoth names each owned initialiser from which Direct edges
	// reach both a collection and an egress member.
	InitReachesBoth []InitReach
	// Unanalyzed lists the owned in-scope functions with an assembly or
	// //go:linkname body, sorted. The graph cannot see what they do.
	Unanalyzed []string
	// UnanalyzedCallees counts the distinct external assembly or linkname
	// callees of owned code that carry no identity capability. They are not
	// rows.
	UnanalyzedCallees int
	// PackageDefaults counts, per package, the distinct row callees whose label
	// is the package default rather than a named rule.
	PackageDefaults []PackageDefault
	// Partial is true when the report does not rest on a fully extracted graph.
	// A capability set over a Partial graph is a
	// soundness caveat, never a clean set (parity with capslock's UNANALYZED).
	Partial bool
	// Caveat is a human-readable soundness note; non-empty only when Partial.
	Caveat string
}

// Capabilities returns the witnessed capability set, sorted by name.
func (r CapabilityReport) Capabilities() []Capability {
	caps := make([]Capability, 0, len(r.Findings))
	for _, f := range r.Findings {
		caps = append(caps, f.Capability)
	}
	slices.Sort(caps)
	return caps
}

// SelectRoots roots the capability traversal at every node the module owns.
// The command is opened to see what a module's code can do, and that code is
// entered through handlers, cgo trampolines, closures and goroutine entries,
// none of them exported, so the artifact kind is not consulted. scope is the
// only narrowing axis: a consumer compiles none of the module's _test.go files.
func SelectRoots(rec cgdomain.CallGraphRecord, scope cgdomain.RootScope) []string {
	candidates := make([]cgdomain.RootCandidate, 0, len(rec.Nodes))
	for _, n := range rec.Nodes {
		candidates = append(candidates, cgdomain.RootCandidate{
			ID:         n.ID,
			IsExternal: n.IsExternal,
			IsTest:     n.IsTest,
		})
	}
	return cgdomain.SelectOwnedRoots(candidates, scope)
}

// Analyse computes the capability report for rec, treating the given node IDs
// as reachability roots. It performs a widest-path search that, for every
// reachable sink node, maximises the minimum edge confidence along the path —
// so each capability is reported with its strongest available witness and that
// path's weakest edge.
//
// scope is the root scope the roots were selected under. Under the production
// scope the search does not enter test-declared nodes either: an over-
// approximated edge from production code into a test function would otherwise
// carry a test-only sink into the default report.
func Analyse(rec cgdomain.CallGraphRecord, roots []string, scope cgdomain.RootScope) CapabilityReport {
	report := CapabilityReport{Partial: true}
	// Each status is named. Testing "not Extracted" put every member that is
	// neither into the unresolved-graph sentence, and one of them is not an
	// analysis outcome at all: ExcludedByConfig is the operator's own decision
	// not to analyse this module, and telling them the graph would not resolve
	// sends them to investigate a tool failure they configured.
	switch rec.OverallStatus {
	case cgdomain.CallGraphStatusExtracted:
		report.Partial = false
	case cgdomain.CallGraphStatusExcludedByConfig:
		report.Caveat = "this module is excluded from call-graph analysis by configuration, so no graph was " +
			"produced and no capability was searched for; the empty set here is not a measurement"
	case cgdomain.CallGraphStatusUnknown,
		cgdomain.CallGraphStatusPartial,
		cgdomain.CallGraphStatusLoadFailed,
		cgdomain.CallGraphStatusOutOfMemory,
		cgdomain.CallGraphStatusCancelled,
		cgdomain.CallGraphStatusExtractionFailed:
		report.Caveat = "call graph did not fully resolve (status " +
			rec.OverallStatus.String() + "); capability set is a lower bound and may be incomplete"
	default:
		report.Caveat = "call graph carries a status this build does not recognise (" +
			rec.OverallStatus.String() + "); capability set is a lower bound and may be incomplete"
	}

	// A graph the analysing binary could not read is not a lower bound found in
	// the source, and the reader is owed the reason and what lifts it.
	if clause, remedy, ok := cgdomain.AnalyserLimitCaveat(rec.FailureDetail); ok && report.Partial {
		report.Caveat = strings.TrimSpace("call graph did not fully resolve (status " + rec.OverallStatus.String() +
			"): " + clause + "; capability set is a lower bound and may be incomplete. " + remedy)
	}

	nodeByID := make(map[string]cgdomain.CallNode, len(rec.Nodes))
	for _, n := range rec.Nodes {
		nodeByID[n.ID] = n
	}

	if scope == cgdomain.RootScopeProduction {
		for id, n := range nodeByID {
			if n.IsTest {
				delete(nodeByID, id)
			}
		}
	}

	adj := buildAdjacency(rec.Edges)
	dist, pred := widestPaths(roots, nodeByID, adj)

	report.Findings, report.Observations = collectFindings(dist, pred, nodeByID)
	addRowEvidence(&report, roots, nodeByID, adj)
	return report
}

// buildAdjacency indexes edges by their FromID, with each bucket sorted for a
// deterministic traversal order.
func buildAdjacency(edges []cgdomain.CallEdge) map[string][]cgdomain.CallEdge {
	adj := make(map[string][]cgdomain.CallEdge)
	for _, e := range edges {
		adj[e.FromID] = append(adj[e.FromID], e)
	}
	for from := range adj {
		bucket := adj[from]
		sort.Slice(bucket, func(i, j int) bool {
			if bucket[i].ToID != bucket[j].ToID {
				return bucket[i].ToID < bucket[j].ToID
			}
			return confRank(bucket[i].Confidence) > confRank(bucket[j].Confidence)
		})
	}
	return adj
}

// widestPaths runs a Dijkstra variant that maximises the minimum edge
// confidence to every reachable node. It returns, per settled node, the
// weakest-edge rank of its chosen path and the predecessor edge that realises
// it (absent for roots). Ties break on shorter depth then smaller node ID so
// the chosen witnessing paths are deterministic.
func widestPaths(
	roots []string,
	nodeByID map[string]cgdomain.CallNode,
	adj map[string][]cgdomain.CallEdge,
) (map[string]int, map[string]cgdomain.CallEdge) {
	dist := make(map[string]int)
	pred := make(map[string]cgdomain.CallEdge)
	settled := make(map[string]bool)

	pq := &widestQueue{}
	heap.Init(pq)
	for _, r := range roots {
		if _, ok := nodeByID[r]; !ok {
			continue
		}
		heap.Push(pq, widestItem{id: r, minRank: rankInf, depth: 0})
	}

	for pq.Len() > 0 {
		it := popWidest(pq)
		if settled[it.id] {
			continue
		}
		settled[it.id] = true
		dist[it.id] = it.minRank
		if it.hasPred {
			pred[it.id] = it.predEdge
		}
		for _, e := range adj[it.id] {
			if settled[e.ToID] {
				continue
			}
			if _, ok := nodeByID[e.ToID]; !ok {
				continue
			}
			cand := min(it.minRank, confRank(e.Confidence))
			heap.Push(pq, widestItem{
				id:       e.ToID,
				minRank:  cand,
				depth:    it.depth + 1,
				predEdge: e,
				hasPred:  true,
			})
		}
	}
	return dist, pred
}

// collectFindings turns settled sink nodes into one finding per capability,
// keeping the best witness for each. It returns two lists: the capabilities
// of the analysed module, and the observations — paths whose sink is an external
// package's init or an external node's body fact, which classify the callee
// rather than the caller. An observation is dropped when the same capability has
// a real witness, because the stronger answer already stands.
func collectFindings(
	dist map[string]int,
	pred map[string]cgdomain.CallEdge,
	nodeByID map[string]cgdomain.CallNode,
) (findings, observations []CapabilityFinding) {
	best := make(map[Capability]CapabilityFinding)
	weak := make(map[Capability]CapabilityFinding)
	// nonPlumbing records a capability with any witness that is not plumbing,
	// so plumbing-only is decided over every witness and not the chosen one.
	nonPlumbing := make(map[Capability]bool)
	for id, rank := range dist {
		n := nodeByID[id]
		caps := NodeCapabilities(n)
		if len(caps) == 0 {
			continue
		}
		path := reconstructPath(id, pred)
		conf := confidenceForRank(rank)
		kind := pathCallerKind(path, nodeByID)
		for _, nc := range caps {
			f := CapabilityFinding{
				Capability:        nc.Capability,
				Path:              path,
				SinkPackage:       ClassificationPackage(n),
				SinkSymbol:        n.Symbol,
				WeakestConfidence: conf,
				Basis:             nc.Basis,
				Reach:             nc.Reach,
				CallerKind:        kind,
				ClassifiedBy:      nc.ClassifiedBy,
			}
			into := best
			if nc.Basis != BasisUse {
				into = weak
			} else if !IsPlumbing(nc.Reach, n.Symbol) {
				nonPlumbing[nc.Capability] = true
			}
			if cur, exists := into[nc.Capability]; !exists || strongerFinding(f, cur) {
				into[nc.Capability] = f
			}
		}
	}

	findings = make([]CapabilityFinding, 0, len(best))
	for c, f := range best {
		f.PlumbingOnly = !nonPlumbing[c]
		findings = append(findings, f)
	}
	observations = make([]CapabilityFinding, 0, len(weak))
	for c, f := range weak {
		if _, witnessed := best[c]; witnessed {
			continue
		}
		observations = append(observations, f)
	}
	sortFindings(findings)
	sortFindings(observations)
	return findings, observations
}

// pathCallerKind is the kind of the last node on path the module owns. A path
// starts at a root, which is owned, so one is always found when the root is in
// the graph.
func pathCallerKind(path []string, nodeByID map[string]cgdomain.CallNode) CallerKind {
	for i := len(path) - 1; i >= 0; i-- {
		if n, ok := nodeByID[path[i]]; ok && !n.IsExternal {
			return NodeCallerKind(n)
		}
	}
	return CallerInternal
}

// sortFindings puts a finding slice in the canonical order.
func sortFindings(fs []CapabilityFinding) {
	sort.Slice(fs, func(i, j int) bool { return CapabilityFindingLess(fs[i], fs[j]) })
}

// CapabilityFindingLess is the canonical ordering for CapabilityFinding slices.
// The tier leads, so Act findings print before Context, then the capability,
// which is what a reader scans by; the sink and the witnessing path follow, so
// two findings for one capability still have a defined order.
func CapabilityFindingLess(a, b CapabilityFinding) bool {
	if a.Capability != b.Capability {
		return capabilityLess(a.Capability, b.Capability)
	}
	if a.SinkPackage != b.SinkPackage {
		return a.SinkPackage < b.SinkPackage
	}
	if a.SinkSymbol != b.SinkSymbol {
		return a.SinkSymbol < b.SinkSymbol
	}
	if a.WeakestConfidence != b.WeakestConfidence {
		return a.WeakestConfidence < b.WeakestConfidence
	}
	if len(a.Path) != len(b.Path) {
		return len(a.Path) < len(b.Path)
	}
	for i := range a.Path {
		if a.Path[i] != b.Path[i] {
			return a.Path[i] < b.Path[i]
		}
	}
	if a.Reach != b.Reach {
		return a.Reach < b.Reach
	}
	if a.CallerKind != b.CallerKind {
		return a.CallerKind < b.CallerKind
	}
	if a.ClassifiedBy != b.ClassifiedBy {
		return a.ClassifiedBy < b.ClassifiedBy
	}
	if a.PlumbingOnly != b.PlumbingOnly {
		return !a.PlumbingOnly
	}
	return a.Basis < b.Basis
}

// strongerFinding reports whether candidate is a better witness than current:
// the more deliberate reach first (witnessRank), then higher confidence, then a shorter
// path, then a lexicographically smaller sink node ID for determinism.
func strongerFinding(cand, cur CapabilityFinding) bool {
	if cr, ur := witnessRank(cand.Reach, cand.SinkSymbol), witnessRank(cur.Reach, cur.SinkSymbol); cr != ur {
		return cr > ur
	}
	cr, ur := confRank(cand.WeakestConfidence), confRank(cur.WeakestConfidence)
	if cr != ur {
		return cr > ur
	}
	if len(cand.Path) != len(cur.Path) {
		return len(cand.Path) < len(cur.Path)
	}
	return sinkID(cand) < sinkID(cur)
}

// sinkID is the last node in a witnessing path (the classified callee).
func sinkID(f CapabilityFinding) string {
	if len(f.Path) == 0 {
		return ""
	}
	return f.Path[len(f.Path)-1]
}

// reconstructPath walks predecessor edges back from a sink to its root and
// returns the node IDs in call order.
func reconstructPath(sink string, pred map[string]cgdomain.CallEdge) []string {
	rev := []string{sink}
	cur := sink
	for {
		e, ok := pred[cur]
		if !ok {
			break
		}
		rev = append(rev, e.FromID)
		cur = e.FromID
	}
	for i, j := 0, len(rev)-1; i < j; i, j = i+1, j-1 {
		rev[i], rev[j] = rev[j], rev[i]
	}
	return rev
}

// -- priority queue --

type widestItem struct {
	id       string
	minRank  int
	depth    int
	predEdge cgdomain.CallEdge
	hasPred  bool
}

// widestQueue orders items so the strongest witness pops first: higher minRank,
// then shorter depth, then smaller node ID, then smaller predecessor.
type widestQueue []widestItem

func (q widestQueue) Len() int { return len(q) }

func (q widestQueue) Less(i, j int) bool {
	if q[i].minRank != q[j].minRank {
		return q[i].minRank > q[j].minRank
	}
	if q[i].depth != q[j].depth {
		return q[i].depth < q[j].depth
	}
	if q[i].id != q[j].id {
		return q[i].id < q[j].id
	}
	// Two routes to one node at equal strength and depth: the smaller caller
	// wins, so the witness does not depend on how full the heap happened to be.
	return q[i].predEdge.FromID < q[j].predEdge.FromID
}

func (q widestQueue) Swap(i, j int) { q[i], q[j] = q[j], q[i] }

// Push is called by container/heap with what heap.Push was given, and only
// this file calls heap.Push, always with a widestItem.
func (q *widestQueue) Push(x any) {
	it, ok := x.(widestItem)
	if !ok {
		panic(fmt.Sprintf("capability: widestQueue pushed %T, not widestItem", x))
	}
	*q = append(*q, it)
}

// popWidest pops the next item. The queue holds widestItem only (see Push).
func popWidest(pq *widestQueue) widestItem {
	x := heap.Pop(pq)
	it, ok := x.(widestItem)
	if !ok {
		panic(fmt.Sprintf("capability: widestQueue popped %T, not widestItem", x))
	}
	return it
}

func (q *widestQueue) Pop() any {
	old := *q
	n := len(old)
	it := old[n-1]
	*q = old[:n-1]
	return it
}
