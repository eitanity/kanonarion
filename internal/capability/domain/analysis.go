package domain

import (
	"container/heap"
	"sort"

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
}

// CapabilityReport is the result of analysing one call graph.
type CapabilityReport struct {
	// Findings holds one finding per witnessed capability, sorted by capability
	// name. Each finding's WeakestConfidence is the strongest available across
	// every witnessing path, so a confirmed witness is never hidden behind an
	// over-approximated one.
	Findings []CapabilityFinding
	// Partial is true when the underlying graph did not fully resolve
	// (OverallStatus != Extracted). A capability set over a Partial graph is a
	// soundness caveat, never a clean set (parity with capslock's UNANALYZED).
	Partial bool
	// Caveat is a human-readable soundness note; non-empty only when Partial.
	Caveat string
}

// Capabilities returns the witnessed capability set, sorted.
func (r CapabilityReport) Capabilities() []Capability {
	caps := make([]Capability, 0, len(r.Findings))
	for _, f := range r.Findings {
		caps = append(caps, f.Capability)
	}
	sort.Slice(caps, func(i, j int) bool { return caps[i] < caps[j] })
	return caps
}

// SelectRoots returns the reachability roots for the record's capability
// analysis, conditioned on the record's artifact kind: an application roots all
// of its own code (a capability present in owned code is a capability of that
// code however the function is entered), a library roots its exported API plus
// package init. Delegates to the shared callgraph-domain selector so it can
// never drift from vuln reachability.
func SelectRoots(rec cgdomain.CallGraphRecord) []string {
	candidates := make([]cgdomain.RootCandidate, 0, len(rec.Nodes))
	for _, n := range rec.Nodes {
		candidates = append(candidates, cgdomain.RootCandidate{
			ID:            n.ID,
			Symbol:        n.Symbol,
			IsExternal:    n.IsExternal,
			IsExportedAPI: n.IsExportedAPI,
		})
	}
	return cgdomain.SelectReachabilityRoots(candidates, rec.ArtifactKind)
}

// Analyse computes the capability report for rec, treating the given node IDs
// as reachability roots. It performs a widest-path search that, for every
// reachable sink node, maximises the minimum edge confidence along the path —
// so each capability is reported with its strongest available witness and that
// path's weakest edge.
func Analyse(rec cgdomain.CallGraphRecord, roots []string) CapabilityReport {
	partial := rec.OverallStatus != cgdomain.CallGraphStatusExtracted
	report := CapabilityReport{Partial: partial}
	if partial {
		report.Caveat = "call graph did not fully resolve (status " +
			rec.OverallStatus.String() + "); capability set is a lower bound and may be incomplete"
	}

	nodeByID := make(map[string]cgdomain.CallNode, len(rec.Nodes))
	for _, n := range rec.Nodes {
		nodeByID[n.ID] = n
	}

	adj := buildAdjacency(rec.Edges)
	dist, pred := widestPaths(roots, nodeByID, adj)

	report.Findings = collectFindings(dist, pred, nodeByID)
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
		it := heap.Pop(pq).(widestItem)
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
// keeping the strongest-witness finding for each capability.
func collectFindings(
	dist map[string]int,
	pred map[string]cgdomain.CallEdge,
	nodeByID map[string]cgdomain.CallNode,
) []CapabilityFinding {
	best := make(map[Capability]CapabilityFinding)
	for id, rank := range dist {
		n := nodeByID[id]
		caps := NodeCapabilities(n)
		if len(caps) == 0 {
			continue
		}
		path := reconstructPath(id, pred)
		conf := confidenceForRank(rank)
		for _, capName := range caps {
			f := CapabilityFinding{
				Capability:        capName,
				Path:              path,
				SinkPackage:       n.Package,
				SinkSymbol:        n.Symbol,
				WeakestConfidence: conf,
			}
			if cur, exists := best[capName]; !exists || strongerFinding(f, cur) {
				best[capName] = f
			}
		}
	}

	findings := make([]CapabilityFinding, 0, len(best))
	for _, f := range best {
		findings = append(findings, f)
	}
	sort.Slice(findings, func(i, j int) bool {
		return findings[i].Capability < findings[j].Capability
	})
	return findings
}

// strongerFinding reports whether candidate is a better witness than current:
// higher confidence first, then a shorter path, then a lexicographically
// smaller sink node ID for determinism.
func strongerFinding(cand, cur CapabilityFinding) bool {
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
// then shorter depth, then smaller node ID.
type widestQueue []widestItem

func (q widestQueue) Len() int { return len(q) }

func (q widestQueue) Less(i, j int) bool {
	if q[i].minRank != q[j].minRank {
		return q[i].minRank > q[j].minRank
	}
	if q[i].depth != q[j].depth {
		return q[i].depth < q[j].depth
	}
	return q[i].id < q[j].id
}

func (q widestQueue) Swap(i, j int) { q[i], q[j] = q[j], q[i] }

func (q *widestQueue) Push(x any) { *q = append(*q, x.(widestItem)) }

func (q *widestQueue) Pop() any {
	old := *q
	n := len(old)
	it := old[n-1]
	*q = old[:n-1]
	return it
}
