package domain

import (
	"slices"
	"sort"

	cgdomain "code.eitanity.com/kanonarion/internal/callgraph/domain"
)

// WitnessRow is one piece of evidence: an owned, in-scope function's edge to a
// classified external callee with basis use, or that function's own body
// fact. Every owned in-scope node is a root, so a row needs no path search.
type WitnessRow struct {
	// Caller is the owned function whose own code makes the call.
	Caller     string
	CallerKind CallerKind
	Capability Capability
	Reach      Reach
	// Callee is the callee node ID; for a body-fact row it is Caller itself.
	Callee        string
	CalleePackage string
	// BodyFact marks a row witnessed by the caller's own body, not an edge.
	BodyFact     bool
	ClassifiedBy ClassifiedBy
	// Confidence is the strongest edge confidence among the edges this row
	// collapses; Direct for a body fact.
	Confidence cgdomain.EdgeConfidence
	// Suppressed hides the row in text unless asked: a suppressed-tier
	// capability, or plumbing reach that is not the promoted representative.
	Suppressed bool
	// PlumbingOnly marks the one row promoted for a capability whose every row
	// is plumbing, so suppression does not hide the capability.
	PlumbingOnly bool
	// isPlumbing is IsPlumbing over the row's reach and callee symbol, the
	// predicate findings use too.
	isPlumbing bool
}

// plumbing is what text suppresses on reach (see IsPlumbing).
func (r WitnessRow) plumbing() bool { return r.isPlumbing }

// rowKey is the row identity: (caller kind, capability, reach, callee) plus the
// caller. Confidence is carried, not keyed, so a strengthened edge is not a
// new row.
func (r WitnessRow) rowKey() string {
	return string(r.CallerKind) + "\x00" + string(r.Capability) + "\x00" + string(r.Reach) + "\x00" +
		r.Callee + "\x00" + r.Caller
}

// RowLess is the diff ranking: caller kind (INIT, TEST_INIT, EXPORTED_API,
// TEST, INTERNAL, MAIN), then tier, then Direct before weaker confidence, then
// capability, callee and caller.
func RowLess(a, b WitnessRow) bool {
	if ka, kb := callerKindRank(a.CallerKind), callerKindRank(b.CallerKind); ka != kb {
		return ka < kb
	}
	if ta, tb := tierRank(a.Capability.Tier()), tierRank(b.Capability.Tier()); ta != tb {
		return ta < tb
	}
	if ca, cb := confRank(a.Confidence), confRank(b.Confidence); ca != cb {
		return ca > cb
	}
	if a.Capability != b.Capability {
		return capabilityLess(a.Capability, b.Capability)
	}
	if a.Callee != b.Callee {
		return a.Callee < b.Callee
	}
	if a.Caller != b.Caller {
		return a.Caller < b.Caller
	}
	return a.Reach < b.Reach
}

func sortRows(rows []WitnessRow) {
	sort.Slice(rows, func(i, j int) bool { return RowLess(rows[i], rows[j]) })
}

// SensitiveCall is one member of the roll-up: a callee whose capability is in
// the sensitive set, reached as a direct call, with at least one row resting on
// a Direct edge.
type SensitiveCall struct {
	// Callee is the callee node ID, with deprecated io/ioutil aliases mapped
	// onto their os equivalents.
	Callee     string
	Capability Capability
	// CallerKinds are the kinds of every caller, in ranking order.
	CallerKinds []CallerKind
	// Callers counts the distinct owned callers.
	Callers int
}

func (s SensitiveCall) key() string { return s.Callee + "\x00" + string(s.Capability) }

// sensitiveCapabilities is the roll-up's membership by capability.
var sensitiveCapabilities = map[Capability]bool{
	CapabilityExecProcess: true, CapabilityExecDynamic: true,
	CapabilityNetDial: true, CapabilityNetListen: true, CapabilityNetTransfer: true,
	CapabilityFSRead: true, CapabilityFSWrite: true, CapabilityEnvRead: true,
	CapabilityCgoCall: true, CapabilityReflectDynamic: true,
}

// collectionCapabilities and egressCapabilities are the two halves of the
// co-location facts.
var (
	collectionCapabilities = map[Capability]bool{CapabilityEnvRead: true, CapabilityFSRead: true}
	egressCapabilities     = map[Capability]bool{CapabilityNetDial: true, CapabilityNetTransfer: true}
)

// ioutilAliases maps deprecated io/ioutil functions onto their os
// equivalents, so a module migrating off io/ioutil does not read as a change.
var ioutilAliases = map[string]string{
	"io/ioutil.ReadFile":  "os.ReadFile",
	"io/ioutil.ReadDir":   "os.ReadDir",
	"io/ioutil.WriteFile": "os.WriteFile",
	"io/ioutil.TempFile":  "os.CreateTemp",
	"io/ioutil.TempDir":   "os.MkdirTemp",
}

// NormaliseCallee maps a deprecated alias onto the function it forwards to.
func NormaliseCallee(id string) string {
	if to, ok := ioutilAliases[id]; ok {
		return to
	}
	return id
}

// CoLocation names one owned function that itself calls, over Direct edges, a
// collection member and an egress member of the sensitive calls.
type CoLocation struct {
	Function   string
	CallerKind CallerKind
	Collection []string
	Egress     []string
}

// InitReach names one owned initialiser from which Direct edges reach both a
// collection and an egress member. Depth is the hop count at which the second
// of the two first appears; Collection and Egress name the nearest member of
// each (the smallest ID at that distance).
type InitReach struct {
	Init            string
	CallerKind      CallerKind
	Depth           int
	CollectionDepth int
	EgressDepth     int
	Collection      string
	Egress          string
}

// key identifies the fact without its depth: the initialiser and the two
// members it reaches.
func (r InitReach) key() string { return r.Init + "\x00" + r.Collection + "\x00" + r.Egress }

// PackageDefault counts the distinct row callees in Package labelled by its
// package default.
type PackageDefault struct {
	Package string
	Callees int
}

// addRowEvidence fills the row-derived parts of report from the owned
// in-scope roots.
func addRowEvidence(report *CapabilityReport, roots []string, nodeByID map[string]cgdomain.CallNode, adj map[string][]cgdomain.CallEdge) {
	owned := ownedRoots(roots, nodeByID)
	report.Rows, report.Unanalyzed, report.UnanalyzedCallees = collectRows(owned, nodeByID, adj)
	report.PackageDefaults = packageDefaults(report.Rows)
	report.SensitiveCalls = sensitiveCalls(report.Rows)
	members := make(map[string]Capability, len(report.SensitiveCalls))
	for _, s := range report.SensitiveCalls {
		members[s.Callee] = s.Capability
	}
	report.CollectsAndEgresses = collectsAndEgresses(report.Rows, members)
	report.InitReachesBoth = initReachesBoth(owned, nodeByID, adj, members)
}

// ownedRoots is the deduplicated, sorted set of roots present in the graph and
// owned by the module.
func ownedRoots(roots []string, nodeByID map[string]cgdomain.CallNode) []cgdomain.CallNode {
	ids := slices.Clone(roots)
	slices.Sort(ids)
	ids = slices.Compact(ids)
	out := make([]cgdomain.CallNode, 0, len(ids))
	for _, id := range ids {
		if n, ok := nodeByID[id]; ok && !n.IsExternal {
			out = append(out, n)
		}
	}
	return out
}

// collectRows builds the witness rows, the owned unanalysed bodies and the
// count of external unanalysed callees with no identity capability.
func collectRows(
	owned []cgdomain.CallNode,
	nodeByID map[string]cgdomain.CallNode,
	adj map[string][]cgdomain.CallEdge,
) (rows []WitnessRow, unanalyzed []string, unanalyzedCallees int) {
	byKey := make(map[string]WitnessRow)
	opaque := make(map[string]bool)
	for _, caller := range owned {
		kind := NodeCallerKind(caller)
		if caller.IsAssemblyOrLinkname {
			unanalyzed = append(unanalyzed, caller.ID)
		}
		if caller.UsesUnsafePointer {
			r := WitnessRow{
				Caller: caller.ID, CallerKind: kind, Capability: CapabilityUnsafePointer,
				Reach: ReachDirectCall, Callee: caller.ID, CalleePackage: caller.Package,
				BodyFact: true, ClassifiedBy: ClassifiedByRule, Confidence: cgdomain.ConfidenceDirect,
			}
			byKey[r.rowKey()] = r
		}
		for _, e := range adj[caller.ID] {
			callee, ok := nodeByID[e.ToID]
			if !ok || !callee.IsExternal {
				continue
			}
			caps := NodeCapabilities(callee)
			if len(caps) == 0 && callee.IsAssemblyOrLinkname {
				opaque[callee.ID] = true
			}
			for _, nc := range caps {
				if nc.Basis != BasisUse {
					continue
				}
				r := WitnessRow{
					Caller: caller.ID, CallerKind: kind, Capability: nc.Capability, Reach: nc.Reach,
					Callee: callee.ID, CalleePackage: ClassificationPackage(callee), ClassifiedBy: nc.ClassifiedBy,
					Confidence: e.Confidence,
					isPlumbing: IsPlumbing(nc.Reach, callee.Symbol),
				}
				if cur, exists := byKey[r.rowKey()]; exists && confRank(cur.Confidence) >= confRank(r.Confidence) {
					continue
				}
				byKey[r.rowKey()] = r
			}
		}
	}
	rows = make([]WitnessRow, 0, len(byKey))
	for _, r := range byKey {
		rows = append(rows, r)
	}
	sortRows(rows)
	markSuppression(rows)
	return rows, unanalyzed, len(opaque)
}

// markSuppression hides suppressed-tier rows and plumbing rows, then promotes
// the first-ranked row of every capability whose rows are all plumbing.
// rows must be in RowLess order.
func markSuppression(rows []WitnessRow) {
	hasOther := make(map[Capability]bool)
	for _, r := range rows {
		if !r.plumbing() {
			hasOther[r.Capability] = true
		}
	}
	promoted := make(map[Capability]bool)
	for i := range rows {
		r := &rows[i]
		r.Suppressed = r.Capability.Tier() == TierSuppressed || r.plumbing()
		if r.plumbing() && !hasOther[r.Capability] && !promoted[r.Capability] {
			promoted[r.Capability] = true
			r.PlumbingOnly = true
			r.Suppressed = r.Capability.Tier() == TierSuppressed
		}
	}
}

func packageDefaults(rows []WitnessRow) []PackageDefault {
	callees := make(map[string]map[string]bool)
	for _, r := range rows {
		if r.ClassifiedBy != ClassifiedByPackageDefault {
			continue
		}
		if callees[r.CalleePackage] == nil {
			callees[r.CalleePackage] = make(map[string]bool)
		}
		callees[r.CalleePackage][r.Callee] = true
	}
	out := make([]PackageDefault, 0, len(callees))
	for pkg, set := range callees {
		out = append(out, PackageDefault{Package: pkg, Callees: len(set)})
	}
	sort.Slice(out, func(i, j int) bool { return packageDefaultLess(out[i], out[j]) })
	return out
}

// packageDefaultLess orders by package, then count.
func packageDefaultLess(a, b PackageDefault) bool {
	if a.Package != b.Package {
		return a.Package < b.Package
	}
	return a.Callees < b.Callees
}

// sensitiveCalls groups rows by normalised callee and keeps the groups that
// meet the membership rule. Only a Direct edge is use, so a callee reached
// only through CHA or weaker edges stays a row and is not a member.
func sensitiveCalls(rows []WitnessRow) []SensitiveCall {
	type group struct {
		call    SensitiveCall
		direct  bool
		kinds   map[CallerKind]bool
		callers map[string]bool
	}
	groups := make(map[string]*group)
	for _, r := range rows {
		if !sensitiveCapabilities[r.Capability] || r.Reach != ReachDirectCall {
			continue
		}
		sc := SensitiveCall{Callee: NormaliseCallee(r.Callee), Capability: r.Capability}
		g, ok := groups[sc.key()]
		if !ok {
			g = &group{call: sc, kinds: make(map[CallerKind]bool), callers: make(map[string]bool)}
			groups[sc.key()] = g
		}
		g.direct = g.direct || r.Confidence == cgdomain.ConfidenceDirect
		g.kinds[r.CallerKind] = true
		g.callers[r.Caller] = true
	}
	out := make([]SensitiveCall, 0, len(groups))
	for _, g := range groups {
		if !g.direct {
			continue
		}
		for k := range g.kinds {
			g.call.CallerKinds = append(g.call.CallerKinds, k)
		}
		sortCallerKinds(g.call.CallerKinds)
		g.call.Callers = len(g.callers)
		out = append(out, g.call)
	}
	sortSensitive(out)
	return out
}

func sortCallerKinds(ks []CallerKind) {
	sort.Slice(ks, func(i, j int) bool { return callerKindLess(ks[i], ks[j]) })
}

// callerKindLess orders by the diff's ranking, then name.
func callerKindLess(a, b CallerKind) bool {
	if ra, rb := callerKindRank(a), callerKindRank(b); ra != rb {
		return ra < rb
	}
	return a < b
}

// sortSensitive orders the roll-up by tier, capability, then callee.
func sortSensitive(s []SensitiveCall) {
	sort.Slice(s, func(i, j int) bool {
		if s[i].Capability != s[j].Capability {
			return capabilityLess(s[i].Capability, s[j].Capability)
		}
		return s[i].Callee < s[j].Callee
	})
}

// collectsAndEgresses names each caller whose own Direct rows hold both a
// collection and an egress member.
func collectsAndEgresses(rows []WitnessRow, members map[string]Capability) []CoLocation {
	byCaller := make(map[string]*CoLocation)
	for _, r := range rows {
		if r.Confidence != cgdomain.ConfidenceDirect {
			continue
		}
		callee := NormaliseCallee(r.Callee)
		if c, ok := members[callee]; !ok || c != r.Capability {
			continue
		}
		cl, ok := byCaller[r.Caller]
		if !ok {
			cl = &CoLocation{Function: r.Caller, CallerKind: r.CallerKind}
			byCaller[r.Caller] = cl
		}
		switch {
		case collectionCapabilities[r.Capability]:
			cl.Collection = appendUnique(cl.Collection, callee)
		case egressCapabilities[r.Capability]:
			cl.Egress = appendUnique(cl.Egress, callee)
		}
	}
	var out []CoLocation
	for _, cl := range byCaller {
		if len(cl.Collection) == 0 || len(cl.Egress) == 0 {
			continue
		}
		slices.Sort(cl.Collection)
		slices.Sort(cl.Egress)
		out = append(out, *cl)
	}
	sort.Slice(out, func(i, j int) bool { return coLocationLess(out[i], out[j]) })
	return out
}

// coLocationLess orders by every field the entry carries.
func coLocationLess(a, b CoLocation) bool {
	if a.Function != b.Function {
		return a.Function < b.Function
	}
	if a.CallerKind != b.CallerKind {
		return a.CallerKind < b.CallerKind
	}
	if c := slices.Compare(a.Collection, b.Collection); c != 0 {
		return c < 0
	}
	return slices.Compare(a.Egress, b.Egress) < 0
}

func appendUnique(xs []string, x string) []string {
	if slices.Contains(xs, x) {
		return xs
	}
	return append(xs, x)
}

// initReachesBoth walks Direct edges backwards from every collection and every
// egress member at once, so each node's distance to the nearest of each is two
// breadth-first passes over the graph rather than one walk per initialiser.
// No depth bound is set.
func initReachesBoth(
	owned []cgdomain.CallNode,
	nodeByID map[string]cgdomain.CallNode,
	adj map[string][]cgdomain.CallEdge,
	members map[string]Capability,
) []InitReach {
	collection, egress := memberNodes(nodeByID, members)
	if len(collection) == 0 || len(egress) == 0 {
		return nil
	}
	reverse := make(map[string][]string)
	for from, es := range adj {
		for _, e := range es {
			// A callee missing from nodeByID is a test node under the production
			// scope: the walk may not pass through it.
			if _, ok := nodeByID[e.ToID]; ok && e.Confidence == cgdomain.ConfidenceDirect {
				reverse[e.ToID] = append(reverse[e.ToID], from)
			}
		}
	}
	cDist, cNear := nearestMember(collection, reverse)
	eDist, eNear := nearestMember(egress, reverse)

	var out []InitReach
	for _, n := range owned {
		if !cgdomain.IsInitSymbol(n.Symbol) {
			continue
		}
		cd, cok := cDist[n.ID]
		ed, eok := eDist[n.ID]
		if !cok || !eok {
			continue
		}
		out = append(out, InitReach{
			Init: n.ID, CallerKind: NodeCallerKind(n), Depth: max(cd, ed),
			CollectionDepth: cd, EgressDepth: ed,
			Collection: NormaliseCallee(cNear[n.ID]), Egress: NormaliseCallee(eNear[n.ID]),
		})
	}
	return out
}

// memberNodes splits the graph nodes that are sensitive-call members into the
// collection and egress halves.
func memberNodes(nodeByID map[string]cgdomain.CallNode, members map[string]Capability) (collection, egress []string) {
	for id, n := range nodeByID {
		for _, nc := range NodeCapabilities(n) {
			if nc.Basis != BasisUse || members[NormaliseCallee(id)] != nc.Capability {
				continue
			}
			if collectionCapabilities[nc.Capability] {
				collection = append(collection, id)
			}
			if egressCapabilities[nc.Capability] {
				egress = append(egress, id)
			}
		}
	}
	return collection, egress
}

// nearestMember is a layered multi-source breadth-first walk over reverse
// edges. For every node that reaches a source it returns the hop count to the
// nearest source and that source, the smallest ID among those at that distance.
func nearestMember(sources []string, reverse map[string][]string) (map[string]int, map[string]string) {
	dist := make(map[string]int, len(sources))
	near := make(map[string]string, len(sources))
	frontier := slices.Clone(sources)
	slices.Sort(frontier)
	for _, s := range frontier {
		dist[s], near[s] = 0, s
	}
	for d := 1; len(frontier) > 0; d++ {
		next := make(map[string]string)
		for _, u := range frontier {
			for _, p := range reverse[u] {
				if _, settled := dist[p]; settled {
					continue
				}
				if cur, ok := next[p]; !ok || near[u] < cur {
					next[p] = near[u]
				}
			}
		}
		frontier = frontier[:0]
		for p, m := range next {
			dist[p], near[p] = d, m
			frontier = append(frontier, p)
		}
		slices.Sort(frontier)
	}
	return dist, near
}
