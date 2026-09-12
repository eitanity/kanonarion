package domain

import (
	"strconv"
	"strings"
)

// DispatchKind names how control reached one hop of a route.
//
// A route is a call stack, and a call stack renders every hop identically
// whether the caller named the callee or the runtime chose it. The two are not
// the same claim. A direct call is a fact about the caller's source; an
// interface dispatch is a fact about the value the caller was handed, and the
// module that supplied that value need not appear on the route at all —
// measured on a working store, a project's own Send(w http.ResponseWriter, ...)
// sits one hop above a router's writer whose wrapper is installed by a third
// module the stack never names.
//
// Every value below is READ off the call-graph edge that reaches the hop —
// its own confidence, reflect-origin and kind fields — and never inferred from
// the shape of the route. Producing a new resolution label rather than reading
// a stored one is edge narrowing, which this deliberately does not do: a
// narrowed dispatch edge can prune a real path into silence.
type DispatchKind string

const (
	// DispatchUnrecorded is the zero value: the hop says nothing about how it was
	// reached. It is the truth about every route stored before this annotation
	// existed, and it means "not recorded" — never "a direct call".
	DispatchUnrecorded DispatchKind = ""

	// DispatchRouteEntry is the route's first hop. Nothing above it is on the
	// route, so there is no call site to read; it is stated rather than left
	// blank so an entry point is not mistaken for a hop the annotation failed on.
	DispatchRouteEntry DispatchKind = "route-entry"

	// DispatchDirect is a statically-known call to a unique concrete callee: the
	// edge's own Direct confidence. It includes an interface site the analyser
	// devirtualised to its sole implementer, which is what the graph recorded.
	DispatchDirect DispatchKind = "direct"

	// DispatchInterface is a call dispatched through an interface: the edge's own
	// CHA-overapprox or VTA confidence. The callee is one of the types satisfying
	// the interface, not a callee the caller named.
	DispatchInterface DispatchKind = "interface"

	// DispatchReflect is an edge resolved through reflection. The callee set is
	// not statically knowable, so the hop is a path the analysis could follow and
	// not one it could bound.
	DispatchReflect DispatchKind = "reflect"

	// DispatchFramework is an edge bound by a framework model or thunk rather
	// than observed in the analysed source.
	DispatchFramework DispatchKind = "framework"

	// DispatchUnresolved is an edge the analyser could not resolve to a concrete
	// callee and did not attribute to reflection. It is recorded as its own kind
	// rather than folded into one of the others, because folding it anywhere is
	// the claim the edge declined to make.
	DispatchUnresolved DispatchKind = "unresolved"

	// DispatchReference is a function VALUE taken at the call site, not an
	// invocation — the shape of every handler registration. It says the callee
	// was named there and nothing about when, or whether, it ran.
	DispatchReference DispatchKind = "reference"

	// DispatchNotAnnotated is the annotation stating it could not read this hop,
	// with HopDispatch.Reason naming the cause. It is a positive value, not an
	// absence, because the one failure this whole annotation exists to prevent is
	// an unreadable hop rendering as a direct call.
	DispatchNotAnnotated DispatchKind = "not-annotated"
)

// IsAnnotated reports whether the kind states something the call graph
// measured about the edge that reached the hop.
//
// DispatchRouteEntry is not annotated: it is the statement that there was no
// edge to read. Neither is the zero value, and neither is the explicit refusal.
func (k DispatchKind) IsAnnotated() bool {
	switch k {
	case DispatchDirect, DispatchInterface, DispatchReflect,
		DispatchFramework, DispatchUnresolved, DispatchReference:
		return true
	default:
		return false
	}
}

// String renders the kind for display, naming the two absences rather than
// printing an empty field.
func (k DispatchKind) String() string {
	switch k {
	case DispatchUnrecorded:
		return "not recorded"
	case DispatchNotAnnotated:
		return "not annotated"
	default:
		return string(k)
	}
}

// HopDispatch states how control reached one hop of a route, read off the
// call-graph edge that reaches it.
//
// It is computed at SCAN time and sealed with the record. A route is inside the
// record's content hash, so an annotation added at read time would either mutate
// a sealed record or produce two renderings of one stored route that disagree.
// The consequence is stated rather than hidden: a route already in the store
// stays unannotated until its finding is re-scanned.
//
// A zero HopDispatch means the hop says nothing — a route written before this
// existed. That is why Kind carries DispatchNotAnnotated for a hop the
// annotation ran on and could not read: "tried and could not" and "never tried"
// are different facts and a reader must be able to tell them apart.
//
// Every field is a scalar and the whole value is comparable, so a frame carrying
// one stays comparable too.
type HopDispatch struct {
	// Kind is how control reached the hop. It is always set on an annotation that
	// ran, including when the answer is that nothing could be read.
	Kind DispatchKind `json:"kind,omitzero"`
	// Confidence is the call-graph edge's own resolution label, verbatim —
	// "Direct", "CHA-overapprox", "VTA", "Framework", "Unknown". Kind is the
	// vocabulary a reader acts on; this is the word the graph actually stored, so
	// nothing is lost in the translation between them.
	Confidence string `json:"confidence,omitzero"`
	// Reason states why an unannotated hop could not be read, in the graph's own
	// terms. It is non-empty whenever Kind is DispatchNotAnnotated.
	Reason string `json:"reason,omitzero"`
	// Graph names the module coordinate whose call graph the edge was read from —
	// the module the CALL SITE is in, which is the caller's, not this hop's. It is
	// stated on every annotation, including a refusal, because it is what a reader
	// re-runs to check the answer.
	Graph string `json:"graph,omitzero"`
	// GraphCompleteness is the fidelity that graph was built at, in the
	// call-graph ladder's own terms. A graph below BUILT_WITH_BODIES has call
	// edges missing by construction, so an annotation over it carries its own
	// caveat.
	GraphCompleteness string `json:"graph_completeness,omitzero"`
	// CallSite is "file:line" within the calling module, where the graph recorded
	// the call being made. Empty when the edge carries no position.
	CallSite string `json:"call_site,omitzero"`
	// Interface is the interface crossed, as a "pkg/path.Name" id, on a hop the
	// graph could attribute to one. Empty on an interface hop the graph records
	// the dispatch of but cannot attribute — the edge does not carry the interface
	// it dispatched through, so it is recovered from the implementation relation,
	// which the analysed module computes over its OWN declarations only.
	Interface string `json:"interface,omitzero"`
	// ImplementationModule is the module supplying the implementation that ran.
	// It is stated because it is the question an interface hop raises and the
	// route alone cannot settle; where it equals the hop's own module, that IS
	// the answer and saying so costs a reader nothing.
	ImplementationModule string `json:"implementation_module,omitzero"`
	// Implementers is how many concrete types the graph records as satisfying
	// Interface, INCLUDING the one that ran. The count is recorded and the list is
	// not: the list is unbounded and belongs in the query ImplementersQuery names.
	//
	// It is never zero when Interface is named — the implementation that ran is
	// itself one — so zero means "not counted" and is never "no implementers".
	Implementers int `json:"implementers,omitzero"`
	// ImplementersQuery is the command that lists them.
	ImplementersQuery string `json:"implementers_query,omitzero"`
}

// IsRecorded reports whether the hop says anything at all about how it was
// reached.
func (d HopDispatch) IsRecorded() bool { return d != HopDispatch{} }

// String renders the annotation for a report: the kind, then what it rests on.
//
// The kind leads and the basis follows, on the same terms as every other
// evidence line in this domain: a bare kind is a label, and a label is what
// turns a measurement into a verdict.
func (d HopDispatch) String() string {
	if !d.IsRecorded() {
		return "dispatch not recorded"
	}
	parts := []string{d.Kind.String()}
	if d.Confidence != "" {
		parts = append(parts, "edge confidence "+d.Confidence)
	}
	if d.Interface != "" {
		iface := "through " + d.Interface
		if d.Implementers > 0 {
			iface += " (" + strconv.Itoa(d.Implementers) + " implementer(s) recorded)"
		}
		parts = append(parts, iface)
	}
	if d.ImplementationModule != "" {
		parts = append(parts, "implementation from "+d.ImplementationModule)
	}
	if d.CallSite != "" {
		parts = append(parts, "at "+d.CallSite)
	}
	// The graph is named only where an edge was actually read from it. On a
	// refusal the reason names the graph itself, and saying "read from the call
	// graph of X" beside "no call graph is held for X" would contradict itself in
	// one line.
	if d.Graph != "" && d.Kind.IsAnnotated() {
		graph := "read from the call graph of " + d.Graph
		if d.GraphCompleteness != "" {
			graph += " (" + d.GraphCompleteness + ")"
		}
		parts = append(parts, graph)
	}
	if d.Reason != "" {
		parts = append(parts, d.Reason)
	}
	line := strings.Join(parts, ", ")
	if d.ImplementersQuery != "" {
		line += " — list them: " + d.ImplementersQuery
	}
	return line
}

// DispatchKindOfEdge is the one place an edge's own fields become a dispatch
// kind. Nothing else may decide one.
//
// The order of the tests is the order the facts dominate each other, and each
// step is a reading rather than a judgement:
//
//  1. A reference edge is not a call at all, whatever confidence it carries, so
//     it can never be reported as one.
//  2. A reflect-dispatched edge is recorded with Unknown confidence — reflection
//     is not a confidence rank — so the reflect origin has to be read before the
//     confidence or it is lost inside "unresolved".
//  3. The confidence vocabulary then decides, value by value.
//
// A confidence this build does not know is UNRESOLVED, never direct. A record
// written by a future analyser must not have an unfamiliar label rounded down to
// the strongest claim in the vocabulary.
func DispatchKindOfEdge(confidence string, reflectDispatch bool, reference bool) DispatchKind {
	switch {
	case reference:
		return DispatchReference
	case reflectDispatch:
		return DispatchReflect
	}
	switch confidence {
	case "Direct":
		return DispatchDirect
	case "CHA-overapprox", "VTA":
		return DispatchInterface
	case "Framework":
		return DispatchFramework
	default:
		return DispatchUnresolved
	}
}

// AnnotateRouteEntries stamps the route-entry kind on the first hop of every
// route that carries no annotation yet, and reports how many it stamped.
//
// It is separate from reading the graph because it needs no graph: the first hop
// of a route has no hop above it, so there is no call site anywhere that could
// be read for it. Saying so is what keeps the entry point out of the
// "unannotated" bucket, which is about hops that HAVE a call site the graph
// could not produce.
func AnnotateRouteEntries(routes []ReachabilityRoute) int {
	stamped := 0
	for _, route := range routes {
		if len(route) == 0 || route[0].Dispatch.IsRecorded() {
			continue
		}
		route[0].Dispatch = HopDispatch{
			Kind:   DispatchRouteEntry,
			Reason: "this is the route's first hop: no hop above it, so there is no call site to read",
		}
		stamped++
	}
	return stamped
}

// DispatchTally counts the hops of a set of routes by dispatch kind, so a scan
// can report what it annotated and what it could not without the caller walking
// the routes a second time.
type DispatchTally struct {
	// Hops is every hop counted, annotated or not.
	Hops int
	// ByKind counts hops per kind, including the unrecorded and route-entry ones.
	ByKind map[DispatchKind]int
}

// TallyDispatch counts the hops of every route by kind.
func TallyDispatch(routes []ReachabilityRoute) DispatchTally {
	tally := DispatchTally{ByKind: map[DispatchKind]int{}}
	for _, route := range routes {
		for _, hop := range route {
			tally.Hops++
			tally.ByKind[hop.Dispatch.Kind]++
		}
	}
	return tally
}

// Annotated is the number of hops whose kind states something the call graph
// measured.
func (t DispatchTally) Annotated() int {
	n := 0
	for kind, count := range t.ByKind {
		if kind.IsAnnotated() {
			n += count
		}
	}
	return n
}

// String renders the tally as "N of M hops annotated" followed by the
// decomposition, so a log line carries the split the acceptance asks for rather
// than a single number that hides it.
func (t DispatchTally) String() string {
	kinds := []DispatchKind{
		DispatchDirect, DispatchInterface, DispatchReflect, DispatchFramework,
		DispatchUnresolved, DispatchReference, DispatchRouteEntry,
		DispatchNotAnnotated, DispatchUnrecorded,
	}
	var b strings.Builder
	b.WriteString(strconv.Itoa(t.Annotated()))
	b.WriteString(" of ")
	b.WriteString(strconv.Itoa(t.Hops))
	b.WriteString(" hops annotated")
	parts := make([]string, 0, len(kinds))
	for _, kind := range kinds {
		if n := t.ByKind[kind]; n > 0 {
			parts = append(parts, kind.String()+" "+strconv.Itoa(n))
		}
	}
	if len(parts) > 0 {
		b.WriteString(" (")
		b.WriteString(strings.Join(parts, ", "))
		b.WriteString(")")
	}
	return b.String()
}
