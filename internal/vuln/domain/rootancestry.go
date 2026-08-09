package domain

import "strconv"

// EntryPointAncestry is how far a route's root sits below the nearest entry
// point, and what the weakest edge on that path was.
//
// WHY THIS IS A DISTANCE AND NOT A KIND. Root classification decides `ingress`
// from the node's own identity — a package initialiser, a receiverless main, a
// ServeHTTP method, or an in-edge from outside the module. A handler that runs
// because it was REGISTERED with a router has none of those properties, so it
// classifies `internal`, correctly by that definition, while an HTTP request
// drives it on every call. Measured on a 21,713-node application graph, 70.7% of
// owned nodes sit transitively under an entry point while classifying
// `internal`; the distinction a triager wants is not the one the kind measures.
//
// Making `ingress` transitive would be worse than leaving it alone. On the same
// graph a majority of the edges into owned nodes are not `Direct` — CHA
// over-approximations and unresolved dispatches outnumber them — so a transitive
// rule would inherit that over-approximation wholesale and label most of the
// codebase `ingress`, which is as useless as labelling all of it `internal` and
// considerably more misleading. So the node keeps its kind and gains a
// measurement beside it: "internal, 4 hops below an ingress, weakest edge on
// that path CHA-overapprox" is a fact a reader can weigh. "ingress" would be a
// claim.
//
// It is NOT an exploitability statement. A short all-`Direct` distance says the
// graph supports the transitive reading; it says nothing about whether the data
// an attacker controls reaches the vulnerable call. This is a statement about
// graph shape.
//
// It is derived at read time and carries no json tags, on the same terms as
// RouteRoot: a classification frozen into a sealed record would be stuck at
// whichever call-graph generation existed when the scan ran.
type EntryPointAncestry struct {
	// Computed reports whether the search ran at all. False means "not asked" —
	// no graph was available, or the root was never resolved — and must never be
	// read as "no ancestor". That distinction is the whole point of the field:
	// an unmeasured axis and a measured absence are different answers.
	Computed bool
	// Found reports whether an entry-point ancestor was reached. False on a
	// computed search is a measurement: nothing in the graph enters this code.
	Found bool
	// Hops is the number of edges from the nearest entry-point ancestor down to
	// the root. Zero with Found means the root is ITSELF an entry point.
	Hops int
	// EntryPointID is the ancestor the search stopped at, and EntryPointReason
	// what made it one — the same reason string the ingress kind carries, so a
	// reader can tell a package initialiser from a request handler.
	EntryPointID     string
	EntryPointReason string
	// Weakest is the weakest edge confidence on the path that was found, in the
	// call graph's own vocabulary. It is what stops a distance being read as a
	// certainty: four hops of CHA over-approximation are not four hops of
	// resolved calls.
	Weakest string
	// ViaReference is true when at least one hop on the path is a REFERENCE
	// rather than a call — a function value taken and handed to a router or a
	// framework. It is carried apart from Weakest because a reference edge is
	// exactly resolved (the analyser knows which function's value was taken) and
	// would otherwise report as `Direct`, laundering a registration into an
	// all-calls chain. A path is an all-`Direct` CALL path only when Weakest is
	// Direct and this is false.
	ViaReference bool
	// SearchBound is the hop limit the search used, or 0 for unbounded. It is
	// recorded so "no ancestor" is readable as what it is: unbounded, nothing
	// enters this code; bounded, nothing enters it within that many hops.
	SearchBound int
}

// IsRecorded reports whether the search ran.
func (a EntryPointAncestry) IsRecorded() bool { return a.Computed }

// IsAllDirectCallPath reports whether every hop from the entry point down to the
// root is a statically-resolved call — the one case where reading the distance
// as "this is driven by that entry point" is sound without caveat.
//
// A reference hop disqualifies it however the edge itself resolved: a
// registration is not a call, and a path that launders a value-flow into a
// direct chain reintroduces exactly the over-approximation this measurement
// refuses to make.
func (a EntryPointAncestry) IsAllDirectCallPath() bool {
	return a.Computed && a.Found && a.Weakest == "Direct" && !a.ViaReference
}

// String renders the ancestry as a clause for the root line, or "" when nothing
// was computed — a caller appending it never has to test first.
//
// There is no separate "all-Direct" phrasing. It would be a third way of saying
// what the distance and the weakest confidence already say together, and the
// measurement that decided the output shape says the set is small: 121 of 10,405
// owned nodes on one real graph, 345 of 21,713 on another. A reader who wants
// that set reads Weakest == Direct with no reference hop, which is the same
// sentence with fewer words to keep in step.
func (a EntryPointAncestry) String() string {
	if !a.Computed {
		return ""
	}
	if !a.Found {
		if a.SearchBound > 0 {
			return "no entry-point ancestor within " + strconv.Itoa(a.SearchBound) + " hops"
		}
		return "no entry-point ancestor anywhere in the analysed graph"
	}
	if a.Hops == 0 {
		return "this root IS the entry point"
	}
	out := strconv.Itoa(a.Hops) + " hops below " + a.EntryPointID
	if a.EntryPointReason != "" {
		out += " (" + a.EntryPointReason + ")"
	}
	if a.Weakest != "" {
		out += ", weakest edge on that path " + a.Weakest
	}
	if a.ViaReference {
		out += ", and at least one hop is a reference rather than a call — the value was registered, not invoked"
	}
	return out
}
