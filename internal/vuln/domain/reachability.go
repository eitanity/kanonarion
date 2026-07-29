package domain

import "strings"

// ReachabilityAnalyser names the instrument that produced a reachability
// answer.
//
// Two instruments answer this question in kanonarion and they are not
// interchangeable. They read different inputs, they fail differently, and one
// of them can name the module version at each hop while the other cannot. An
// answer that does not say which one produced it cannot be weighed against
// another answer at all.
type ReachabilityAnalyser string

const (
	// AnalyserUnrecorded is the zero value: the answer does not say what
	// produced it. Every reachability result written before the derivation was
	// recorded carries it. It means "not recorded", never "no analysis".
	AnalyserUnrecorded ReachabilityAnalyser = ""

	// AnalyserGovulncheck is govulncheck's own analysis, read out of the trace
	// it reports beside each finding. It is the instrument behind almost every
	// reachability answer in a working store, because it runs on both the
	// isolated and the target-rooted paths. Its route names a module path at
	// every hop and a version at every hop OUTSIDE the analysed root, which has
	// none because a main module has none in a Go build.
	AnalyserGovulncheck ReachabilityAnalyser = "govulncheck"

	// AnalyserCallGraphBFS is kanonarion's own breadth-first search over the
	// stored call graph. It runs only on an isolated scan asked for
	// reachability. Its route is UNVERSIONED — see ReachabilityRoute.
	AnalyserCallGraphBFS ReachabilityAnalyser = "callgraph-bfs"
)

// IsRecorded reports whether the answer names the instrument that produced it.
func (a ReachabilityAnalyser) IsRecorded() bool { return a != AnalyserUnrecorded }

// String renders the analyser for display, naming the unrecorded case rather
// than printing an empty field.
func (a ReachabilityAnalyser) String() string {
	if a == AnalyserUnrecorded {
		return "not recorded"
	}
	return string(a)
}

// ReachabilityFrame is one hop on the route from an entry point to a vulnerable
// symbol.
//
// ModuleVersion is what makes the route checkable against another build, and it
// is the field a route of bare symbol strings cannot carry. Without it a reader
// cannot tell whether their own build traverses the same modules at the same
// versions — and it very often does not, which is the whole reason a route is
// not a fact about a dependency pair.
//
// ModuleVersion is empty when the producing analyser does not know it. That is
// a statement, not a gap: see AnalyserCallGraphBFS.
type ReachabilityFrame struct {
	ModulePath    string `json:"module_path,omitzero"`
	ModuleVersion string `json:"module_version,omitzero"`
	Package       string `json:"package,omitzero"`
	Receiver      string `json:"receiver,omitzero"`
	Symbol        string `json:"symbol,omitzero"`
}

// String renders one hop as "module@version pkg.(Recv).Symbol", omitting the
// parts the analyser could not supply rather than printing empty delimiters.
func (f ReachabilityFrame) String() string {
	var b strings.Builder
	if f.ModulePath != "" {
		b.WriteString(f.ModulePath)
		if f.ModuleVersion != "" {
			b.WriteString("@")
			b.WriteString(f.ModuleVersion)
		}
		b.WriteString(" ")
	}
	if f.Package != "" && f.Package != f.ModulePath {
		b.WriteString(f.Package)
		b.WriteString(".")
	}
	if f.Receiver != "" {
		b.WriteString("(")
		b.WriteString(f.Receiver)
		b.WriteString(").")
	}
	b.WriteString(f.Symbol)
	return strings.TrimSpace(b.String())
}

// ReachabilityRoute is one path from an entry point to the vulnerable symbol,
// ordered ENTRY POINT FIRST and vulnerable symbol last.
//
// The order is normalised here because the two analysers disagree about it:
// govulncheck's trace runs from the vulnerable symbol up the call stack, and
// the call-graph search runs the other way. A stored route that could be in
// either order is a route no consumer can render without guessing.
//
// A route is A path, exactly as the producing analyser reported it. It is a
// CALL STACK, not a dependency chain, and the difference shows wherever a hop
// crosses an interface: the route names the concrete function that ran, not the
// module that supplied or installed the implementation. Measured on a working
// store: a project's own Send(w http.ResponseWriter, ...) appears one hop above
// github.com/go-chi/chi's middleware writer, because the value it was handed was
// chi's — while the module that installs that wrapper is a third one that never
// appears, and correctly so, since it is not on the stack.
//
// So a route answers "here is a way this ran", never "here is every module
// involved in making it run". Absence from a route is not evidence a module is
// uninvolved.
type ReachabilityRoute []ReachabilityFrame

// IsVersioned reports whether the route can be checked against another build:
// it crosses at least one module boundary, and every hop outside the root
// module names the version it was in.
//
// Hops in the ROOT module are exempt, and that is a fact about Go rather than a
// concession. The root of an analysis is a main module, which has no version in
// a build, so govulncheck emits every one of its frames with an empty version —
// and a route often spends several hops inside the project before it reaches a
// dependency at all. Requiring a version of those would report almost every
// real route as uncheckable. Measured on a working store: a route through three
// of the project's own functions before reaching google.golang.org/grpc@v1.82.0
// is entirely checkable, because the only part a reader compares against their
// own build is the dependency part.
//
// Every hop OUTSIDE the root must name a version. A route versioned for some
// dependencies and not others cannot be checked at all, so it is reported as
// unversioned rather than inviting the misreading the version exists to
// prevent.
//
// A route that never leaves the root module is not checkable either: there is
// no dependency in it to compare. That is what a route from the call-graph
// search reduces to as well — the projection it reads records no module
// versions anywhere.
func (r ReachabilityRoute) IsVersioned() bool {
	if len(r) < 2 {
		return false
	}
	root := r[0].ModulePath
	crossed := false
	for _, f := range r[1:] {
		if f.ModulePath == root {
			continue
		}
		crossed = true
		// A hop kanonarion cannot identify at all fails here too: treating a
		// nameless hop as satisfied would let an unidentifiable route report
		// itself as checkable.
		if f.ModuleVersion == "" {
			return false
		}
	}
	return crossed
}

// Reverse returns the route in the opposite order. It exists for the
// govulncheck adapter, whose trace arrives vulnerable-symbol-first.
func (r ReachabilityRoute) Reverse() ReachabilityRoute {
	out := make(ReachabilityRoute, len(r))
	for i, f := range r {
		out[len(r)-1-i] = f
	}
	return out
}

// ReachabilityDerivation states how a reachability answer was reached.
//
// It qualifies the whole answer, not just the route. A bare IsReachable is
// exactly as dependent on its derivation as the path is: "reachable" from a
// binary-mode symbol-table scan and "reachable" from a source-mode call graph
// are different claims, and "not reachable" from a metadata-only graph is
// barely a claim at all.
//
// It is carried on the result rather than left to be read off the record's own
// Rooting because a finding travels: it is copied into scan reports, into
// vuln-by-id answers, into the JSON output and into scan-run diffs, separately
// from the record that holds it. A label that requires its parent to be
// interpreted is a label that will be read without one.
type ReachabilityDerivation struct {
	// Analyser is the instrument.
	Analyser ReachabilityAnalyser `json:"analyser,omitzero"`
	// Fidelity is how well that instrument could see, in the instrument's own
	// terms: the scan mode (source or binary) for govulncheck, the call-graph
	// completeness level for the search. It is deliberately one opaque string
	// rather than a union — the two scales are not comparable, and the analyser
	// field is what says which scale is in use.
	Fidelity string `json:"fidelity,omitzero"`
	// Rooting is the analysis frame the answer was reached in, repeated from the
	// record for the reason given on the type. Empty when the writer did not
	// state one.
	Rooting Rooting `json:"rooting,omitzero"`
}

// IsRecorded reports whether the derivation says anything at all.
func (d ReachabilityDerivation) IsRecorded() bool { return d != ReachabilityDerivation{} }

// String renders the derivation for a report: the instrument, how well it could
// see, and what it was rooted at.
func (d ReachabilityDerivation) String() string {
	if !d.IsRecorded() {
		return "derivation not recorded"
	}
	parts := []string{"by " + d.Analyser.String()}
	if d.Fidelity != "" {
		parts = append(parts, "fidelity "+d.Fidelity)
	}
	if d.Rooting.IsRecorded() {
		parts = append(parts, "rooted at "+d.Rooting.String())
	}
	return strings.Join(parts, ", ")
}

// StampReachabilityRooting copies the record's analysis frame onto every
// reachability answer it carries that does not already state one.
//
// The frame is decided by the use case that persists the record, and the
// analysers that produce reachability run below it and cannot know it. This is
// the one place the two meet, so every writer calls it before sealing.
//
// It fills only what is empty. An analyser that could state the frame itself
// keeps its own answer, on the same terms as the record seal's axis handling.
func StampReachabilityRooting(record *VulnerabilityRecord) {
	for i := range record.Findings {
		r := record.Findings[i].Reachable
		if r == nil || r.DerivedBy.Rooting.IsRecorded() {
			continue
		}
		r.DerivedBy.Rooting = record.Rooting
	}
}
