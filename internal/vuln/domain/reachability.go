package domain

import (
	"strconv"
	"strings"
)

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

// String renders the route as its hops joined by arrows, entry point first.
//
// A long route is elided in the middle rather than truncated at the end: the
// two hops a reader checks first are where the path starts and what it reaches,
// and dropping the tail would remove the second one.
func (r ReachabilityRoute) String() string {
	const shown = 6
	frames := make([]string, 0, len(r))
	for _, f := range r {
		frames = append(frames, f.String())
	}
	if len(frames) > shown {
		head := frames[:shown-1]
		tail := frames[len(frames)-1]
		return strings.Join(head, " -> ") +
			" -> … (" + strconv.Itoa(len(frames)-shown) + " more) -> " + tail
	}
	return strings.Join(frames, " -> ")
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

// NegativeSearch is the result of running kanonarion's own call-graph search
// for a finding whose recorded negative rests on another analyser's silence.
//
// It is attached at READ time and never serialised: the stored record is left
// byte-identical, so a search that runs today classifies every negative already
// in the store without a re-scan and without a pipeline generation. It is the
// same move NegativeSoundness itself makes — derive from what is held rather
// than freeze an answer into new records — carried one step further, from
// classifying the recorded derivation to running the search that derivation
// admits never ran.
//
// A nil NegativeSearch means no search ran: no call graph is held for the
// coordinate, the graph names none of the advisory's symbols, or the negative
// was not one this search may speak to. It never means "searched and found
// nothing"; that is a non-nil value with PathFound false.
type NegativeSearch struct {
	// Fidelity is the completeness level of the graph searched, in the
	// call-graph ladder's own terms. It is what decides whether a clean search
	// may confirm the negative.
	Fidelity string
	// PathFound reports that the search DID reach a vulnerable symbol from an
	// entry point — a direct contradiction of the negative the record states.
	PathFound bool
	// Route is that path, entry point first. Empty unless PathFound.
	Route ReachabilityRoute
	// InRecordedFrame reports whether the graph searched is a graph OF the frame
	// the record was measured in — the analysed module's own build — rather than
	// a graph of the module standing alone inside someone else's.
	//
	// It decides what a found path is allowed to mean, and the asymmetry is the
	// point. A search that finds NOTHING confirms in any frame: a consumer can
	// only enter a module through the roots this graph already traverses from, so
	// what the module cannot reach in its own graph, no build above it reaches
	// either. A search that finds a path proves only that the module reaches the
	// symbol WITHIN ITSELF, which is not the question a record measured in
	// another build asked, and contradicting that record with it would report a
	// disagreement that does not exist.
	InRecordedFrame bool
}

// disputedReason states a contradiction between two analysers in full, naming
// both answers and the path the second one found.
//
// It says what each instrument was answering about, because the two questions
// are not the same one: an analyser's silence is about the build it analysed,
// and a search over the stored graph is about the graph kanonarion holds. A
// disagreement between them is therefore information — most often about
// dispatch the first analyser could not follow — and not automatically an error
// in either.
func disputedReason(recorded ReachabilityDerivation, s *NegativeSearch) string {
	var b strings.Builder
	b.WriteString("the negative was recorded by " + recorded.Analyser.String())
	if recorded.Fidelity != "" {
		b.WriteString(" at fidelity " + recorded.Fidelity)
	}
	b.WriteString(", but a call-graph search over kanonarion's own ")
	b.WriteString(s.Fidelity)
	b.WriteString(" graph reaches the vulnerable symbol")
	if len(s.Route) == 1 {
		// A one-hop route is not a call chain: the symbol is itself a root the
		// search starts from. Saying "a path was found" for it would overstate
		// what was measured, and being a root is the substance of the
		// disagreement — a root is shipped code an application enters by dispatch
		// no static analysis can enumerate, or a library's own exported API, and
		// the recorded analyser treated it as entered by nothing.
		b.WriteString(" as a traversal root: " + s.Route[0].String() +
			" is itself an entry point of the analysed module's graph, not a symbol behind one")
	} else if r := s.Route.String(); r != "" {
		b.WriteString(" along " + r)
	}
	b.WriteString(". The two disagree — the recorded answer is about the build that analyser saw, " +
		"the search is about the graph this store holds — so the negative is reported as measured " +
		"and is NOT confirmed; treat it as open until one of the two is explained")
	return b.String()
}

// completenessBuiltWithBodies is the one call-graph fidelity a confident
// negative may rest on, as a string because a VulnerabilityRecord and a
// ReachabilityDerivation both store the level as one and this domain does not
// depend on the call-graph domain — the same reason completenessRung compares
// strings. TestNegativeSoundness_CoversEveryCallGraphLevel pins the two
// together, so a level added there cannot quietly acquire a confirmed negative.
const completenessBuiltWithBodies = "BUILT_WITH_BODIES"

// NegativeSoundness states how thorough the search behind a negative
// reachability answer was, and why, deriving both from what the finding already
// records rather than from a field a scan would have had to write.
//
// Deriving is the point. The producing analyser and its own fidelity are already
// on every answer, so a rung computed here classifies every record in a working
// store the moment it lands — including the 1,209 written before this existed —
// and improves whenever the inputs improve. A recorded rung would freeze the
// answer at scan time and be blank on all of them.
//
// The rules, in the order they are applied:
//
//  1. A finding with no reachability answer, and a REACHABLE one, state no
//     soundness. A route is its own evidence; there is no absence to qualify.
//  2. An advisory that names no symbols for this module path is unsearchable,
//     checked before everything else because it is the one cause no fidelity and
//     no re-run can change. The read side already orders these the same way, for
//     the same reason: advice to go and build a better call graph cannot help
//     resolve a symbol the advisory never named.
//  3. A call-graph search confirms a negative only at BUILT_WITH_BODIES. Every
//     lower rung of that ladder — TYPE_ONLY, METADATA_ONLY, FAILED, unrecorded —
//     leaves call edges unbuilt, so a route may exist that the search could not
//     see.
//  4. GOVULNCHECK NEVER CONFIRMS A NEGATIVE, at any fidelity. This is structural,
//     not a judgement about the tool: govulncheck emits findings for what it
//     REACHED, so a module it examined and did not report produces no finding at
//     all, and the negative kanonarion holds for it was manufactured by matching
//     the advisory database against the coordinate afterwards. Measured on a
//     working store: every one of the 236 confident negatives arrived by that
//     route, and none by a search. Source mode is the strongest form of that
//     silence — packages loaded, call graph built over the whole build — and is
//     inferred; binary mode inspected a symbol table with no call graph behind it
//     and is unconfirmed.
//  5. An answer that does not name its analyser is unconfirmed. It may have come
//     from anywhere, and a search that cannot be identified cannot be weighed.
//
// Between rules 2 and 3 sits the read-time search — see NegativeSearch. Where
// one ran and came back empty it becomes the derivation rules 3 to 5 weigh, so a
// negative stamped from silence is judged on the search that has since run over
// it rather than on the silence. Where it found a path instead, rule 4 still
// refuses to confirm and the rung says the two analysers disagree; the recorded
// verdict is never overwritten by the search, in either direction.
//
// reason is always non-empty when a rung is returned, and it names the basis in
// the producing analyser's own terms. A bare rung is a label, and a label is what
// turns a measurement into a verdict.
func NegativeSoundness(f VulnerabilityFinding) (soundness ReachabilitySoundness, reason string) {
	if f.Reachable == nil || f.Reachable.IsReachable {
		return SoundnessNotStated, ""
	}
	if f.AdvisoryNamesNoSymbols {
		return SoundnessUnsearchable, "the advisory names no symbols for this module path, so there was never a symbol for a search to look for; no fidelity and no re-scan changes that"
	}

	d := f.Reachable.DerivedBy
	// A search that ran at read time answers ahead of the recorded derivation,
	// which by construction is one that never searched. Where it found the path
	// the record denies, neither answer is discarded: rule 4 still refuses to
	// confirm, and the rung says the two disagree.
	if s := f.NegativeSearch; s != nil {
		switch {
		case s.PathFound && s.InRecordedFrame:
			return SoundnessDisputed, disputedReason(d, s)
		case s.PathFound:
			// A path inside the module's own graph is not a contradiction of a
			// negative measured in another build. The recorded rung stands, and the
			// path is stated beside it rather than dropped: a route this tool found
			// and did not report is the one outcome a reachability tool must never
			// produce.
			rung, reason := soundnessFromDerivation(d)
			return rung, reason + crossFrameNote(s)
		default:
			d = ReachabilityDerivation{Analyser: AnalyserCallGraphBFS, Fidelity: s.Fidelity, Rooting: d.Rooting}
		}
	}
	return soundnessFromDerivation(d)
}

// crossFrameNote states a path the search found in the module's own graph that
// the recorded frame's question did not ask about.
func crossFrameNote(s *NegativeSearch) string {
	note := " — separately, a call-graph search over this module's own " + s.Fidelity +
		" graph does reach the vulnerable symbol from that module's own entry points"
	if r := s.Route.String(); r != "" && len(s.Route) > 1 {
		note += " along " + r
	}
	return note + ". That is a different question from the one this record answers, so it does not contradict the negative;" +
		" it is stated because a route found and not reported is worse than one reported with its frame named"
}

// soundnessFromDerivation is the rung a negative earns from the instrument that
// produced it and how well that instrument could see. It is separate from
// NegativeSoundness so that a read-time search and a recorded derivation are
// weighed on exactly one ladder.
func soundnessFromDerivation(d ReachabilityDerivation) (soundness ReachabilitySoundness, reason string) {
	switch d.Analyser {
	case AnalyserCallGraphBFS:
		if d.Fidelity == completenessBuiltWithBodies {
			return SoundnessConfirmed, "a call-graph search ran over a graph built with function bodies and found no path from an entry point to the vulnerable symbol"
		}
		if d.Fidelity == "" {
			return SoundnessUnconfirmed, "a call-graph search ran, but the graph does not state the fidelity it was built at, so the absence of a path cannot be weighed"
		}
		return SoundnessUnconfirmed, "the call graph was " + d.Fidelity + ", not " + completenessBuiltWithBodies +
			" — call edges out of unbuilt bodies are absent, so a route may exist that this search could not see"
	case AnalyserGovulncheck:
		switch ScanMode(d.Fidelity) {
		case ScanModeSource:
			return SoundnessInferred, "govulncheck analysed this build from source and reported no route to the vulnerable symbol; the negative reads that silence, not a search over a call graph that ran and came back empty"
		case ScanModeBinary:
			return SoundnessUnconfirmed, "govulncheck inspected a symbol table in binary mode; no call graph existed, so no route could have been found whether or not one exists"
		default:
			return SoundnessUnconfirmed, "the answer came from govulncheck but does not state the mode it ran in, so it cannot be told from a binary-mode one"
		}
	default:
		return SoundnessUnconfirmed, "the answer does not name the analyser that produced it, so the search behind it cannot be weighed"
	}
}
