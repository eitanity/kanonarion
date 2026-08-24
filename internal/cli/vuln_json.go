package cli

import (
	vuldomain "github.com/eitanity/kanonarion/internal/vuln/domain"
)

// This file holds the one JSON projection every command that publishes a stored
// vulnerability finding renders through.
//
// A negative reachability answer is the answer an operator acts on by NOT
// upgrading, so it owes the reader the rung that says how thorough the search
// behind it was. That rung is DERIVED from the finding — vuldomain.NegativeSoundness
// reads the producing analyser and that analyser's own fidelity — and is not, and
// must not become, a stored field: the record hash is taken over the record's own
// JSON, so a field written into the domain type would re-hash every stored record
// to say something the store can already work out.
//
// The projections below therefore wrap the domain types rather than extending
// them. Each embeds the domain value so every field it carries — including fields
// added to it later — keeps reaching the wire unchanged, and shadows only the
// collection whose elements gain the rung. A hand-copied field list would go
// silently short the first time the domain grew a field, which is the failure this
// shape exists to make impossible.

// vulnFindingRungJSON is one stored finding on the wire with its derived
// reachability rung beside it.
//
// Soundness is emitted on every finding, positive and negative alike, and never
// omitted. "not stated" on a reachable finding is a statement — a route is its
// own evidence and there is no absence to qualify — and it is a different
// statement from the key being missing, which says the producer does not derive
// the rung at all. SoundnessReason is omitted when there is none, because
// NegativeSoundness returns a reason exactly when it returns a rung.
type vulnFindingRungJSON struct {
	vuldomain.VulnerabilityFinding
	Soundness       vuldomain.ReachabilitySoundness `json:"soundness"`
	SoundnessReason string                          `json:"soundness_reason,omitempty"`
}

// vulnFindingJSON is a finding whose producer holds the record its routes were
// measured in, and therefore derives the root of the first of them too.
//
// RouteRoot is the same object, under the same key and with the same field
// names, that 'reachability --json' publishes for a single advisory, built by
// the same two functions the text renderer calls. It answers the question the
// route alone cannot: whether the path begins at a genuine entry point or at
// the node the analyser happened to stop at, how far below the nearest entry
// point that is, how weak the weakest edge on the way is, and whether a hop was
// a registration rather than a call. A reader weighing a reachable verdict is
// weighing exactly those things, and the text surface has printed them all
// along.
//
// It is NEVER omitted, and it is null on a finding that records no route. The
// two absences say different things and a consumer must be able to tell them
// apart: null is "this finding has no route to classify", and the key missing —
// which is what vulnFindingRungJSON emits — is "this producer does not derive
// the root at all". Emitting nothing for a routeless finding would have collapsed
// them, which is the reading rule this object already applies to its ancestry
// block one level down.
type vulnFindingJSON struct {
	vulnFindingRungJSON
	RouteRoot *routeRootOutput `json:"route_root"`
}

// toVulnFindingRungJSON derives the rung for one finding.
func toVulnFindingRungJSON(f vuldomain.VulnerabilityFinding) vulnFindingRungJSON {
	soundness, reason := vuldomain.NegativeSoundness(f)
	return vulnFindingRungJSON{VulnerabilityFinding: f, Soundness: soundness, SoundnessReason: reason}
}

// toVulnFindingJSON derives the rung and the first route's root for one finding.
//
// classify is the record's own classifier. A nil one is the caller that holds no
// call-graph reader, and it yields the same null a routeless finding does — so
// every producer of this type must pass a real classifier when the store has
// one, or emit vulnFindingRungJSON instead and leave the key off.
func toVulnFindingJSON(f vuldomain.VulnerabilityFinding, classify routeRootFunc) vulnFindingJSON {
	if classify == nil {
		classify = unclassifiedRoutes
	}
	return vulnFindingJSON{
		vulnFindingRungJSON: toVulnFindingRungJSON(f),
		RouteRoot:           rootToOutput(firstRouteRootOf(f, classify)),
	}
}

// toVulnFindingsJSON derives both for a finding list, preserving order. A nil
// list stays nil so an absent collection is not rendered as an empty one.
func toVulnFindingsJSON(fs []vuldomain.VulnerabilityFinding, classify routeRootFunc) []vulnFindingJSON {
	if fs == nil {
		return nil
	}
	out := make([]vulnFindingJSON, 0, len(fs))
	for _, f := range fs {
		out = append(out, toVulnFindingJSON(f, classify))
	}
	return out
}

// vulnRecordJSON is a stored vulnerability record on the wire whose findings
// each carry their derived rung.
//
// The embedded record's own Findings field is shadowed by the one below:
// encoding/json resolves a name collision in favour of the shallower field, so
// the record's every other field is emitted by the domain type itself and only
// the findings are re-rendered.
// Superseded is the second derived field, and it is derived for the same reason
// soundness is: whether a record is superseded is a fact about this build's
// reading of it, not about the record, and writing it into the domain type would
// re-hash every stored record to say something a comparison already settles.
// PipelineVersion is on the wire beside it, but only a consumer that already
// knows which generation this binary serves can compare the two — and a machine
// reading a history listing is exactly the consumer that does not. It is emitted
// on every record, false included: absent would be indistinguishable from a
// producer that does not derive it.
type vulnRecordJSON struct {
	vuldomain.VulnerabilityRecord
	Findings   []vulnFindingJSON `json:"findings,omitzero"`
	Superseded bool              `json:"superseded"`
	// Toolchain shadows the embedded field, which is omitempty because the record
	// shape is what the seal covers. On the wire it is emitted on every record,
	// empty included: absent would be indistinguishable from a producer that does
	// not state it, and "not recorded" is itself the answer.
	Toolchain string `json:"toolchain"`
}

// toVulnRecordJSON projects one record, classifying its routes against the
// frame the record itself states.
func toVulnRecordJSON(rec vuldomain.VulnerabilityRecord, bind recordRootFunc) vulnRecordJSON {
	if bind == nil {
		bind = unclassifiedRecords
	}
	return vulnRecordJSON{
		VulnerabilityRecord: rec,
		Toolchain:           string(rec.Toolchain),
		Findings:            toVulnFindingsJSON(rec.Findings, bind(rec)),
		Superseded:          rec.PipelineVersion != vulnPipelineVersion,
	}
}

// toVulnRecordsJSON projects a record list, preserving order. An empty input
// yields an empty slice rather than nil, so a command that promises a JSON array
// still emits "[]".
//
// Each record is classified against its OWN frame. A list spans frames — a
// history spans generations too — and classifying the second record against the
// first's rooting would report a closure-rooted route as a project-rooted one.
func toVulnRecordsJSON(recs []vuldomain.VulnerabilityRecord, bind recordRootFunc) []vulnRecordJSON {
	out := make([]vulnRecordJSON, 0, len(recs))
	for _, rec := range recs {
		out = append(out, toVulnRecordJSON(rec, bind))
	}
	return out
}

// scanDiffJSON is a scan-run diff on the wire whose every finding carries its
// derived reachability rung.
//
// Each delta list is shadowed rather than the diff being rebuilt field by field,
// for the reason vulnRecordJSON gives: the embedded diff keeps emitting anything
// the domain type grows, and only the collections whose elements gain the rung
// are re-rendered here.
type scanDiffJSON struct {
	vuldomain.ScanRunDiff
	NewFindings         []findingDeltaJSON       `json:"NewFindings"`
	ResolvedFindings    []findingDeltaJSON       `json:"ResolvedFindings"`
	WithdrawnFindings   []findingDeltaJSON       `json:"WithdrawnFindings"`
	ReachabilityChanges []reachabilityChangeJSON `json:"ReachabilityChanges"`
	UnresolvedFindings  []unresolvedFindingJSON  `json:"UnresolvedFindings"`
}

// findingDeltaJSON is one finding delta with its rung.
//
// A delta carries the coordinate its finding was recorded against and nothing
// else about the record — in particular not the analysis frame, which only the
// record states and which decides whether a route is closure-rooted. So the
// deltas publish the rung and stop there: the route root is left off the wire
// entirely rather than derived from a frame this diff does not know, because a
// root computed against a guessed frame would contradict the one vuln-show
// prints for the same finding. The missing key says the producer does not derive
// it, which is the true statement here.
type findingDeltaJSON struct {
	vuldomain.FindingDelta
	Finding vulnFindingRungJSON
}

// reachabilityChangeJSON is one reachability transition with the rung behind the
// answer the LATER run gives. The rung qualifies where the finding stands now,
// which is what a reader deciding whether to act on the change is asking.
type reachabilityChangeJSON struct {
	vuldomain.ReachabilityChange
	Finding vulnFindingRungJSON
}

// unresolvedFindingJSON is one withheld verdict with its rung.
type unresolvedFindingJSON struct {
	vuldomain.UnresolvedFinding
	Finding vulnFindingRungJSON
}

// toScanDiffJSON projects a diff. A shadowed list that is empty stays empty:
// encoding/json emits the shallower field either way, so the projection and the
// embedded diff cannot disagree about what a collection holds.
func toScanDiffJSON(d vuldomain.ScanRunDiff) scanDiffJSON {
	out := scanDiffJSON{ScanRunDiff: d}
	for _, x := range d.NewFindings {
		out.NewFindings = append(out.NewFindings, toFindingDeltaJSON(x))
	}
	for _, x := range d.ResolvedFindings {
		out.ResolvedFindings = append(out.ResolvedFindings, toFindingDeltaJSON(x))
	}
	for _, x := range d.WithdrawnFindings {
		out.WithdrawnFindings = append(out.WithdrawnFindings, toFindingDeltaJSON(x))
	}
	for _, x := range d.ReachabilityChanges {
		out.ReachabilityChanges = append(out.ReachabilityChanges,
			reachabilityChangeJSON{ReachabilityChange: x, Finding: toVulnFindingRungJSON(x.Finding)})
	}
	for _, x := range d.UnresolvedFindings {
		out.UnresolvedFindings = append(out.UnresolvedFindings,
			unresolvedFindingJSON{UnresolvedFinding: x, Finding: toVulnFindingRungJSON(x.Finding)})
	}
	return out
}

func toFindingDeltaJSON(d vuldomain.FindingDelta) findingDeltaJSON {
	return findingDeltaJSON{FindingDelta: d, Finding: toVulnFindingRungJSON(d.Finding)}
}
