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

// vulnFindingJSON is one stored finding on the wire with its derived
// reachability rung beside it.
//
// Soundness is emitted on every finding, positive and negative alike, and never
// omitted. "not stated" on a reachable finding is a statement — a route is its
// own evidence and there is no absence to qualify — and it is a different
// statement from the key being missing, which says the producer does not derive
// the rung at all. SoundnessReason is omitted when there is none, because
// NegativeSoundness returns a reason exactly when it returns a rung.
type vulnFindingJSON struct {
	vuldomain.VulnerabilityFinding
	Soundness       vuldomain.ReachabilitySoundness `json:"soundness"`
	SoundnessReason string                          `json:"soundness_reason,omitempty"`
}

// toVulnFindingJSON derives the rung for one finding.
func toVulnFindingJSON(f vuldomain.VulnerabilityFinding) vulnFindingJSON {
	soundness, reason := vuldomain.NegativeSoundness(f)
	return vulnFindingJSON{VulnerabilityFinding: f, Soundness: soundness, SoundnessReason: reason}
}

// toVulnFindingsJSON derives the rung for a finding list, preserving order. A
// nil list stays nil so an absent collection is not rendered as an empty one.
func toVulnFindingsJSON(fs []vuldomain.VulnerabilityFinding) []vulnFindingJSON {
	if fs == nil {
		return nil
	}
	out := make([]vulnFindingJSON, 0, len(fs))
	for _, f := range fs {
		out = append(out, toVulnFindingJSON(f))
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
type vulnRecordJSON struct {
	vuldomain.VulnerabilityRecord
	Findings []vulnFindingJSON `json:"findings,omitzero"`
}

// toVulnRecordJSON projects one record.
func toVulnRecordJSON(rec vuldomain.VulnerabilityRecord) vulnRecordJSON {
	return vulnRecordJSON{VulnerabilityRecord: rec, Findings: toVulnFindingsJSON(rec.Findings)}
}

// toVulnRecordsJSON projects a record list, preserving order. An empty input
// yields an empty slice rather than nil, so a command that promises a JSON array
// still emits "[]".
func toVulnRecordsJSON(recs []vuldomain.VulnerabilityRecord) []vulnRecordJSON {
	out := make([]vulnRecordJSON, 0, len(recs))
	for _, rec := range recs {
		out = append(out, toVulnRecordJSON(rec))
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
type findingDeltaJSON struct {
	vuldomain.FindingDelta
	Finding vulnFindingJSON
}

// reachabilityChangeJSON is one reachability transition with the rung behind the
// answer the LATER run gives. The rung qualifies where the finding stands now,
// which is what a reader deciding whether to act on the change is asking.
type reachabilityChangeJSON struct {
	vuldomain.ReachabilityChange
	Finding vulnFindingJSON
}

// unresolvedFindingJSON is one withheld verdict with its rung.
type unresolvedFindingJSON struct {
	vuldomain.UnresolvedFinding
	Finding vulnFindingJSON
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
			reachabilityChangeJSON{ReachabilityChange: x, Finding: toVulnFindingJSON(x.Finding)})
	}
	for _, x := range d.UnresolvedFindings {
		out.UnresolvedFindings = append(out.UnresolvedFindings,
			unresolvedFindingJSON{UnresolvedFinding: x, Finding: toVulnFindingJSON(x.Finding)})
	}
	return out
}

func toFindingDeltaJSON(d vuldomain.FindingDelta) findingDeltaJSON {
	return findingDeltaJSON{FindingDelta: d, Finding: toVulnFindingJSON(d.Finding)}
}
