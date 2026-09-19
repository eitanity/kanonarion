package cli

import (
	"github.com/eitanity/kanonarion/internal/recordstamp"
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
// reachability state and rung beside it.
//
// ReachabilityState is the answer; soundness qualifies it. The embedded record
// carries reachable.is_reachable, which is a stored bit with two positions, and
// the question has more answers than that — an advisory that names no symbol in
// this module path was never determinable at symbol level, and the bit says
// nothing about it in either position. A consumer reading the bit alone counted
// exactly such a finding as reachable and published it. The state is derived
// here by the same function every other surface calls, so no reader has to
// reconstruct it from the bit and AdvisoryNamesNoSymbols itself.
//
// Both are emitted on every finding, and never omitted. "not stated" on a
// reachable finding is a statement — a route is its own evidence and there is no
// absence to qualify — and it is a different statement from the key being
// missing, which says the producer does not derive the rung at all. The state
// key carries the same rule for the same reason: absent, "not_reachable" and
// "package_level_only" collapse back into one another. SoundnessReason is
// omitted when there is none, because NegativeSoundness returns a reason exactly
// when it returns a rung.
type vulnFindingRungJSON struct {
	vuldomain.VulnerabilityFinding
	ReachabilityState vuldomain.ReachabilityState     `json:"reachability_state"`
	Soundness         vuldomain.ReachabilitySoundness `json:"soundness"`
	SoundnessReason   string                          `json:"soundness_reason,omitempty"`
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

// toVulnFindingRungJSON derives the state and the rung for one finding.
func toVulnFindingRungJSON(f vuldomain.VulnerabilityFinding) vulnFindingRungJSON {
	soundness, reason := vuldomain.NegativeSoundness(f)
	return vulnFindingRungJSON{
		VulnerabilityFinding: f,
		ReachabilityState:    vuldomain.FindingReachabilityState(f),
		Soundness:            soundness,
		SoundnessReason:      reason,
	}
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
	// ScannedAt and FirstScannedAt shadow the embedded time.Time fields so the
	// stamps a consumer reads have ONE width.
	//
	// encoding/json renders a time.Time through RFC3339Nano, which strips
	// trailing zeros — so the same instant went out as ".05377068Z" here and as a
	// whole second on the text surface, and neither matched what the ledger holds.
	// A reader lining a rendered answer up against a record or a log line had to
	// reconcile three spellings first. These are the ledger's own encoding.
	//
	// Shadowing rather than changing the domain type, because the domain type's
	// JSON IS the seal: re-spelling ScannedAt there would change the bytes 734
	// stored records hash to and darken every one of them for a rendering
	// concern. The value is the same instant either way.
	//
	// Each shadow keeps the PRESENCE the field it hides had, because a consumer
	// decodes this document back into the record type. ScannedAt is always on the
	// wire, so a zero one renders as the zero instant rather than as the empty
	// string, which is not a time any decoder accepts. FirstScannedAt is omitzero
	// on the record — the anchor is absent until a re-scan — so it stays absent.
	ScannedAt      string `json:"scanned_at"`
	FirstScannedAt string `json:"first_scanned_at,omitempty"`
	// FirstScannedAtAnchor says what the stamp above is anchored to and names the
	// reader that answers the question its name invites. It rides beside the
	// stamp and is absent whenever the stamp is, so a consumer that never reads
	// the stamp sees no change. See firstScannedAtAnchorNote.
	FirstScannedAtAnchor string `json:"first_scanned_at_anchor,omitempty"`
}

// toVulnRecordJSON projects one record, classifying its routes against the
// frame the record itself states.
func toVulnRecordJSON(rec vuldomain.VulnerabilityRecord, bind recordRootFunc) vulnRecordJSON {
	if bind == nil {
		bind = unclassifiedRecords
	}
	out := vulnRecordJSON{
		VulnerabilityRecord: rec,
		Toolchain:           string(rec.Toolchain),
		Findings:            toVulnFindingsJSON(rec.Findings, bind(rec)),
		Superseded:          rec.PipelineVersion != vulnPipelineVersion,
		ScannedAt:           recordstamp.Format(rec.ScannedAt),
		FirstScannedAt:      ledgerStamp(rec.FirstScannedAt),
	}
	if out.FirstScannedAt != "" {
		out.FirstScannedAtAnchor = firstScannedAtAnchorNote(rec.Coordinate)
	}
	return out
}

// vulnRecordNativeJSON is a stored record published by a producer that also
// read what the module's own artefact compiles into the binary from native
// source it ships — the C library a cgo module amalgamates into its zip.
//
// It is a type of its own rather than a field on vulnRecordJSON, for the reason
// RouteRoot is: a producer that does not derive the statement emits no key at
// all, and a producer that does derive it always emits a complete one. The two
// absences say different things. A record read through --history is the case
// that matters: that read spans pipeline generations, and the native statement
// is a fact about the artefact NOW, so attaching it to a scan taken months ago
// would read as something that scan established. It did not.
//
// NativeCoverage is never null here. Every module has a native state, including
// "nobody looked", so a producer that derives the statement always has one to
// publish.
type vulnRecordNativeJSON struct {
	vulnRecordJSON
	NativeCoverage nativeCoverage `json:"native_coverage"`
}

// toVulnRecordNativeJSON projects one record together with the native statement
// derived for its coordinate.
//
// A nil cov means the caller holds no native reader, and the result is the
// plain record projection — the key is then absent, saying this producer does
// not derive it, rather than present and empty, which would assert an absence
// nothing measured.
func toVulnRecordNativeJSON(rec vuldomain.VulnerabilityRecord, bind recordRootFunc, cov *nativeCoverage) any {
	base := toVulnRecordJSON(rec, bind)
	if cov == nil {
		return base
	}
	return vulnRecordNativeJSON{vulnRecordJSON: base, NativeCoverage: *cov}
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

// unreadableRecordJSON is one stored record a record listing could not verify,
// on the wire beside the records it could.
//
// It joins the same array rather than a section of its own, for the reason the
// scan-run listing puts its unreadable rows in the same array: a consumer that
// reads this output as "the records the store holds" must not be able to miss
// them, and one that filters on status still can. It carries overall_status —
// the key every record row states its verdict in — with a value no verdict has,
// so a filter sees it and a decoder cannot mistake it for one.
//
// Every other field is under the key its READABLE siblings use, and carries what
// the store recovered from the head of the suspect bytes — nothing composed, and
// nothing inferred. A consumer asking "which coordinate" reads `coordinate`,
// exactly as it does on a record; it does not pull one out of a display string.
// Each is omitted where the head did not yield it, absence included: a row that
// will not say which module it is is reported with no coordinate rather than
// with a guess.
type unreadableRecordJSON struct {
	Coordinate       string                  `json:"coordinate,omitempty"`
	PipelineVersion  string                  `json:"pipeline_version,omitempty"`
	DatabaseSnapshot *unreadableSnapshotJSON `json:"database_snapshot,omitempty"`
	OverallStatus    string                  `json:"overall_status"`
	Reason           string                  `json:"reason"`
}

// unreadableSnapshotJSON is the advisory snapshot a suspect record named, under
// the key and in the shape a readable record states its own. Only the two fields
// the head yields are on it: the rest of a snapshot — its content hash, when it
// was retrieved — is sealed content this row's bytes cannot be trusted for.
type unreadableSnapshotJSON struct {
	Source  string `json:"source,omitempty"`
	Version string `json:"version,omitempty"`
}

// toUnreadableRecordJSON projects one unreadable row for a record listing.
func toUnreadableRecordJSON(e unreadableRowEntry) unreadableRecordJSON {
	out := unreadableRecordJSON{
		Coordinate:      e.ID,
		PipelineVersion: e.PipelineVersion,
		OverallStatus:   statusUnreadable,
		Reason:          e.Reason,
	}
	if e.SnapshotSource != "" || e.SnapshotVersion != "" {
		out.DatabaseSnapshot = &unreadableSnapshotJSON{Source: e.SnapshotSource, Version: e.SnapshotVersion}
	}
	return out
}

// vulnRecordListJSON renders a record listing that may be partial: the records
// that verified, then the rows that did not.
//
// The result is []any because the two are different documents and pretending
// otherwise would mean giving an unreadable row a verdict's fields. An empty
// input yields an empty slice, so a command that promises a JSON array still
// emits "[]".
func vulnRecordListJSON(recs []vuldomain.VulnerabilityRecord, unreadable []unreadableRowEntry, bind recordRootFunc) []any {
	out := make([]any, 0, len(recs)+len(unreadable))
	for _, rec := range toVulnRecordsJSON(recs, bind) {
		out = append(out, rec)
	}
	for _, u := range unreadable {
		out = append(out, toUnreadableRecordJSON(u))
	}
	return out
}
