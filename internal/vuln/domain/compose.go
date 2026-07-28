package domain

import (
	"errors"
	"sort"
)

// ErrNoRecordsToCompose is returned by Compose when handed no records. It is a
// programming error rather than an absence: absence is reported by the store as
// "not found", and composing nothing has no meaningful answer.
var ErrNoRecordsToCompose = errors.New("no vulnerability records to compose")

// Compose returns the record a reader gets for one coordinate, given every
// record the ledger holds for it, without naming an analysis frame.
//
// Records must each have verified their own content hash before reaching here:
// a record that cannot be checked stops the read, so composition never has to
// decide what to do about an unverifiable row.
//
// Composition PICKS a stored record; it never merges two. A merged record would
// carry a content hash describing neither of the measurements it was built
// from, and the hash is the whole evidence chain. So the answer to "advisory
// known since snapshot X, reachability last established at completeness Y" is a
// record that states its own snapshot, completeness and frame — the served
// record names its provenance rather than having it summarised away — plus the
// ledger, which still holds every generation for a reader that wants the rest.
//
// A caller that has a frame in mind must use ComposeAt instead. This entry
// point is for the reader who has explicitly declined to name one and is asking
// "what is the best-founded thing this store knows about the module". The
// served record still states the frame it was reached in, so an answer is never
// laundered into an answer to the other question; what is forbidden — carrying a
// reachability finding across a rooting boundary — is a merge, and this does not
// merge.
func Compose(records []VulnerabilityRecord) (VulnerabilityRecord, error) {
	if len(records) == 0 {
		return VulnerabilityRecord{}, ErrNoRecordsToCompose
	}
	ordered := make([]VulnerabilityRecord, len(records))
	copy(ordered, records)
	sort.SliceStable(ordered, func(i, j int) bool { return servesBefore(ordered[i], ordered[j]) })
	return ordered[0], nil
}

// ComposeAt returns the record a reader gets for one coordinate within one
// analysis frame. ok is false when the ledger holds nothing in that frame — a
// caller asking about an isolated analysis is never handed a target-rooted
// record, because the two answer different questions and a scan that reused the
// wrong one would attribute a reachability finding to a build it was never
// computed against.
//
// Records written before the frame was recorded are the one exception, and it is
// deliberately narrow: they are considered only when NO record in the group
// states a frame at all. A store that has not been re-scanned since the field
// landed therefore still answers as it always did, while a coordinate that has
// been measured in a stated frame stops matching against rows that cannot say
// which question they answer.
func ComposeAt(records []VulnerabilityRecord, rooting Rooting) (VulnerabilityRecord, bool, error) {
	candidates := atRooting(records, rooting)
	if len(candidates) == 0 {
		return VulnerabilityRecord{}, false, nil
	}
	composed, err := Compose(candidates)
	if err != nil {
		return VulnerabilityRecord{}, false, err
	}
	return composed, true, nil
}

// atRooting narrows records to the requested frame, falling back to the whole
// group only when no record in it states a frame.
func atRooting(records []VulnerabilityRecord, rooting Rooting) []VulnerabilityRecord {
	matched := make([]VulnerabilityRecord, 0, len(records))
	anyStated := false
	for _, r := range records {
		if RecordRooting(r).IsRecorded() {
			anyStated = true
		}
		if RecordRooting(r) == rooting {
			matched = append(matched, r)
		}
	}
	if !anyStated {
		// Nothing in this group can say which question it answers, so narrowing
		// on the frame would report "never measured in this frame" for a store
		// whose every record predates the field. The records compete as they did
		// before the frame existed.
		return records
	}
	return matched
}

// servesBefore orders two records by which should be served first.
//
// The ladder, in order, and each rung is a rule about authority rather than
// about time:
//
//  1. A record reporting a matched advisory outranks one that does not. A
//     finding does not decay into an all-clear because a later scan ran; a
//     transition out of a finding needs a stated reason, and the findings axis
//     carries the one reason there is — Withdrawn, which reports the retraction
//     and stays in this tier so the record holding the reason is the one served.
//  2. Among records reporting nothing, an analysed one outranks a coverage gap.
//     Evidence of absence beats absence of evidence; ranking them together let a
//     failed scan answer a security question purely on being newer.
//  3. The higher call-graph completeness wins. This is the rung that stops a
//     newer, weaker measurement from displacing better-founded evidence: a scan
//     against a newer advisory database backed by a metadata-only graph is
//     better at "does an advisory exist" and worse at "is it reachable in what
//     we ship", and serving it unconditionally would replace an established
//     not-reachable finding with an unresolved one and call that an update.
//     Rung 1 is what keeps the other half honest — a genuinely new advisory
//     makes the newer record report a finding, and rung 1 serves it before this
//     rung is ever consulted.
//  4. The newer advisory-database snapshot wins. That axis is monotone: a later
//     database knows about strictly more advisories.
//  5. The newer scan wins, and finally the content hash decides. The hash is not
//     authority and is not claimed to be — it is here so the served record does
//     not depend on the order rows happen to come back in.
//
// Rooting is deliberately absent from the ladder. It is a dimension, and
// laddering it would silently discard the answer to one of the two questions;
// ComposeAt is where a caller says which one it is asking.
func servesBefore(a, b VulnerabilityRecord) bool {
	coverageA, findingsA := RecordAxes(a)
	coverageB, findingsB := RecordAxes(b)

	if ra, rb := reportsAdvisory(findingsA), reportsAdvisory(findingsB); ra != rb {
		return ra
	}
	if aa, ab := coverageA == CoverageAnalysed, coverageB == CoverageAnalysed; aa != ab {
		return aa
	}
	if ra, rb := completenessRung(a.CallGraphCompleteness), completenessRung(b.CallGraphCompleteness); ra != rb {
		return ra > rb
	}
	if !a.DatabaseSnapshot.RetrievedAt.Equal(b.DatabaseSnapshot.RetrievedAt) {
		return a.DatabaseSnapshot.RetrievedAt.After(b.DatabaseSnapshot.RetrievedAt)
	}
	if a.DatabaseSnapshot.Version != b.DatabaseSnapshot.Version {
		// Both snapshots claim the same retrieval instant, so the instant cannot
		// order them. The version string is the database's own generation label
		// and is the only remaining statement about which is later.
		return a.DatabaseSnapshot.Version > b.DatabaseSnapshot.Version
	}
	if !a.ScannedAt.Equal(b.ScannedAt) {
		return a.ScannedAt.After(b.ScannedAt)
	}
	return a.ContentHash < b.ContentHash
}

// reportsAdvisory reports whether a findings axis states that an advisory
// matched this module — live or retracted — as opposed to reporting none.
func reportsAdvisory(f RecordFindingsStatus) bool {
	return f == FindingsRecordAffected || f == FindingsRecordWithdrawn
}

// completenessRung orders the call-graph fidelity a record's reachability
// findings were derived at. Higher is more complete.
//
// The levels mirror internal/callgraph/domain.CompletenessLevel, which is the
// source of truth for the ladder; the values are compared as strings here
// because a VulnerabilityRecord stores the level as one and this domain does not
// depend on the call-graph domain. TestCompletenessRung_CoversEveryCallGraphLevel
// pins the two together, so a level added there cannot silently fall to the
// bottom rung here.
//
// An unrecorded level ranks below every stated one but above nothing else: a
// record that consulted no call graph made no reachability claim, so it must not
// displace one that did, and it must still be servable when it is all there is.
func completenessRung(level string) int {
	switch level {
	case "BUILT_WITH_BODIES":
		return 5
	case "TYPE_ONLY":
		return 4
	case "METADATA_ONLY":
		return 3
	case "FAILED":
		return 2
	case "VERSION_NOT_IN_TOOLCHAIN":
		// Below FAILED rather than beside it. A failed load produced no graph and
		// says so; a version the host toolchain never built produced a graph of a
		// module the build never selected, so its reachability answers are about
		// different code. It is the least sound basis for a finding, not merely an
		// absent one.
		return 1
	default:
		return 0
	}
}
