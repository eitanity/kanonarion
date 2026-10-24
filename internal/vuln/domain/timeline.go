package domain

import (
	"cmp"
	"fmt"
	"slices"
	"sort"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"
)

// TimelineStateKind is what one record says about one advisory.
type TimelineStateKind string

const (
	TimelineNotReported TimelineStateKind = "not_reported"
	TimelineReported    TimelineStateKind = "reported"
	TimelineWithdrawn   TimelineStateKind = "withdrawn"
)

// TimelineState is one record's answer for one advisory. Reachability is the
// record's own word and is set only on a reported state.
type TimelineState struct {
	Kind         TimelineStateKind  `json:"kind"`
	Reachability *ReachabilityState `json:"reachability,omitempty"`
}

// String renders the state as the timeline prints it.
func (s TimelineState) String() string {
	switch s.Kind {
	case TimelineReported:
		return "reported (" + s.Reachability.String() + ")"
	case TimelineWithdrawn:
		return "withdrawn"
	default:
		return "not reported"
	}
}

// TimelineReason is why a state changed between two records of one generation,
// drawn from the two records alone.
type TimelineReason string

const (
	ReasonWithdrawn             TimelineReason = "withdrawn"
	ReasonReachabilityCorrected TimelineReason = "reachability-corrected"
	ReasonCoverageLost          TimelineReason = "coverage-lost"
	ReasonAdvisoryAdded         TimelineReason = "advisory-added"
	ReasonUnattributed          TimelineReason = "unattributed"
)

// TimelineEntryKind separates a change from a pair that differs only because
// two pipeline generations read the same coordinate differently.
type TimelineEntryKind string

const (
	TimelineChange                 TimelineEntryKind = "change"
	TimelineGenerationDisagreement TimelineEntryKind = "generation-disagreement"
)

// TimelinePoint names the record an entry or boundary rests on.
type TimelinePoint struct {
	ScannedAt       time.Time            `json:"scanned_at"`
	PipelineVersion string               `json:"pipeline_version"`
	Snapshot        DatabaseSnapshot     `json:"snapshot"`
	Coverage        RecordCoverageStatus `json:"coverage"`
	ContentHash     string               `json:"content_hash"`
}

// TimelineEntry is one state change, or one generation disagreement, between
// two consecutive records of one (coordinate, frame).
type TimelineEntry struct {
	Kind        TimelineEntryKind `json:"kind"`
	Reason      TimelineReason    `json:"reason,omitempty"`
	From        TimelineState     `json:"from"`
	To          TimelineState     `json:"to"`
	FromRecord  TimelinePoint     `json:"from_record"`
	ToRecord    TimelinePoint     `json:"to_record"`
	WithdrawnAt time.Time         `json:"withdrawn_at,omitzero"`
}

// TimelineBoundary is a first-reported or no-longer-reported claim and the
// record it rests on. AtOrBefore says no earlier record of the same generation
// bounds it; Established false says the record cannot carry the claim.
type TimelineBoundary struct {
	Record      TimelinePoint     `json:"record"`
	Previous    *TimelinePoint    `json:"previous,omitempty"`
	AtOrBefore  bool              `json:"at_or_before,omitempty"`
	Established bool              `json:"established"`
	Reason      TimelineReason    `json:"reason,omitempty"`
	EntryKind   TimelineEntryKind `json:"entry_kind,omitempty"`
}

// FindingTimeline is the ordered changes one advisory went through on one
// coordinate within one analysis frame.
type FindingTimeline struct {
	Coordinate       coordinate.ModuleCoordinate `json:"coordinate"`
	Rooting          Rooting                     `json:"rooting"`
	RecordCount      int                         `json:"record_count"`
	State            TimelineState               `json:"state"`
	FirstReported    *TimelineBoundary           `json:"first_reported,omitempty"`
	NoLongerReported *TimelineBoundary           `json:"no_longer_reported,omitempty"`
	Entries          []TimelineEntry             `json:"entries"`
}

// SnapshotAdvisoryCheck says whether the store holds a snapshot's exact bytes
// and, if so, whether they list the advisory.
type SnapshotAdvisoryCheck func(snapshot DatabaseSnapshot, advisoryID string) (held, lists bool, err error)

// BuildFindingTimelines groups records by (coordinate, frame) and reports, for
// each group in which some record carries findingID, the changes of state.
// Frames are never compared and a pipeline change is never a change of state.
func BuildFindingTimelines(findingID string, records []VulnerabilityRecord, check SnapshotAdvisoryCheck) ([]FindingTimeline, error) {
	groups := map[string][]VulnerabilityRecord{}
	for _, r := range records {
		k := r.Coordinate.String() + "\x00" + string(r.Rooting)
		groups[k] = append(groups[k], r)
	}
	keys := make([]string, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var out []FindingTimeline
	for _, k := range keys {
		tl, carried, err := buildOneTimeline(findingID, groups[k], check)
		if err != nil {
			return nil, err
		}
		if carried {
			out = append(out, tl)
		}
	}
	return out, nil
}

func buildOneTimeline(findingID string, recs []VulnerabilityRecord, check SnapshotAdvisoryCheck) (FindingTimeline, bool, error) {
	recs = slices.Clone(recs)
	slices.SortFunc(recs, timelineOrder)
	states := make([]TimelineState, len(recs))
	carried := false
	for i, r := range recs {
		states[i], _ = advisoryState(r, findingID)
		carried = carried || states[i].Kind != TimelineNotReported
	}
	tl := FindingTimeline{
		Coordinate: recs[0].Coordinate, Rooting: recs[0].Rooting,
		RecordCount: len(recs), State: states[len(recs)-1], Entries: []TimelineEntry{},
	}
	entryAt := map[int]TimelineEntry{}
	for i := 1; i < len(recs); i++ {
		if states[i].String() == states[i-1].String() {
			continue
		}
		e, err := timelineEntry(findingID, recs[i-1], recs[i], states[i-1], states[i], check)
		if err != nil {
			return FindingTimeline{}, false, err
		}
		tl.Entries = append(tl.Entries, e)
		entryAt[i] = e
	}
	tl.FirstReported = firstReported(recs, states)
	tl.NoLongerReported = noLongerReported(states, entryAt)
	return tl, carried, nil
}

// timelineOrder orders one stream by scan time; the content hash, unique per
// record, settles a tie so the order never depends on the store's.
func timelineOrder(a, b VulnerabilityRecord) int {
	if c := a.ScannedAt.Compare(b.ScannedAt); c != 0 {
		return c
	}
	return cmp.Compare(a.ContentHash, b.ContentHash)
}

// advisoryState reads findingID off a record: a live match wins over a
// withdrawn one, and the first live match in the record's order speaks.
func advisoryState(r VulnerabilityRecord, findingID string) (TimelineState, VulnerabilityFinding) {
	var withdrawn *VulnerabilityFinding
	for i, f := range r.Findings {
		if f.ID != findingID && !slices.Contains(f.Aliases, findingID) {
			continue
		}
		if f.IsWithdrawn() {
			if withdrawn == nil {
				withdrawn = &r.Findings[i]
			}
			continue
		}
		rs := FindingReachabilityState(f)
		return TimelineState{Kind: TimelineReported, Reachability: &rs}, f
	}
	if withdrawn != nil {
		return TimelineState{Kind: TimelineWithdrawn}, *withdrawn
	}
	return TimelineState{Kind: TimelineNotReported}, VulnerabilityFinding{}
}

func timelinePoint(r VulnerabilityRecord) TimelinePoint {
	coverage, _ := RecordAxes(r)
	return TimelinePoint{
		ScannedAt: r.ScannedAt, PipelineVersion: r.PipelineVersion,
		Snapshot: r.DatabaseSnapshot, Coverage: coverage, ContentHash: r.ContentHash,
	}
}

func timelineEntry(findingID string, prev, cur VulnerabilityRecord, from, to TimelineState, check SnapshotAdvisoryCheck) (TimelineEntry, error) {
	e := TimelineEntry{From: from, To: to, FromRecord: timelinePoint(prev), ToRecord: timelinePoint(cur)}
	if prev.PipelineVersion != cur.PipelineVersion {
		e.Kind = TimelineGenerationDisagreement
		return e, nil
	}
	e.Kind = TimelineChange
	_, finding := advisoryState(cur, findingID)
	switch {
	case to.Kind == TimelineWithdrawn:
		e.Reason, e.WithdrawnAt = ReasonWithdrawn, finding.WithdrawnAt
	case e.ToRecord.Coverage != CoverageAnalysed:
		// A record that analysed nothing cannot correct reachability.
		e.Reason = ReasonCoverageLost
	case from.Kind == TimelineReported && to.Kind == TimelineReported:
		e.Reason = ReasonReachabilityCorrected
	case from.Kind == TimelineNotReported && to.Kind == TimelineReported:
		added, err := advisoryAdded(prev.DatabaseSnapshot, finding.ID, check)
		if err != nil {
			return TimelineEntry{}, err
		}
		e.Reason = ReasonUnattributed
		if added {
			e.Reason = ReasonAdvisoryAdded
		}
	default:
		e.Reason = ReasonUnattributed
	}
	return e, nil
}

// advisoryAdded holds only when the earlier record's snapshot is held by its
// content hash and does not list the advisory; a snapshot not held proves nothing.
func advisoryAdded(snap DatabaseSnapshot, advisoryID string, check SnapshotAdvisoryCheck) (bool, error) {
	if snap.IsZero() || snap.ContentHash() == "" {
		return false, nil
	}
	held, lists, err := check(snap, advisoryID)
	if err != nil {
		return false, fmt.Errorf("reading advisory %s in snapshot %s: %w", advisoryID, snap, err)
	}
	return held && !lists, nil
}

// firstReported names the earliest record reporting the advisory live. Only an
// analysed same-generation predecessor bounds it from below: a failed one looked
// at nothing.
func firstReported(recs []VulnerabilityRecord, states []TimelineState) *TimelineBoundary {
	for i, s := range states {
		if s.Kind != TimelineReported {
			continue
		}
		b := &TimelineBoundary{Record: timelinePoint(recs[i]), Established: true, AtOrBefore: true}
		if prev := timelinePoint(recs[max(i-1, 0)]); i > 0 &&
			prev.PipelineVersion == recs[i].PipelineVersion && prev.Coverage == CoverageAnalysed {
			b.Previous, b.AtOrBefore = &prev, false
		}
		return b
	}
	return nil
}

// noLongerReported names the record after the last live report when the stream
// ends without one. A coverage loss or a pipeline change cannot establish it.
func noLongerReported(states []TimelineState, entryAt map[int]TimelineEntry) *TimelineBoundary {
	last := -1
	for i, s := range states {
		if s.Kind == TimelineReported {
			last = i
		}
	}
	if last < 0 || last == len(states)-1 {
		return nil
	}
	// A reported state differs from the next one, so the pair always has an entry.
	e := entryAt[last+1]
	return &TimelineBoundary{
		Record: e.ToRecord, EntryKind: e.Kind, Reason: e.Reason,
		Established: e.Kind == TimelineChange && e.Reason != ReasonCoverageLost,
	}
}
