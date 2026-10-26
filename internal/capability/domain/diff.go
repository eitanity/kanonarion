package domain

import (
	"slices"
	"strings"

	cgdomain "code.eitanity.com/kanonarion/internal/callgraph/domain"
)

// CapabilityDiff compares two capability reports (for example two versions of a
// module) to answer the update-validity question: what evidence did the bump
// add, and what did it remove? Additions and removals are kept apart; nothing
// is netted.
type CapabilityDiff struct {
	// Added holds capabilities present in "to" but not "from", sorted.
	Added []Capability
	// Removed holds capabilities present in "from" but not "to", sorted.
	Removed []Capability
	// Common holds capabilities present on both sides, sorted.
	Common []Capability
	// RowsAdded and RowsRemoved are the witness rows only one side holds, in
	// RowLess order, each carrying its own side's suppression.
	RowsAdded   []WitnessRow
	RowsRemoved []WitnessRow
	// FromRows and ToRows count each side's rows.
	FromRows int
	ToRows   int
	// SensitiveAdded and SensitiveRemoved are the roll-up members only one side
	// holds, keyed on callee and capability.
	SensitiveAdded   []SensitiveCall
	SensitiveRemoved []SensitiveCall
	// CollectsAndEgressesAdded/Removed are keyed on the function.
	CollectsAndEgressesAdded   []CoLocation
	CollectsAndEgressesRemoved []CoLocation
	// InitReachesBothAdded/Removed are keyed on the initialiser and the two
	// members it reaches. The same fact at another depth is not an add and a
	// remove: it is listed in InitReachesBothDepthChanged.
	InitReachesBothAdded        []InitReach
	InitReachesBothRemoved      []InitReach
	InitReachesBothDepthChanged []InitReachDepthChange
	// UnanalyzedAdded/Removed are owned unanalysed bodies only one side holds.
	UnanalyzedAdded   []string
	UnanalyzedRemoved []string
	// ParityOK is false when either report was computed over a Partial graph. A
	// capability diff is only valid when both sides were analysed at equal
	// completeness; when false, everything added or removed is provisional.
	ParityOK bool
	// Caveat is a human-readable note; non-empty only when ParityOK is false.
	Caveat string
}

// Unchanged reports whether nothing the diff compares moved.
func (d CapabilityDiff) Unchanged() bool {
	return len(d.Added) == 0 && len(d.Removed) == 0 &&
		len(d.RowsAdded) == 0 && len(d.RowsRemoved) == 0 &&
		len(d.SensitiveAdded) == 0 && len(d.SensitiveRemoved) == 0 &&
		len(d.CollectsAndEgressesAdded) == 0 && len(d.CollectsAndEgressesRemoved) == 0 &&
		len(d.InitReachesBothAdded) == 0 && len(d.InitReachesBothRemoved) == 0 &&
		len(d.InitReachesBothDepthChanged) == 0 &&
		len(d.UnanalyzedAdded) == 0 && len(d.UnanalyzedRemoved) == 0
}

// DiffCapabilities compares two reports. The diff honours the diff-parity
// requirement: it is only valid when neither side is Partial.
func DiffCapabilities(from, to CapabilityReport) CapabilityDiff {
	fromSet := capabilitySet(from)
	toSet := capabilitySet(to)

	diff := CapabilityDiff{ParityOK: !from.Partial && !to.Partial, FromRows: len(from.Rows), ToRows: len(to.Rows)}
	if !diff.ParityOK {
		diff.Caveat = "capability diff is not valid: at least one version was analysed over a Partial call graph; re-analyse both at equal completeness before trusting added/removed"
	}

	for c := range toSet {
		if !fromSet[c] {
			diff.Added = append(diff.Added, c)
		} else {
			diff.Common = append(diff.Common, c)
		}
	}
	for c := range fromSet {
		if !toSet[c] {
			diff.Removed = append(diff.Removed, c)
		}
	}
	slices.Sort(diff.Added)
	slices.Sort(diff.Removed)
	slices.Sort(diff.Common)

	rowKey := func(r WitnessRow) string { return r.rowKey() }
	diff.RowsAdded, diff.RowsRemoved = onlyOn(from.Rows, to.Rows, rowKey)
	diff.SensitiveAdded, diff.SensitiveRemoved = onlyOn(from.SensitiveCalls, to.SensitiveCalls, SensitiveCall.key)
	diff.CollectsAndEgressesAdded, diff.CollectsAndEgressesRemoved = onlyOn(from.CollectsAndEgresses, to.CollectsAndEgresses,
		func(c CoLocation) string { return c.Function })
	diff.InitReachesBothAdded, diff.InitReachesBothRemoved = onlyOn(from.InitReachesBoth, to.InitReachesBoth, InitReach.key)
	diff.InitReachesBothDepthChanged = depthChanges(from.InitReachesBoth, to.InitReachesBoth)
	diff.UnanalyzedAdded, diff.UnanalyzedRemoved = onlyOn(from.Unanalyzed, to.Unanalyzed,
		func(s string) string { return s })
	return diff
}

// InitReachDepthChange is one initialiser reaching the same two members at a
// different depth in each version.
type InitReachDepthChange struct {
	From InitReach
	To   InitReach
}

// depthChanges pairs the facts both sides hold whose depths differ, in "to"
// order.
func depthChanges(from, to []InitReach) []InitReachDepthChange {
	byKey := make(map[string]InitReach, len(from))
	for _, r := range from {
		byKey[r.key()] = r
	}
	var out []InitReachDepthChange
	for _, r := range to {
		if f, ok := byKey[r.key()]; ok && f.Depth != r.Depth {
			out = append(out, InitReachDepthChange{From: f, To: r})
		}
	}
	return out
}

// onlyOn returns the elements of to whose key from lacks, and the elements of
// from whose key to lacks, each in its input order.
func onlyOn[T any](from, to []T, key func(T) string) (added, removed []T) {
	inFrom := make(map[string]bool, len(from))
	for _, x := range from {
		inFrom[key(x)] = true
	}
	inTo := make(map[string]bool, len(to))
	for _, x := range to {
		inTo[key(x)] = true
		if !inFrom[key(x)] {
			added = append(added, x)
		}
	}
	for _, x := range from {
		if !inTo[key(x)] {
			removed = append(removed, x)
		}
	}
	return added, removed
}

func capabilitySet(r CapabilityReport) map[Capability]bool {
	set := make(map[Capability]bool, len(r.Findings))
	for _, f := range r.Findings {
		set[f.Capability] = true
	}
	return set
}

// RowGroup is how a diff presents rows: per caller for INIT, TEST_INIT,
// EXPORTED_API and MAIN; one line per (capability, reach, callee) with a
// caller count for TEST and INTERNAL.
type RowGroup struct {
	CallerKind CallerKind
	Capability Capability
	Reach      Reach
	Callee     string
	BodyFact   bool
	// Callers are the callers the group holds, sorted.
	Callers []string
	// Confidence is the strongest among the group's rows: the first row's.
	Confidence cgdomain.EdgeConfidence
	// Suppressed is true only when every row in the group is.
	Suppressed   bool
	PlumbingOnly bool
}

// GroupRows collapses rows for presentation, keeping RowLess order by each
// group's first row.
func GroupRows(rows []WitnessRow) []RowGroup {
	sorted := slices.Clone(rows)
	sortRows(sorted)
	index := make(map[string]int)
	var out []RowGroup
	for _, r := range sorted {
		key := r.rowKey()
		if r.CallerKind.Collapsed() {
			key = strings.Join([]string{string(r.CallerKind), string(r.Capability), string(r.Reach), r.Callee}, "\x00")
		}
		i, ok := index[key]
		if !ok {
			index[key] = len(out)
			out = append(out, RowGroup{
				CallerKind: r.CallerKind, Capability: r.Capability, Reach: r.Reach, Callee: r.Callee,
				BodyFact: r.BodyFact, Confidence: r.Confidence, Suppressed: true,
			})
			i = len(out) - 1
		}
		// RowLess puts the strongest confidence first within a kind and tier, so
		// the row that opened the group already carries it.
		g := &out[i]
		g.Callers = append(g.Callers, r.Caller)
		g.Suppressed = g.Suppressed && r.Suppressed
		g.PlumbingOnly = g.PlumbingOnly || r.PlumbingOnly
	}
	for i := range out {
		slices.Sort(out[i].Callers)
	}
	return out
}
