package domain

import "sort"

// CapabilityDiff compares two capability reports (for example two versions of a
// module) to answer the update-validity question: did the capability set change?
type CapabilityDiff struct {
	// Added holds capabilities present in "to" but not "from", sorted.
	Added []Capability
	// Removed holds capabilities present in "from" but not "to", sorted.
	Removed []Capability
	// Common holds capabilities present on both sides, sorted.
	Common []Capability
	// ParityOK is false when either report was computed over a Partial graph. A
	// capability diff is only valid when both sides were analysed at equal
	// completeness; when false, Added/Removed are provisional.
	ParityOK bool
	// Caveat is a human-readable note; non-empty only when ParityOK is false.
	Caveat string
}

// DiffCapabilities compares the capability sets of two reports. The diff honours
// the diff-parity requirement: it is only valid when neither side is Partial.
func DiffCapabilities(from, to CapabilityReport) CapabilityDiff {
	fromSet := capabilitySet(from)
	toSet := capabilitySet(to)

	diff := CapabilityDiff{ParityOK: !from.Partial && !to.Partial}
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

	sortCaps(diff.Added)
	sortCaps(diff.Removed)
	sortCaps(diff.Common)
	return diff
}

func capabilitySet(r CapabilityReport) map[Capability]bool {
	set := make(map[Capability]bool, len(r.Findings))
	for _, f := range r.Findings {
		set[f.Capability] = true
	}
	return set
}

func sortCaps(caps []Capability) {
	sort.Slice(caps, func(i, j int) bool { return caps[i] < caps[j] })
}
