package domain

import (
	"slices"
	"strings"
)

// DirectiveDiff is the deterministic delta between two directive scan records
// of the same project. Mirrors the vuln-scan ScanRunDiff shape.
type DirectiveDiff struct {
	// ScanA / ScanB carry the two scans being compared (older → newer).
	ScanA Record
	ScanB Record

	// Added contains directives present in B but not in A.
	Added []Directive
	// Removed contains directives present in A but not in B.
	Removed []Directive
	// Reclassified contains directives present in both scans whose
	// classification or policy verdict changed between A and B.
	Reclassified []Reclassification
}

// Reclassification records a directive that exists in both scans but with a
// different risk class or policy verdict in B than in A. The B form is
// authoritative; A's class/outcome are kept for the human-readable summary.
type Reclassification struct {
	Before Directive
	After  Directive
}

// Identity returns the stable identity of a directive for diff matching. It
// excludes classification, policy verdict and applied-flag so a Reclassified
// directive is recognised as the same entity across scans.
func Identity(d Directive) string {
	var b strings.Builder
	b.WriteString(string(d.Kind))
	b.WriteByte('|')
	b.WriteString(d.Source)
	b.WriteByte('|')
	b.WriteString(d.OldPath)
	b.WriteByte('|')
	b.WriteString(d.OldVersion)
	b.WriteByte('|')
	b.WriteString(d.NewPath)
	b.WriteByte('|')
	b.WriteString(d.NewVersion)
	b.WriteByte('|')
	b.WriteString(d.LocalPath)
	return b.String()
}

// DiffScans computes the deterministic delta between scanA and scanB. It is a
// pure function: no I/O, no clock. Output is sorted by Identity for
// determinism so the same inputs always yield byte-identical bytes.
func DiffScans(scanA, scanB Record) DirectiveDiff {
	idxA := indexByIdentity(scanA.Directives)
	idxB := indexByIdentity(scanB.Directives)

	diff := DirectiveDiff{ScanA: scanA, ScanB: scanB}

	for id, b := range idxB {
		a, ok := idxA[id]
		if !ok {
			diff.Added = append(diff.Added, b)
			continue
		}
		if a.Class != b.Class || a.PolicyOutcome != b.PolicyOutcome || a.PolicyBlocking != b.PolicyBlocking {
			diff.Reclassified = append(diff.Reclassified, Reclassification{Before: a, After: b})
		}
	}
	for id, a := range idxA {
		if _, ok := idxB[id]; !ok {
			diff.Removed = append(diff.Removed, a)
		}
	}

	slices.SortFunc(diff.Added, compareByIdentity)
	slices.SortFunc(diff.Removed, compareByIdentity)
	slices.SortFunc(diff.Reclassified, func(a, b Reclassification) int {
		return compareByIdentity(a.After, b.After)
	})
	return diff
}

// HasChanges reports whether the diff contains any added, removed or
// reclassified directives. Callers use it to short-circuit "no change" output.
func (d DirectiveDiff) HasChanges() bool {
	return len(d.Added)+len(d.Removed)+len(d.Reclassified) > 0
}

func indexByIdentity(ds []Directive) map[string]Directive {
	m := make(map[string]Directive, len(ds))
	for _, d := range ds {
		m[Identity(d)] = d
	}
	return m
}

func compareByIdentity(a, b Directive) int {
	ai, bi := Identity(a), Identity(b)
	if ai < bi {
		return -1
	}
	if ai > bi {
		return 1
	}
	return 0
}
