package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// DirectiveLess is the canonical ordering for Directive slices: where the
// directive was read from, then what it says.
//
// It was keyed on source, line, kind and the left-hand side only. Those do not
// identify a directive — a workspace and a go.mod can put two different
// directives on one line number of two files that trim to one Source, and the
// right-hand side, the applied flag and the classification were all invisible to
// the comparator. A tie left the pair to the sort, and the pair's order reaches
// both the rendered list and Hash. Every field the type carries is keyed here,
// so two distinct directives always have a defined order.
func DirectiveLess(a, b Directive) bool {
	if a.Source != b.Source {
		return a.Source < b.Source
	}
	if a.Line != b.Line {
		return a.Line < b.Line
	}
	if a.Kind != b.Kind {
		return a.Kind < b.Kind
	}
	if a.OldPath != b.OldPath {
		return a.OldPath < b.OldPath
	}
	if a.OldVersion != b.OldVersion {
		return a.OldVersion < b.OldVersion
	}
	if a.NewPath != b.NewPath {
		return a.NewPath < b.NewPath
	}
	if a.NewVersion != b.NewVersion {
		return a.NewVersion < b.NewVersion
	}
	if a.IsLocal != b.IsLocal {
		return !a.IsLocal
	}
	if a.LocalPath != b.LocalPath {
		return a.LocalPath < b.LocalPath
	}
	if a.Applied != b.Applied {
		return !a.Applied
	}
	if a.Class != b.Class {
		return a.Class < b.Class
	}
	if a.ReachabilityTarget != b.ReachabilityTarget {
		return a.ReachabilityTarget < b.ReachabilityTarget
	}
	if a.PolicyOutcome != b.PolicyOutcome {
		return a.PolicyOutcome < b.PolicyOutcome
	}
	if a.PolicyBlocking != b.PolicyBlocking {
		return !a.PolicyBlocking
	}
	return false
}

// Sort orders directives by DirectiveLess. Output must be in a canonical order
// before hashing or serialising, and the comparator is a total order, so the
// result is a function of the set and not of the order the files were read in.
func Sort(ds []Directive) {
	sort.Slice(ds, func(i, j int) bool { return DirectiveLess(ds[i], ds[j]) })
}

// Hash returns a deterministic content hash of the sorted directive set. The
// caller must Sort first; Hash does not re-sort so the hash reflects exactly
// what is serialised.
func Hash(ds []Directive) string {
	var b strings.Builder
	for _, d := range ds {
		fmt.Fprintf(&b, "%s|%s|%d|%s|%s|%t|%s|%s|%s|%t|%s\n",
			d.Kind, d.Source, d.Line, d.OldPath, d.OldVersion,
			d.IsLocal, d.LocalPath, d.NewPath, d.NewVersion,
			d.Applied, d.Class)
	}
	sum := sha256.Sum256([]byte(b.String()))
	return "sha256:" + hex.EncodeToString(sum[:])
}
