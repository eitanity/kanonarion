package domain

import (
	"sort"

	"github.com/eitanity/kanonarion/internal/coordinate"
)

// This file holds the one canonical ordering per collection in a WalkRecord.
//
// Nodes were ordered on the selected coordinate and edges on the endpoint pair.
// Neither identifies its element. A replace directive gives one selected
// coordinate two origins, so two nodes tie on the coordinate and differ in
// OriginalCoordinate; two requirements on one dependency give one endpoint pair
// two constraint versions. On a tie the comparator gave no answer and
// sort.Slice, which is not stable, decided the pair by the order resolution
// emitted it in — an order that comes from map iteration, so it is not a
// property of the module graph and sort.SliceStable would not have helped.
//
// Each comparator is keyed on every field the canonical wire shape carries, so
// no two distinct elements compare equal and the order is a function of the set
// alone.

// GraphNodeLess is the canonical ordering for GraphNode slices. The selected
// coordinate leads, because that is what a reader scans the node list by; the
// origin, the resolution and the measured facts follow so that two nodes on one
// coordinate still have a defined order.
func GraphNodeLess(a, b GraphNode) bool {
	if result, decided := coordinateLess(a.Coordinate, b.Coordinate); decided {
		return result
	}
	if result, decided := coordinateLess(a.OriginalCoordinate, b.OriginalCoordinate); decided {
		return result
	}
	if a.ResolutionSource != b.ResolutionSource {
		return a.ResolutionSource < b.ResolutionSource
	}
	if a.DirectDependency != b.DirectDependency {
		return !a.DirectDependency
	}
	if a.Retracted != b.Retracted {
		return !a.Retracted
	}
	if a.LocalPath != b.LocalPath {
		return a.LocalPath < b.LocalPath
	}
	if a.ErrorDetail != b.ErrorDetail {
		return a.ErrorDetail < b.ErrorDetail
	}
	if a.Digests.SHA256 != b.Digests.SHA256 {
		return a.Digests.SHA256 < b.Digests.SHA256
	}
	if a.Digests.SHA384 != b.Digests.SHA384 {
		return a.Digests.SHA384 < b.Digests.SHA384
	}
	if a.Digests.SHA512 != b.Digests.SHA512 {
		return a.Digests.SHA512 < b.Digests.SHA512
	}
	return stdlibFactsLess(a.Stdlib, b.Stdlib)
}

// GraphEdgeLess is the canonical ordering for GraphEdge slices. The endpoints
// lead; the pre-resolution constraint follows, so two requirements on one
// dependency at different constraint versions still have a defined order.
func GraphEdgeLess(a, b GraphEdge) bool {
	if result, decided := coordinateLess(a.From, b.From); decided {
		return result
	}
	if result, decided := coordinateLess(a.To, b.To); decided {
		return result
	}
	return a.ConstraintVersion < b.ConstraintVersion
}

// CoordinateLess is the canonical ordering for module coordinates: path, then
// version. A coordinate is those two strings and nothing else, so this is a
// total order over distinct coordinates.
func CoordinateLess(a, b coordinate.ModuleCoordinate) bool {
	result, _ := coordinateLess(a, b)
	return result
}

// coordinateLess reports whether a sorts before b and whether it decided
// anything, so a caller can fall through to its next key.
func coordinateLess(a, b coordinate.ModuleCoordinate) (result, decided bool) {
	if a.Path() != b.Path() {
		return a.Path() < b.Path(), true
	}
	if a.Version() != b.Version() {
		return a.Version() < b.Version(), true
	}
	return false, false
}

// stdlibFactsLess orders the standard library's custody evidence, which is
// carried by at most one node in a walk. A node without it sorts first, so the
// absence is ordered rather than left to the sort.
func stdlibFactsLess(a, b *StdlibFacts) bool {
	switch {
	case a == nil && b == nil:
		return false
	case a == nil:
		return true
	case b == nil:
		return false
	}
	if a.LicenseSPDX != b.LicenseSPDX {
		return a.LicenseSPDX < b.LicenseSPDX
	}
	if a.VerificationStatus != b.VerificationStatus {
		return a.VerificationStatus < b.VerificationStatus
	}
	if a.VerificationDetail != b.VerificationDetail {
		return a.VerificationDetail < b.VerificationDetail
	}
	if a.PublishedSHA256 != b.PublishedSHA256 {
		return a.PublishedSHA256 < b.PublishedSHA256
	}
	if a.SourceURL != b.SourceURL {
		return a.SourceURL < b.SourceURL
	}
	if a.VCSURL != b.VCSURL {
		return a.VCSURL < b.VCSURL
	}
	if a.VCSRef != b.VCSRef {
		return a.VCSRef < b.VCSRef
	}
	return a.VCSCommit < b.VCSCommit
}

// sortSlice orders a slice through one of the named comparators above.
func sortSlice[T any](s []T, less func(a, b T) bool) {
	sort.Slice(s, func(i, j int) bool { return less(s[i], s[j]) })
}
