// Package versionorder holds the two version comparisons this codebase makes,
// so that neither is spelled as a string idiom again.
//
// A version is a sequence of numbers written down as text, and text order
// inverts against number order at every digit-count boundary: "v10" sorts
// before "v9", "0.10.0" before "0.9.0". Both comparisons regrew here as `a < b`
// in a comparator, which reads correct and is wrong for exactly the pairs a
// long-lived ledger eventually holds.
//
// The two comparisons are separate functions because their inputs are separate
// vocabularies. A module version is semver and x/mod/semver already decides it.
// A pipeline version is a generation counter this project writes, in one of two
// shapes — "v19" on the vuln and sbom ledgers, "0.4.1" on the callgraph, vendor
// and directive ones — and semver rejects both.
package versionorder

import (
	"strings"

	"golang.org/x/mod/semver"
)

// ComparePipelineVersions orders two pipeline version strings by the numbers
// they state: -1 if a is the older generation, +1 if it is the newer, 0 if they
// state the same generation.
//
// Both shapes the ledgers use are read: an optional leading "v", then
// dot-separated decimal components. Absent trailing components are zero, so
// "0.4" and "0.4.0" name one generation.
//
// A version that cannot state its number ranks BELOW every one that can, and
// equal to every other that cannot. A newest-wins selection must not be won by
// a value whose generation is unreadable — serving it would answer from a
// record nothing can place on the ladder.
//
// Two versions in different shapes ("v19" against "0.4.1") are compared as the
// numbers they hold. No ledger mixes the shapes, so the case does not arise in
// the store; it is defined rather than left to chance because a comparator
// returning an arbitrary answer for an input it did not expect is the shape
// this package exists to remove.
func ComparePipelineVersions(a, b string) int {
	na, aok := pipelineComponents(a)
	nb, bok := pipelineComponents(b)
	switch {
	case !aok && !bok:
		return 0
	case !aok:
		return -1
	case !bok:
		return 1
	}
	for i := range max(len(na), len(nb)) {
		ca, cb := componentAt(na, i), componentAt(nb, i)
		if c := compareNumeral(ca, cb); c != 0 {
			return c
		}
	}
	return 0
}

// CompareModuleVersions orders two module versions semantically: -1 if a sorts
// first, +1 if b does, 0 if they order alike.
//
// It is semver.Compare with a defined answer for the inputs semver refuses. A
// module version reaching a comparator is not always valid semver — a
// "+incompatible" tail is, a bare branch name written into a replace directive
// is not — and semver.Compare returns 0 for anything it cannot read, which
// would collapse every invalid version into one position and leave the pair to
// the sort. Invalid versions fall back to string order between themselves and
// rank below every valid one, which keeps the comparison a total order.
//
// Use it wherever the ordering is one a reader sees. A comparator that exists
// only to make a serialisation deterministic may use any total order, and
// converting one of those changes the bytes a record hashes for no correction.
func CompareModuleVersions(a, b string) int {
	av, bv := semver.IsValid(a), semver.IsValid(b)
	switch {
	case av && bv:
		return semver.Compare(a, b)
	case av:
		return 1
	case bv:
		return -1
	}
	return strings.Compare(a, b)
}

// pipelineComponents splits a pipeline version into its decimal components,
// reporting false when any part of it is not a number.
func pipelineComponents(v string) ([]string, bool) {
	v = strings.TrimPrefix(v, "v")
	if v == "" {
		return nil, false
	}
	parts := strings.Split(v, ".")
	for _, p := range parts {
		if p == "" {
			return nil, false
		}
		for i := range len(p) {
			if p[i] < '0' || p[i] > '9' {
				return nil, false
			}
		}
	}
	return parts, true
}

// componentAt returns component i, or "0" past the end: a version that stops
// early states zero for the components it does not mention.
func componentAt(parts []string, i int) string {
	if i < len(parts) {
		return parts[i]
	}
	return "0"
}

// compareNumeral compares two decimal digit strings as numbers, without
// converting them to an integer type. A component wider than an int64 is not a
// version anyone writes, but a comparison that silently wraps on one is the
// same defect in a second place.
func compareNumeral(a, b string) int {
	a, b = strings.TrimLeft(a, "0"), strings.TrimLeft(b, "0")
	if len(a) != len(b) {
		if len(a) < len(b) {
			return -1
		}
		return 1
	}
	return strings.Compare(a, b)
}
