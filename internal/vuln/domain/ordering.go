package domain

import (
	"cmp"
	"slices"
)

// This file holds the one canonical ordering per collection in a
// VulnerabilityRecord, and the classification that says which collections have
// one.
//
// A collection whose order carries no meaning is an arrangement, and an
// arrangement that reaches the seal makes the seal describe the arrangement
// rather than the measurement. Measured on the real store: two scans of one
// walk against one advisory snapshot produced six records out of 128 that
// differed on nothing but the order of affected_symbols inside a finding, and
// the routes that follow those symbols. The values were equal as sets every
// time.
//
// Each comparator below is keyed on every field its collection puts on the
// wire, so no two distinct elements compare equal and the sorted order is a
// function of the set alone. That is what makes an unstable sort correct here;
// a stable one would not be an alternative, because stability decides ties by
// input order, which is exactly the input the record must not depend on.

// CollectionOrder says what a collection's order means.
type CollectionOrder string

const (
	// OrderUnordered marks a collection that is a SET on the wire: its elements
	// carry no relation to one another and the producer's arrangement is an
	// accident of how the scan ran. canonicalOrder sorts it.
	OrderUnordered CollectionOrder = "unordered"

	// OrderByMeaning marks a collection whose order IS part of what it says, so
	// sorting it would destroy a fact. canonicalOrder leaves it alone.
	OrderByMeaning CollectionOrder = "ordered-by-meaning"
)

// SealedCollections classifies every slice the sealed VulnerabilityRecord wire
// shape carries, by its JSON path, as a set or as an ordered statement.
//
// It is a classification of the shape, not a list somebody kept in their head:
// TestSealedCollections_ClassifiesEverySlice enumerates the record type by
// reflection and fails when a slice is added to the shape without being
// classified either way. That is the check that stops this defect recurring —
// the failure mode is silent, because an unclassified collection does not
// misbehave until two runs happen to produce it in two orders, and by then the
// disagreeing records are already in the store.
//
// How each was established:
//
//   - findings — the govulncheck parse accumulates one finding per advisory in
//     the order the advisory's messages arrive off the stream. Nothing about
//     that order is a fact about the module. Already sorted before this change,
//     by ID alone.
//   - findings[].affected_symbols — appended as each reached symbol arrives, one
//     govulncheck finding message per symbol (see processFinding). This is the
//     collection the disagreement was measured on: 52 of the 392 multi-symbol
//     findings in the store are in an order sorting would change.
//   - findings[].reachable.routes — appended beside those same messages, so the
//     routes ARRIVE in the symbols' order and move with them. It is classified
//     here on its own evidence rather than by following the symbols: 47 of the
//     59 multi-route findings in the store are in an order sorting would change.
//   - findings[].aliases and findings[].references — copied out of the matched
//     OSV entry's own arrays. They are sets of identifiers and URLs; the OSV
//     document happens to present them sorted today (146 multi-alias findings in
//     the store, none out of order, and no finding carries references at all),
//     so sorting them changes nothing now and pins them if an upstream document
//     ever presents them otherwise.
//   - findings[].reachable.routes[] — a single ReachabilityRoute, which is a
//     CALL STACK: entry point first, vulnerable symbol last. Its order is the
//     one thing it says. ReachabilityRoute's own doc records that the two
//     analysers disagreed about the direction and that it is normalised at the
//     producer for exactly this reason. Sorting it would turn a path into a bag
//     of hops.
func SealedCollections() map[string]CollectionOrder {
	return map[string]CollectionOrder{
		"findings":                      OrderUnordered,
		"findings[].affected_symbols":   OrderUnordered,
		"findings[].aliases":            OrderUnordered,
		"findings[].references":         OrderUnordered,
		"findings[].reachable.routes":   OrderUnordered,
		"findings[].reachable.routes[]": OrderByMeaning,
	}
}

// canonicalOrder returns r with every unordered collection in the order the
// canonical bytes carry, on copies: canonicalising a record never rearranges
// the caller's slices.
//
// The inner collections are sorted before the findings are, so the finding
// comparator compares canonical findings and cannot order two findings by an
// arrangement that is about to be discarded.
func canonicalOrder(r VulnerabilityRecord) VulnerabilityRecord {
	// A nil collection stays nil. Every one of these fields is omitzero, so
	// replacing a nil with an empty slice would put a "findings":[] member on the
	// wire that no stored record carries, changing the sealed shape of every
	// clean record in the store.
	if r.Findings == nil {
		return r
	}
	findings := make([]VulnerabilityFinding, len(r.Findings))
	for i, f := range r.Findings {
		findings[i] = canonicalFinding(f)
	}
	SortFindings(findings)
	r.Findings = findings
	return r
}

// canonicalFinding returns f with its own unordered collections sorted, on
// copies.
func canonicalFinding(f VulnerabilityFinding) VulnerabilityFinding {
	f.AffectedSymbols = sortedStrings(f.AffectedSymbols)
	f.Aliases = sortedStrings(f.Aliases)
	f.References = sortedStrings(f.References)
	if f.Reachable != nil {
		reachable := *f.Reachable
		// The routes are reordered; no route is. A route is a call stack, and its
		// hops are the statement.
		routes := slices.Clone(reachable.Routes)
		slices.SortFunc(routes, CompareReachabilityRoute)
		reachable.Routes = routes
		f.Reachable = &reachable
	}
	return f
}

// sortedStrings returns a sorted copy of s, preserving a nil as nil so an empty
// collection does not start appearing on the wire as [].
func sortedStrings(s []string) []string {
	if s == nil {
		return nil
	}
	out := slices.Clone(s)
	slices.Sort(out)
	return out
}

// SortFindings orders findings by the canonical total order below, so a record
// built from any of the paths that produce findings hashes and serialises
// identically across runs.
//
// It was keyed on ID alone, under a doc comment claiming a version tiebreak it
// never had. sort.Slice is not stable, so two findings sharing an ID ordered
// arbitrarily — no store holds such a pair today, and a comparator that decides
// the case is cheaper than a store that has to be checked for it.
func SortFindings(findings []VulnerabilityFinding) {
	slices.SortFunc(findings, CompareFinding)
}

// CompareFinding is the canonical total order on findings: the advisory ID
// first, because that is what a reader scans a finding list by, then every
// other field the finding puts on the wire so that two findings sharing an ID
// still have a defined order.
func CompareFinding(a, b VulnerabilityFinding) int {
	if c := cmp.Compare(a.ID, b.ID); c != 0 {
		return c
	}
	if c := cmp.Compare(a.AffectedRange, b.AffectedRange); c != 0 {
		return c
	}
	if c := cmp.Compare(a.FixedIn, b.FixedIn); c != 0 {
		return c
	}
	if c := cmp.Compare(a.Summary, b.Summary); c != 0 {
		return c
	}
	if c := cmp.Compare(a.Details, b.Details); c != 0 {
		return c
	}
	if c := compareSeverity(a.Severity, b.Severity); c != 0 {
		return c
	}
	if c := slices.Compare(a.AffectedSymbols, b.AffectedSymbols); c != 0 {
		return c
	}
	if c := slices.Compare(a.Aliases, b.Aliases); c != 0 {
		return c
	}
	if c := slices.Compare(a.References, b.References); c != 0 {
		return c
	}
	if c := compareBool(a.AdvisoryNamesNoSymbols, b.AdvisoryNamesNoSymbols); c != 0 {
		return c
	}
	if c := cmp.Compare(a.ReachabilityNote, b.ReachabilityNote); c != 0 {
		return c
	}
	if c := a.PublishedAt.Compare(b.PublishedAt); c != 0 {
		return c
	}
	if c := a.ModifiedAt.Compare(b.ModifiedAt); c != 0 {
		return c
	}
	if c := a.WithdrawnAt.Compare(b.WithdrawnAt); c != 0 {
		return c
	}
	return compareReachability(a.Reachable, b.Reachable)
}

// compareSeverity orders the optional severity, an absent one before a stated
// one. Score is compared with cmp.Compare rather than <, which orders a NaN
// score deterministically instead of reporting it equal to everything.
func compareSeverity(a, b *Severity) int {
	if a == nil || b == nil {
		return compareBool(a != nil, b != nil)
	}
	if c := cmp.Compare(a.Label, b.Label); c != 0 {
		return c
	}
	if c := cmp.Compare(a.Score, b.Score); c != 0 {
		return c
	}
	return cmp.Compare(a.Vector, b.Vector)
}

// compareReachability orders the optional reachability answer, an absent one
// before a stated one. A nil Reachable is a fact in its own right — see
// VulnerabilityFinding.ReachabilityAttemptFailed — so it sorts rather than
// being skipped.
func compareReachability(a, b *ReachabilityResult) int {
	if a == nil || b == nil {
		return compareBool(a != nil, b != nil)
	}
	if c := compareBool(a.IsReachable, b.IsReachable); c != 0 {
		return c
	}
	if c := cmp.Compare(string(a.Confidence), string(b.Confidence)); c != 0 {
		return c
	}
	if c := cmp.Compare(string(a.DerivedBy.Analyser), string(b.DerivedBy.Analyser)); c != 0 {
		return c
	}
	if c := cmp.Compare(a.DerivedBy.Fidelity, b.DerivedBy.Fidelity); c != 0 {
		return c
	}
	if c := cmp.Compare(string(a.DerivedBy.Rooting), string(b.DerivedBy.Rooting)); c != 0 {
		return c
	}
	return slices.CompareFunc(a.Routes, b.Routes, CompareReachabilityRoute)
}

// CompareReachabilityRoute is the canonical order on the ROUTES of one finding.
// It compares two routes hop by hop, and a route that is a prefix of another
// sorts first. It orders routes; it never reorders the hops within one.
func CompareReachabilityRoute(a, b ReachabilityRoute) int {
	return slices.CompareFunc(a, b, compareReachabilityFrame)
}

// compareReachabilityFrame orders two hops on every field a hop puts on the
// wire, so no two distinct hops compare equal.
func compareReachabilityFrame(a, b ReachabilityFrame) int {
	if c := cmp.Compare(a.ModulePath, b.ModulePath); c != 0 {
		return c
	}
	if c := cmp.Compare(a.ModuleVersion, b.ModuleVersion); c != 0 {
		return c
	}
	if c := cmp.Compare(a.Package, b.Package); c != 0 {
		return c
	}
	if c := cmp.Compare(a.Receiver, b.Receiver); c != 0 {
		return c
	}
	return cmp.Compare(a.Symbol, b.Symbol)
}

// compareBool orders false before true.
func compareBool(a, b bool) int {
	switch {
	case a == b:
		return 0
	case b:
		return -1
	default:
		return 1
	}
}
