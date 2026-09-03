package domain

import "slices"

// MergeCoordinateMatches merges a coordinate match's findings into the findings
// an analysis reported for the same module, FIELD BY FIELD rather than by
// whole finding. It returns the merged set in canonical order, and the number
// of findings the analysis did not report at all.
//
// The two producing routes are complementary, and picking one whole finding
// discards what the other knows. The analysis route (govulncheck) reads the
// stream: it establishes which symbols the build reaches and, through the
// reachability step, whether it reaches them — facts a coordinate lookup cannot
// derive at all. The coordinate route (an OSV advisory read by module path and
// version) renders the advisory's own affected range, which the analysis route
// never sets. Before this merge, an advisory reported by BOTH routes was stored
// with the range and without it depending on which route got there first, in a
// field that is sealed and content-hashed.
//
// AUTHORITY, field by field. "Analysis" means the finding the analysis
// reported; "match" means the coordinate match for the same advisory ID.
//
//	ID                       analysis   the merge key; the two are equal by construction
//	Reachable                analysis   ONLY the analysis can establish it. A coordinate
//	                                    match knows nothing about reachability, and the
//	                                    not-reachable verdict this package's callers
//	                                    attach to an unreported match is derived from the
//	                                    analysis's SILENCE — it is not a fact about the
//	                                    advisory and must never displace a real answer.
//	                                    AdvisoryNamesNoSymbols below only WITHDRAWS it.
//	ReachabilityNote         analysis   states why a requested analysis produced no
//	                                    answer; the match never requests one.
//	AffectedSymbols          analysis   the analysis states the advisory's symbols this
//	                                    build reaches, or the advisory's whole list where
//	                                    it reached none. Either way the match's list is
//	                                    NEVER merged in or substituted — an analysis that
//	                                    reached one symbol would otherwise come to look
//	                                    like one that reached every symbol the advisory
//	                                    names.
//	AffectedRange            match      the analysis route never sets it. This is the
//	                                    field the whole-finding merge was losing.
//	Summary, Details         either     advisory-level prose; identical from both routes.
//	Aliases, References      either     advisory-level lists, carried whole from the
//	                                    advisory by both routes.
//	Severity                 either     neither route populates it today.
//	FixedIn                  either     both routes state it, from the stream's fixed
//	                                    version and from the advisory's range respectively.
//	PublishedAt, ModifiedAt  either     advisory-level timestamps.
//	WithdrawnAt              either     the retraction timestamp. Absence means "live OR
//	                                    no advisory was read", so a match that carries one
//	                                    fills an analysis that does not: a finding missing
//	                                    it is counted as live.
//	AdvisoryNamesNoSymbols   either     a fact about the advisory entry, which both
//	                                    routes read from the same snapshot. Adopting it
//	                                    empties AffectedSymbols and withdraws Reachable's
//	                                    symbol-level claim, keeping the routes, so the
//	                                    flag can never contradict what stands beside it.
//
// Where the table says "either", the analysis's value wins when it is set and
// the match fills it when it is not. That direction is not arbitrary: an empty
// advisory-level field on the analysis side means the enrichment did not happen
// (the stream carried a finding whose OSV message never arrived), so the match
// is filling a gap rather than overruling a fact.
//
// DETERMINISM. Findings are sealed and content-hashed, so the merged set must
// depend on the two inputs alone and not on the order of either. Every rule
// above is a per-field function of the (analysis, match) pair; matches are
// merged in canonical order so that two matches sharing an ID resolve the same
// way whatever order they arrived in; and the result is always sorted, because
// filling a field changes the finding's own sort key.
//
// onAdd, when non-nil, is applied to each match the analysis did not report,
// before it joins the set. It is where a caller states what the analysis's
// silence about that advisory means. Findings are never dropped in either
// direction.
func MergeCoordinateMatches(
	analysis, matched []VulnerabilityFinding,
	onAdd func(*VulnerabilityFinding),
) (merged []VulnerabilityFinding, added int) {
	merged = slices.Clone(analysis)
	byID := make(map[string]int, len(merged))
	for i, f := range merged {
		if _, ok := byID[f.ID]; !ok {
			byID[f.ID] = i
		}
	}
	// The match order decides nothing about the outcome, which is why it is
	// normalised here rather than left to the adapter that produced it.
	ordered := slices.Clone(matched)
	SortFindings(ordered)
	for _, m := range ordered {
		if i, ok := byID[m.ID]; ok {
			merged[i] = mergeCoordinateMatch(merged[i], m)
			continue
		}
		if onAdd != nil {
			onAdd(&m)
		}
		byID[m.ID] = len(merged)
		merged = append(merged, m)
		added++
	}
	// Unconditional, unlike the sort this replaced: a field-wise merge changes
	// the sort key of a finding it fills, so a set that gained no member can
	// still have changed order.
	SortFindings(merged)
	return merged, added
}

// mergeCoordinateMatch applies the authority table documented on
// MergeCoordinateMatches to one advisory reported by both routes.
func mergeCoordinateMatch(analysis, match VulnerabilityFinding) VulnerabilityFinding {
	f := analysis
	if f.AffectedRange == "" {
		f.AffectedRange = match.AffectedRange
	}
	if f.FixedIn == "" {
		f.FixedIn = match.FixedIn
	}
	if f.Summary == "" {
		f.Summary = match.Summary
	}
	if f.Details == "" {
		f.Details = match.Details
	}
	if len(f.Aliases) == 0 {
		f.Aliases = match.Aliases
	}
	if len(f.References) == 0 {
		f.References = match.References
	}
	if f.Severity == nil {
		f.Severity = match.Severity
	}
	if f.PublishedAt.IsZero() {
		f.PublishedAt = match.PublishedAt
	}
	if f.ModifiedAt.IsZero() {
		f.ModifiedAt = match.ModifiedAt
	}
	if f.WithdrawnAt.IsZero() {
		f.WithdrawnAt = match.WithdrawnAt
	}
	if match.AdvisoryNamesNoSymbols {
		f.AdvisoryNamesNoSymbols = true
		// An advisory naming no symbols for this path is neither the source of a
		// list under it nor a target anything could have reached, so both go. The
		// routes stay; only the analysis route can normally reach this, and it does
		// so already — this covers a stream whose OSV message never arrived.
		f.AffectedSymbols = nil
		if f.Reachable != nil {
			// Copied, never written through: the merged set is a shallow clone, so
			// mutating the pointee would rewrite the caller's own finding.
			r := *f.Reachable
			r.IsReachable = false
			r.Confidence = ConfidenceUnknown
			f.Reachable = &r
		}
	}
	return f
}
