package domain_test

import (
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/vuln/domain"
)

// TestMergeCoordinateMatches_FillsEveryEmptyFieldFromTheMatch. The analysis
// route reports what it reached; the coordinate route reports what the advisory
// says. A finding the analysis raised carries the reachability answer and often
// little else, and every field left empty is one a reader needs and the advisory
// already holds. A field the analysis DID state is never overwritten: the
// analysis measured this build, and the advisory did not.
func TestMergeCoordinateMatches_FillsEveryEmptyFieldFromTheMatch(t *testing.T) {
	t.Parallel()
	published := time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)
	modified := time.Date(2026, 3, 4, 0, 0, 0, 0, time.UTC)
	analysis := []domain.VulnerabilityFinding{{ID: "GO-2026-0001", Summary: "measured by the analysis"}}
	match := []domain.VulnerabilityFinding{{
		ID:            "GO-2026-0001",
		Summary:       "from the advisory",
		Details:       "the long form",
		AffectedRange: "< v1.2.3",
		FixedIn:       "v1.2.3",
		Aliases:       []string{"CVE-2026-0001"},
		References:    []domain.AdvisoryReference{{Type: "ADVISORY", URL: "https://example.invalid/a"}},
		Severity:      &domain.Severity{},
		PublishedAt:   published,
		ModifiedAt:    modified,
	}}

	merged, added := domain.MergeCoordinateMatches(analysis, match, nil)

	if added != 0 || len(merged) != 1 {
		t.Fatalf("merged %d finding(s) with %d added, want one finding and nothing added", len(merged), added)
	}
	got := merged[0]
	if got.Summary != "measured by the analysis" {
		t.Errorf("Summary = %q; a field the analysis stated must not be overwritten by the advisory", got.Summary)
	}
	for name, ok := range map[string]bool{
		"Details":       got.Details == "the long form",
		"AffectedRange": got.AffectedRange == "< v1.2.3",
		"FixedIn":       got.FixedIn == "v1.2.3",
		"Aliases":       len(got.Aliases) == 1,
		"References":    len(got.References) == 1,
		"Severity":      got.Severity != nil,
		"PublishedAt":   got.PublishedAt.Equal(published),
		"ModifiedAt":    got.ModifiedAt.Equal(modified),
	} {
		if !ok {
			t.Errorf("%s was left empty; the advisory holds it and the reader needs it", name)
		}
	}
}

// TestMergeCoordinateMatches_StatesWhatTheAnalysesSilenceMeans: a match the
// analysis never raised joins the set, and onAdd is where the caller says what
// the analysis not reporting it means. Findings are never dropped in either
// direction, so a hook that never fired would leave an advisory in the record
// with no account of why the analysis is silent about it.
func TestMergeCoordinateMatches_StatesWhatTheAnalysesSilenceMeans(t *testing.T) {
	t.Parallel()
	analysis := []domain.VulnerabilityFinding{{ID: "GO-2026-0001"}}
	match := []domain.VulnerabilityFinding{{ID: "GO-2026-0001"}, {ID: "GO-2026-0002"}}

	var stamped []string
	merged, added := domain.MergeCoordinateMatches(analysis, match, func(f *domain.VulnerabilityFinding) {
		stamped = append(stamped, f.ID)
		f.Summary = "matched by coordinate; the analysis did not raise it"
	})

	if added != 1 {
		t.Errorf("added = %d, want 1", added)
	}
	if len(stamped) != 1 || stamped[0] != "GO-2026-0002" {
		t.Errorf("onAdd saw %v, want only the match the analysis did not report", stamped)
	}
	for _, f := range merged {
		if f.ID == "GO-2026-0002" && f.Summary == "" {
			t.Error("the added match reached the record with no account of the analysis's silence")
		}
	}
}

// TestNegativeSoundness_AOneHopRouteIsNotACallChain. A route of one hop means the
// vulnerable symbol is itself a root the search starts from, and calling that "a
// path was found" would overstate what was measured — being a root is the
// substance of the disagreement, not a chain to it.
func TestNegativeSoundness_AOneHopRouteIsNotACallChain(t *testing.T) {
	t.Parallel()
	symbol := domain.ReachabilityFrame{ModulePath: "example.com/dep", ModuleVersion: "v1.0.0", Package: "dep", Symbol: "Vulnerable"}
	f := domain.VulnerabilityFinding{
		ID: "GO-2026-0001",
		Reachable: &domain.ReachabilityResult{
			IsReachable: false,
			DerivedBy:   domain.ReachabilityDerivation{Analyser: domain.AnalyserGovulncheck, Fidelity: "Complete"},
		},
		NegativeSearch: &domain.NegativeSearch{
			Fidelity: "Complete", PathFound: true, InRecordedFrame: true,
			Route: domain.ReachabilityRoute{symbol},
		},
	}

	soundness, reason := domain.NegativeSoundness(f)

	if soundness != domain.SoundnessDisputed {
		t.Errorf("soundness = %v, want disputed: a search that reaches the symbol contradicts the recorded negative", soundness)
	}
	if !strings.Contains(reason, "is itself an entry point of the analysed module's graph, not a symbol behind one") {
		t.Errorf("the reason reads a one-hop route as a call chain:\n%s", reason)
	}
	if strings.Contains(reason, " along ") {
		t.Errorf("a one-hop route was rendered as a path travelled:\n%s", reason)
	}
}

// TestNegativeSoundness_ACrossFrameRouteIsStatedWithItsFrameNamed. A path in the
// module's own graph does not contradict a negative measured in another build, so
// the recorded rung stands — but the route is reported beside it, because a route
// this tool found and did not report is the one outcome a reachability tool must
// never produce.
func TestNegativeSoundness_ACrossFrameRouteIsStatedWithItsFrameNamed(t *testing.T) {
	t.Parallel()
	route := domain.ReachabilityRoute{
		{ModulePath: "example.com/dep", ModuleVersion: "v1.0.0", Package: "dep", Symbol: "Entry"},
		{ModulePath: "example.com/dep", ModuleVersion: "v1.0.0", Package: "dep", Symbol: "Vulnerable"},
	}
	f := domain.VulnerabilityFinding{
		ID: "GO-2026-0001",
		Reachable: &domain.ReachabilityResult{
			IsReachable: false,
			DerivedBy:   domain.ReachabilityDerivation{Analyser: domain.AnalyserGovulncheck, Fidelity: "Complete"},
		},
		NegativeSearch: &domain.NegativeSearch{Fidelity: "Complete", PathFound: true, Route: route},
	}

	_, reason := domain.NegativeSoundness(f)

	if !strings.Contains(reason, "That is a different question from the one this record answers") {
		t.Errorf("the cross-frame route was not stated with its frame named:\n%s", reason)
	}
	if !strings.Contains(reason, " along ") {
		t.Errorf("a multi-hop cross-frame route was reported without the route:\n%s", reason)
	}
}
