package domain_test

import (
	"encoding/json"
	"slices"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/vuln/domain"
)

// analysisFinding is what the analysis route produces for an advisory it
// reported: symbols it saw, a reachability answer, a fixed version from the
// stream — and no affected range, which that route never sets.
func analysisFinding() domain.VulnerabilityFinding {
	return domain.VulnerabilityFinding{
		ID:              "GO-2025-3553",
		Summary:         "excessive memory allocation",
		Details:         "the parser allocates without bound",
		FixedIn:         "v4.5.2",
		AffectedSymbols: []string{"Parser.ParseUnverified"},
		Reachable: &domain.ReachabilityResult{
			IsReachable: true,
			Confidence:  domain.ConfidenceHigh,
			DerivedBy: domain.ReachabilityDerivation{
				Analyser: domain.AnalyserGovulncheck,
				Fidelity: string(domain.ScanModeSource),
			},
		},
		PublishedAt: time.Date(2025, 2, 1, 0, 0, 0, 0, time.UTC),
	}
}

// coordinateMatch is what the coordinate route produces for the SAME advisory:
// the advisory's rendered range, and the advisory's own declared symbol list,
// with no reachability answer at all.
func coordinateMatch() domain.VulnerabilityFinding {
	return domain.VulnerabilityFinding{
		ID:              "GO-2025-3553",
		Summary:         "excessive memory allocation",
		Details:         "the parser allocates without bound",
		AffectedRange:   "< v4.5.2",
		FixedIn:         "v4.5.2",
		AffectedSymbols: []string{"Parser.Parse", "Parser.ParseUnverified", "Parser.ParseWithClaims"},
		References:      []domain.AdvisoryReference{{Type: "FIX", URL: "https://example.invalid/fix"}},
		PublishedAt:     time.Date(2025, 2, 1, 0, 0, 0, 0, time.UTC),
	}
}

// TestMergeCoordinateMatches_KeepsBothRoutesFacts is the regression test for the
// two-shapes defect: one advisory reported by both routes was stored with the
// affected range or without it depending on which route reached it, because the
// merge picked a whole finding. The analysis's symbols and route must survive
// AND the range must arrive.
func TestMergeCoordinateMatches_KeepsBothRoutesFacts(t *testing.T) {
	merged, added := domain.MergeCoordinateMatches(
		[]domain.VulnerabilityFinding{analysisFinding()},
		[]domain.VulnerabilityFinding{coordinateMatch()},
		nil,
	)
	if added != 0 {
		t.Fatalf("added = %d, want 0: the advisory was already reported", added)
	}
	if len(merged) != 1 {
		t.Fatalf("merged = %d findings, want 1: an advisory reported twice is one finding", len(merged))
	}
	got := merged[0]
	if got.AffectedRange != "< v4.5.2" {
		t.Errorf("AffectedRange = %q, want %q: the coordinate match carries the range the analysis route never sets", got.AffectedRange, "< v4.5.2")
	}
	if !slices.Equal(got.AffectedSymbols, []string{"Parser.ParseUnverified"}) {
		t.Errorf("AffectedSymbols = %v, want the analysis's own list: the advisory's declared symbols are a different fact and must not replace or join what the build reached", got.AffectedSymbols)
	}
	if got.Reachable == nil || !got.Reachable.IsReachable {
		t.Errorf("Reachable = %+v, want the analysis's reachable answer", got.Reachable)
	}
	if len(got.References) != 1 {
		t.Errorf("References = %v, want the match's advisory links filling an analysis that carried none", got.References)
	}
	if got.FixedIn != "v4.5.2" {
		t.Errorf("FixedIn = %q, want v4.5.2", got.FixedIn)
	}
}

// TestMergeCoordinateMatches_CoordinateMatchNeverDisplacesReachability pins the
// one direction that would be a wrong answer rather than a shape difference: a
// coordinate match knows nothing about reachability, and the not-reachable
// verdict a caller attaches to an UNREPORTED match is derived from the
// analysis's silence. Neither may overwrite a real answer.
func TestMergeCoordinateMatches_CoordinateMatchNeverDisplacesReachability(t *testing.T) {
	match := coordinateMatch()
	// The strongest form: the match arrives already carrying the fabricated
	// not-reachable verdict, as it would if a caller's onAdd ever reached it.
	match.Reachable = &domain.ReachabilityResult{IsReachable: false, Confidence: domain.ConfidenceHigh}

	onAddCalled := false
	merged, _ := domain.MergeCoordinateMatches(
		[]domain.VulnerabilityFinding{analysisFinding()},
		[]domain.VulnerabilityFinding{match},
		func(*domain.VulnerabilityFinding) { onAddCalled = true },
	)
	if onAddCalled {
		t.Error("onAdd ran for an advisory the analysis reported: the silence rule applies only to a match the analysis never mentioned")
	}
	if r := merged[0].Reachable; r == nil || !r.IsReachable {
		t.Fatalf("Reachable = %+v, want the analysis's reachable=true answer to stand", r)
	}
}

// TestMergeCoordinateMatches_SingleRouteFindingIsUnchanged covers the case the
// fix must not touch: an advisory only one route reports keeps exactly what that
// route produced.
func TestMergeCoordinateMatches_SingleRouteFindingIsUnchanged(t *testing.T) {
	only := analysisFinding()
	merged, added := domain.MergeCoordinateMatches([]domain.VulnerabilityFinding{only}, nil, nil)
	if added != 0 || len(merged) != 1 {
		t.Fatalf("merged = %d findings, added = %d, want 1 and 0", len(merged), added)
	}
	if !equalFindingJSON(t, merged[0], only) {
		t.Errorf("analysis-only finding changed:\n got %s\nwant %s", findingJSON(t, merged[0]), findingJSON(t, only))
	}

	match := coordinateMatch()
	match.ID = "GO-2025-9999"
	merged, added = domain.MergeCoordinateMatches(nil, []domain.VulnerabilityFinding{match}, nil)
	if added != 1 || len(merged) != 1 {
		t.Fatalf("merged = %d findings, added = %d, want 1 and 1", len(merged), added)
	}
	if !equalFindingJSON(t, merged[0], match) {
		t.Errorf("coordinate-only finding changed:\n got %s\nwant %s", findingJSON(t, merged[0]), findingJSON(t, match))
	}
}

// TestMergeCoordinateMatches_IsOrderIndependent: findings are sealed and
// content-hashed, so the merged set must be byte-identical whatever order either
// source presents its findings in.
func TestMergeCoordinateMatches_IsOrderIndependent(t *testing.T) {
	second := analysisFinding()
	second.ID = "GO-2025-1111"
	second.AffectedSymbols = []string{"Other.Symbol"}
	extra := coordinateMatch()
	extra.ID = "GO-2025-2222"
	extra.AffectedRange = ">= v1.0.0"

	analysis := []domain.VulnerabilityFinding{analysisFinding(), second}
	matched := []domain.VulnerabilityFinding{coordinateMatch(), extra}

	forward, addedForward := domain.MergeCoordinateMatches(analysis, matched, nil)
	reversed, addedReversed := domain.MergeCoordinateMatches(
		[]domain.VulnerabilityFinding{second, analysisFinding()},
		[]domain.VulnerabilityFinding{extra, coordinateMatch()},
		nil,
	)
	if addedForward != addedReversed {
		t.Fatalf("added = %d and %d across orderings", addedForward, addedReversed)
	}
	if a, b := findingsJSON(t, forward), findingsJSON(t, reversed); a != b {
		t.Errorf("merged set differs by input order:\n %s\n %s", a, b)
	}
	// The consequence, stated where it bites: a record's identity is a hash over
	// its findings, so an order-dependent merge would seal one scan's result under
	// two identities.
	if a, b := sealedHash(t, forward), sealedHash(t, reversed); a != b {
		t.Errorf("sealed record hash differs by input order: %s vs %s", a, b)
	}
}

// sealedHash seals a record carrying fs and returns its content hash.
func sealedHash(t *testing.T, fs []domain.VulnerabilityFinding) string {
	t.Helper()
	rec := sampleRecord(t)
	rec.Findings = fs
	sealed, err := domain.VulnerabilityRecordHasher{}.SetContentHash(rec)
	if err != nil {
		t.Fatalf("SetContentHash: %v", err)
	}
	return sealed.ContentHash
}

// TestMergeCoordinateMatches_FillsARetractionTheAnalysisMissed: an absent
// withdrawal timestamp means "live OR no advisory was read", and a finding
// missing it counts as live. A match that read the advisory fills it.
func TestMergeCoordinateMatches_FillsARetractionTheAnalysisMissed(t *testing.T) {
	withdrawnAt := time.Date(2026, 4, 8, 13, 33, 56, 0, time.UTC)
	match := coordinateMatch()
	match.WithdrawnAt = withdrawnAt

	merged, _ := domain.MergeCoordinateMatches(
		[]domain.VulnerabilityFinding{analysisFinding()},
		[]domain.VulnerabilityFinding{match},
		nil,
	)
	if !merged[0].WithdrawnAt.Equal(withdrawnAt) {
		t.Errorf("WithdrawnAt = %v, want %v: a retraction one route read must not be dropped by the merge", merged[0].WithdrawnAt, withdrawnAt)
	}
	if got := domain.DetermineFindingsAxis(merged); got != domain.FindingsRecordWithdrawn {
		t.Errorf("findings axis = %q, want %q", got, domain.FindingsRecordWithdrawn)
	}
}

// TestMergeCoordinateMatches_SymbolFlagNeverContradictsASymbolList: the record
// can never state both the "advisory names no symbols" flag and a symbol list.
// The flag is what the advisory entry says, and it decides: a list standing
// under it did not come from the advisory, so adopting the flag empties it.
func TestMergeCoordinateMatches_SymbolFlagNeverContradictsASymbolList(t *testing.T) {
	match := coordinateMatch()
	match.AffectedSymbols = nil
	match.AdvisoryNamesNoSymbols = true

	merged, _ := domain.MergeCoordinateMatches(
		[]domain.VulnerabilityFinding{analysisFinding()},
		[]domain.VulnerabilityFinding{match},
		nil,
	)
	if !merged[0].AdvisoryNamesNoSymbols {
		t.Error("AdvisoryNamesNoSymbols dropped: the advisory fact the match read is the one thing the analysis route could not have")
	}
	if len(merged[0].AffectedSymbols) != 0 {
		t.Errorf("AffectedSymbols = %v, want empty: the record would say the advisory named none while listing one", merged[0].AffectedSymbols)
	}
	// The same reasoning reaches the reachability answer: with no symbol named
	// there was nothing for the analysis to reach, so the record must not seal a
	// symbol-level claim beside the flag. The route stays — a real call frame is
	// evidence about which dependency reaches the package.
	if r := merged[0].Reachable; r == nil {
		t.Error("the reachability answer was dropped rather than withdrawn")
	} else {
		if r.IsReachable {
			t.Error("is_reachable = true beside a flag saying the advisory names no symbol for this path")
		}
		if r.Confidence != domain.ConfidenceUnknown {
			t.Errorf("confidence = %q, want %q", r.Confidence, domain.ConfidenceUnknown)
		}
	}
	// And the caller's own finding is untouched: the merge returns a shallow clone,
	// so withdrawing the claim through the shared pointer would rewrite its input.
	if src := analysisFinding(); !src.Reachable.IsReachable || src.Reachable.Confidence != domain.ConfidenceHigh {
		t.Fatal("fixture changed")
	}
	input := analysisFinding()
	_, _ = domain.MergeCoordinateMatches(
		[]domain.VulnerabilityFinding{input},
		[]domain.VulnerabilityFinding{match},
		nil,
	)
	if !input.Reachable.IsReachable || input.Reachable.Confidence != domain.ConfidenceHigh {
		t.Errorf("the merge rewrote its own input's reachability answer: %+v", input.Reachable)
	}

	bare := analysisFinding()
	bare.AffectedSymbols = nil
	merged, _ = domain.MergeCoordinateMatches(
		[]domain.VulnerabilityFinding{bare},
		[]domain.VulnerabilityFinding{match},
		nil,
	)
	if !merged[0].AdvisoryNamesNoSymbols {
		t.Error("AdvisoryNamesNoSymbols not adopted where the analysis names no symbols: an empty symbol list would read as a gap rather than as the advisory naming none")
	}
}

// TestMergeCoordinateMatches_AddedMatchNamingNoSymbolsCarriesNoConfidentNegative
// drives the leg no test covered: an advisory the analysis never reported at all,
// added by the coordinate match alone. The flag arrives from the advisory entry
// and the verdict beside it is stamped by the caller's onAdd, so neither producer
// on its own can see the contradiction — and a "not reachable at High confidence"
// on an advisory naming no symbol asserts a search that had no target.
func TestMergeCoordinateMatches_AddedMatchNamingNoSymbolsCarriesNoConfidentNegative(t *testing.T) {
	match := coordinateMatch()
	match.ID = "GO-2026-5932"
	match.AffectedSymbols = nil
	match.AdvisoryNamesNoSymbols = true

	// The stamp the project-rooted scan applies to an advisory the build analysis
	// did not report: its silence is the answer, at high confidence.
	stamped := 0
	merged, added := domain.MergeCoordinateMatches(
		[]domain.VulnerabilityFinding{analysisFinding()},
		[]domain.VulnerabilityFinding{match},
		func(f *domain.VulnerabilityFinding) {
			stamped++
			f.Reachable = &domain.ReachabilityResult{
				IsReachable: false,
				Confidence:  domain.ConfidenceHigh,
				DerivedBy: domain.ReachabilityDerivation{
					Analyser: domain.AnalyserGovulncheck,
					Fidelity: string(domain.ScanModeSource),
				},
			}
		},
	)
	if added != 1 || stamped != 1 || len(merged) != 2 {
		t.Fatalf("added = %d, onAdd calls = %d, merged = %d; want 1, 1, 2", added, stamped, len(merged))
	}

	var got *domain.VulnerabilityFinding
	for i := range merged {
		if merged[i].ID == match.ID {
			got = &merged[i]
		}
	}
	if got == nil {
		t.Fatal("the coordinate match was dropped")
	}
	if !got.AdvisoryNamesNoSymbols {
		t.Fatal("AdvisoryNamesNoSymbols dropped from the added match")
	}
	if len(got.AffectedSymbols) != 0 {
		t.Errorf("AffectedSymbols = %v, want empty", got.AffectedSymbols)
	}
	if got.Reachable == nil {
		t.Fatal("the caller's answer was dropped rather than withdrawn")
	}
	if got.Reachable.IsReachable {
		t.Error("is_reachable = true beside a flag saying the advisory names no symbol for this path")
	}
	if got.Reachable.Confidence != domain.ConfidenceUnknown {
		t.Errorf("confidence = %q, want %q: High asserts a thorough search and there was no target to search for",
			got.Reachable.Confidence, domain.ConfidenceUnknown)
	}
	if got.Reachable.DerivedBy.Analyser != domain.AnalyserGovulncheck {
		t.Errorf("derivation = %+v, want the caller's: withdrawing the claim must not erase what produced it", got.Reachable.DerivedBy)
	}

	// The control: an added match whose advisory DOES name symbols keeps the
	// confident negative. A fix that demoted every added match would pass the
	// assertions above and fail here.
	named := coordinateMatch()
	named.ID = "GO-2026-6354"
	merged, _ = domain.MergeCoordinateMatches(
		nil,
		[]domain.VulnerabilityFinding{named},
		func(f *domain.VulnerabilityFinding) {
			f.Reachable = &domain.ReachabilityResult{IsReachable: false, Confidence: domain.ConfidenceHigh}
		},
	)
	if len(merged) != 1 || merged[0].Reachable.Confidence != domain.ConfidenceHigh {
		t.Errorf("an advisory naming symbols lost its confidence: %+v", merged[0].Reachable)
	}
	if len(merged[0].AffectedSymbols) == 0 {
		t.Error("an advisory naming symbols lost its symbol list")
	}
}

func findingJSON(t *testing.T, f domain.VulnerabilityFinding) string {
	t.Helper()
	b, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("marshalling finding: %v", err)
	}
	return string(b)
}

func findingsJSON(t *testing.T, fs []domain.VulnerabilityFinding) string {
	t.Helper()
	b, err := json.Marshal(fs)
	if err != nil {
		t.Fatalf("marshalling findings: %v", err)
	}
	return string(b)
}

func equalFindingJSON(t *testing.T, a, b domain.VulnerabilityFinding) bool {
	t.Helper()
	return findingJSON(t, a) == findingJSON(t, b)
}
