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

// TestMergeCoordinateMatches_SymbolFlagNeverContradictsASymbolList: the
// "advisory names no symbols" flag is adopted from the match only where the
// analysis names none of its own, so the record can never state both.
func TestMergeCoordinateMatches_SymbolFlagNeverContradictsASymbolList(t *testing.T) {
	match := coordinateMatch()
	match.AffectedSymbols = nil
	match.AdvisoryNamesNoSymbols = true

	merged, _ := domain.MergeCoordinateMatches(
		[]domain.VulnerabilityFinding{analysisFinding()},
		[]domain.VulnerabilityFinding{match},
		nil,
	)
	if merged[0].AdvisoryNamesNoSymbols {
		t.Error("AdvisoryNamesNoSymbols set on a finding that names symbols: the record would say the advisory named none while listing one")
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
