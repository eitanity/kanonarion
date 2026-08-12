package application_test

import (
	"log/slog"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	"github.com/eitanity/kanonarion/internal/fetch/fetchtest"

	application "github.com/eitanity/kanonarion/internal/vuln/application"
	"github.com/eitanity/kanonarion/internal/vuln/domain"
	"github.com/eitanity/kanonarion/internal/vuln/vulntest"
)

// TestScanWalk_BothRoutesReportOneAdvisory_MergesTheirFields is the regression
// test for the two-shapes defect on the target-rooted path. The analysis reports
// the advisory with the symbols it saw and a reachability answer; the pinned
// snapshot reports the same advisory with its rendered range. Taking the
// analysis finding whole — what this path did — stored the advisory without the
// range, while a module only the coordinate route reported stored it with one.
func TestScanWalk_BothRoutesReportOneAdvisory_MergesTheirFields(t *testing.T) {
	ctx := t.Context()
	scanner := &fakeScanner{targetRooted: true}
	f := newTargetScanFixture(t, scanner)

	scanner.targetFindings = map[coordinate.ModuleCoordinate][]domain.VulnerabilityFinding{
		f.depA: {{
			ID:              "GO-2024-0001",
			Summary:         "bad",
			FixedIn:         "v3.0.2",
			AffectedSymbols: []string{"Decoder.Decode"},
			Reachable: &domain.ReachabilityResult{
				IsReachable: true,
				Confidence:  domain.ConfidenceHigh,
				DerivedBy: domain.ReachabilityDerivation{
					Analyser: domain.AnalyserGovulncheck,
					Fidelity: string(domain.ScanModeSource),
				},
			},
		}},
	}
	f.db.findings = map[coordinate.ModuleCoordinate][]domain.VulnerabilityFinding{
		f.depA: {{
			ID:              "GO-2024-0001",
			Summary:         "bad",
			AffectedRange:   "< v3.0.2",
			FixedIn:         "v3.0.2",
			AffectedSymbols: []string{"Decoder.Decode", "Unmarshal"},
			References:      []domain.AdvisoryReference{{Type: "FIX", URL: "https://example.invalid/fix"}},
		}},
	}

	if _, err := f.walkUC.Scan(ctx, application.ScanWalkParams{WalkID: f.walkID, Operator: "tester"}); err != nil {
		t.Fatalf("Scan: %v", err)
	}

	rec, ok, err := f.vulnStore.GetLatestVulnerabilityRecordForWalk(ctx, f.depA, "v1", f.walkID)
	if err != nil || !ok {
		t.Fatalf("record for depA: ok=%v err=%v", ok, err)
	}
	if len(rec.Findings) != 1 {
		t.Fatalf("depA findings = %+v, want one: an advisory both routes report is one finding", rec.Findings)
	}
	got := rec.Findings[0]
	if got.AffectedRange != "< v3.0.2" {
		t.Errorf("AffectedRange = %q, want %q: the coordinate match's range must survive the merge", got.AffectedRange, "< v3.0.2")
	}
	if !slices.Equal(got.AffectedSymbols, []string{"Decoder.Decode"}) {
		t.Errorf("AffectedSymbols = %v, want the analysis's own list", got.AffectedSymbols)
	}
	if got.Reachable == nil || !got.Reachable.IsReachable {
		t.Errorf("Reachable = %+v, want the analysis's reachable answer, not the coordinate route's silence", got.Reachable)
	}
	if len(got.References) != 1 {
		t.Errorf("References = %v, want the advisory's links from the route that read them", got.References)
	}
}

// TestScanModule_BothRoutesReportOneAdvisory_MergesTheirFields is the same
// regression on the isolated path, which merges at its own site. The two sites
// had the same defect, so they are pinned by the same shape of test.
func TestScanModule_BothRoutesReportOneAdvisory_MergesTheirFields(t *testing.T) {
	ctx := t.Context()
	coord := coordinatetest.MustNew("github.com/foo/bar", "v1.0.0")
	now := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

	facts := newFakeFacts()
	blobs := newFakeBlob()
	vulnStore := newFakeVulnStore()

	analysed := domain.VulnerabilityFinding{
		ID:              "GO-VULN-ID",
		Summary:         "bad",
		FixedIn:         "v1.1.0",
		AffectedSymbols: []string{"Parse"},
		Reachable: &domain.ReachabilityResult{
			IsReachable: true,
			Confidence:  domain.ConfidenceHigh,
			DerivedBy: domain.ReachabilityDerivation{
				Analyser: domain.AnalyserGovulncheck,
				Fidelity: string(domain.ScanModeSource),
			},
		},
	}
	scanner := &fakeScanner{results: map[string]domain.VulnerabilityRecord{
		coord.String(): {
			Coordinate:     coord,
			Findings:       []domain.VulnerabilityFinding{analysed},
			OverallStatus:  domain.StatusAffected,
			CoverageStatus: domain.CoverageAnalysed,
			FindingsStatus: domain.FindingsRecordAffected,
		},
	}}
	db := &fakeDatabase{
		snapshot:    vulntest.MustNewAt("test", "v1", now),
		vulnerables: map[coordinate.ModuleCoordinate][]string{coord: {"GO-VULN-ID"}},
		findings: map[coordinate.ModuleCoordinate][]domain.VulnerabilityFinding{
			coord: {{
				ID:              "GO-VULN-ID",
				Summary:         "bad",
				AffectedRange:   ">= v1.0.0, < v1.1.0",
				FixedIn:         "v1.1.0",
				AffectedSymbols: []string{"Parse", "ParseAll"},
			}},
		},
	}

	seedRec := fetchtest.Record(t, fetchtest.Coordinate(coord), fetchtest.PipelineVersion("v1"), fetchtest.Content("zip content"))
	if err := blobs.Put(ctx, fetchtest.ZipIdentity(t, seedRec), strings.NewReader("zip content")); err != nil {
		t.Fatalf("blobs.Put: %v", err)
	}
	if err := facts.PutFetchRecord(ctx, fetchtest.Sealed(t, fetchtest.Coordinate(coord), fetchtest.PipelineVersion("v1"), fetchtest.Content("zip content"))); err != nil {
		t.Fatalf("PutFetchRecord: %v", err)
	}

	uc := application.NewScanModuleUseCase(
		facts, blobs, vulnStore, nil, scanner, db, nil, fixedClock{t: now}, "v1", slog.Default(),
	)

	res, err := uc.Scan(ctx, application.ScanModuleParams{Coordinate: coord, WalkID: "walk-1"})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("findings = %+v, want one", res.Findings)
	}
	got := res.Findings[0]
	if got.AffectedRange != ">= v1.0.0, < v1.1.0" {
		t.Errorf("AffectedRange = %q, want the coordinate match's range", got.AffectedRange)
	}
	if !slices.Equal(got.AffectedSymbols, []string{"Parse"}) {
		t.Errorf("AffectedSymbols = %v, want the source analysis's own list", got.AffectedSymbols)
	}
	if got.Reachable == nil || !got.Reachable.IsReachable {
		t.Errorf("Reachable = %+v, want the source analysis's answer", got.Reachable)
	}
}
