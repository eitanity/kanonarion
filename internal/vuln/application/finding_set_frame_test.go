package application_test

import (
	"testing"

	"code.eitanity.com/kanonarion/internal/coordinate"
	application "code.eitanity.com/kanonarion/internal/vuln/application"
	"code.eitanity.com/kanonarion/internal/vuln/domain"
)

// Two builds rooted at one target report one advisory set for a dependency,
// whatever each build's analysis reached: every advisory the snapshot matches
// by coordinate is added. So a dispute key needs nothing that tells two builds
// of one root apart, and two such builds compose without a dispute.
func TestScanWalk_TwoBuildsOfOneRootReportOneAdvisorySet(t *testing.T) {
	ctx := t.Context()
	advisory := domain.VulnerabilityFinding{ID: "GO-2024-0001", Summary: "bad"}
	reached := advisory
	reached.Reachable = &domain.ReachabilityResult{IsReachable: true, Confidence: domain.ConfidenceHigh}

	// The first build reaches the advisory; the second reaches nothing.
	var recs []domain.VulnerabilityRecord
	for _, attributed := range [][]domain.VulnerabilityFinding{{reached}, nil} {
		scanner := &fakeScanner{targetRooted: true}
		f := newTargetScanFixture(t, scanner)
		f.db.findings = map[coordinate.ModuleCoordinate][]domain.VulnerabilityFinding{f.depA: {advisory}}
		if attributed != nil {
			scanner.targetFindings = map[coordinate.ModuleCoordinate][]domain.VulnerabilityFinding{f.depA: attributed}
		}
		if _, err := f.walkUC.Scan(ctx, application.ScanWalkParams{WalkID: f.walkID, Operator: "tester"}); err != nil {
			t.Fatalf("Scan: %v", err)
		}
		got, err := f.vulnStore.ListVulnerabilityRecordsForModule(ctx, f.depA, "v1")
		if err != nil || len(got) != 1 {
			t.Fatalf("records for depA = %d, %v; want one", len(got), err)
		}
		recs = append(recs, got[0])
	}

	if recs[0].ContentHash == recs[1].ContentHash || recs[0].Rooting != recs[1].Rooting || !recs[0].Rooting.IsTargetRooted() {
		t.Fatalf("want two distinct builds in one target-rooted frame, got %s and %s", recs[0].Rooting, recs[1].Rooting)
	}
	for _, r := range recs {
		if len(r.Findings) != 1 || r.Findings[0].ID != advisory.ID {
			t.Errorf("record %s reports %+v, want exactly %s", r.ContentHash, r.Findings, advisory.ID)
		}
	}
	if _, _, err := domain.ComposeAt(recs, recs[0].Rooting); err != nil {
		t.Errorf("two builds of one root disputed each other: %v", err)
	}
}
