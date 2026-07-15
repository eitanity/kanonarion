package domain

import "testing"

// TestFindByID_NotFound covers findByID's miss branch. DiffScanRuns only calls it
// after a containsFinding hit, so the not-found path is unreachable through the
// public API and is exercised directly here.
func TestFindByID_NotFound(t *testing.T) {
	findings := []VulnerabilityFinding{{ID: "GO-1"}, {ID: "GO-2"}}
	if _, ok := findByID(findings, "GO-ABSENT"); ok {
		t.Errorf("findByID reported a match for an absent ID")
	}
	if f, ok := findByID(findings, "GO-2"); !ok || f.ID != "GO-2" {
		t.Errorf("findByID missed a present ID: ok=%v f=%+v", ok, f)
	}
}
