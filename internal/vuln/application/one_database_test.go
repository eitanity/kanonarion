package application_test

import (
	"testing"

	application "github.com/eitanity/kanonarion/internal/vuln/application"
)

// TestScanWalk_CoordinateMatchIsAskedForTheRecordsOwnSnapshot is the regression
// test for a record answered from two advisory databases.
//
// The findings are not what fails here. The coordinate route answered correctly
// for whatever database it happened to read; the defect was that it read a
// different one from the analysis and the record named only one of them. So the
// assertion is on the question asked, not the answer given: every coordinate
// match must be asked for the snapshot the record it feeds states.
//
// Without the snapshot parameter this test cannot be written at all, which is
// the point — the route had no way to be told which database to read, so it read
// whatever vuln.go.dev was publishing at the moment of the scan.
func TestScanWalk_CoordinateMatchIsAskedForTheRecordsOwnSnapshot(t *testing.T) {
	ctx := t.Context()
	scanner := &fakeScanner{targetRooted: true}
	f := newTargetScanFixture(t, scanner)

	if _, err := f.walkUC.Scan(ctx, application.ScanWalkParams{WalkID: f.walkID, Operator: "tester"}); err != nil {
		t.Fatalf("Scan: %v", err)
	}

	asked := f.db.lookupsSaw()
	if len(asked) == 0 {
		t.Fatal("no coordinate match was made: this run proves nothing about which database they read")
	}
	for i, identity := range asked {
		if identity.IsZero() {
			t.Fatalf("coordinate match %d was asked for no snapshot at all: an unnamed database is how the two routes diverged", i)
		}
		if identity.Source() != f.db.snapshot.Source() || identity.Version() != f.db.snapshot.Version() {
			t.Errorf("coordinate match %d read %s@%s, want the run's snapshot %s@%s",
				i, identity.Source(), identity.Version(), f.db.snapshot.Source(), f.db.snapshot.Version())
		}
	}

	// And the records name that same database, so "the route read what the record
	// states" is asserted end to end rather than at the seam alone.
	rec, ok, err := f.vulnStore.GetLatestVulnerabilityRecordForWalk(ctx, f.depA, "v1", f.walkID)
	if err != nil || !ok {
		t.Fatalf("record for depA: ok=%v err=%v", ok, err)
	}
	if rec.DatabaseSnapshot.Version() != f.db.snapshot.Version() {
		t.Errorf("record names %s, but the matches read %s: a record states one advisory database",
			rec.DatabaseSnapshot.Version(), f.db.snapshot.Version())
	}
	if rec.PipelineVersion != "v1" {
		t.Errorf("PipelineVersion = %q, want the fixture's", rec.PipelineVersion)
	}
}
