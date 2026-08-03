package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/cli/testfakes"
	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	vuldomain "github.com/eitanity/kanonarion/internal/vuln/domain"
	"github.com/eitanity/kanonarion/internal/vuln/vulntest"
)

// The fixture every test in this file runs against, and the shape of the defect
// they pin.
//
// Measured on a real store: an isolated scan of
// github.com/golang-jwt/jwt/v4@v4.5.1 built the module alone, so it recorded
// call-graph completeness BUILT_WITH_BODIES and "not reachable" at 17:49. A
// govulncheck analysis rooted at the consuming project recorded the route to the
// vulnerable symbol at 17:54 and, having searched a call graph this tool did not
// build, recorded no completeness at all. The frame-blind ladder decides on the
// completeness rung before it ever reaches recency, so the older isolated
// stand-down won — and every record-serving surface except 'reachability'
// headlined it.
const (
	frameFixtureVulnID = "GO-2025-3553"
	frameFixtureModule = "github.com/golang-jwt/jwt/v4"
	frameFixtureVer    = "v4.5.1"
)

func frameFixtureCoord(t *testing.T) coordinate.ModuleCoordinate {
	t.Helper()
	return coordinatetest.MustNew(frameFixtureModule, frameFixtureVer)
}

// twoFrameLedger returns the isolated record first, so a surface that merely
// takes the first row it is handed fails these tests.
func twoFrameLedger(t *testing.T, snapshot vuldomain.DatabaseSnapshot) []vuldomain.VulnerabilityRecord {
	t.Helper()
	coord := frameFixtureCoord(t)
	consumerRoot := coordinatetest.MustNew("example.com/app", coordinate.LocalVersion)

	isolated := frameRecord(t, frameRecordSpec{
		coord:        coord,
		snapshot:     snapshot,
		rooting:      vuldomain.RootingIsolated,
		completeness: "BUILT_WITH_BODIES",
		scannedAt:    time.Date(2026, 7, 31, 17, 49, 28, 0, time.UTC),
		reachable:    false,
	})
	consumer := frameRecord(t, frameRecordSpec{
		coord:     coord,
		snapshot:  snapshot,
		rooting:   vuldomain.TargetRootedAt(consumerRoot),
		scannedAt: time.Date(2026, 7, 31, 17, 54, 8, 0, time.UTC),
		reachable: true,
	})
	return []vuldomain.VulnerabilityRecord{isolated, consumer}
}

type frameRecordSpec struct {
	coord        coordinate.ModuleCoordinate
	snapshot     vuldomain.DatabaseSnapshot
	rooting      vuldomain.Rooting
	completeness string
	scannedAt    time.Time
	reachable    bool
}

func frameRecord(t *testing.T, s frameRecordSpec) vuldomain.VulnerabilityRecord {
	t.Helper()
	// The frame is stamped onto the reachability answer before sealing, exactly
	// as the use case that persists a record does it. Without this step the
	// fixture's findings would say "rooted at: not recorded" — a shape no
	// producer writes, and one that hides whether a surface reports the frame.
	draft := vuldomain.VulnerabilityRecord{
		Ecosystem:     fetchdomain.EcosystemGo,
		Coordinate:    s.coord,
		WalkID:        "walk-frame",
		OverallStatus: vuldomain.StatusAffected,
		Findings: []vuldomain.VulnerabilityFinding{{
			ID:            frameFixtureVulnID,
			Summary:       "jwt parses without verification",
			AffectedRange: "< v4.5.2",
			Reachable: &vuldomain.ReachabilityResult{
				IsReachable: s.reachable,
				Confidence:  vuldomain.ConfidenceHigh,
			},
		}},
		DatabaseSnapshot:      s.snapshot,
		ScannedAt:             s.scannedAt,
		PipelineVersion:       vulnPipelineVersion,
		CallGraphCompleteness: s.completeness,
		Rooting:               s.rooting,
	}
	vuldomain.StampReachabilityRooting(&draft)
	rec, err := vuldomain.VulnerabilityRecordHasher{}.SetContentHash(draft)
	if err != nil {
		t.Fatalf("sealing frame fixture: %v", err)
	}
	return rec
}

// The ladder must still reproduce the defect, or these tests have stopped
// measuring anything: frame-first selection is only load-bearing while the
// frame-blind read it replaced would have answered differently.
func TestFrameFixture_TheFrameBlindLadderStillServesTheIsolatedStandDown(t *testing.T) {
	snap := vulntest.MustNew("test", "v1")
	recs := twoFrameLedger(t, snap)
	plain, err := vuldomain.Compose(recs)
	if err != nil {
		t.Fatalf("Compose: %v", err)
	}
	if plain.Rooting != vuldomain.RootingIsolated {
		t.Fatal("the frame-blind ladder no longer serves the isolated record; this fixture measures nothing")
	}
}

// -- vuln-show --------------------------------------------------------------

// vuln-show without --walk-id answers "what does this store know about this
// module", which a consumer asks about a module they depend on. It served the
// isolated NOT-reachable verdict while 'reachability', over the same store,
// served the consumer's route: two commands, one store, opposite headlines.
func TestVulnShow_ServesTheConsumerFrameNotTheIsolatedStandDown(t *testing.T) {
	coord := frameFixtureCoord(t)
	uc := testfakes.NewFakeQueryVuln()
	uc.AddRecords(coord, twoFrameLedger(t, vulntest.MustNew("test", "v1"))...)

	var buf bytes.Buffer
	err := runVulnShow(context.Background(), coord.String(), "", "", false, false, false,
		uc, testfakes.NewFakeQueryScanRuns(), testfakes.NewFakeQueryWalks(), nil, &buf)
	if err != nil {
		t.Fatalf("runVulnShow: %v", err)
	}
	got := buf.String()
	if !strings.Contains(got, "Analysis frame:  target-rooted:example.com/app@") {
		t.Errorf("vuln-show did not headline the consumer frame:\n%s", got)
	}
	if !strings.Contains(got, "GO-2025-3553 [reachable]") {
		t.Errorf("vuln-show did not carry the consumer route's verdict:\n%s", got)
	}
}

// The isolated answer is declined, not discarded. The two frames disagreeing is
// itself information, and a reader who has seen the isolated verdict elsewhere is
// owed the reason it is not the headline.
func TestVulnShow_ReportsTheDeclinedIsolatedFrameAsAnAside(t *testing.T) {
	coord := frameFixtureCoord(t)
	uc := testfakes.NewFakeQueryVuln()
	uc.AddRecords(coord, twoFrameLedger(t, vulntest.MustNew("test", "v1"))...)

	var buf bytes.Buffer
	if err := runVulnShow(context.Background(), coord.String(), "", "", false, false, false,
		uc, testfakes.NewFakeQueryScanRuns(), testfakes.NewFakeQueryWalks(), nil, &buf); err != nil {
		t.Fatalf("runVulnShow: %v", err)
	}
	got := buf.String()
	if !strings.Contains(got, "Isolated frame (a different question") {
		t.Errorf("the declined isolated frame was dropped instead of reported:\n%s", got)
	}
	if !strings.Contains(got, frameFixtureVulnID+": not_reachable") {
		t.Errorf("the aside does not say what the isolated frame answered:\n%s", got)
	}
}

// A ledger with only one frame has nothing to decline, so no aside is printed.
// An aside with nothing to say is noise beside the answer.
func TestVulnShow_NoAsideWhenOnlyOneFrameWasMeasured(t *testing.T) {
	coord := frameFixtureCoord(t)
	consumerRoot := coordinatetest.MustNew("example.com/app", coordinate.LocalVersion)
	uc := testfakes.NewFakeQueryVuln()
	uc.AddRecords(coord, frameRecord(t, frameRecordSpec{
		coord:     coord,
		snapshot:  vulntest.MustNew("test", "v1"),
		rooting:   vuldomain.TargetRootedAt(consumerRoot),
		scannedAt: time.Date(2026, 7, 31, 17, 54, 8, 0, time.UTC),
		reachable: true,
	}))

	var buf bytes.Buffer
	if err := runVulnShow(context.Background(), coord.String(), "", "", false, false, false,
		uc, testfakes.NewFakeQueryScanRuns(), testfakes.NewFakeQueryWalks(), nil, &buf); err != nil {
		t.Fatalf("runVulnShow: %v", err)
	}
	if strings.Contains(buf.String(), "Isolated frame") {
		t.Errorf("an aside was printed for a frame the ledger does not hold:\n%s", buf.String())
	}
}

// -- context / inspect ------------------------------------------------------

// context (and inspect, which ends in a context render) reads per scan run. The
// run-scoped read was frame-blind too, so the section headlined the isolated
// verdict for every module a project-rooted scan had computed a route through.
func TestContextVulnerabilities_ServesTheConsumerFrameWithinTheRunsSnapshot(t *testing.T) {
	coord := frameFixtureCoord(t)
	snap := vulntest.MustNew("test", "v1")
	uc := testfakes.NewFakeQueryVuln()
	uc.AddRecords(coord, twoFrameLedger(t, snap)...)

	batch := &vulnBatchCtx{
		window: []string{"walk-frame"},
		runs: map[string][]vuldomain.WalkScanRun{
			"walk-frame": {{
				WalkID:           "walk-frame",
				Snapshot:         snap,
				OverallStatus:    vuldomain.WalkStatusAffected,
				PerModuleResults: map[coordinate.ModuleCoordinate]string{coord: ""},
			}},
		},
	}

	v := buildVulnerabilitiesFromBatch(context.Background(), coord, uc, batch)

	if !strings.HasPrefix(v.Frame, "target-rooted:") {
		t.Errorf("context served frame %q, want the consumer-rooted one", v.Frame)
	}
	if len(v.Findings) != 1 || v.Findings[0].Reachable == nil || !*v.Findings[0].Reachable {
		t.Errorf("context did not carry the consumer route's reachability: %+v", v.Findings)
	}
}

// The same selection on the whole-ledger path, which answers for a module no run
// in the batch's walk window covers.
func TestContextVulnerabilities_ServesTheConsumerFrameOnTheWholeLedgerPath(t *testing.T) {
	coord := frameFixtureCoord(t)
	uc := testfakes.NewFakeQueryVuln()
	uc.AddRecords(coord, twoFrameLedger(t, vulntest.MustNew("test", "v1"))...)

	v := buildVulnerabilitiesFromBatch(context.Background(), coord, uc, &vulnBatchCtx{})

	if !strings.HasPrefix(v.Frame, "target-rooted:") {
		t.Errorf("context served frame %q, want the consumer-rooted one", v.Frame)
	}
	if len(v.Findings) != 1 || v.Findings[0].Reachable == nil || !*v.Findings[0].Reachable {
		t.Errorf("context did not carry the consumer route's reachability: %+v", v.Findings)
	}
}

// A run scanned against a different advisory-database snapshot must not answer
// for this one. The per-run read was keyed on the run's own snapshot, and
// narrowing the ledger in memory has to key the same way or a newer generation
// would silently answer for an older run.
func TestContextVulnerabilities_ARunAnswersOnlyFromItsOwnSnapshot(t *testing.T) {
	coord := frameFixtureCoord(t)
	uc := testfakes.NewFakeQueryVuln()
	uc.AddRecords(coord, twoFrameLedger(t, vulntest.MustNew("test", "v1"))...)

	batch := &vulnBatchCtx{
		window: []string{"walk-frame"},
		runs: map[string][]vuldomain.WalkScanRun{
			"walk-frame": {{
				WalkID:           "walk-frame",
				Snapshot:         vulntest.MustNew("test", "v2"),
				PerModuleResults: map[coordinate.ModuleCoordinate]string{coord: ""},
			}},
		},
	}

	v := buildVulnerabilitiesFromBatch(context.Background(), coord, uc, batch)

	// The run contributes nothing, so the whole-ledger path answers — and it
	// answers without claiming the run's status.
	if v.WalkStatus != "" {
		t.Errorf("a run from another snapshot supplied the walk status %q", v.WalkStatus)
	}
	if v.Status != string(vuldomain.StatusAffected) {
		t.Errorf("Status = %q, want the ledger's answer", v.Status)
	}
}

// An isolated record that recorded no reachability answer has nothing to say
// beside the served one. Announcing the frame alone would imply a disagreement
// that was never measured.
func TestVulnShow_NoAsideWhenTheIsolatedRecordAnsweredNoReachabilityQuestion(t *testing.T) {
	coord := frameFixtureCoord(t)
	snap := vulntest.MustNew("test", "v1")
	consumerRoot := coordinatetest.MustNew("example.com/app", coordinate.LocalVersion)

	silent := frameRecord(t, frameRecordSpec{
		coord:        coord,
		snapshot:     snap,
		rooting:      vuldomain.RootingIsolated,
		completeness: "BUILT_WITH_BODIES",
		scannedAt:    time.Date(2026, 7, 31, 17, 49, 28, 0, time.UTC),
	})
	silent.Findings[0].Reachable = nil
	sealed, err := vuldomain.VulnerabilityRecordHasher{}.SetContentHash(silent)
	if err != nil {
		t.Fatalf("resealing fixture: %v", err)
	}
	consumer := frameRecord(t, frameRecordSpec{
		coord:     coord,
		snapshot:  snap,
		rooting:   vuldomain.TargetRootedAt(consumerRoot),
		scannedAt: time.Date(2026, 7, 31, 17, 54, 8, 0, time.UTC),
		reachable: true,
	})

	uc := testfakes.NewFakeQueryVuln()
	uc.AddRecords(coord, sealed, consumer)

	var buf bytes.Buffer
	if rerr := runVulnShow(context.Background(), coord.String(), "", "", false, false, false,
		uc, testfakes.NewFakeQueryScanRuns(), testfakes.NewFakeQueryWalks(), nil, &buf); rerr != nil {
		t.Fatalf("runVulnShow: %v", rerr)
	}
	if strings.Contains(buf.String(), "Isolated frame") {
		t.Errorf("an aside was printed for a frame that answered nothing:\n%s", buf.String())
	}
}
