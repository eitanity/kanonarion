package cli

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/cli/testfakes"
	configdomain "github.com/eitanity/kanonarion/internal/config/domain"
	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	licdomain "github.com/eitanity/kanonarion/internal/license/domain"
	vuldomain "github.com/eitanity/kanonarion/internal/vuln/domain"
	"github.com/eitanity/kanonarion/internal/vuln/vulntest"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
)

// The fixture here is the multi-project store, which is a different defect from
// the isolated-vs-consumer one in vuln_frame_test.go.
//
// Measured on a real store holding scans of two projects: one project's build
// reached github.com/golang-jwt/jwt/v4's ParseUnverified through a SAML session
// codec (reachable, High confidence, five hops); another project's build did not
// reach it at all. Asked for the first project's triage, both vuln-show and
// reachability answered from the second — the newest scan store-wide — at exit
// 0, inverting the verdict. Pinning the first project's walk did not help: the
// walk's membership index carries no frame, so the pinned candidate set held
// every project's records and the frame-blind ladder picked one of the others,
// naming a walk the operator had not asked for.
const (
	twoProjectVulnID = "GO-2025-3553"
	walkA            = "01KYZA49FCAKVFM3ZPA9GKSSPP"
	walkB            = "01KZ0EC54VEZ8GNAT93CPBEANC"
	walkC            = "01KYW179BZAPV0N69A8EMJT356"
)

func twoProjectCoord(t *testing.T) coordinate.ModuleCoordinate {
	t.Helper()
	return coordinatetest.MustNew("github.com/golang-jwt/jwt/v4", "v4.5.1")
}

func projectRoot(t *testing.T, path string) coordinate.ModuleCoordinate {
	t.Helper()
	return coordinatetest.MustNew(path, coordinate.LocalVersion)
}

// twoProjectLedger holds one coordinate measured in two consumers' builds, with
// opposing reachability verdicts. Project B's record is the newer one, so any
// read that falls back to recency serves it.
func twoProjectLedger(t *testing.T) []vuldomain.VulnerabilityRecord {
	t.Helper()
	coord := twoProjectCoord(t)
	snap := vulntest.MustNew("test", "v1")
	return []vuldomain.VulnerabilityRecord{
		frameRecord(t, frameRecordSpec{
			coord:     coord,
			snapshot:  snap,
			rooting:   vuldomain.TargetRootedAt(projectRoot(t, "example.com/project-a")),
			scannedAt: time.Date(2026, 8, 1, 18, 42, 27, 0, time.UTC),
			reachable: true,
		}),
		frameRecord(t, frameRecordSpec{
			coord:     coord,
			snapshot:  snap,
			rooting:   vuldomain.TargetRootedAt(projectRoot(t, "example.com/project-b")),
			scannedAt: time.Date(2026, 8, 2, 5, 38, 37, 0, time.UTC),
			reachable: false,
		}),
	}
}

// twoProjectAuditLedger is the same two-consumer fixture as an audit or a walk
// closure sees it: a status per build rather than a reachability verdict, with
// the CLEAN record the newer one, so a frame-blind read reports the shared
// dependency clean in a build whose own scan found it affected.
func twoProjectAuditLedger(t *testing.T) []vuldomain.VulnerabilityRecord {
	t.Helper()
	coord := twoProjectCoord(t)
	snap := vulntest.MustNew("test", "v1")
	return []vuldomain.VulnerabilityRecord{
		frameRecord(t, frameRecordSpec{
			coord: coord, snapshot: snap,
			rooting:   vuldomain.TargetRootedAt(projectRoot(t, "example.com/project-a")),
			scannedAt: time.Date(2026, 8, 1, 18, 42, 27, 0, time.UTC),
			reachable: true,
		}),
		cleanFrameRecord(t, coord, snap,
			vuldomain.TargetRootedAt(projectRoot(t, "example.com/project-b")),
			time.Date(2026, 8, 2, 5, 38, 37, 0, time.UTC)),
	}
}

// cleanFrameRecord is a record carrying no finding at all — the shape a build
// that does not resolve the affected version writes.
func cleanFrameRecord(t *testing.T, coord coordinate.ModuleCoordinate, snap vuldomain.DatabaseSnapshot, rooting vuldomain.Rooting, at time.Time) vuldomain.VulnerabilityRecord {
	t.Helper()
	rec, err := vuldomain.VulnerabilityRecordHasher{}.SetContentHash(vuldomain.VulnerabilityRecord{
		Ecosystem:        fetchdomain.EcosystemGo,
		Coordinate:       coord,
		WalkID:           "walk-frame",
		OverallStatus:    vuldomain.StatusClean,
		DatabaseSnapshot: snap,
		ScannedAt:        at,
		PipelineVersion:  vulnPipelineVersion,
		Rooting:          rooting,
	})
	if err != nil {
		t.Fatalf("sealing clean fixture: %v", err)
	}
	return rec
}

// walksKnowing returns a walk store that resolves each named walk to a project
// root, which is where the frame of a pinned read comes from.
func walksKnowing(t *testing.T, byWalk map[string]string) *testfakes.FakeQueryWalks {
	t.Helper()
	walks := testfakes.NewFakeQueryWalks()
	for id, root := range byWalk {
		walks.AddWalk(walkdomain.WalkRecord{ID: id, Target: projectRoot(t, root)})
	}
	return walks
}

func twoProjectFakes(t *testing.T) (*testfakes.FakeQueryVuln, *testfakes.FakeQueryWalks) {
	t.Helper()
	uc := testfakes.NewFakeQueryVuln()
	uc.AddRecords(twoProjectCoord(t), twoProjectLedger(t)...)
	walks := walksKnowing(t, map[string]string{
		walkA: "example.com/project-a",
		walkB: "example.com/project-b",
		walkC: "example.com/project-c",
	})
	return uc, walks
}

// The fixture must keep reproducing the defect, or these tests measure nothing:
// a frame-blind read of the candidate set has to serve project B — the answer
// the pinned reads below must NOT return.
func TestTwoProjectFixture_AFrameBlindReadStillServesTheOtherProject(t *testing.T) {
	blind, err := vuldomain.Compose(twoProjectLedger(t))
	if err != nil {
		t.Fatalf("Compose: %v", err)
	}
	if !blind.Rooting.IsRootedAt(projectRoot(t, "example.com/project-b")) {
		t.Fatalf("the frame-blind ladder no longer serves project B (%s); this fixture measures nothing", blind.Rooting)
	}
}

// -- vuln-show --------------------------------------------------------------

func TestVulnShow_WalkIDIsHonouredAndNotSubstituted(t *testing.T) {
	coord := twoProjectCoord(t)
	uc, walks := twoProjectFakes(t)

	var buf bytes.Buffer
	if err := runVulnShow(context.Background(), coord.String(), walkA, "", false, false, false,
		uc, testfakes.NewFakeQueryScanRuns(), walks, nil, &buf); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "target-rooted:example.com/project-a@"+coordinate.LocalVersion) {
		t.Errorf("the pinned walk's frame is not the one served:\n%s", out)
	}
	if strings.Contains(out, "project-b") {
		t.Errorf("the pinned read answered from another project's scan:\n%s", out)
	}
	if !strings.Contains(out, "notice: results restricted to the records walk \""+walkA+"\"") {
		t.Errorf("a restricted answer must say what it was restricted to:\n%s", out)
	}
}

func TestVulnShow_PinnedWalkWithNoRecordInItsFrameRefusesRatherThanSubstituting(t *testing.T) {
	coord := twoProjectCoord(t)
	uc, walks := twoProjectFakes(t)

	var buf bytes.Buffer
	err := runVulnShow(context.Background(), coord.String(), walkC, "", false, false, false,
		uc, testfakes.NewFakeQueryScanRuns(), walks, nil, &buf)
	if err == nil {
		t.Fatalf("want a refusal for a walk holding no record in its own frame, got output:\n%s", buf.String())
	}
	var ee *exitError
	if !errors.As(err, &ee) || ee.code != ExitNotFound {
		t.Fatalf("want ExitNotFound, got %v", err)
	}
	if !strings.Contains(err.Error(), walkC) {
		t.Errorf("the refusal must name the walk that was pinned: %v", err)
	}
	if buf.Len() != 0 {
		t.Errorf("a refusal must print no verdict, got:\n%s", buf.String())
	}
}

func TestVulnShow_UnanchoredRefusesNamingEveryConsumerFrame(t *testing.T) {
	coord := twoProjectCoord(t)
	uc, walks := twoProjectFakes(t)

	var buf bytes.Buffer
	err := runVulnShow(context.Background(), coord.String(), "", "", false, false, false,
		uc, testfakes.NewFakeQueryScanRuns(), walks, nil, &buf)
	if err == nil {
		t.Fatalf("want a refusal on a two-consumer store, got output:\n%s", buf.String())
	}
	var ee *exitError
	if !errors.As(err, &ee) || ee.code != ExitConfig {
		t.Fatalf("want ExitConfig, got %v", err)
	}
	for _, want := range []string{
		"target-rooted:example.com/project-a@" + coordinate.LocalVersion,
		"target-rooted:example.com/project-b@" + coordinate.LocalVersion,
		"--walk-id", "--gomod", "--history",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal must name %q so the reader can pick one:\n%v", want, err)
		}
	}
	if buf.Len() != 0 {
		t.Errorf("a refusal must print no verdict, got:\n%s", buf.String())
	}
}

// A store holding one project's scans has nothing to disambiguate, so the
// answer must be byte-for-byte what it was before the anchors existed: the
// served record printed, and nothing else.
func TestVulnShow_SingleConsumerFrameIsUnchanged(t *testing.T) {
	coord := twoProjectCoord(t)
	only := twoProjectLedger(t)[:1]
	uc := testfakes.NewFakeQueryVuln()
	uc.AddRecords(coord, only...)

	var got bytes.Buffer
	if err := runVulnShow(context.Background(), coord.String(), "", "", false, false, false,
		uc, testfakes.NewFakeQueryScanRuns(), testfakes.NewFakeQueryWalks(), nil, &got); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var want bytes.Buffer
	printVulnRecord(&want, only[0], nil)
	if got.String() != want.String() {
		t.Errorf("single-frame output changed:\ngot:\n%s\nwant:\n%s", got.String(), want.String())
	}
}

// -- reachability -----------------------------------------------------------

func TestReachability_WalkIDAnswersInThatWalksFrame(t *testing.T) {
	coord := twoProjectCoord(t)
	uc, walks := twoProjectFakes(t)

	var buf bytes.Buffer
	if err := runVulnReachability(context.Background(), coord.String(), twoProjectVulnID, walkA, "", false, false,
		uc, walks, nil, &buf); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "is REACHABLE") {
		t.Errorf("the pinned project's own verdict is reachable; got:\n%s", out)
	}
	if !strings.Contains(out, "rooted at: target-rooted:example.com/project-a@"+coordinate.LocalVersion) {
		t.Errorf("every answer names its rooting; got:\n%s", out)
	}
	if !strings.Contains(out, "notice: results restricted to the records walk \""+walkA+"\"") {
		t.Errorf("a restricted answer must say what it was restricted to:\n%s", out)
	}
}

// The other project's pin returns the other project's verdict — the same read,
// two builds, two answers, each labelled.
func TestReachability_WalkIDOfTheOtherProjectReturnsItsOwnVerdict(t *testing.T) {
	coord := twoProjectCoord(t)
	uc, walks := twoProjectFakes(t)

	var buf bytes.Buffer
	if err := runVulnReachability(context.Background(), coord.String(), twoProjectVulnID, walkB, "", false, false,
		uc, walks, nil, &buf); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out := buf.String(); !strings.Contains(out, "NOT reachable") ||
		!strings.Contains(out, "rooted at: target-rooted:example.com/project-b@"+coordinate.LocalVersion) {
		t.Errorf("want project B's own not-reachable verdict, got:\n%s", out)
	}
}

func TestReachability_UnanchoredRefusesNamingEveryConsumerFrame(t *testing.T) {
	coord := twoProjectCoord(t)
	uc, walks := twoProjectFakes(t)

	var buf bytes.Buffer
	err := runVulnReachability(context.Background(), coord.String(), twoProjectVulnID, "", "", false, false,
		uc, walks, nil, &buf)
	if err == nil {
		t.Fatalf("want a refusal on a two-consumer store, got output:\n%s", buf.String())
	}
	var ee *exitError
	if !errors.As(err, &ee) || ee.code != ExitConfig {
		t.Fatalf("want ExitConfig, got %v", err)
	}
	for _, want := range []string{
		"target-rooted:example.com/project-a@" + coordinate.LocalVersion,
		"target-rooted:example.com/project-b@" + coordinate.LocalVersion,
		"--walk-id", "--gomod",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal must name %q so the reader can pick one:\n%v", want, err)
		}
	}
	if buf.Len() != 0 {
		t.Errorf("a refusal must print no verdict, got:\n%s", buf.String())
	}
}

// One project's scans in the store: nothing is ambiguous, so the answer is the
// one this command has always given, with no notice line above it.
func TestReachability_SingleConsumerFrameIsUnchanged(t *testing.T) {
	coord := twoProjectCoord(t)
	only := twoProjectLedger(t)[:1]
	uc := testfakes.NewFakeQueryVuln()
	uc.AddRecords(coord, only...)

	var buf bytes.Buffer
	if err := runVulnReachability(context.Background(), coord.String(), twoProjectVulnID, "", "", false, false,
		uc, testfakes.NewFakeQueryWalks(), nil, &buf); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out := buf.String()
	if strings.Contains(out, "notice:") {
		t.Errorf("an unrestricted answer withholds nothing and must not claim to:\n%s", out)
	}
	if !strings.Contains(out, "is REACHABLE") {
		t.Errorf("want the single stored verdict, got:\n%s", out)
	}
}

// -- the anchor itself ------------------------------------------------------

func TestFrameAnchor_WalkIDAndGoModAreMutuallyExclusive(t *testing.T) {
	_, _, err := resolveVulnFrameAnchor(context.Background(), testfakes.NewFakeQueryWalks(), walkA, "./go.mod", true)
	var ee *exitError
	if !errors.As(err, &ee) || ee.code != ExitConfig {
		t.Fatalf("want ExitConfig for two conflicting build names, got %v", err)
	}
}

// A walk the walk store no longer holds still restricts the read to that walk's
// records; what is lost is the frame, and the anchor says so rather than
// inventing one.
func TestFrameAnchor_UnknownWalkKeepsThePinAndDropsTheFrame(t *testing.T) {
	anchor, ok, err := resolveVulnFrameAnchor(context.Background(), testfakes.NewFakeQueryWalks(), walkA, "", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok || anchor.walkID != walkA {
		t.Fatalf("the pin must survive a missing walk record: %+v", anchor)
	}
	if anchor.rooting.IsRecorded() {
		t.Errorf("a frame cannot be read off a walk record the store does not hold: %s", anchor.rooting)
	}
}

func TestConsumerFrames_ExcludesTheModulesOwnRootAndTheIsolatedFrame(t *testing.T) {
	coord := twoProjectCoord(t)
	snap := vulntest.MustNew("test", "v1")
	recs := []vuldomain.VulnerabilityRecord{
		frameRecord(t, frameRecordSpec{coord: coord, snapshot: snap, rooting: vuldomain.RootingIsolated,
			scannedAt: time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)}),
		frameRecord(t, frameRecordSpec{coord: coord, snapshot: snap, rooting: vuldomain.TargetRootedAt(coord),
			scannedAt: time.Date(2026, 8, 1, 1, 0, 0, 0, time.UTC)}),
		frameRecord(t, frameRecordSpec{coord: coord, snapshot: snap,
			rooting:   vuldomain.TargetRootedAt(projectRoot(t, "example.com/project-a")),
			scannedAt: time.Date(2026, 8, 1, 2, 0, 0, 0, time.UTC)}),
	}
	got := consumerFrames(recs, coord)
	if len(got) != 1 || !got[0].IsRootedAt(projectRoot(t, "example.com/project-a")) {
		t.Fatalf("want only the one consumer build, got %v", got)
	}
}

// -- the batch surfaces: audit and context ----------------------------------

// audit reports one walk, so the walk it audits is the frame every vuln column
// answers in. Read frame-blind, a second project's newer scan of a shared
// dependency decides this project's audit row — the same substitution the
// single-coordinate commands refuse, arriving silently in a compliance report.
func TestAuditRow_VulnColumnAnswersInTheAuditedWalksFrame(t *testing.T) {
	prev := activeConfig
	t.Cleanup(func() { activeConfig = prev })
	activeConfig = configdomain.DefaultConfig()

	coord := twoProjectCoord(t)
	uc := testfakes.NewFakeQueryVuln()
	uc.AddRecords(coord, twoProjectAuditLedger(t)...)
	ctr := &Container{
		QueryFetch:   unfetchedQueryFetch{},
		QueryLicense: testfakes.NewFakeQueryLicense(),
		QueryVuln:    uc,
	}
	node := walkdomain.GraphNode{Coordinate: coord}

	res, err := buildAuditResult(context.Background(), node,
		walkFrameAnchor(walkA, projectRoot(t, "example.com/project-a")), "production",
		licdomain.NewLicenseOverrideSet(nil), nil, ctr, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("buildAuditResult: %v", err)
	}
	if res.VulnStatus != string(vuldomain.StatusAffected) {
		t.Errorf("the audited walk's own scan reports the module Affected; got %q (%s)", res.VulnStatus, res.VulnReason)
	}
}

// The same row, audited under the other project's walk, reports that project's
// own verdict. One store, two builds, two rows, each true of its own build.
func TestAuditRow_TheOtherWalksFrameGivesTheOtherVerdict(t *testing.T) {
	prev := activeConfig
	t.Cleanup(func() { activeConfig = prev })
	activeConfig = configdomain.DefaultConfig()

	coord := twoProjectCoord(t)
	uc := testfakes.NewFakeQueryVuln()
	uc.AddRecords(coord, twoProjectAuditLedger(t)...)
	ctr := &Container{
		QueryFetch:   unfetchedQueryFetch{},
		QueryLicense: testfakes.NewFakeQueryLicense(),
		QueryVuln:    uc,
	}
	node := walkdomain.GraphNode{Coordinate: coord}

	res, err := buildAuditResult(context.Background(), node,
		walkFrameAnchor(walkB, projectRoot(t, "example.com/project-b")), "production",
		licdomain.NewLicenseOverrideSet(nil), nil, ctr, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("buildAuditResult: %v", err)
	}
	if res.VulnStatus != string(vuldomain.StatusClean) {
		t.Errorf("project B's own scan reports the module Clean; got %q (%s)", res.VulnStatus, res.VulnReason)
	}
}

// context's walk closure asks "which of this walk's modules are affected". A
// peer's verdict has to come from this walk's frame: another project's newer
// Clean scan of a shared dependency must not drop it out of this walk's
// affected set.
func TestAffectedSetForRun_AnswersInTheRunsOwnFrame(t *testing.T) {
	coord := twoProjectCoord(t)
	uc := testfakes.NewFakeQueryVuln()
	uc.AddRecords(coord, twoProjectAuditLedger(t)...)

	run := vuldomain.WalkScanRun{
		WalkID:           walkA,
		OverallStatus:    vuldomain.WalkStatusAffected,
		PerModuleResults: map[coordinate.ModuleCoordinate]string{coord: ""},
	}

	got, err := affectedSetForRun(context.Background(), uc, run,
		walkFrameAnchor(walkA, projectRoot(t, "example.com/project-a")))
	if err != nil {
		t.Fatalf("affectedSetForRun: %v", err)
	}
	if _, ok := got[coord]; !ok {
		t.Errorf("the run's own scan reports the module Affected; the walk's affected set dropped it: %v", got)
	}

	clean, err := affectedSetForRun(context.Background(), uc, run,
		walkFrameAnchor(walkB, projectRoot(t, "example.com/project-b")))
	if err != nil {
		t.Fatalf("affectedSetForRun: %v", err)
	}
	if _, ok := clean[coord]; ok {
		t.Errorf("project B's own scan reports the module Clean; its affected set must not carry it: %v", clean)
	}
}

// A walk rooted at a published module scans its dependencies through an
// isolated per-module pool, so its own target-rooted frame holds nothing for
// them. That answer is served, labelled by the record's own frame — an isolated
// record answers a question with no consumer in it, so it misattributes
// nothing. Another consumer's record in the same candidate set is still never
// served.
func TestSelectRecordInFrame_FallsBackToIsolatedButNeverToAnotherConsumer(t *testing.T) {
	coord := twoProjectCoord(t)
	snap := vulntest.MustNew("test", "v1")
	recs := []vuldomain.VulnerabilityRecord{
		frameRecord(t, frameRecordSpec{coord: coord, snapshot: snap,
			rooting:   vuldomain.TargetRootedAt(projectRoot(t, "example.com/project-b")),
			scannedAt: time.Date(2026, 8, 2, 0, 0, 0, 0, time.UTC), reachable: false}),
		frameRecord(t, frameRecordSpec{coord: coord, snapshot: snap, rooting: vuldomain.RootingIsolated,
			completeness: "BUILT_WITH_BODIES",
			scannedAt:    time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC), reachable: true}),
	}

	rec, _, _, ok := selectRecordInFrame(recs, vuldomain.TargetRootedAt(projectRoot(t, "example.com/project-a")))
	if !ok {
		t.Fatal("an isolated record answers a frame the walk itself never measured; want it served")
	}
	if vuldomain.RecordRooting(rec) != vuldomain.RootingIsolated {
		t.Errorf("want the isolated record, got one rooted at %s", vuldomain.RecordRooting(rec))
	}

	onlyOtherConsumer := recs[:1]
	if _, _, _, ok := selectRecordInFrame(onlyOtherConsumer, vuldomain.TargetRootedAt(projectRoot(t, "example.com/project-a"))); ok {
		t.Error("another consumer's record must never answer for this one's frame")
	}
}

// context in walk mode reports one walk, and its per-module section used to
// iterate the whole walk window: whichever walk in it covered the module first
// answered, so a walk-pinned report carried other projects' frames. Measured on
// a real store, 20 of one project's 128 modules answered in three other
// projects' frames, one of them inverting a reachability verdict.
func TestContextBatch_AnchoredReportAnswersOnlyInTheAnchoredWalksFrame(t *testing.T) {
	coord := twoProjectCoord(t)
	snap := vulntest.MustNew("test", "v1")
	uc := testfakes.NewFakeQueryVuln()
	uc.AddRecords(coord, twoProjectLedger(t)...)

	runFor := func(walkID string) vuldomain.WalkScanRun {
		return vuldomain.WalkScanRun{
			WalkID:           walkID,
			Snapshot:         snap,
			OverallStatus:    vuldomain.WalkStatusAffected,
			PerModuleResults: map[coordinate.ModuleCoordinate]string{coord: ""},
		}
	}
	newBatch := func(anchorWalk, root string) *vulnBatchCtx {
		b := &vulnBatchCtx{
			hasSnapshot: true,
			snap:        snap,
			runs: map[string][]vuldomain.WalkScanRun{
				walkA: {runFor(walkA)},
				walkB: {runFor(walkB)},
			},
			frameCache: map[string]vulnFrameAnchor{},
		}
		b.frameCache[anchorWalk] = walkFrameAnchor(anchorWalk, projectRoot(t, root))
		b.anchorTo(context.Background(), anchorWalk)
		return b
	}

	gotA := buildVulnerabilitiesFromBatch(context.Background(), coord, uc, newBatch(walkA, "example.com/project-a"))
	if gotA.Frame != string(vuldomain.TargetRootedAt(projectRoot(t, "example.com/project-a"))) {
		t.Errorf("anchored to project A's walk, answered in %q", gotA.Frame)
	}
	gotB := buildVulnerabilitiesFromBatch(context.Background(), coord, uc, newBatch(walkB, "example.com/project-b"))
	if gotB.Frame != string(vuldomain.TargetRootedAt(projectRoot(t, "example.com/project-b"))) {
		t.Errorf("anchored to project B's walk, answered in %q", gotB.Frame)
	}
	if gotA.Frame == gotB.Frame {
		t.Fatal("two builds, one coordinate: the anchored answers must differ, or the anchor does nothing")
	}
}
