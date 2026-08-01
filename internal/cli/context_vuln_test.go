package cli

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"

	"github.com/eitanity/kanonarion/internal/cli/testfakes"

	vuldomain "github.com/eitanity/kanonarion/internal/vuln/domain"
	"github.com/eitanity/kanonarion/internal/vuln/vulntest"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
)

// Regression pair per a genuinely unscanned module reports not_run,
// while an analysed-but-unreadable record reports read_error — never not_run.

func TestBuildVulnerabilities_NotScannedIsNotRun(t *testing.T) {
	coord := mustContextCoord(t)
	uc := testfakes.NewFakeQueryVuln()

	v := buildVulnerabilitiesFromBatch(context.Background(), coord, uc, &vulnBatchCtx{})

	if v.Status != sectionStatusNotRun {
		t.Errorf("Status = %q, want %q", v.Status, sectionStatusNotRun)
	}
	if v.Error != "" {
		t.Errorf("Error = %q, want empty for genuine absence", v.Error)
	}
}

func TestBuildVulnerabilities_StoreReadErrorIsReadError(t *testing.T) {
	coord := mustContextCoord(t)
	uc := testfakes.NewFakeQueryVuln()
	uc.Err = errors.New("unmarshalling vulnerability record: unsupported ecosystem")

	v := buildVulnerabilitiesFromBatch(context.Background(), coord, uc, &vulnBatchCtx{})

	if v.Status != sectionStatusReadError {
		t.Errorf("Status = %q, want %q", v.Status, sectionStatusReadError)
	}
	if !strings.Contains(v.Error, "unsupported ecosystem") {
		t.Errorf("Error = %q, want the store error surfaced", v.Error)
	}
}

// A run that covers the coordinate, over a ledger that cannot be read, must
// report the fault — never the not_run that a caller reads as "never scanned".
//
// The two-read shape this used to guard (a per-snapshot read whose error a
// later fallback miss could mask) is gone: the section now reads every
// generation once and selects in memory, so there is no second read to lose the
// error in. What must not regress is the outcome.
func TestBuildVulnerabilities_UnreadableLedgerIsReadErrorNotNotRun(t *testing.T) {
	coord := mustContextCoord(t)
	uc := testfakes.NewFakeQueryVuln()
	uc.Err = errors.New("record unreadable")
	batch := &vulnBatchCtx{
		runs: map[string][]vuldomain.WalkScanRun{
			"walk-1": {{PerModuleResults: map[coordinate.ModuleCoordinate]string{coord: ""}}},
		},
	}

	v := buildVulnerabilitiesFromBatch(context.Background(), coord, uc, batch)

	if v.Status != sectionStatusReadError {
		t.Errorf("Status = %q, want %q", v.Status, sectionStatusReadError)
	}
	if !strings.Contains(v.Error, "record unreadable") {
		t.Errorf("Error = %q, want the batch read error surfaced", v.Error)
	}
}

// cln builds a Clean vuln record for a coordinate.
func cln(c coordinate.ModuleCoordinate) vuldomain.VulnerabilityRecord {
	return vuldomain.VulnerabilityRecord{Coordinate: c, OverallStatus: vuldomain.StatusClean}
}

// TestVulnRecordToContext_CarriesScanProvenance pins that the snapshot and
// pipeline versions that produced a verdict reach the context struct, so every
// rendering surface can name the data and the analysis behind the verdict.
func TestVulnRecordToContext_CarriesScanProvenance(t *testing.T) {
	rec := vuldomain.VulnerabilityRecord{
		Coordinate:       mustContextCoord(t),
		OverallStatus:    vuldomain.StatusClean,
		PipelineVersion:  "0.10.0",
		DatabaseSnapshot: vulntest.MustNew("vuln.go.dev", "2026-07-08T17:05:00Z"),
	}

	v := vulnRecordToContext(&rec, "", "")

	if v.SnapshotVersion != "2026-07-08T17:05:00Z" {
		t.Errorf("SnapshotVersion = %q, want %q", v.SnapshotVersion, "2026-07-08T17:05:00Z")
	}
	if v.PipelineVersion != "0.10.0" {
		t.Errorf("PipelineVersion = %q, want %q", v.PipelineVersion, "0.10.0")
	}
}

// aff builds an Affected vuln record for a coordinate.
func aff(c coordinate.ModuleCoordinate) vuldomain.VulnerabilityRecord {
	return vuldomain.VulnerabilityRecord{Coordinate: c, OverallStatus: vuldomain.StatusAffected}
}

// walkAffectedFixture wires a single Affected walk run whose root depends on
// `subject`, plus a separate affected peer, and returns the batch context and
// vuln fake. The graph is: root → subject (clean); root → peer (affected).
// subject has no edge to peer, so peer is NOT in subject's closure.
func walkAffectedFixture(t *testing.T, subjectEdges []walkdomain.GraphEdge, records ...vuldomain.VulnerabilityRecord) (*vulnBatchCtx, *testfakes.FakeQueryVuln) {
	return walkAffectedFixtureCoverage(t, vuldomain.WalkStatusAffected, vuldomain.CoverageComplete, subjectEdges, records...)
}

// walkAffectedFixtureCoverage is walkAffectedFixture with an explicit coverage
// axis, so a test can exercise an affected peer under a Partial (incomplete
// coverage) run. FindingsStatus is always Affected here — that is what the
// fixture models.
func walkAffectedFixtureCoverage(t *testing.T, overall vuldomain.WalkScanStatus, coverage vuldomain.CoverageStatus, subjectEdges []walkdomain.GraphEdge, records ...vuldomain.VulnerabilityRecord) (*vulnBatchCtx, *testfakes.FakeQueryVuln) {
	t.Helper()
	root := coordinatetest.MustNew("example.com/root", "local")

	vuln := testfakes.NewFakeQueryVuln()
	perModule := map[coordinate.ModuleCoordinate]string{}
	for _, r := range records {
		vuln.AddRecord(r.Coordinate, r)
		perModule[r.Coordinate] = ""
	}

	walks := testfakes.NewFakeQueryWalks()
	walks.AddWalk(walkdomain.WalkRecord{
		ID:     "walk-1",
		Target: root,
		Graph:  walkdomain.Graph{Edges: subjectEdges},
	})

	batch := &vulnBatchCtx{
		runs: map[string][]vuldomain.WalkScanRun{
			"walk-1": {{
				WalkID:           "walk-1",
				OverallStatus:    overall,
				CoverageStatus:   coverage,
				FindingsStatus:   vuldomain.FindingsAffected,
				PerModuleResults: perModule,
			}},
		},
		walkUC:        walks,
		graphCache:    map[string]*walkdomain.Graph{},
		affectedCache: map[string]map[coordinate.ModuleCoordinate]struct{}{},
	}
	return batch, vuln
}

// Regression pair for transitive-dep-filtered walk annotation: a clean module
// with an affected peer that is NOT in its dependency closure shows no walk
// annotation, while one whose closure contains an affected peer names it.

func TestBuildVulnerabilities_WalkAffectedPeerNotInClosure_Suppressed(t *testing.T) {
	root := coordinatetest.MustNew("example.com/root", "local")
	subject := mustContextCoord(t) // example.com/mod@v1.0.0, clean
	peer := coordinatetest.MustNew("example.com/peer", "v2.0.0")

	// root → subject ; root → peer. subject has no path to peer.
	edges := []walkdomain.GraphEdge{
		{From: root, To: subject},
		{From: root, To: peer},
	}
	batch, vuln := walkAffectedFixture(t, edges, cln(subject), aff(peer))

	v := buildVulnerabilitiesFromBatch(context.Background(), subject, vuln, batch)

	// The affected peer is not in this module's closure, so it is not named.
	if len(v.WalkAffected) != 0 {
		t.Errorf("WalkAffected = %v, want none (peer not in closure)", v.WalkAffected)
	}
	// Coverage is complete on this run, so no coverage caveat either. With no
	// findings peer and no coverage caveat, the rendered walk note is empty.
	if v.WalkCoverage != "" {
		t.Errorf("WalkCoverage = %q, want empty (coverage complete)", v.WalkCoverage)
	}
	if got := walkAnnotation(v); got != "" {
		t.Errorf("walkAnnotation() = %q, want empty (nothing actionable for this module)", got)
	}
}

func TestBuildVulnerabilities_WalkAffectedPeerInClosure_Named(t *testing.T) {
	root := coordinatetest.MustNew("example.com/root", "local")
	subject := mustContextCoord(t) // example.com/mod@v1.0.0, clean
	peer := coordinatetest.MustNew("example.com/peer", "v2.0.0")

	// root → subject → peer. peer IS in subject's transitive closure.
	edges := []walkdomain.GraphEdge{
		{From: root, To: subject},
		{From: subject, To: peer},
	}
	batch, vuln := walkAffectedFixture(t, edges, cln(subject), aff(peer))

	v := buildVulnerabilitiesFromBatch(context.Background(), subject, vuln, batch)

	if len(v.WalkAffected) != 1 || v.WalkAffected[0] != peer.String() {
		t.Fatalf("WalkAffected = %v, want [%s]", v.WalkAffected, peer.String())
	}
	if v.WalkStatus != string(vuldomain.WalkStatusAffected) {
		t.Errorf("WalkStatus = %q, want %q", v.WalkStatus, vuldomain.WalkStatusAffected)
	}
}

// Regression: a run left Partial by an unscannable module still carries an affected
// peer in the target's closure. Keying the narrowing on the collapsed
// OverallStatus (Partial) suppressed the peer and reported a bare "Clean"; the
// findings axis (FindingsStatus == Affected) must drive it instead, and the
// coverage caveat must surface alongside the named peer rather than replacing it.
func TestBuildVulnerabilities_PartialRunWithAffectedPeerInClosure_Named(t *testing.T) {
	root := coordinatetest.MustNew("example.com/root", "local")
	subject := mustContextCoord(t) // example.com/mod@v1.0.0, clean
	peer := coordinatetest.MustNew("example.com/peer", "v2.0.0")

	// root → subject → peer. peer IS in subject's transitive closure.
	edges := []walkdomain.GraphEdge{
		{From: root, To: subject},
		{From: subject, To: peer},
	}
	// The run is Partial (an unscannable module left coverage incomplete) yet the
	// findings axis is Affected.
	batch, vuln := walkAffectedFixtureCoverage(t, vuldomain.WalkStatusPartial, vuldomain.CoveragePartial, edges, cln(subject), aff(peer))

	v := buildVulnerabilitiesFromBatch(context.Background(), subject, vuln, batch)

	if len(v.WalkAffected) != 1 || v.WalkAffected[0] != peer.String() {
		t.Fatalf("WalkAffected = %v, want [%s] (Partial must not suppress the affected peer)", v.WalkAffected, peer.String())
	}
	if v.WalkCoverage != string(vuldomain.CoveragePartial) {
		t.Errorf("WalkCoverage = %q, want %q (coverage caveat surfaces alongside the peer)", v.WalkCoverage, vuldomain.CoveragePartial)
	}
	// Both axes render together; neither suppresses the other.
	if got := walkAnnotation(v); got != "[walk: affected via "+peer.String()+"] [walk coverage: Partial — other modules unscanned]" {
		t.Errorf("walkAnnotation() = %q, want both the peer and the coverage caveat", got)
	}
}

// A store read error while resolving the walk's affected peers must not be
// fabricated into an affected-peer verdict, nor misattributed to this module's
// own (successfully read) verdict. filterWalkAnnotation records it on WalkError
// and leaves the peer set empty, so the module keeps its own verdict.
func TestFilterWalkAnnotation_PeerReadError_RecordedNotFabricated(t *testing.T) {
	root := coordinatetest.MustNew("example.com/root", "local")
	subject := mustContextCoord(t)
	peer := coordinatetest.MustNew("example.com/peer", "v2.0.0")

	edges := []walkdomain.GraphEdge{
		{From: root, To: subject},
		{From: subject, To: peer},
	}
	batch, vuln := walkAffectedFixtureCoverage(t, vuldomain.WalkStatusAffected, vuldomain.CoverageComplete, edges, cln(subject), aff(peer))
	// The peer-resolution pass errors. (Exercised directly so the subject's own
	// successfully-read verdict is not entangled with the peer read.)
	vuln.Err = errors.New("peer store unreadable")

	result := contextVulnerabilities{Status: string(vuldomain.StatusClean)}
	run := batch.runs["walk-1"][0]
	batch.filterWalkAnnotation(context.Background(), &result, subject, run, vuln)

	if len(result.WalkAffected) != 0 {
		t.Errorf("WalkAffected = %v, want none (a read error must not fabricate an affected peer)", result.WalkAffected)
	}
	if result.WalkError == "" || !strings.Contains(result.WalkError, "peer store unreadable") {
		t.Errorf("WalkError = %q, want the peer read fault recorded", result.WalkError)
	}
	// The module's own verdict is preserved, not overwritten with a read error.
	if result.Status != string(vuldomain.StatusClean) {
		t.Errorf("Status = %q, want the module's own verdict preserved", result.Status)
	}
	if got := walkAnnotation(result); !strings.Contains(got, "affected-peer status unavailable") {
		t.Errorf("walkAnnotation() = %q, want it to state the peer status is unavailable", got)
	}
}

func TestBuildVulnerabilities_WalkGraphUnavailable_KeepsGenericAnnotation(t *testing.T) {
	subject := mustContextCoord(t)
	peer := coordinatetest.MustNew("example.com/peer", "v2.0.0")

	// No walkUC / graphCache wired → graph cannot be loaded, so the generic
	// walk annotation is preserved rather than silently dropped.
	vuln := testfakes.NewFakeQueryVuln()
	vuln.AddRecord(subject, cln(subject))
	vuln.AddRecord(peer, aff(peer))
	batch := &vulnBatchCtx{
		runs: map[string][]vuldomain.WalkScanRun{
			"walk-1": {{
				WalkID:           "walk-1",
				OverallStatus:    vuldomain.WalkStatusAffected,
				CoverageStatus:   vuldomain.CoverageComplete,
				FindingsStatus:   vuldomain.FindingsAffected,
				PerModuleResults: map[coordinate.ModuleCoordinate]string{subject: "", peer: ""},
			}},
		},
	}

	v := buildVulnerabilitiesFromBatch(context.Background(), subject, vuln, batch)

	// The findings axis says Affected, but with no graph there is no basis to
	// narrow to this module's closure, so no peer is named. WalkStatus keeps the
	// run's collapsed summary as a compatibility field.
	if v.WalkStatus != string(vuldomain.WalkStatusAffected) {
		t.Errorf("WalkStatus = %q, want %q (compat summary)", v.WalkStatus, vuldomain.WalkStatusAffected)
	}
	if len(v.WalkAffected) != 0 {
		t.Errorf("WalkAffected = %v, want none when graph unavailable", v.WalkAffected)
	}
}

func TestWalkAnnotation_rendering(t *testing.T) {
	tests := []struct {
		name string
		v    contextVulnerabilities
		want string
	}{
		{"single peer", contextVulnerabilities{Status: "Clean", WalkAffected: []string{"a@v1"}}, "[walk: affected via a@v1]"},
		{"multiple peers", contextVulnerabilities{Status: "Clean", WalkAffected: []string{"a@v1", "b@v2", "c@v3"}}, "[walk: affected via a@v1 +2 more]"},
		{"partial coverage", contextVulnerabilities{Status: "Clean", WalkCoverage: "Partial"}, "[walk coverage: Partial — other modules unscanned]"},
		{"failed coverage", contextVulnerabilities{Status: "Clean", WalkCoverage: "Failed"}, "[walk coverage: Failed — other modules failed]"},
		// Both axes are informative and neither suppresses the other: a Partial
		// run that also names an affected peer prints both notes.
		{"peer and partial coverage together", contextVulnerabilities{Status: "Clean", WalkAffected: []string{"a@v1"}, WalkCoverage: "Partial"}, "[walk: affected via a@v1] [walk coverage: Partial — other modules unscanned]"},
		// The collapsed OverallStatus carried on WalkStatus never renders — it is a
		// compatibility field only; the coverage caveat comes from WalkCoverage.
		{"overall status alone renders nothing", contextVulnerabilities{Status: "Clean", WalkStatus: "Partial"}, ""},
		{"affected overall status alone renders nothing", contextVulnerabilities{Status: "Affected", WalkStatus: "Affected"}, ""},
		{"no annotation", contextVulnerabilities{Status: "Clean"}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := walkAnnotation(tt.v); got != tt.want {
				t.Errorf("walkAnnotation() = %q, want %q", got, tt.want)
			}
		})
	}
}
