package cli

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"

	"github.com/eitanity/kanonarion/internal/cli/testfakes"

	vuldomain "github.com/eitanity/kanonarion/internal/vuln/domain"
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

// latestNotFoundQueryVuln errors on the per-snapshot read but reports a clean
// miss from the latest-record fallback, isolating the remembered batch read
// error from the fallback's own error path.
type latestNotFoundQueryVuln struct {
	*testfakes.FakeQueryVuln
}

func (f latestNotFoundQueryVuln) GetLatestRecord(_ context.Context, _ coordinate.ModuleCoordinate, _ string) (vuldomain.VulnerabilityRecord, bool, error) {
	return vuldomain.VulnerabilityRecord{}, false, nil
}

func TestBuildVulnerabilities_BatchReadErrorSurvivesFallbackMiss(t *testing.T) {
	coord := mustContextCoord(t)
	inner := testfakes.NewFakeQueryVuln()
	inner.Err = errors.New("record unreadable")
	batch := &vulnBatchCtx{
		runs: map[string][]vuldomain.WalkScanRun{
			"walk-1": {{PerModuleResults: map[coordinate.ModuleCoordinate]string{coord: ""}}},
		},
	}

	v := buildVulnerabilitiesFromBatch(context.Background(), coord, latestNotFoundQueryVuln{inner}, batch)

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

// aff builds an Affected vuln record for a coordinate.
func aff(c coordinate.ModuleCoordinate) vuldomain.VulnerabilityRecord {
	return vuldomain.VulnerabilityRecord{Coordinate: c, OverallStatus: vuldomain.StatusAffected}
}

// walkAffectedFixture wires a single Affected walk run whose root depends on
// `subject`, plus a separate affected peer, and returns the batch context and
// vuln fake. The graph is: root → subject (clean); root → peer (affected).
// subject has no edge to peer, so peer is NOT in subject's closure.
func walkAffectedFixture(t *testing.T, subjectEdges []walkdomain.GraphEdge, records ...vuldomain.VulnerabilityRecord) (*vulnBatchCtx, *testfakes.FakeQueryVuln) {
	t.Helper()
	root := coordinate.ModuleCoordinate{Path: "example.com/root", Version: "local"}

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
				OverallStatus:    vuldomain.WalkStatusAffected,
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
	root := coordinate.ModuleCoordinate{Path: "example.com/root", Version: "local"}
	subject := mustContextCoord(t) // example.com/mod@v1.0.0, clean
	peer := coordinate.ModuleCoordinate{Path: "example.com/peer", Version: "v2.0.0"}

	// root → subject ; root → peer. subject has no path to peer.
	edges := []walkdomain.GraphEdge{
		{From: root, To: subject},
		{From: root, To: peer},
	}
	batch, vuln := walkAffectedFixture(t, edges, cln(subject), aff(peer))

	v := buildVulnerabilitiesFromBatch(context.Background(), subject, vuln, batch)

	if v.WalkStatus != "" {
		t.Errorf("WalkStatus = %q, want empty (peer not in closure → annotation suppressed)", v.WalkStatus)
	}
	if len(v.WalkAffected) != 0 {
		t.Errorf("WalkAffected = %v, want none", v.WalkAffected)
	}
}

func TestBuildVulnerabilities_WalkAffectedPeerInClosure_Named(t *testing.T) {
	root := coordinate.ModuleCoordinate{Path: "example.com/root", Version: "local"}
	subject := mustContextCoord(t) // example.com/mod@v1.0.0, clean
	peer := coordinate.ModuleCoordinate{Path: "example.com/peer", Version: "v2.0.0"}

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

func TestBuildVulnerabilities_WalkGraphUnavailable_KeepsGenericAnnotation(t *testing.T) {
	subject := mustContextCoord(t)
	peer := coordinate.ModuleCoordinate{Path: "example.com/peer", Version: "v2.0.0"}

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
				PerModuleResults: map[coordinate.ModuleCoordinate]string{subject: "", peer: ""},
			}},
		},
	}

	v := buildVulnerabilitiesFromBatch(context.Background(), subject, vuln, batch)

	if v.WalkStatus != string(vuldomain.WalkStatusAffected) {
		t.Errorf("WalkStatus = %q, want %q (graph unavailable → generic annotation kept)", v.WalkStatus, vuldomain.WalkStatusAffected)
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
		{"partial fallback", contextVulnerabilities{Status: "Clean", WalkStatus: "Partial"}, "[walk coverage: Partial — other modules unscanned]"},
		{"scanfailed fallback", contextVulnerabilities{Status: "Clean", WalkStatus: "ScanFailed"}, "[walk coverage: ScanFailed — other modules failed]"},
		{"allclean is redundant noise", contextVulnerabilities{Status: "Clean", WalkStatus: "AllClean"}, ""},
		{"matching status suppressed", contextVulnerabilities{Status: "Affected", WalkStatus: "Affected"}, ""},
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
