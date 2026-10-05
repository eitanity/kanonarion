package cli

import (
	"context"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/adapters/recordseal"
	"github.com/eitanity/kanonarion/internal/adapters/sqlitestore"
	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	vulnsqlite "github.com/eitanity/kanonarion/internal/vuln/adapters/store/sqlite"
	vulndomain "github.com/eitanity/kanonarion/internal/vuln/domain"
	walkadapters "github.com/eitanity/kanonarion/internal/walk/adapters/walks/sqlite"
	walkapp "github.com/eitanity/kanonarion/internal/walk/application"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
)

const (
	asideLocalWalkID = "01JS0NGARD0000000000000WL1"
	asideLocalRunID  = "01JS0NGARD0000000000000RL1"
)

// A re-scan of a local project whose walk names no directory settles its frame
// from the walk's scan runs. With its only run set aside nothing this build can
// serve decides the frame, so the refusal is exit 4 with the statement, not a
// configuration error, and it happens before any snapshot is fetched.
func TestVulnScanRescan_FrameDecidedOnlyBySetAsideRunIsNotServable(t *testing.T) {
	var seal string
	root := asideStore(t, func(ctx context.Context, db sqlitestore.DB) {
		seedJSONDocWalk(t, ctx, db)
		seedJSONDocVulnerabilities(t, ctx, db)

		local := coordinatetest.MustNew("example.com/app", coordinate.LocalVersion)
		graph := walkdomain.Graph{Target: local, Nodes: []walkdomain.GraphNode{{Coordinate: local, ResolutionSource: walkdomain.ResolutionTarget}},
			ResolvedAt: jsonDocAt, PipelineVersion: walkapp.PipelineVersion}
		outcome := walkdomain.WalkOutcome{Target: local, Graph: graph,
			PerNodeResults: map[coordinate.ModuleCoordinate]walkdomain.NodeResult{local: {Coordinate: local, Status: walkdomain.NodeSucceeded}},
			StartedAt:      jsonDocAt, CompletedAt: jsonDocAt, OverallStatus: walkdomain.WalkSucceeded}
		walk, err := walkdomain.WalkRecordHasher{}.SetContentHash(walkdomain.NewWalkRecord(asideLocalWalkID, "guard", walkapp.PipelineVersion,
			walkdomain.WalkScopeCode, walkdomain.WalkDepthFull, outcome, walkdomain.DefaultDepthPolicy(), ""))
		if err != nil {
			t.Fatal(err)
		}
		if err := walkadapters.New(db).PutWalk(ctx, walk); err != nil {
			t.Fatalf("seeding the local walk: %v", err)
		}

		store := vulnsqlite.New(db)
		run, found, err := store.GetWalkScanRun(ctx, jsonDocScanRunID)
		if err != nil || !found {
			t.Fatalf("reading the seeded run: %v", err)
		}
		run.ID, run.WalkID, run.ContentHash = asideLocalRunID, asideLocalWalkID, ""
		if run, err = (vulndomain.WalkScanRunHasher{}).SetContentHash(run); err != nil {
			t.Fatal(err)
		}
		if err := store.PutWalkScanRun(ctx, run); err != nil {
			t.Fatalf("seeding the local walk's run: %v", err)
		}
		seal = widenStoredRow(t, ctx, db, "walk_scan_runs", "serialised", "content_hash", "id", asideLocalRunID, false, nil)
	})

	_, stderr, err := runAside("vuln-scan-rescan", asideLocalWalkID, "--store-root", root)
	if code := ExitCodeForError(err); code != ExitNotFound {
		t.Fatalf("exit %d (%v), want %d\n%s", code, err, ExitNotFound, stderr)
	}
	for _, want := range []string{"without the scan runs this build cannot reproduce", seal, recordseal.SetAsideRemedy} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal %q does not state %q", err, want)
		}
	}
	if strings.Contains(err.Error(), "integrity") || strings.Contains(stderr, "fetching fresh") {
		t.Errorf("refusal reads as tampering, or came after a snapshot fetch:\n%v\n%s", err, stderr)
	}
}
