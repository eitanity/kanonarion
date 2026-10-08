package application_test

import (
	"log/slog"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/adapters/sqlitestore"
	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	"github.com/eitanity/kanonarion/internal/fetch/fetchtest"
	vulnsqlite "github.com/eitanity/kanonarion/internal/vuln/adapters/store/sqlite"
	"github.com/eitanity/kanonarion/internal/vuln/application"
	"github.com/eitanity/kanonarion/internal/vuln/domain"
	"github.com/eitanity/kanonarion/internal/vuln/vulntest"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
)

var nanoRunID = regexp.MustCompile(`^vscan-w1-\d{19}$`)

// Two scans of one walk inside one second are two runs. With a whole-second id
// they shared one, and the store kept the second scan's header over the first
// scan's membership rows, so the two readers of a run answered from different
// scans.
func TestScanWalk_TwoScansInOneSecondAreTwoCompleteRuns(t *testing.T) {
	ctx := t.Context()
	now := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := &steppedClock{t: now}

	db, err := sqlitestore.Open(":memory:", vulnsqlite.Migrations(), sqlitestore.IntentCreate)
	if err != nil {
		t.Fatalf("opening in-memory db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	vulnStore := vulnsqlite.New(db)

	m1 := coordinatetest.MustNew("m1", "v1")
	walkStore := newFakeWalkStore()
	_ = walkStore.PutWalk(ctx, walkdomain.WalkRecord{
		ID:    "w1",
		Graph: walkdomain.Graph{Nodes: []walkdomain.GraphNode{{Coordinate: m1}}},
	})
	facts := newFakeFacts()
	blobs := newFakeBlob()
	seedRec := fetchtest.Record(t, fetchtest.Coordinate(m1), fetchtest.PipelineVersion("v1"), fetchtest.Content("zip"))
	_ = blobs.Put(ctx, fetchtest.ZipIdentity(t, seedRec), strings.NewReader("zip"))
	_ = facts.PutFetchRecord(ctx, fetchtest.Sealed(t, fetchtest.Coordinate(m1), fetchtest.PipelineVersion("v1"), fetchtest.Content("zip")))

	snapshot := vulntest.MustNewAt("test", "v1", now.Add(-time.Hour))
	if err := vulnStore.PutDatabaseSnapshot(ctx, snapshot, strings.NewReader("cached")); err != nil {
		t.Fatalf("PutDatabaseSnapshot: %v", err)
	}
	scanner := &fakeScanner{}
	moduleUC := application.NewScanModuleUseCase(
		facts, blobs, vulnStore, walkStore, scanner, &fakeDatabase{snapshot: snapshot}, nil, clock, "v1", slog.Default(),
	)
	walkUC := application.NewScanWalkUseCase(walkStore, vulnStore, moduleUC, nil, clock, "v1", slog.Default())

	first, err := walkUC.Scan(ctx, application.ScanWalkParams{WalkID: "w1", Force: true})
	if err != nil {
		t.Fatalf("first Scan: %v", err)
	}
	// The second scan finds something the first did not, so the two runs name
	// different record generations and a mix of them is visible.
	scanner.mu.Lock()
	scanner.results = map[string]domain.VulnerabilityRecord{m1.String(): {
		Coordinate:    m1,
		OverallStatus: domain.StatusAffected,
		Findings:      []domain.VulnerabilityFinding{{ID: "GO-2024-0001"}},
	}}
	scanner.mu.Unlock()
	clock.advance(250 * time.Millisecond)
	second, err := walkUC.Scan(ctx, application.ScanWalkParams{WalkID: "w1", Force: true})
	if err != nil {
		t.Fatalf("second Scan: %v", err)
	}

	if first.Counts.Affected != 0 || second.Counts.Affected != 1 {
		t.Fatalf("control: affected counts %d then %d, want 0 then 1", first.Counts.Affected, second.Counts.Affected)
	}
	if first.StartedAt.Unix() != second.StartedAt.Unix() {
		t.Fatalf("control: scans started in seconds %d and %d, want one", first.StartedAt.Unix(), second.StartedAt.Unix())
	}
	if first.ID == second.ID {
		t.Fatalf("both scans got run id %s", first.ID)
	}
	for _, id := range []string{first.ID, second.ID} {
		if !nanoRunID.MatchString(id) {
			t.Errorf("run id %q is not vscan-<walk>-<19-digit nanoseconds>", id)
		}
	}

	runs, err := vulnStore.ListWalkScanRuns(ctx, "w1")
	if err != nil {
		t.Fatalf("ListWalkScanRuns: %v", err)
	}
	if len(runs) != 2 {
		t.Fatalf("store holds %d runs of w1, want 2", len(runs))
	}

	hashes := make(map[string]string, 2)
	for _, want := range []domain.WalkScanRun{first, second} {
		got, found, err := vulnStore.GetWalkScanRun(ctx, want.ID)
		if err != nil || !found {
			t.Fatalf("GetWalkScanRun(%s) = (%v, %v)", want.ID, found, err)
		}
		if got.ContentHash != want.ContentHash {
			t.Errorf("run %s stored seal %s, want the one its scan returned %s", want.ID, got.ContentHash, want.ContentHash)
		}
		index := membershipHashes(t, db, want.ID)
		if len(index) != 1 || index[m1] == "" {
			t.Fatalf("run %s membership index = %v, want one row for %s", want.ID, index, m1)
		}
		if index[m1] != got.PerModuleResults[m1] {
			t.Errorf("run %s: header names %s for %s, membership index names %s",
				want.ID, got.PerModuleResults[m1], m1, index[m1])
		}
		hashes[want.ID] = index[m1]
	}
	if hashes[first.ID] == hashes[second.ID] {
		t.Errorf("control: both runs name record %s, so a mix of the two would not show", hashes[first.ID])
	}
}

func membershipHashes(t *testing.T, db sqlitestore.DB, runID string) map[coordinate.ModuleCoordinate]string {
	t.Helper()
	rows, err := db.DB().Query(`SELECT module_path, module_version, record_content_hash
FROM walk_scan_run_modules WHERE walk_scan_run_id = ?`, runID)
	if err != nil {
		t.Fatalf("querying membership index: %v", err)
	}
	defer func() { _ = rows.Close() }()
	out := make(map[coordinate.ModuleCoordinate]string)
	for rows.Next() {
		var path, version, hash string
		if err := rows.Scan(&path, &version, &hash); err != nil {
			t.Fatalf("scanning membership row: %v", err)
		}
		out[coordinatetest.MustNew(path, version)] = hash
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterating membership index: %v", err)
	}
	return out
}
