package application_test

import (
	"log/slog"
	"testing"
	"time"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/vuln/application"
	"github.com/eitanity/kanonarion/internal/vuln/domain"
)

// TestScanWalk_ProgressOnScanFailure covers the progress-callback path when a
// module scan fails (scan_walk.go lines 118-124). scan_module.Scan returns an
// error when the module has no fetch record.
func TestScanWalk_ProgressOnScanFailure(t *testing.T) {
	walkStore := newFakeWalkStore()
	coord := fetchdomain.ModuleCoordinate{Path: "github.com/a/b", Version: "v1.0.0"}
	seedWalk(t, walkStore, "w1", coord)

	vulnStore := newFakeVulnStore()
	snap := domain.DatabaseSnapshot{Source: "s", Version: "v1"}
	// No fact record → scan_module.Scan returns error → scan_walk hits line 118
	facts := newFakeFacts()
	blobs := newFakeBlob()
	scanner := &fakeScanner{results: map[string]domain.VulnerabilityRecord{}}
	clock := fixedClock{t: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)}
	db := &fakeDatabase{snapshot: snap}
	moduleUC := application.NewScanModuleUseCase(
		facts, blobs, vulnStore, walkStore, scanner, db, nil, clock, "v1", "v1", slog.Default(),
	)
	uc := application.NewScanWalkUseCase(walkStore, vulnStore, moduleUC, nil, clock, "v1", slog.Default())

	var progressCalled int
	_, _ = uc.Scan(t.Context(), application.ScanWalkParams{
		WalkID:   "w1",
		Snapshot: &snap,
		Progress: func(_ fetchdomain.ModuleCoordinate, _ domain.VulnerabilityRecord, _, _ int) {
			progressCalled++
		},
	})
	if progressCalled != 1 {
		t.Errorf("expected Progress called once on failure, got %d", progressCalled)
	}
}

// TestRescan_PutSnapshotError covers rescan_walk.go line 74-76.
func TestRescan_PutSnapshotError(t *testing.T) {
	walkStore := newFakeWalkStore()
	coord := fetchdomain.ModuleCoordinate{Path: "github.com/a/b", Version: "v1.0.0"}
	seedWalk(t, walkStore, "w1", coord)

	vulnStore := newFakeVulnStore()
	vulnStore.errOnPutSnap = errStore
	db := &fakeDatabase{snapshot: domain.DatabaseSnapshot{Source: "s", Version: "v1"}, content: "data"}
	facts := newFakeFacts()
	blobs := newFakeBlob()
	clock := fixedClock{t: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)}
	scanner := &fakeScanner{results: map[string]domain.VulnerabilityRecord{}}
	moduleUC := application.NewScanModuleUseCase(
		facts, blobs, vulnStore, walkStore, scanner, db, nil, clock, "v1", "v1", slog.Default(),
	)
	uc := application.NewRescanWalkUseCase(walkStore, vulnStore, moduleUC, nil, clock, "v1", slog.Default())

	_, err := uc.Rescan(t.Context(), application.RescanRequest{WalkID: "w1"})
	if err == nil {
		t.Fatal("expected error from PutDatabaseSnapshot in rescan, got nil")
	}
}

// TestScanWalk_PutFreshSnapshotError covers scan_walk.go line 80-83.
func TestScanWalk_PutFreshSnapshotError(t *testing.T) {
	walkStore := newFakeWalkStore()
	coord := fetchdomain.ModuleCoordinate{Path: "github.com/a/b", Version: "v1.0.0"}
	seedWalk(t, walkStore, "w1", coord)

	vulnStore := newFakeVulnStore()
	vulnStore.errOnPutSnap = errStore
	// No cached snapshot → will fetch from db → then try to persist → error
	db := &fakeDatabase{snapshot: domain.DatabaseSnapshot{Source: "s", Version: "v1"}, content: "data"}

	uc := makeScanWalkUC(t, walkStore, vulnStore, db)
	_, err := uc.Scan(t.Context(), application.ScanWalkParams{WalkID: "w1"})
	if err == nil {
		t.Fatal("expected error from PutDatabaseSnapshot in scan walk, got nil")
	}
}
