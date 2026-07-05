package application_test

import (
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/vuln/application"
	"github.com/eitanity/kanonarion/internal/vuln/domain"
)

// helpers shared across this file

func newAffectedScannerFor(coord fetchdomain.ModuleCoordinate, findingID string, symbols []string) *fakeScanner {
	return &fakeScanner{
		results: map[string]domain.VulnerabilityRecord{
			coord.String(): {
				Coordinate:    coord,
				OverallStatus: domain.StatusAffected,
				Findings: []domain.VulnerabilityFinding{
					{ID: findingID, AffectedSymbols: symbols},
				},
			},
		},
	}
}

func seedFact(t *testing.T, facts *fakeFacts, blobs *fakeBlob, coord fetchdomain.ModuleCoordinate) {
	t.Helper()
	handle, err := blobs.Put(t.Context(), strings.NewReader("zip"))
	if err != nil {
		t.Fatalf("blobs.Put: %v", err)
	}
	if err := facts.PutFetchRecord(t.Context(), fetchdomain.FactRecord{
		ModulePath:      coord.Path,
		ModuleVersion:   coord.Version,
		PipelineVersion: "v1",
		ContentLocation: string(handle),
	}); err != nil {
		t.Fatalf("PutFetchRecord: %v", err)
	}
}

func newScanUCWith(
	facts *fakeFacts,
	blobs *fakeBlob,
	vulnStore *fakeVulnStore,
	scanner *fakeScanner,
	db *fakeDatabase,
	reachability *fakeReachabilityAnalyser,
	loader *fakeCallGraphLoader,
	spawner *fakeCallGraphSpawner,
) *application.ScanModuleUseCase {
	uc := application.NewScanModuleUseCase(
		facts, blobs, vulnStore, nil,
		scanner, db, reachability,
		fixedClock{t: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)},
		"v1", "v1",
		slog.New(slog.NewTextHandler(io.Discard, nil)),
	).WithCallGraphLoader(loader)
	if spawner != nil {
		uc = uc.WithCallGraphSpawner(spawner)
	}
	return uc
}

// TestOnDemandCallGraph_SpawnedOnMiss verifies that when a finding has
// AffectedSymbols and no callgraph exists in the store, the spawner is invoked
// and reachability.Analyse is called on success.
func TestOnDemandCallGraph_SpawnedOnMiss(t *testing.T) {
	ctx := t.Context()
	coord := fetchdomain.ModuleCoordinate{Path: "github.com/foo/bar", Version: "v1.0.0"}

	facts := newFakeFacts()
	blobs := newFakeBlob()
	seedFact(t, facts, blobs, coord)

	vulnStore := newFakeVulnStore()
	snap := domain.DatabaseSnapshot{Source: "test", Version: "v1"}
	_ = vulnStore.PutDatabaseSnapshot(ctx, snap, strings.NewReader(""))

	db := &fakeDatabase{
		snapshot:    snap,
		vulnerables: map[fetchdomain.ModuleCoordinate][]string{coord: {"GO-2024-0001"}},
	}
	scanner := newAffectedScannerFor(coord, "GO-2024-0001", []string{"Vuln"})

	loader := &fakeCallGraphLoader{present: false}
	spawner := &fakeCallGraphSpawner{}
	reach := &fakeReachabilityAnalyser{result: domain.ReachabilityResult{IsReachable: true, Confidence: domain.ConfidenceHigh}}

	// After spawn, make the callgraph available so reachability can proceed.
	spawner.onSpawn = func() { loader.setPresent(true) }

	uc := newScanUCWith(facts, blobs, vulnStore, scanner, db, reach, loader, spawner)

	rec, err := uc.Scan(ctx, application.ScanModuleParams{
		Coordinate:         coord,
		WalkID:             "walk-1",
		Snapshot:           &snap,
		EnableReachability: true,
	})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	if spawner.callCount() != 1 {
		t.Errorf("expected 1 spawn call, got %d", spawner.callCount())
	}
	if reach.callCount() != 1 {
		t.Errorf("expected 1 reachability.Analyse call, got %d", reach.callCount())
	}
	if len(rec.Findings) == 0 || rec.Findings[0].Reachable == nil {
		t.Errorf("expected Reachable to be set on finding; got %+v", rec.Findings)
	}
	if rec.Findings[0].ReachabilityNote != "" {
		t.Errorf("expected empty ReachabilityNote on success, got %q", rec.Findings[0].ReachabilityNote)
	}
}

// TestOnDemandCallGraph_CacheHit verifies that when a callgraph already exists
// in the store, the spawner is NOT invoked.
func TestOnDemandCallGraph_CacheHit(t *testing.T) {
	ctx := t.Context()
	coord := fetchdomain.ModuleCoordinate{Path: "github.com/foo/bar", Version: "v1.0.0"}

	facts := newFakeFacts()
	blobs := newFakeBlob()
	seedFact(t, facts, blobs, coord)

	vulnStore := newFakeVulnStore()
	snap := domain.DatabaseSnapshot{Source: "test", Version: "v1"}
	_ = vulnStore.PutDatabaseSnapshot(ctx, snap, strings.NewReader(""))

	db := &fakeDatabase{
		snapshot:    snap,
		vulnerables: map[fetchdomain.ModuleCoordinate][]string{coord: {"GO-2024-0001"}},
	}
	scanner := newAffectedScannerFor(coord, "GO-2024-0001", []string{"Vuln"})
	reach := &fakeReachabilityAnalyser{}

	loader := &fakeCallGraphLoader{present: true} // already in store
	spawner := &fakeCallGraphSpawner{}

	uc := newScanUCWith(facts, blobs, vulnStore, scanner, db, reach, loader, spawner)

	_, err := uc.Scan(ctx, application.ScanModuleParams{
		Coordinate:         coord,
		WalkID:             "walk-1",
		Snapshot:           &snap,
		EnableReachability: true,
	})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	if spawner.callCount() != 0 {
		t.Errorf("spawner must not be called when callgraph is already in store; got %d calls", spawner.callCount())
	}
	if reach.callCount() != 1 {
		t.Errorf("expected 1 reachability call (using existing callgraph), got %d", reach.callCount())
	}
}

// TestOnDemandCallGraph_SpawnFailureSetsNote verifies that a subprocess failure
// leaves Reachable nil and sets a non-empty ReachabilityNote; the finding and
// record are still persisted with StatusAffected.
func TestOnDemandCallGraph_SpawnFailureSetsNote(t *testing.T) {
	ctx := t.Context()
	coord := fetchdomain.ModuleCoordinate{Path: "github.com/foo/bar", Version: "v1.0.0"}

	facts := newFakeFacts()
	blobs := newFakeBlob()
	seedFact(t, facts, blobs, coord)

	vulnStore := newFakeVulnStore()
	snap := domain.DatabaseSnapshot{Source: "test", Version: "v1"}
	_ = vulnStore.PutDatabaseSnapshot(ctx, snap, strings.NewReader(""))

	db := &fakeDatabase{
		snapshot:    snap,
		vulnerables: map[fetchdomain.ModuleCoordinate][]string{coord: {"GO-2024-0002"}},
	}
	scanner := newAffectedScannerFor(coord, "GO-2024-0002", []string{"Vuln"})
	reach := &fakeReachabilityAnalyser{}

	loader := &fakeCallGraphLoader{present: false}
	spawner := &fakeCallGraphSpawner{
		err:    errors.New("exit status 137"),
		stderr: []byte("signal: killed"),
	}

	uc := newScanUCWith(facts, blobs, vulnStore, scanner, db, reach, loader, spawner)

	rec, err := uc.Scan(ctx, application.ScanModuleParams{
		Coordinate:         coord,
		WalkID:             "walk-1",
		Snapshot:           &snap,
		EnableReachability: true,
	})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	if rec.OverallStatus != domain.StatusAffected {
		t.Errorf("expected StatusAffected after spawn failure, got %s", rec.OverallStatus)
	}
	if len(rec.Findings) == 0 {
		t.Fatal("expected at least one finding")
	}
	f := rec.Findings[0]
	if f.Reachable != nil {
		t.Errorf("expected Reachable to be nil after spawn failure, got %+v", f.Reachable)
	}
	if f.ReachabilityNote == "" {
		t.Error("expected non-empty ReachabilityNote after spawn failure")
	}
	if !strings.Contains(f.ReachabilityNote, "signal: killed") {
		t.Errorf("ReachabilityNote should contain stderr; got %q", f.ReachabilityNote)
	}

	// Record must be persisted despite the spawn failure.
	persisted, ok, perr := vulnStore.GetVulnerabilityRecord(ctx, coord, "v1", snap)
	if perr != nil || !ok {
		t.Fatal("record not persisted after spawn failure")
	}
	if persisted.Findings[0].Reachable != nil {
		t.Error("persisted record must have nil Reachable")
	}
	if persisted.Findings[0].ReachabilityNote == "" {
		t.Error("persisted record must have non-empty ReachabilityNote")
	}

	if reach.callCount() != 0 {
		t.Errorf("reachability.Analyse must not be called after spawn failure, got %d calls", reach.callCount())
	}
}

// TestOnDemandCallGraph_ForceBypassesCache verifies that --force causes a spawn
// even when a callgraph record already exists in the store.
func TestOnDemandCallGraph_ForceBypassesCache(t *testing.T) {
	ctx := t.Context()
	coord := fetchdomain.ModuleCoordinate{Path: "github.com/foo/bar", Version: "v1.0.0"}

	facts := newFakeFacts()
	blobs := newFakeBlob()
	seedFact(t, facts, blobs, coord)

	vulnStore := newFakeVulnStore()
	snap := domain.DatabaseSnapshot{Source: "test", Version: "v1"}
	_ = vulnStore.PutDatabaseSnapshot(ctx, snap, strings.NewReader(""))

	db := &fakeDatabase{
		snapshot:    snap,
		vulnerables: map[fetchdomain.ModuleCoordinate][]string{coord: {"GO-2024-0003"}},
	}
	scanner := newAffectedScannerFor(coord, "GO-2024-0003", []string{"Vuln"})
	reach := &fakeReachabilityAnalyser{}

	loader := &fakeCallGraphLoader{present: true} // already in store
	spawner := &fakeCallGraphSpawner{}

	uc := newScanUCWith(facts, blobs, vulnStore, scanner, db, reach, loader, spawner)

	_, err := uc.Scan(ctx, application.ScanModuleParams{
		Coordinate:         coord,
		WalkID:             "walk-1",
		Snapshot:           &snap,
		EnableReachability: true,
		Force:              true,
	})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	if spawner.callCount() != 1 {
		t.Errorf("expected 1 spawn call under --force even with cached callgraph, got %d", spawner.callCount())
	}
}

// TestOnDemandCallGraph_NoSpawnForClean verifies that StatusClean modules
// never trigger a subprocess.
func TestOnDemandCallGraph_NoSpawnForClean(t *testing.T) {
	ctx := t.Context()
	coord := fetchdomain.ModuleCoordinate{Path: "github.com/foo/clean", Version: "v1.0.0"}

	facts := newFakeFacts()
	blobs := newFakeBlob()
	seedFact(t, facts, blobs, coord)

	vulnStore := newFakeVulnStore()
	snap := domain.DatabaseSnapshot{Source: "test", Version: "v1"}
	_ = vulnStore.PutDatabaseSnapshot(ctx, snap, strings.NewReader(""))

	db := &fakeDatabase{snapshot: snap} // no vulnerabilities
	scanner := &fakeScanner{}           // returns StatusClean

	loader := &fakeCallGraphLoader{present: false}
	spawner := &fakeCallGraphSpawner{}
	reach := &fakeReachabilityAnalyser{}

	uc := newScanUCWith(facts, blobs, vulnStore, scanner, db, reach, loader, spawner)

	rec, err := uc.Scan(ctx, application.ScanModuleParams{
		Coordinate:         coord,
		WalkID:             "walk-1",
		Snapshot:           &snap,
		EnableReachability: true,
	})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if rec.OverallStatus != domain.StatusClean {
		t.Errorf("expected StatusClean, got %s", rec.OverallStatus)
	}
	if spawner.callCount() != 0 {
		t.Errorf("spawner must not be called for clean modules, got %d calls", spawner.callCount())
	}
}

// TestOnDemandCallGraph_NoSpawnWhenSymbolsEmpty verifies that findings without
// AffectedSymbols (metadata-only) never trigger a subprocess.
func TestOnDemandCallGraph_NoSpawnWhenSymbolsEmpty(t *testing.T) {
	ctx := t.Context()
	coord := fetchdomain.ModuleCoordinate{Path: "github.com/foo/bar", Version: "v1.0.0"}

	facts := newFakeFacts()
	blobs := newFakeBlob()
	seedFact(t, facts, blobs, coord)

	vulnStore := newFakeVulnStore()
	snap := domain.DatabaseSnapshot{Source: "test", Version: "v1"}
	_ = vulnStore.PutDatabaseSnapshot(ctx, snap, strings.NewReader(""))

	db := &fakeDatabase{
		snapshot:    snap,
		vulnerables: map[fetchdomain.ModuleCoordinate][]string{coord: {"GO-2024-0004"}},
	}
	// Scanner returns a finding with NO AffectedSymbols (metadata-only finding).
	scanner := &fakeScanner{
		results: map[string]domain.VulnerabilityRecord{
			coord.String(): {
				Coordinate:    coord,
				OverallStatus: domain.StatusAffected,
				Findings: []domain.VulnerabilityFinding{
					{ID: "GO-2024-0004", AffectedSymbols: nil},
				},
			},
		},
	}

	loader := &fakeCallGraphLoader{present: false}
	spawner := &fakeCallGraphSpawner{}
	reach := &fakeReachabilityAnalyser{}

	uc := newScanUCWith(facts, blobs, vulnStore, scanner, db, reach, loader, spawner)

	rec, err := uc.Scan(ctx, application.ScanModuleParams{
		Coordinate:         coord,
		WalkID:             "walk-1",
		Snapshot:           &snap,
		EnableReachability: true,
	})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if spawner.callCount() != 0 {
		t.Errorf("spawner must not be called when AffectedSymbols is empty, got %d calls", spawner.callCount())
	}
	if reach.callCount() != 0 {
		t.Errorf("reachability.Analyse must not be called when AffectedSymbols is empty, got %d calls", reach.callCount())
	}
	_ = rec
}

// TestOnDemandCallGraph_SemaphoreSerialises verifies that --callgraph-workers 1
// (the default) prevents more than one concurrent callgraph subprocess. Two
// module scans running concurrently must not both hold the semaphore at the
// same time.
func TestOnDemandCallGraph_SemaphoreSerialises(t *testing.T) {
	ctx := t.Context()

	coordA := fetchdomain.ModuleCoordinate{Path: "github.com/foo/a", Version: "v1.0.0"}
	coordB := fetchdomain.ModuleCoordinate{Path: "github.com/foo/b", Version: "v1.0.0"}

	facts := newFakeFacts()
	blobs := newFakeBlob()
	seedFact(t, facts, blobs, coordA)
	seedFact(t, facts, blobs, coordB)

	vulnStore := newFakeVulnStore()
	snap := domain.DatabaseSnapshot{Source: "test", Version: "v1"}
	_ = vulnStore.PutDatabaseSnapshot(ctx, snap, strings.NewReader(""))

	db := &fakeDatabase{
		snapshot: snap,
		vulnerables: map[fetchdomain.ModuleCoordinate][]string{
			coordA: {"GO-A"},
			coordB: {"GO-B"},
		},
	}
	scanner := &fakeScanner{
		results: map[string]domain.VulnerabilityRecord{
			coordA.String(): {Coordinate: coordA, OverallStatus: domain.StatusAffected, Findings: []domain.VulnerabilityFinding{{ID: "GO-A", AffectedSymbols: []string{"VulnA"}}}},
			coordB.String(): {Coordinate: coordB, OverallStatus: domain.StatusAffected, Findings: []domain.VulnerabilityFinding{{ID: "GO-B", AffectedSymbols: []string{"VulnB"}}}},
		},
	}
	reach := &fakeReachabilityAnalyser{}

	// Track maximum concurrent spawns.
	var concurrentSpawns atomic.Int32
	var maxConcurrent atomic.Int32

	loader := &fakeCallGraphLoader{present: false}

	spawner := &fakeCallGraphSpawner{}
	spawner.onSpawn = func() {
		cur := concurrentSpawns.Add(1)
		for {
			old := maxConcurrent.Load()
			if cur <= old || maxConcurrent.CompareAndSwap(old, cur) {
				break
			}
		}
		// brief yield to let another goroutine attempt to spawn concurrently
		time.Sleep(5 * time.Millisecond)
		concurrentSpawns.Add(-1)
		loader.setPresent(true)
	}

	uc := newScanUCWith(facts, blobs, vulnStore, scanner, db, reach, loader, spawner)

	sem := make(chan struct{}, 1) // callgraph-workers = 1

	var wg sync.WaitGroup
	for _, coord := range []fetchdomain.ModuleCoordinate{coordA, coordB} {
		wg.Add(1)
		go func(c fetchdomain.ModuleCoordinate) {
			defer wg.Done()
			_, _ = uc.Scan(ctx, application.ScanModuleParams{
				Coordinate:         c,
				WalkID:             "walk-1",
				Snapshot:           &snap,
				EnableReachability: true,
				CallGraphSem:       sem,
			})
		}(coord)
	}
	wg.Wait()

	if maxConcurrent.Load() > 1 {
		t.Errorf("semaphore did not serialise spawns: max concurrent = %d, want ≤ 1", maxConcurrent.Load())
	}
	if spawner.callCount() < 1 {
		t.Error("expected at least one spawn call")
	}
}
