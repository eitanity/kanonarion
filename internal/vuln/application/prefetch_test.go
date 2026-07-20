package application_test

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/vuln/application"
	"github.com/eitanity/kanonarion/internal/vuln/domain"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
)

// fakeFetcher is a minimal ModuleFetcher that records which coordinates were fetched.
type fakeFetcher struct {
	mu      sync.Mutex
	fetched []coordinate.ModuleCoordinate
	err     error
}

func (f *fakeFetcher) FetchModule(_ context.Context, coord coordinate.ModuleCoordinate) error {
	if f.err != nil {
		return f.err
	}
	f.mu.Lock()
	f.fetched = append(f.fetched, coord)
	f.mu.Unlock()
	return nil
}

func (f *fakeFetcher) wasFetched(coord coordinate.ModuleCoordinate) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.fetched {
		if c == coord {
			return true
		}
	}
	return false
}

func (f *fakeFetcher) fetchCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.fetched)
}

// makePrefetchScanWalkUC builds a ScanWalkUseCase wired with the given fetcher and facts.
func makePrefetchScanWalkUC(
	t *testing.T,
	walkStore *fakeWalkStore,
	vulnStore *fakeVulnStore,
	facts *fakeFacts,
	blobs *fakeBlob,
	fetcher *fakeFetcher,
) *application.ScanWalkUseCase {
	t.Helper()
	scanner := &fakeScanner{}
	db := &fakeDatabase{snapshot: domain.DatabaseSnapshot{Source: "test", Version: "v1"}}
	clock := fixedClock{t: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)}
	moduleUC := application.NewScanModuleUseCase(
		facts, blobs, vulnStore, walkStore, scanner, db, nil, clock, "v1", "v1", slog.Default(),
	)
	return application.NewScanWalkUseCase(
		walkStore, vulnStore, moduleUC, fetcher, clock, "v1", slog.Default(),
	)
}

// TestPrefetchMissing_FetchesMissingModules verifies that modules absent from the
// fact store are pre-fetched before the modcache populate step.
func TestPrefetchMissing_FetchesMissingModules(t *testing.T) {
	ctx := t.Context()
	walkID := "w1"

	present := coordinate.ModuleCoordinate{Path: "github.com/present/mod", Version: "v1.0.0"}
	missing := coordinate.ModuleCoordinate{Path: "github.com/missing/mod", Version: "v2.0.0"}

	walkStore := newFakeWalkStore()
	_ = walkStore.PutWalk(ctx, walkdomain.WalkRecord{
		ID: walkID,
		Graph: walkdomain.Graph{
			Nodes: []walkdomain.GraphNode{{Coordinate: present}, {Coordinate: missing}},
		},
	})

	facts := newFakeFacts()
	blobs := newFakeBlob()

	// Only seed the 'present' module in the fact store and blob store.
	h, _ := blobs.Put(ctx, strings.NewReader("zip-present"))
	_ = facts.PutFetchRecord(ctx, fetchdomain.FactRecord{
		ModulePath: present.Path, ModuleVersion: present.Version,
		PipelineVersion: "v1", ContentLocation: string(h),
	})

	vulnStore := newFakeVulnStore()
	fetcher := &fakeFetcher{}

	uc := makePrefetchScanWalkUC(t, walkStore, vulnStore, facts, blobs, fetcher)

	// The scan will fail to populate the modcache for 'missing' since there's no
	// blob, but that's fine — we only care that FetchModule was called for it.
	_, _ = uc.Scan(ctx, application.ScanWalkParams{WalkID: walkID})

	if !fetcher.wasFetched(missing) {
		t.Errorf("expected FetchModule to be called for %s, but it was not", missing)
	}
	if fetcher.wasFetched(present) {
		t.Errorf("FetchModule should not be called for %s (already in fact store)", present)
	}
}

// TestPrefetchMissing_NilFetcherIsNoop verifies that a nil fetcher does not panic
// and the scan proceeds normally.
func TestPrefetchMissing_NilFetcherIsNoop(t *testing.T) {
	ctx := t.Context()
	walkID := "w2"

	coord := coordinate.ModuleCoordinate{Path: "github.com/foo/bar", Version: "v1.0.0"}
	walkStore := newFakeWalkStore()
	_ = walkStore.PutWalk(ctx, walkdomain.WalkRecord{
		ID:    walkID,
		Graph: walkdomain.Graph{Nodes: []walkdomain.GraphNode{{Coordinate: coord}}},
	})

	facts := newFakeFacts()
	blobs := newFakeBlob()
	h, _ := blobs.Put(ctx, strings.NewReader("zip"))
	_ = facts.PutFetchRecord(ctx, fetchdomain.FactRecord{
		ModulePath: coord.Path, ModuleVersion: coord.Version,
		PipelineVersion: "v1", ContentLocation: string(h),
	})

	vulnStore := newFakeVulnStore()

	clock := fixedClock{t: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)}
	scanner := &fakeScanner{}
	db := &fakeDatabase{snapshot: domain.DatabaseSnapshot{Source: "test", Version: "v1"}}
	moduleUC := application.NewScanModuleUseCase(
		facts, blobs, vulnStore, walkStore, scanner, db, nil, clock, "v1", "v1", slog.Default(),
	)
	uc := application.NewScanWalkUseCase(
		walkStore, vulnStore, moduleUC, nil, clock, "v1", slog.Default(),
	)

	_, err := uc.Scan(ctx, application.ScanWalkParams{WalkID: walkID})
	if err != nil {
		t.Fatalf("Scan with nil fetcher: %v", err)
	}
}

// TestPrefetchMissing_FetchErrorIsWarningOnly verifies that a pre-fetch failure
// does not abort the scan — it is logged as a warning and scanning continues.
func TestPrefetchMissing_FetchErrorIsWarningOnly(t *testing.T) {
	ctx := t.Context()
	walkID := "w3"

	coord := coordinate.ModuleCoordinate{Path: "github.com/foo/bar", Version: "v1.0.0"}
	walkStore := newFakeWalkStore()
	_ = walkStore.PutWalk(ctx, walkdomain.WalkRecord{
		ID:    walkID,
		Graph: walkdomain.Graph{Nodes: []walkdomain.GraphNode{{Coordinate: coord}}},
	})

	// Module is NOT in the fact store — prefetch will be attempted.
	facts := newFakeFacts()
	blobs := newFakeBlob()
	vulnStore := newFakeVulnStore()

	fetcher := &fakeFetcher{err: fmt.Errorf("network unavailable")}

	uc := makePrefetchScanWalkUC(t, walkStore, vulnStore, facts, blobs, fetcher)

	// The scan should return without error even though the pre-fetch failed.
	_, err := uc.Scan(ctx, application.ScanWalkParams{WalkID: walkID})
	if err != nil {
		t.Fatalf("expected scan to continue after fetch error, got: %v", err)
	}
}

// TestPrefetchMissing_AllPresentSkipsFetch verifies that no FetchModule calls are
// made when all modules are already present in the fact store.
func TestPrefetchMissing_AllPresentSkipsFetch(t *testing.T) {
	ctx := t.Context()
	walkID := "w4"

	coords := []coordinate.ModuleCoordinate{
		{Path: "github.com/a/a", Version: "v1.0.0"},
		{Path: "github.com/b/b", Version: "v1.0.0"},
	}

	walkStore := newFakeWalkStore()
	nodes := make([]walkdomain.GraphNode, len(coords))
	for i, c := range coords {
		nodes[i] = walkdomain.GraphNode{Coordinate: c}
	}
	_ = walkStore.PutWalk(ctx, walkdomain.WalkRecord{ID: walkID, Graph: walkdomain.Graph{Nodes: nodes}})

	facts := newFakeFacts()
	blobs := newFakeBlob()
	for _, c := range coords {
		h, _ := blobs.Put(ctx, strings.NewReader("zip-"+c.Path))
		_ = facts.PutFetchRecord(ctx, fetchdomain.FactRecord{
			ModulePath: c.Path, ModuleVersion: c.Version,
			PipelineVersion: "v1", ContentLocation: string(h),
		})
	}

	vulnStore := newFakeVulnStore()
	fetcher := &fakeFetcher{}

	uc := makePrefetchScanWalkUC(t, walkStore, vulnStore, facts, blobs, fetcher)

	_, err := uc.Scan(ctx, application.ScanWalkParams{WalkID: walkID})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	if fetcher.fetchCount() != 0 {
		t.Errorf("expected 0 FetchModule calls, got %d", fetcher.fetchCount())
	}
}
