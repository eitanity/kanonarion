package application_test

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/coordinate/coordinatetest"
	"github.com/eitanity/kanonarion/internal/fetch/fetchtest"

	"github.com/eitanity/kanonarion/internal/vuln/application"
	"github.com/eitanity/kanonarion/internal/vuln/domain"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
)

// fakeFetcher is a minimal ModuleFetcher that records which coordinates were fetched.
type fakeFetcher struct {
	mu        sync.Mutex
	fetched   []coordinate.ModuleCoordinate
	goModOnly []coordinate.ModuleCoordinate
	err       error
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

func (f *fakeFetcher) FetchModuleGoMod(_ context.Context, coord coordinate.ModuleCoordinate) error {
	if f.err != nil {
		return f.err
	}
	f.mu.Lock()
	f.goModOnly = append(f.goModOnly, coord)
	f.mu.Unlock()
	return nil
}

func (f *fakeFetcher) wasFetchedGoModOnly(coord coordinate.ModuleCoordinate) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Contains(f.goModOnly, coord)
}

func (f *fakeFetcher) wasFetched(coord coordinate.ModuleCoordinate) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Contains(f.fetched, coord)
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

	present := coordinatetest.MustNew("github.com/present/mod", "v1.0.0")
	missing := coordinatetest.MustNew("github.com/missing/mod", "v2.0.0")

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
	presentRec := fetchtest.Record(t, fetchtest.Coordinate(present), fetchtest.PipelineVersion("v1"), fetchtest.Content("zip-present"))
	_ = blobs.Put(ctx, fetchtest.ZipIdentity(t, presentRec), strings.NewReader("zip-present"))
	_ = facts.PutFetchRecord(ctx, fetchtest.Sealed(t, fetchtest.Coordinate(present), fetchtest.PipelineVersion("v1"), fetchtest.Content("zip-present")))

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

// TestPrefetchMissing_RefetchesGoModOnlyRecord verifies that a go.mod-only
// record (no zip) does not satisfy the source a scan needs: prefetchMissing must
// re-fetch the full artefact for it, and the scan must not error trying to read
// a missing zip — it falls back to metadata-only.
func TestPrefetchMissing_RefetchesGoModOnlyRecord(t *testing.T) {
	ctx := t.Context()
	walkID := "wgomod"

	node := coordinatetest.MustNew("github.com/gomod/only", "v1.0.0")

	walkStore := newFakeWalkStore()
	_ = walkStore.PutWalk(ctx, walkdomain.WalkRecord{
		ID:    walkID,
		Graph: walkdomain.Graph{Nodes: []walkdomain.GraphNode{{Coordinate: node}}},
	})

	facts := newFakeFacts()
	blobs := newFakeBlob()

	// Seed a go.mod-only record: the go.mod is held and no zip was ever fetched.
	goModRec := fetchtest.Record(t, fetchtest.Coordinate(node), fetchtest.PipelineVersion("v1"), fetchtest.GoModOnly("gomod-only"))
	_ = blobs.Put(ctx, fetchtest.GoModIdentity(t, goModRec), strings.NewReader("module github.com/gomod/only"))
	_ = facts.PutFetchRecord(ctx, fetchtest.Sealed(t, fetchtest.Coordinate(node), fetchtest.PipelineVersion("v1"), fetchtest.GoModOnly("gomod-only")))

	vulnStore := newFakeVulnStore()
	fetcher := &fakeFetcher{}

	uc := makePrefetchScanWalkUC(t, walkStore, vulnStore, facts, blobs, fetcher)

	_, err := uc.Scan(ctx, application.ScanWalkParams{WalkID: walkID})
	if err != nil {
		t.Fatalf("Scan over a go.mod-only record: %v", err)
	}

	if !fetcher.wasFetched(node) {
		t.Errorf("expected FetchModule to re-fetch the full artefact for the go.mod-only node %s", node)
	}
	if fetcher.wasFetchedGoModOnly(node) {
		t.Errorf("prefetchMissing must use the full fetch, not the go.mod-only path, for node %s", node)
	}
}

// TestPrefetchMissing_NilFetcherIsNoop verifies that a nil fetcher does not panic
// and the scan proceeds normally.
func TestPrefetchMissing_NilFetcherIsNoop(t *testing.T) {
	ctx := t.Context()
	walkID := "w2"

	coord := coordinatetest.MustNew("github.com/foo/bar", "v1.0.0")
	walkStore := newFakeWalkStore()
	_ = walkStore.PutWalk(ctx, walkdomain.WalkRecord{
		ID:    walkID,
		Graph: walkdomain.Graph{Nodes: []walkdomain.GraphNode{{Coordinate: coord}}},
	})

	facts := newFakeFacts()
	blobs := newFakeBlob()
	seedRec := fetchtest.Record(t, fetchtest.Coordinate(coord), fetchtest.PipelineVersion("v1"), fetchtest.Content("zip"))
	_ = blobs.Put(ctx, fetchtest.ZipIdentity(t, seedRec), strings.NewReader("zip"))
	_ = facts.PutFetchRecord(ctx, fetchtest.Sealed(t, fetchtest.Coordinate(coord), fetchtest.PipelineVersion("v1"), fetchtest.Content("zip")))

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

	coord := coordinatetest.MustNew("github.com/foo/bar", "v1.0.0")
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
		coordinatetest.MustNew("github.com/a/a", "v1.0.0"),
		coordinatetest.MustNew("github.com/b/b", "v1.0.0"),
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
		rec := fetchtest.Record(t, fetchtest.Coordinate(c), fetchtest.PipelineVersion("v1"), fetchtest.Content("zip-"+c.Path()))
		_ = blobs.Put(ctx, fetchtest.ZipIdentity(t, rec), strings.NewReader("zip-"+c.Path()))
		_ = facts.PutFetchRecord(ctx, fetchtest.Sealed(t, fetchtest.Coordinate(c), fetchtest.PipelineVersion("v1"), fetchtest.Content("zip-"+c.Path())))
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
