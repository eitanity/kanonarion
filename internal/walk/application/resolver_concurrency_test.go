package application_test

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"reflect"
	"sync"
	"testing"
	"time"

	domain2 "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/walk/adapters/gomod/xmod"
	"github.com/eitanity/kanonarion/internal/walk/application"
	domain3 "github.com/eitanity/kanonarion/internal/walk/domain"
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
)

// concurrencyTracker wraps a ModuleFetcher to record the peak number of fetches
// in flight at once, and adds a small delay so genuinely concurrent fetches
// overlap observably. Safe for concurrent use.
type concurrencyTracker struct {
	inner walkports.ModuleFetcher
	delay time.Duration

	mu       sync.Mutex
	inFlight int
	maxSeen  int
}

func (c *concurrencyTracker) EnsureFetched(ctx context.Context, coord domain2.ModuleCoordinate) (walkports.ModuleFetchResult, error) {
	c.mu.Lock()
	c.inFlight++
	if c.inFlight > c.maxSeen {
		c.maxSeen = c.inFlight
	}
	c.mu.Unlock()

	if c.delay > 0 {
		time.Sleep(c.delay)
	}

	res, err := c.inner.EnsureFetched(ctx, coord)

	c.mu.Lock()
	c.inFlight--
	c.mu.Unlock()
	if err != nil {
		return res, fmt.Errorf("concurrencyTracker: %w", err)
	}
	return res, nil
}

func (c *concurrencyTracker) peak() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.maxSeen
}

func newResolverWithFetcher(fetcher walkports.ModuleFetcher, blobs *fakeBlobStore) *application.GraphResolver {
	return application.NewGraphResolver(
		xmod.New(),
		fetcher,
		blobs,
		fixedClock{fixedNow},
		"",
		slog.New(slog.NewTextHandler(io.Discard, nil)),
	)
}

// diamondFetcher builds a multi-level graph with a shared dependency selected by
// MVS to its higher version, exercising the version-bump and expansion paths
// whose order the per-level concurrency must not perturb.
//
//	target → a, b, c (direct)
//	a → shared@v1.0.0
//	b → shared@v1.5.0   (MVS selects v1.5.0)
//	c → leaf
//	shared@v1.5.0 → deep
func diamondFetcher(t *testing.T) (*fakeModuleFetcher, *fakeBlobStore) {
	t.Helper()
	blobs := newFakeBlobStore()
	fetcher := newFakeFetcher()
	fetcher.add("example.com/target", "v1.0.0", `module example.com/target
go 1.21
require (
	example.com/a v1.0.0
	example.com/b v1.0.0
	example.com/c v1.0.0
)
`, blobs)
	// a, b, c declare go 1.16 (pre-pruning) so their requirements expand,
	// exercising the expansion-propagation path the per-level concurrency must
	// keep order-stable; shared is then reached via two versions (MVS picks the
	// higher, v1.5.0).
	fetcher.add("example.com/a", "v1.0.0", `module example.com/a
go 1.16
require example.com/shared v1.0.0
`, blobs)
	fetcher.add("example.com/b", "v1.0.0", `module example.com/b
go 1.16
require example.com/shared v1.5.0
`, blobs)
	fetcher.add("example.com/c", "v1.0.0", `module example.com/c
go 1.16
require example.com/leaf v1.0.0
`, blobs)
	fetcher.add("example.com/shared", "v1.0.0", `module example.com/shared
go 1.16
`, blobs)
	fetcher.add("example.com/shared", "v1.5.0", `module example.com/shared
go 1.16
require example.com/deep v1.0.0
`, blobs)
	fetcher.add("example.com/deep", "v1.0.0", `module example.com/deep
go 1.21
`, blobs)
	fetcher.add("example.com/leaf", "v1.0.0", `module example.com/leaf
go 1.21
`, blobs)
	return fetcher, blobs
}

// TestResolve_DeterministicAcrossWorkerCounts proves the per-level fetch
// concurrency does not change the resolved graph: a sequential (workers=1) walk
// and a parallel (workers=8) walk of the same input produce byte-identical
// graphs, so the persisted walk content hash is preserved.
func TestResolve_DeterministicAcrossWorkerCounts(t *testing.T) {
	depth := domain3.StageDepth{MaxDepth: 0, FollowReplace: true, FollowIndirect: true}
	target := coord("example.com/target", "v1.0.0")

	fetcher1, blobs1 := diamondFetcher(t)
	seq, err := newResolverWithFetcher(fetcher1, blobs1).WithWorkers(1).
		Resolve(context.Background(), target, depth)
	if err != nil {
		t.Fatalf("sequential Resolve: %v", err)
	}

	fetcher8, blobs8 := diamondFetcher(t)
	par, err := newResolverWithFetcher(fetcher8, blobs8).WithWorkers(8).
		Resolve(context.Background(), target, depth)
	if err != nil {
		t.Fatalf("parallel Resolve: %v", err)
	}

	if !reflect.DeepEqual(seq, par) {
		t.Fatalf("graph differs between workers=1 and workers=8:\n seq=%+v\n par=%+v", seq, par)
	}

	// Guard against a degenerate "both empty/equal" pass: the MVS-selected
	// shared@v1.5.0 (and its deep child) must be present.
	paths := nodeSet(seq.Nodes)
	for _, want := range []string{
		"example.com/target", "example.com/a", "example.com/b", "example.com/c",
		"example.com/shared", "example.com/deep", "example.com/leaf",
	} {
		if !paths[want] {
			t.Errorf("expected node %q in resolved graph", want)
		}
	}
	for _, n := range seq.Nodes {
		if n.Coordinate.Path == "example.com/shared" && n.Coordinate.Version != "v1.5.0" {
			t.Errorf("shared selected at %s, want v1.5.0 (MVS)", n.Coordinate.Version)
		}
	}
}

// TestResolveProject_BuildListDeterministicAndConcurrent proves the build-list
// fetch loop (project walks) is both order-stable across worker counts and
// genuinely concurrent: a sequential and a parallel resolve produce identical
// graphs, and the parallel resolve overlaps fetches.
func TestResolveProject_BuildListDeterministicAndConcurrent(t *testing.T) {
	target := coord("example.com/project", domain2.LocalVersion)

	// A build list with eight independent fetchable modules off the main module.
	mods := []walkports.BuildListModule{{Path: "example.com/project", Main: true}}
	edges := []walkports.BuildListEdge{}
	build := func() *fakeModuleFetcher {
		blobs := newFakeBlobStore()
		fetcher := newFakeFetcher()
		for _, p := range []string{"a", "b", "c", "d", "e", "f", "g", "h"} {
			fetcher.add("example.com/"+p, "v1.0.0", "module example.com/"+p+"\ngo 1.21\n", blobs)
		}
		return fetcher
	}
	for _, p := range []string{"a", "b", "c", "d", "e", "f", "g", "h"} {
		mods = append(mods, walkports.BuildListModule{Path: "example.com/" + p, Version: "v1.0.0", Indirect: true})
		edges = append(edges, walkports.BuildListEdge{From: "example.com/project", To: "example.com/" + p + "@v1.0.0"})
	}
	bl := &fakeBuildListResolver{list: walkports.BuildList{Modules: mods, Edges: edges}}
	depth := domain3.DefaultDepthPolicy().FetchStage()

	seqFetcher := build()
	seq, err := newResolverWithFetcher(seqFetcher, newFakeBlobStore()).
		WithBuildListResolver(bl).WithWorkers(1).
		ResolveProject(context.Background(), target, nil, "/proj", depth, nil)
	if err != nil {
		t.Fatalf("sequential ResolveProject: %v", err)
	}

	tracker := &concurrencyTracker{inner: build(), delay: 5 * time.Millisecond}
	par, err := newResolverWithFetcher(tracker, newFakeBlobStore()).
		WithBuildListResolver(bl).WithWorkers(8).
		ResolveProject(context.Background(), target, nil, "/proj", depth, nil)
	if err != nil {
		t.Fatalf("parallel ResolveProject: %v", err)
	}

	if !reflect.DeepEqual(seq, par) {
		t.Fatalf("build-list graph differs between workers=1 and workers=8:\n seq=%+v\n par=%+v", seq, par)
	}
	if peak := tracker.peak(); peak < 2 {
		t.Errorf("peak in-flight build-list fetches = %d, want > 1 (should fetch concurrently)", peak)
	}
}

// TestResolve_ParallelFetchOverlaps proves a level's independent modules are
// fetched concurrently when workers > 1: the target's direct deps form one level
// of independent fetches, so the peak in-flight count exceeds one.
func TestResolve_ParallelFetchOverlaps(t *testing.T) {
	blobs := newFakeBlobStore()
	fetcher := newFakeFetcher()
	// target → six independent leaf deps, all discovered in the first level.
	fetcher.add("example.com/target", "v1.0.0", `module example.com/target
go 1.21
require (
	example.com/a v1.0.0
	example.com/b v1.0.0
	example.com/c v1.0.0
	example.com/d v1.0.0
	example.com/e v1.0.0
	example.com/f v1.0.0
)
`, blobs)
	for _, p := range []string{"a", "b", "c", "d", "e", "f"} {
		fetcher.add("example.com/"+p, "v1.0.0", "module example.com/"+p+"\ngo 1.21\n", blobs)
	}

	tracker := &concurrencyTracker{inner: fetcher, delay: 5 * time.Millisecond}
	depth := domain3.StageDepth{MaxDepth: 0, FollowReplace: true, FollowIndirect: true}
	_, err := newResolverWithFetcher(tracker, blobs).WithWorkers(6).
		Resolve(context.Background(), coord("example.com/target", "v1.0.0"), depth)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	if peak := tracker.peak(); peak < 2 {
		t.Errorf("peak in-flight fetches = %d, want > 1 (level should fetch concurrently)", peak)
	}
}

// TestResolve_WorkerLimitRespected proves the bound is honoured: with a level of
// six independent modules and workers=2, no more than two fetches run at once,
// and workers=1 reproduces strictly sequential fetching.
func TestResolve_WorkerLimitRespected(t *testing.T) {
	build := func() (*fakeModuleFetcher, *fakeBlobStore) {
		blobs := newFakeBlobStore()
		fetcher := newFakeFetcher()
		fetcher.add("example.com/target", "v1.0.0", `module example.com/target
go 1.21
require (
	example.com/a v1.0.0
	example.com/b v1.0.0
	example.com/c v1.0.0
	example.com/d v1.0.0
	example.com/e v1.0.0
	example.com/f v1.0.0
)
`, blobs)
		for _, p := range []string{"a", "b", "c", "d", "e", "f"} {
			fetcher.add("example.com/"+p, "v1.0.0", "module example.com/"+p+"\ngo 1.21\n", blobs)
		}
		return fetcher, blobs
	}
	depth := domain3.StageDepth{MaxDepth: 0, FollowReplace: true, FollowIndirect: true}
	target := coord("example.com/target", "v1.0.0")

	t.Run("bounded at 2", func(t *testing.T) {
		fetcher, blobs := build()
		tracker := &concurrencyTracker{inner: fetcher, delay: 5 * time.Millisecond}
		if _, err := newResolverWithFetcher(tracker, blobs).WithWorkers(2).
			Resolve(context.Background(), target, depth); err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if peak := tracker.peak(); peak > 2 {
			t.Errorf("peak in-flight fetches = %d, want ≤ 2 (worker bound)", peak)
		}
	})

	t.Run("workers=1 is sequential", func(t *testing.T) {
		fetcher, blobs := build()
		tracker := &concurrencyTracker{inner: fetcher, delay: 2 * time.Millisecond}
		if _, err := newResolverWithFetcher(tracker, blobs).WithWorkers(1).
			Resolve(context.Background(), target, depth); err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if peak := tracker.peak(); peak != 1 {
			t.Errorf("peak in-flight fetches = %d, want exactly 1 (sequential)", peak)
		}
	})
}
