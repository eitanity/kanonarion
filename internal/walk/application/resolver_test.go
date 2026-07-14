package application_test

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	domain2 "github.com/eitanity/kanonarion/internal/fetch/domain"
	fetchports "github.com/eitanity/kanonarion/internal/fetch/ports"
	"github.com/eitanity/kanonarion/internal/walk/adapters/gomod/xmod"
	"github.com/eitanity/kanonarion/internal/walk/application"
	domain3 "github.com/eitanity/kanonarion/internal/walk/domain"
	walkports "github.com/eitanity/kanonarion/internal/walk/ports"
)

// ---- test helpers ----

var fixedNow = time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

func coord(path, version string) domain2.ModuleCoordinate {
	return domain2.ModuleCoordinate{Path: path, Version: version}
}

// makeFactRecord builds a minimal FactRecord whose ContentLocation is "path@version".
func makeFactRecord(path, version string) domain2.FactRecord {
	return domain2.FactRecord{
		SchemaVersion:   "2",
		ModulePath:      path,
		ModuleVersion:   version,
		ContentLocation: path + "@" + version,
		PipelineVersion: "1.0.0",
	}
}

// ---- fake implementations ----

type fakeModuleFetcher struct {
	records map[string]domain2.FactRecord
	errors  map[string]error
}

func newFakeFetcher() *fakeModuleFetcher {
	return &fakeModuleFetcher{
		records: make(map[string]domain2.FactRecord),
		errors:  make(map[string]error),
	}
}

func (f *fakeModuleFetcher) add(path, version, goModContent string, blobs *fakeBlobStore) {
	c := coord(path, version)
	rec := makeFactRecord(path, version)
	f.records[c.String()] = rec
	blobs.data[path+"@"+version] = buildFakeZip(path, version, goModContent)
}

func (f *fakeModuleFetcher) addRetracted(path, version, goModContent string, blobs *fakeBlobStore) {
	c := coord(path, version)
	rec := makeFactRecord(path, version)
	rec.Retracted = true
	f.records[c.String()] = rec
	blobs.data[path+"@"+version] = buildFakeZip(path, version, goModContent)
}

func (f *fakeModuleFetcher) addError(path, version string, err error) {
	f.errors[coord(path, version).String()] = err
}

func (f *fakeModuleFetcher) EnsureFetched(_ context.Context, c domain2.ModuleCoordinate) (walkports.ModuleFetchResult, error) {
	key := c.String()
	if err, ok := f.errors[key]; ok {
		return walkports.ModuleFetchResult{}, err
	}
	if rec, ok := f.records[key]; ok {
		return walkports.ModuleFetchResult{Record: rec}, nil
	}
	return walkports.ModuleFetchResult{}, fmt.Errorf("no fake record for %s", key)
}

// buildFakeZip is a test helper that builds a minimal zip for a given module.
func buildFakeZip(path, version, goModContent string) []byte {
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	f, err := w.Create(path + "@" + version + "/go.mod")
	if err != nil {
		panic(fmt.Sprintf("buildFakeZip: %v", err))
	}
	if _, err := io.WriteString(f, goModContent); err != nil {
		panic(fmt.Sprintf("buildFakeZip write: %v", err))
	}
	if err := w.Close(); err != nil {
		panic(fmt.Sprintf("buildFakeZip close: %v", err))
	}
	return buf.Bytes()
}

type fakeBlobStore struct {
	data map[string][]byte
}

func newFakeBlobStore() *fakeBlobStore {
	return &fakeBlobStore{data: make(map[string][]byte)}
}

func (b *fakeBlobStore) Put(_ context.Context, _ io.Reader) (fetchports.BlobHandle, error) {
	return "", errors.New("fakeBlobStore.Put not implemented")
}

func (b *fakeBlobStore) Get(_ context.Context, handle fetchports.BlobHandle) (io.ReadCloser, error) {
	d, ok := b.data[string(handle)]
	if !ok {
		return nil, fmt.Errorf("blob not found: %s", handle)
	}
	return io.NopCloser(bytes.NewReader(d)), nil
}

func (b *fakeBlobStore) Exists(_ context.Context, handle fetchports.BlobHandle) (bool, error) {
	_, ok := b.data[string(handle)]
	return ok, nil
}

func (b *fakeBlobStore) GetPath(_ context.Context, handle fetchports.BlobHandle) (string, error) {
	_, ok := b.data[string(handle)]
	if !ok {
		return "", fmt.Errorf("blob not found: %s", handle)
	}
	return "/fake/path/" + string(handle), nil
}

type fixedClock struct{ t time.Time }

func (c fixedClock) Now() time.Time { return c.t }

// fakeStopwatch is a deterministic ports.Stopwatch: every lap reports d.
type fakeStopwatch struct{ d time.Duration }

func (s fakeStopwatch) Start() fetchports.Lap { return fakeLap(s) }

type fakeLap struct{ d time.Duration }

func (l fakeLap) Elapsed() time.Duration { return l.d }

func newResolver(fetcher *fakeModuleFetcher, blobs *fakeBlobStore) *application.GraphResolver {
	return application.NewGraphResolver(
		xmod.New(),
		fetcher,
		blobs,
		fixedClock{fixedNow},
		"",
		slog.New(slog.NewTextHandler(io.Discard, nil)),
	)
}

// countingParser wraps a real GoModParser and counts how many times Parse is
// called. Used to verify that each go.mod is parsed at most once per resolve.
// The counter is mutex-guarded because the resolver now parses a BFS level's
// go.mods concurrently.
type countingParser struct {
	inner walkports.GoModParser
	mu    sync.Mutex
	calls int
}

func newCountingParser() *countingParser {
	return &countingParser{inner: xmod.New()}
}

func (p *countingParser) Parse(filename string, data []byte) (domain3.ParsedGoMod, error) {
	p.mu.Lock()
	p.calls++
	p.mu.Unlock()
	out, err := p.inner.Parse(filename, data)
	if err != nil {
		return domain3.ParsedGoMod{}, fmt.Errorf("countingParser: %w", err)
	}
	return out, nil
}

// callCount returns the number of Parse calls observed so far.
func (p *countingParser) callCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.calls
}

func newResolverWithParser(parser walkports.GoModParser, fetcher *fakeModuleFetcher, blobs *fakeBlobStore) *application.GraphResolver {
	return application.NewGraphResolver(
		parser,
		fetcher,
		blobs,
		fixedClock{fixedNow},
		"",
		slog.New(slog.NewTextHandler(io.Discard, nil)),
	)
}

// ---- actual tests ----

func TestResolve_noDependencies(t *testing.T) {
	blobs := newFakeBlobStore()
	fetcher := newFakeFetcher()
	fetcher.add("example.com/target", "v1.0.0", `module example.com/target

go 1.21
`, blobs)

	r := newResolver(fetcher, blobs)
	g, err := r.Resolve(context.Background(), coord("example.com/target", "v1.0.0"), domain3.DefaultDepthPolicy().FetchStage())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(g.Nodes) != 1 {
		t.Errorf("node count = %d, want 1", len(g.Nodes))
	}
	if len(g.Edges) != 0 {
		t.Errorf("edge count = %d, want 0", len(g.Edges))
	}
	if g.Partial {
		t.Errorf("graph should not be partial")
	}
	if g.Nodes[0].Coordinate.String() != "example.com/target@v1.0.0" {
		t.Errorf("target node = %q", g.Nodes[0].Coordinate.String())
	}
	if g.Nodes[0].ResolutionSource != domain3.ResolutionTarget {
		t.Errorf("target node source = %q", g.Nodes[0].ResolutionSource)
	}
}

func TestResolve_singleDirectDependency(t *testing.T) {
	blobs := newFakeBlobStore()
	fetcher := newFakeFetcher()
	fetcher.add("example.com/target", "v1.0.0", `module example.com/target

go 1.21

require github.com/dep/one v1.2.3
`, blobs)
	fetcher.add("github.com/dep/one", "v1.2.3", `module github.com/dep/one

go 1.21
`, blobs)

	r := newResolver(fetcher, blobs)
	g, err := r.Resolve(context.Background(), coord("example.com/target", "v1.0.0"), domain3.DefaultDepthPolicy().FetchStage())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(g.Nodes) != 2 {
		t.Errorf("node count = %d, want 2", len(g.Nodes))
	}
	if len(g.Edges) != 1 {
		t.Errorf("edge count = %d, want 1", len(g.Edges))
	}
	if g.Partial {
		t.Errorf("graph should not be partial")
	}

	depNode := findNode(t, g.Nodes, "github.com/dep/one")
	if !depNode.DirectDependency {
		t.Error("dep should be a direct dependency")
	}
}

func TestResolve_carriesDigestsToNodes(t *testing.T) {
	blobs := newFakeBlobStore()
	fetcher := newFakeFetcher()
	fetcher.add("example.com/target", "v1.0.0", `module example.com/target

go 1.21

require github.com/dep/one v1.2.3
`, blobs)
	// The dependency's fact record carries artefact digests; the resolver must
	// copy them onto the graph node so the SBOM can emit component hashes.
	depRec := makeFactRecord("github.com/dep/one", "v1.2.3")
	depRec.ZipSHA256 = "dep256"
	depRec.ZipSHA384 = "dep384"
	depRec.ZipSHA512 = "dep512"
	fetcher.records[coord("github.com/dep/one", "v1.2.3").String()] = depRec
	blobs.data["github.com/dep/one@v1.2.3"] = buildFakeZip("github.com/dep/one", "v1.2.3", "module github.com/dep/one\n\ngo 1.21\n")

	r := newResolver(fetcher, blobs)
	g, err := r.Resolve(context.Background(), coord("example.com/target", "v1.0.0"), domain3.DefaultDepthPolicy().FetchStage())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	depNode := findNode(t, g.Nodes, "github.com/dep/one")
	want := domain2.ArtifactDigests{SHA256: "dep256", SHA384: "dep384", SHA512: "dep512"}
	if depNode.Digests != want {
		t.Errorf("dep node digests = %+v, want %+v", depNode.Digests, want)
	}
	// The target record has no digests, so its node stays zero (no fabricated hashes).
	targetNode := findNode(t, g.Nodes, "example.com/target")
	if !targetNode.Digests.IsZero() {
		t.Errorf("target node digests = %+v, want zero", targetNode.Digests)
	}
}

func TestResolve_diamond_MVS(t *testing.T) {
	// A(target) → B@v1.0, C@v1.0
	// B@v1.0 → D@v1.1
	// C@v1.0 → D@v1.2
	// MVS selects D@v1.2
	blobs := newFakeBlobStore()
	fetcher := newFakeFetcher()
	fetcher.add("example.com/a", "v1.0.0", `module example.com/a

go 1.21

require (
	example.com/b v1.0.0
	example.com/c v1.0.0
)
`, blobs)
	fetcher.add("example.com/b", "v1.0.0", `module example.com/b

go 1.21

require example.com/d v1.1.0
`, blobs)
	fetcher.add("example.com/c", "v1.0.0", `module example.com/c

go 1.21

require example.com/d v1.2.0
`, blobs)
	fetcher.add("example.com/d", "v1.1.0", `module example.com/d

go 1.21
`, blobs)
	fetcher.add("example.com/d", "v1.2.0", `module example.com/d

go 1.21
`, blobs)

	r := newResolver(fetcher, blobs)
	g, err := r.Resolve(context.Background(), coord("example.com/a", "v1.0.0"), domain3.DefaultDepthPolicy().FetchStage())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	if len(g.Nodes) != 4 {
		t.Errorf("node count = %d, want 4 (a,b,c,d)", len(g.Nodes))
	}
	if g.Partial {
		t.Errorf("graph should not be partial")
	}

	// D should appear exactly once, at MVS-selected v1.2.0.
	dNode := findNode(t, g.Nodes, "example.com/d")
	if dNode.Coordinate.Version != "v1.2.0" {
		t.Errorf("D version = %q, want v1.2.0 (MVS)", dNode.Coordinate.Version)
	}

	// Two edges pointing to D (from B and from C), both with To.Version = v1.2.0.
	dEdges := edgesTo(g.Edges, "example.com/d")
	if len(dEdges) != 2 {
		t.Errorf("edges to D = %d, want 2", len(dEdges))
	}
	for _, e := range dEdges {
		if e.To.Version != "v1.2.0" {
			t.Errorf("edge to D has To.Version=%q, want v1.2.0", e.To.Version)
		}
	}
}

func TestResolve_mvsVersionBump(t *testing.T) {
	// A → B@v1.0, B@v1.1 (direct, listed twice via two requires)
	// MVS selects B@v1.1
	blobs := newFakeBlobStore()
	fetcher := newFakeFetcher()
	fetcher.add("example.com/a", "v1.0.0", `module example.com/a

go 1.21

require (
	example.com/b v1.0.0
	example.com/c v1.0.0
)
`, blobs)
	fetcher.add("example.com/b", "v1.0.0", `module example.com/b

go 1.21

require example.com/c v1.1.0
`, blobs)
	fetcher.add("example.com/c", "v1.0.0", `module example.com/c

go 1.21
`, blobs)
	fetcher.add("example.com/c", "v1.1.0", `module example.com/c

go 1.21
`, blobs)

	r := newResolver(fetcher, blobs)
	g, err := r.Resolve(context.Background(), coord("example.com/a", "v1.0.0"), domain3.DefaultDepthPolicy().FetchStage())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	cNode := findNode(t, g.Nodes, "example.com/c")
	if cNode.Coordinate.Version != "v1.1.0" {
		t.Errorf("C version = %q, want v1.1.0 (MVS bump)", cNode.Coordinate.Version)
	}
}

func TestResolve_replaceDirective(t *testing.T) {
	// Target replaces old/pkg v1.0.0 → new/pkg v1.1.0
	blobs := newFakeBlobStore()
	fetcher := newFakeFetcher()
	fetcher.add("example.com/target", "v1.0.0", `module example.com/target

go 1.21

require github.com/old/pkg v1.0.0

replace github.com/old/pkg v1.0.0 => github.com/new/pkg v1.1.0
`, blobs)
	fetcher.add("github.com/new/pkg", "v1.1.0", `module github.com/new/pkg

go 1.21
`, blobs)

	r := newResolver(fetcher, blobs)
	g, err := r.Resolve(context.Background(), coord("example.com/target", "v1.0.0"), domain3.DefaultDepthPolicy().FetchStage())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	// old/pkg should not be in the graph; new/pkg should be.
	for _, n := range g.Nodes {
		if n.Coordinate.Path == "github.com/old/pkg" {
			t.Error("old/pkg should not be in graph after replace")
		}
	}
	newNode := findNode(t, g.Nodes, "github.com/new/pkg")
	if newNode.Coordinate.Version != "v1.1.0" {
		t.Errorf("new/pkg version = %q, want v1.1.0", newNode.Coordinate.Version)
	}
}

func TestResolve_excludeDirective(t *testing.T) {
	// Target excludes dep/b v1.0.0 — it should not appear in the graph.
	blobs := newFakeBlobStore()
	fetcher := newFakeFetcher()
	fetcher.add("example.com/target", "v1.0.0", `module example.com/target

go 1.21

require (
	example.com/a v1.0.0
	example.com/b v1.0.0
)

exclude example.com/b v1.0.0
`, blobs)
	fetcher.add("example.com/a", "v1.0.0", `module example.com/a

go 1.21
`, blobs)

	r := newResolver(fetcher, blobs)
	g, err := r.Resolve(context.Background(), coord("example.com/target", "v1.0.0"), domain3.DefaultDepthPolicy().FetchStage())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	for _, n := range g.Nodes {
		if n.Coordinate.Path == "example.com/b" {
			t.Error("excluded module b should not be in graph")
		}
	}
}

func TestResolve_fetchFailedTransitive(t *testing.T) {
	// One transitive dep fails to fetch — graph is partial but other deps complete.
	blobs := newFakeBlobStore()
	fetcher := newFakeFetcher()
	fetcher.add("example.com/target", "v1.0.0", `module example.com/target

go 1.21

require (
	example.com/good v1.0.0
	example.com/bad v1.0.0
)
`, blobs)
	fetcher.add("example.com/good", "v1.0.0", `module example.com/good

go 1.21
`, blobs)
	fetcher.addError("example.com/bad", "v1.0.0", errors.New("simulated fetch failure"))

	r := newResolver(fetcher, blobs)
	g, err := r.Resolve(context.Background(), coord("example.com/target", "v1.0.0"), domain3.DefaultDepthPolicy().FetchStage())
	if err != nil {
		t.Fatalf("Resolve should not fail on transitive error: %v", err)
	}
	if !g.Partial {
		t.Error("graph should be partial when a dep fails")
	}

	badNode := findNode(t, g.Nodes, "example.com/bad")
	if badNode.ResolutionSource != domain3.ResolutionFetchFailed {
		t.Errorf("bad node source = %q, want fetch_failed", badNode.ResolutionSource)
	}
	if badNode.ErrorDetail == "" {
		t.Error("bad node should have non-empty ErrorDetail")
	}

	// Good dep should still be in the graph.
	findNode(t, g.Nodes, "example.com/good")
}

func TestResolve_parseFailedTransitive(t *testing.T) {
	// A transitive dep's zip has a malformed go.mod — graph is partial.
	blobs := newFakeBlobStore()
	fetcher := newFakeFetcher()
	fetcher.add("example.com/target", "v1.0.0", `module example.com/target

go 1.21

require example.com/bad v1.0.0
`, blobs)
	// Register a FactRecord but put invalid go.mod content in the zip.
	rec := makeFactRecord("example.com/bad", "v1.0.0")
	fetcher.records["example.com/bad@v1.0.0"] = rec
	blobs.data["example.com/bad@v1.0.0"] = buildFakeZip("example.com/bad", "v1.0.0", "this is not valid go.mod ;;;")

	r := newResolver(fetcher, blobs)
	g, err := r.Resolve(context.Background(), coord("example.com/target", "v1.0.0"), domain3.DefaultDepthPolicy().FetchStage())
	if err != nil {
		t.Fatalf("Resolve should not fail on transitive parse error: %v", err)
	}
	if !g.Partial {
		t.Error("graph should be partial when a dep go.mod fails to parse")
	}

	badNode := findNode(t, g.Nodes, "example.com/bad")
	if badNode.ResolutionSource != domain3.ResolutionParseFailed {
		t.Errorf("bad node source = %q, want parse_failed", badNode.ResolutionSource)
	}
}

func TestResolve_targetFetchFails(t *testing.T) {
	blobs := newFakeBlobStore()
	fetcher := newFakeFetcher()
	fetcher.addError("example.com/target", "v1.0.0", errors.New("target fetch error"))

	r := newResolver(fetcher, blobs)
	_, err := r.Resolve(context.Background(), coord("example.com/target", "v1.0.0"), domain3.DefaultDepthPolicy().FetchStage())
	if err == nil {
		t.Fatal("expected error when target fetch fails")
	}
	if !strings.Contains(err.Error(), "target fetch error") {
		t.Errorf("error = %q, want to contain 'target fetch error'", err.Error())
	}
}

func TestResolve_contextCancellation(t *testing.T) {
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
	// Add only the target — other deps have no records; context will be
	// cancelled before they're processed.
	fetcher.add("example.com/a", "v1.0.0", `module example.com/a

go 1.21
`, blobs)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately so no transitive fetches happen

	r := newResolver(fetcher, blobs)
	g, err := r.Resolve(ctx, coord("example.com/target", "v1.0.0"), domain3.DefaultDepthPolicy().FetchStage())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if !g.Partial {
		t.Error("cancelled graph should be partial")
	}
	if g.PartialReason != "cancelled" {
		t.Errorf("PartialReason = %q, want 'cancelled'", g.PartialReason)
	}
}

func TestResolve_deterministic(t *testing.T) {
	// Running the same resolution twice must produce byte-identical node/edge ordering.
	blobs := newFakeBlobStore()
	fetcher := newFakeFetcher()
	fetcher.add("example.com/target", "v1.0.0", `module example.com/target

go 1.21

require (
	example.com/c v1.0.0
	example.com/a v1.0.0
	example.com/b v1.0.0
)
`, blobs)
	for _, mod := range []string{"a", "b", "c"} {
		fetcher.add("example.com/"+mod, "v1.0.0",
			"module example.com/"+mod+"\n\ngo 1.21\n", blobs)
	}

	r := newResolver(fetcher, blobs)
	g1, err := r.Resolve(context.Background(), coord("example.com/target", "v1.0.0"), domain3.DefaultDepthPolicy().FetchStage())
	if err != nil {
		t.Fatalf("first Resolve: %v", err)
	}
	g2, err := r.Resolve(context.Background(), coord("example.com/target", "v1.0.0"), domain3.DefaultDepthPolicy().FetchStage())
	if err != nil {
		t.Fatalf("second Resolve: %v", err)
	}

	if len(g1.Nodes) != len(g2.Nodes) {
		t.Fatalf("node counts differ: %d vs %d", len(g1.Nodes), len(g2.Nodes))
	}
	for i := range g1.Nodes {
		if g1.Nodes[i].Coordinate != g2.Nodes[i].Coordinate {
			t.Errorf("node[%d] differs: %v vs %v", i, g1.Nodes[i].Coordinate, g2.Nodes[i].Coordinate)
		}
	}
}

// A fetched target's own filesystem replace directives are development-time
// artefacts: Go ignores a dependency module's replaces, and the local target is
// absent from the published module zip. The resolver must ignore them and
// resolve the required module normally from the proxy — never strand a
// fetchable, scannable dependency as an unanalysable local-replace node.
func TestResolve_FetchedTargetLocalReplaceIgnored(t *testing.T) {
	blobs := newFakeBlobStore()
	fetcher := newFakeFetcher()
	fetcher.add("example.com/target", "v1.0.0", `module example.com/target

go 1.21

require example.com/dep v1.0.0

replace example.com/dep => ./local/dep
`, blobs)
	fetcher.add("example.com/dep", "v1.0.0", `module example.com/dep

go 1.21
`, blobs)

	r := newResolver(fetcher, blobs)
	g, err := r.Resolve(context.Background(), coord("example.com/target", "v1.0.0"), domain3.DefaultDepthPolicy().FetchStage())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if g.HasLocalReplace {
		t.Error("a fetched target's local replace must be ignored; HasLocalReplace should be false")
	}
	dep := findNode(t, g.Nodes, "example.com/dep")
	if dep.ResolutionSource != domain3.ResolutionMVS {
		t.Errorf("dep ResolutionSource = %q, want mvs (resolved from proxy, not local_replace)", dep.ResolutionSource)
	}
	if dep.LocalPath != "" {
		t.Errorf("dep LocalPath = %q, want empty", dep.LocalPath)
	}
}

// Regression for the otel multi-module shape: a published module member whose
// go.mod carries `replace <sibling> => ../` (as go.opentelemetry.io/otel/trace
// does) must not strand the sibling as a local-replace node. The sibling is a
// normal, fetchable proxy module and must resolve via MVS.
func TestResolve_FetchedTargetSiblingReplaceResolvesFromProxy(t *testing.T) {
	blobs := newFakeBlobStore()
	fetcher := newFakeFetcher()
	fetcher.add("example.com/otel/trace", "v1.41.0", `module example.com/otel/trace

go 1.24

require example.com/otel v1.41.0

replace example.com/otel => ../
`, blobs)
	fetcher.add("example.com/otel", "v1.41.0", "module example.com/otel\n\ngo 1.24\n", blobs)

	r := newResolver(fetcher, blobs)
	g, err := r.Resolve(context.Background(), coord("example.com/otel/trace", "v1.41.0"), domain3.DefaultDepthPolicy().FetchStage())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	sib := findNode(t, g.Nodes, "example.com/otel")
	if sib.ResolutionSource != domain3.ResolutionMVS {
		t.Errorf("sibling ResolutionSource = %q, want mvs (fetched from proxy)", sib.ResolutionSource)
	}
	if sib.LocalPath != "" {
		t.Errorf("sibling LocalPath = %q, want empty", sib.LocalPath)
	}
	if g.HasLocalReplace {
		t.Error("HasLocalReplace should be false when the only replace is a fetched target's own local replace")
	}
}

func TestResolve_retractedDepRecorded(t *testing.T) {
	blobs := newFakeBlobStore()
	fetcher := newFakeFetcher()
	fetcher.add("example.com/target", "v1.0.0", `module example.com/target

go 1.21

require example.com/dep v1.0.0
`, blobs)
	fetcher.addRetracted("example.com/dep", "v1.0.0", `module example.com/dep

go 1.21
`, blobs)

	r := newResolver(fetcher, blobs)
	g, err := r.Resolve(context.Background(), coord("example.com/target", "v1.0.0"), domain3.DefaultDepthPolicy().FetchStage())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	depNode := findNode(t, g.Nodes, "example.com/dep")
	if !depNode.Retracted {
		t.Error("dep node should be marked as retracted")
	}
}

func TestResolve_graphSorted(t *testing.T) {
	blobs := newFakeBlobStore()
	fetcher := newFakeFetcher()
	fetcher.add("example.com/target", "v1.0.0", `module example.com/target

go 1.21

require (
	z.example.com/z v1.0.0
	a.example.com/a v1.0.0
	m.example.com/m v1.0.0
)
`, blobs)
	for _, p := range []string{"z.example.com/z", "a.example.com/a", "m.example.com/m"} {
		fetcher.add(p, "v1.0.0", "module "+p+"\n\ngo 1.21\n", blobs)
	}

	r := newResolver(fetcher, blobs)
	g, err := r.Resolve(context.Background(), coord("example.com/target", "v1.0.0"), domain3.DefaultDepthPolicy().FetchStage())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	for i := 1; i < len(g.Nodes); i++ {
		prev := g.Nodes[i-1].Coordinate.Path
		curr := g.Nodes[i].Coordinate.Path
		if prev > curr {
			t.Errorf("nodes not sorted: %q > %q at index %d", prev, curr, i)
		}
	}
}

func TestResolve_replaceWildcard(t *testing.T) {
	// Wildcard replace: replace github.com/old/pkg => github.com/new/pkg v1.1.0
	blobs := newFakeBlobStore()
	fetcher := newFakeFetcher()
	fetcher.add("example.com/target", "v1.0.0", `module example.com/target

go 1.21

require github.com/old/pkg v1.0.0

replace github.com/old/pkg => github.com/new/pkg v1.1.0
`, blobs)
	fetcher.add("github.com/new/pkg", "v1.1.0", `module github.com/new/pkg

go 1.21
`, blobs)

	r := newResolver(fetcher, blobs)
	g, err := r.Resolve(context.Background(), coord("example.com/target", "v1.0.0"), domain3.DefaultDepthPolicy().FetchStage())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	for _, n := range g.Nodes {
		if n.Coordinate.Path == "github.com/old/pkg" {
			t.Error("old/pkg should not be in graph after wildcard replace")
		}
	}
	newNode := findNode(t, g.Nodes, "github.com/new/pkg")
	if newNode.Coordinate.Version != "v1.1.0" {
		t.Errorf("new/pkg version = %q, want v1.1.0", newNode.Coordinate.Version)
	}
	if newNode.ResolutionSource != domain3.ResolutionReplace {
		t.Errorf("ResolutionSource = %q, want replace", newNode.ResolutionSource)
	}
}

func TestResolve_multiplePartialReasons(t *testing.T) {
	// One dep fails to fetch, another has an unparseable go.mod.
	// PartialReason should contain both reasons.
	blobs := newFakeBlobStore()
	fetcher := newFakeFetcher()
	fetcher.add("example.com/target", "v1.0.0", `module example.com/target

go 1.21

require (
	example.com/fetchfail v1.0.0
	example.com/parsefail v1.0.0
)
`, blobs)
	fetcher.addError("example.com/fetchfail", "v1.0.0", errors.New("simulated network error"))
	// Register parsefail fact but put invalid go.mod content in the zip.
	rec := makeFactRecord("example.com/parsefail", "v1.0.0")
	fetcher.records["example.com/parsefail@v1.0.0"] = rec
	blobs.data["example.com/parsefail@v1.0.0"] = buildFakeZip("example.com/parsefail", "v1.0.0", "this is not valid go.mod ;;;")

	r := newResolver(fetcher, blobs)
	g, err := r.Resolve(context.Background(), coord("example.com/target", "v1.0.0"), domain3.DefaultDepthPolicy().FetchStage())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if !g.Partial {
		t.Error("graph should be partial")
	}
	if !strings.Contains(g.PartialReason, "fetch_failed") {
		t.Errorf("PartialReason %q should contain fetch_failed", g.PartialReason)
	}
	if !strings.Contains(g.PartialReason, "parse_failed") {
		t.Errorf("PartialReason %q should contain parse_failed", g.PartialReason)
	}
}

func TestResolve_blobMissingForTransitiveDep(t *testing.T) {
	// FactRecord exists for a dep but its blob is missing from the store.
	// The dep should be marked as parse_failed (extractGoMod error).
	blobs := newFakeBlobStore()
	fetcher := newFakeFetcher()
	fetcher.add("example.com/target", "v1.0.0", `module example.com/target

go 1.21

require example.com/dep v1.0.0
`, blobs)
	// Register fact but do NOT add zip to blobs.
	fetcher.records["example.com/dep@v1.0.0"] = makeFactRecord("example.com/dep", "v1.0.0")

	r := newResolver(fetcher, blobs)
	g, err := r.Resolve(context.Background(), coord("example.com/target", "v1.0.0"), domain3.DefaultDepthPolicy().FetchStage())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if !g.Partial {
		t.Error("graph should be partial when blob is missing")
	}
	depNode := findNode(t, g.Nodes, "example.com/dep")
	if depNode.ResolutionSource != domain3.ResolutionParseFailed {
		t.Errorf("ResolutionSource = %q, want parse_failed", depNode.ResolutionSource)
	}
	if depNode.ErrorDetail == "" {
		t.Error("missing blob node should have non-empty ErrorDetail")
	}
}

func TestResolve_directDepAlreadyAtHigherVersion(t *testing.T) {
	// Two direct requires for the same module path; higher version listed first.
	// The lower-version entry triggers the seedDirectDeps default case,
	// which should preserve DirectDependency=true on the node.
	blobs := newFakeBlobStore()
	fetcher := newFakeFetcher()
	// go.mod with duplicate require paths (higher version first, then lower).
	// modfile.Parse allows this; go mod tidy would deduplicate, but real-world
	// go.mod files occasionally contain such entries before tidying.
	fetcher.add("example.com/target", "v1.0.0", `module example.com/target

go 1.21

require (
	example.com/dep v1.2.0
	example.com/dep v1.0.0
)
`, blobs)
	fetcher.add("example.com/dep", "v1.2.0", `module example.com/dep

go 1.21
`, blobs)
	fetcher.add("example.com/dep", "v1.0.0", `module example.com/dep

go 1.21
`, blobs)

	r := newResolver(fetcher, blobs)
	g, err := r.Resolve(context.Background(), coord("example.com/target", "v1.0.0"), domain3.DefaultDepthPolicy().FetchStage())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	depNode := findNode(t, g.Nodes, "example.com/dep")
	if depNode.Coordinate.Version != "v1.2.0" {
		t.Errorf("dep version = %q, want v1.2.0 (MVS)", depNode.Coordinate.Version)
	}
	if !depNode.DirectDependency {
		t.Error("dep should be DirectDependency=true")
	}
}

func TestResolve_directDepLowerThenHigherVersion(t *testing.T) {
	// First require lists v1.0.0, second lists v1.2.0 for the same path.
	// This triggers the versionGT branch in seedDirectDeps.
	blobs := newFakeBlobStore()
	fetcher := newFakeFetcher()
	fetcher.add("example.com/target", "v1.0.0", `module example.com/target

go 1.21

require (
	example.com/dep v1.0.0
	example.com/dep v1.2.0
)
`, blobs)
	fetcher.add("example.com/dep", "v1.0.0", `module example.com/dep

go 1.21
`, blobs)
	fetcher.add("example.com/dep", "v1.2.0", `module example.com/dep

go 1.21
`, blobs)

	r := newResolver(fetcher, blobs)
	g, err := r.Resolve(context.Background(), coord("example.com/target", "v1.0.0"), domain3.DefaultDepthPolicy().FetchStage())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	depNode := findNode(t, g.Nodes, "example.com/dep")
	if depNode.Coordinate.Version != "v1.2.0" {
		t.Errorf("dep version = %q, want v1.2.0 (MVS)", depNode.Coordinate.Version)
	}
	if !depNode.DirectDependency {
		t.Error("dep should be DirectDependency=true")
	}
}

func TestResolve_corruptZipForTransitiveDep(t *testing.T) {
	// A transitive dep's blob contains invalid zip bytes.
	blobs := newFakeBlobStore()
	fetcher := newFakeFetcher()
	fetcher.add("example.com/target", "v1.0.0", `module example.com/target

go 1.21

require example.com/dep v1.0.0
`, blobs)
	rec := makeFactRecord("example.com/dep", "v1.0.0")
	fetcher.records["example.com/dep@v1.0.0"] = rec
	blobs.data["example.com/dep@v1.0.0"] = []byte("this is not a valid zip file")

	r := newResolver(fetcher, blobs)
	g, err := r.Resolve(context.Background(), coord("example.com/target", "v1.0.0"), domain3.DefaultDepthPolicy().FetchStage())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if !g.Partial {
		t.Error("graph should be partial with corrupt zip")
	}
	depNode := findNode(t, g.Nodes, "example.com/dep")
	if depNode.ResolutionSource != domain3.ResolutionParseFailed {
		t.Errorf("source = %q, want parse_failed", depNode.ResolutionSource)
	}
}

func TestResolve_zipWithoutGoMod(t *testing.T) {
	// A transitive dep's zip is valid but contains no go.mod entry.
	blobs := newFakeBlobStore()
	fetcher := newFakeFetcher()
	fetcher.add("example.com/target", "v1.0.0", `module example.com/target

go 1.21

require example.com/dep v1.0.0
`, blobs)
	rec := makeFactRecord("example.com/dep", "v1.0.0")
	fetcher.records["example.com/dep@v1.0.0"] = rec
	// Build a zip that contains something else, but not go.mod.
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	f, err := w.Create("example.com/dep@v1.0.0/README.md")
	if err != nil {
		t.Fatalf("creating zip entry: %v", err)
	}
	if _, err := io.WriteString(f, "readme"); err != nil {
		t.Fatalf("writing zip entry: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("closing zip: %v", err)
	}
	blobs.data["example.com/dep@v1.0.0"] = buf.Bytes()

	r := newResolver(fetcher, blobs)
	g, err := r.Resolve(context.Background(), coord("example.com/target", "v1.0.0"), domain3.DefaultDepthPolicy().FetchStage())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if g.Partial {
		t.Error("graph should not be partial when go.mod absent (pre-module era leaf)")
	}
	depNode := findNode(t, g.Nodes, "example.com/dep")
	if depNode.ResolutionSource != domain3.ResolutionMVS {
		t.Errorf("source = %q, want mvs (no-go.mod treated as leaf)", depNode.ResolutionSource)
	}
	if depNode.ErrorDetail != "" {
		t.Errorf("ErrorDetail should be empty for no-go.mod leaf, got %q", depNode.ErrorDetail)
	}
}

// A version-specific filesystem replace on a fetched target is likewise
// ignored — the dependency resolves from the proxy at its required version.
func TestResolve_FetchedTargetVersionSpecificLocalReplaceIgnored(t *testing.T) {
	blobs := newFakeBlobStore()
	fetcher := newFakeFetcher()
	fetcher.add("example.com/target", "v1.0.0", `module example.com/target

go 1.21

require example.com/dep v1.0.0

replace example.com/dep v1.0.0 => ./local/dep
`, blobs)
	fetcher.add("example.com/dep", "v1.0.0", "module example.com/dep\n\ngo 1.21\n", blobs)

	r := newResolver(fetcher, blobs)
	g, err := r.Resolve(context.Background(), coord("example.com/target", "v1.0.0"), domain3.DefaultDepthPolicy().FetchStage())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	depNode := findNode(t, g.Nodes, "example.com/dep")
	if depNode.ResolutionSource != domain3.ResolutionMVS {
		t.Errorf("ResolutionSource = %q, want mvs (resolved from proxy)", depNode.ResolutionSource)
	}
	if depNode.LocalPath != "" {
		t.Errorf("LocalPath = %q, want empty", depNode.LocalPath)
	}
	if g.HasLocalReplace {
		t.Error("HasLocalReplace should be false for a fetched target")
	}
}

func TestResolve_pipelineVersionDefault(t *testing.T) {
	blobs := newFakeBlobStore()
	fetcher := newFakeFetcher()
	fetcher.add("example.com/target", "v1.0.0", `module example.com/target

go 1.21
`, blobs)

	r := newResolver(fetcher, blobs)
	g, err := r.Resolve(context.Background(), coord("example.com/target", "v1.0.0"), domain3.DefaultDepthPolicy().FetchStage())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if g.PipelineVersion != application.PipelineVersion {
		t.Errorf("PipelineVersion = %q, want %q", g.PipelineVersion, application.PipelineVersion)
	}
}

// ---- depth policy acceptance tests ----

func TestResolve_MaxDepth_Limits_Traversal(t *testing.T) {
	// target → dep1 → dep2 → dep3
	// With MaxDepth=1: target and dep1 are fetched and processed; dep2 is registered
	// from dep1's requires but its go.mod is never parsed; dep3 is never encountered.
	blobs := newFakeBlobStore()
	fetcher := newFakeFetcher()
	fetcher.add("example.com/target", "v1.0.0", `module example.com/target
go 1.21
require example.com/dep1 v1.0.0
`, blobs)
	fetcher.add("example.com/dep1", "v1.0.0", `module example.com/dep1
go 1.21
require example.com/dep2 v1.0.0
`, blobs)
	fetcher.add("example.com/dep2", "v1.0.0", `module example.com/dep2
go 1.21
require example.com/dep3 v1.0.0
`, blobs)

	r := newResolver(fetcher, blobs)
	depth := domain3.StageDepth{MaxDepth: 1, FollowReplace: true, FollowIndirect: true}
	g, err := r.Resolve(context.Background(), coord("example.com/target", "v1.0.0"), depth)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	paths := nodeSet(g.Nodes)
	for _, want := range []string{"example.com/target", "example.com/dep1"} {
		if !paths[want] {
			t.Errorf("expected node %q in graph", want)
		}
	}
	// dep2 is registered (from dep1's requires) but not traversed — no fetch_failed.
	// dep3 is unreachable (dep2's go.mod was never parsed) so it must not appear.
	if paths["example.com/dep3"] {
		t.Error("dep3 should not appear in graph; MaxDepth=1 prevents traversing dep2")
	}
	for _, n := range g.Nodes {
		if n.Coordinate.Path == "example.com/dep2" && n.ResolutionSource == domain3.ResolutionFetchFailed {
			t.Error("dep2 should not be fetch_failed; it was registered but not enqueued for fetch")
		}
	}
}

func TestResolve_FollowIndirect_False_Skips_Indirect(t *testing.T) {
	blobs := newFakeBlobStore()
	fetcher := newFakeFetcher()
	fetcher.add("example.com/target", "v1.0.0", `module example.com/target
go 1.21
require (
	example.com/direct v1.0.0
	example.com/indirect v1.0.0 // indirect
)
`, blobs)
	fetcher.add("example.com/direct", "v1.0.0", `module example.com/direct
go 1.21
`, blobs)
	fetcher.add("example.com/indirect", "v1.0.0", `module example.com/indirect
go 1.21
`, blobs)

	r := newResolver(fetcher, blobs)
	depth := domain3.StageDepth{MaxDepth: 0, FollowReplace: true, FollowIndirect: false}
	g, err := r.Resolve(context.Background(), coord("example.com/target", "v1.0.0"), depth)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	paths := nodeSet(g.Nodes)
	if !paths["example.com/direct"] {
		t.Error("direct dep should be in graph")
	}
	if paths["example.com/indirect"] {
		t.Error("indirect dep should be skipped when FollowIndirect=false")
	}
}

func TestResolve_FollowReplace_False_Ignores_Replace(t *testing.T) {
	blobs := newFakeBlobStore()
	fetcher := newFakeFetcher()
	fetcher.add("example.com/target", "v1.0.0", `module example.com/target
go 1.21
require example.com/dep v1.0.0
replace example.com/dep v1.0.0 => example.com/replacement v2.0.0
`, blobs)
	fetcher.add("example.com/dep", "v1.0.0", `module example.com/dep
go 1.21
`, blobs)
	fetcher.add("example.com/replacement", "v2.0.0", `module example.com/replacement
go 1.21
`, blobs)

	r := newResolver(fetcher, blobs)
	depth := domain3.StageDepth{MaxDepth: 0, FollowReplace: false, FollowIndirect: true}
	g, err := r.Resolve(context.Background(), coord("example.com/target", "v1.0.0"), depth)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	paths := nodeSet(g.Nodes)
	if !paths["example.com/dep"] {
		t.Error("original dep should be in graph when FollowReplace=false")
	}
	if paths["example.com/replacement"] {
		t.Error("replacement should not appear when FollowReplace=false")
	}
}

// ---- test-internal helpers ----

func findNode(t *testing.T, nodes []domain3.GraphNode, path string) domain3.GraphNode {
	t.Helper()
	for _, n := range nodes {
		if n.Coordinate.Path == path {
			return n
		}
	}
	t.Fatalf("node %q not found in graph", path)
	return domain3.GraphNode{} // unreachable
}

func edgesTo(edges []domain3.GraphEdge, path string) []domain3.GraphEdge {
	var result []domain3.GraphEdge
	for _, e := range edges {
		if e.To.Path == path {
			result = append(result, e)
		}
	}
	return result
}

// nodeSet returns a set of module paths present in nodes.
func nodeSet(nodes []domain3.GraphNode) map[string]bool {
	m := make(map[string]bool, len(nodes))
	for _, n := range nodes {
		m[n.Coordinate.Path] = true
	}
	return m
}

// ---- ResolveShallow tests ----

func TestResolveShallow_OnlyFetchesTarget(t *testing.T) {
	blobs := newFakeBlobStore()
	fetcher := newFakeFetcher()
	fetcher.add("example.com/target", "v1.0.0", `module example.com/target

go 1.21

require (
	github.com/dep/one v1.2.3
	github.com/dep/other v1.5.0
)
`, blobs)
	// Do NOT add dep/one or dep/other to fetcher; ResolveShallow must not fetch them.

	r := newResolver(fetcher, blobs)
	_, err := r.ResolveShallow(context.Background(), coord("example.com/target", "v1.0.0"))
	if err != nil {
		t.Fatalf("ResolveShallow: %v", err)
	}

	// Only the target should have been fetched.
	if len(fetcher.records) != 1 {
		t.Errorf("fetcher has %d records after ResolveShallow, want 1 (target only)", len(fetcher.records))
	}
}

func TestResolveShallow_GraphIsPartial(t *testing.T) {
	blobs := newFakeBlobStore()
	fetcher := newFakeFetcher()
	fetcher.add("example.com/target", "v1.0.0", `module example.com/target

go 1.21

require github.com/dep/one v1.2.3
`, blobs)

	r := newResolver(fetcher, blobs)
	g, err := r.ResolveShallow(context.Background(), coord("example.com/target", "v1.0.0"))
	if err != nil {
		t.Fatalf("ResolveShallow: %v", err)
	}

	if !g.Partial {
		t.Error("graph should be marked Partial")
	}
	if g.PartialReason != "shallow" {
		t.Errorf("PartialReason = %q, want %q", g.PartialReason, "shallow")
	}
}

func TestResolveShallow_IncludesDirectRequires(t *testing.T) {
	blobs := newFakeBlobStore()
	fetcher := newFakeFetcher()
	fetcher.add("example.com/target", "v1.0.0", `module example.com/target

go 1.21

require (
	github.com/dep/one v1.2.3
	github.com/dep/other v1.5.0
)
`, blobs)

	r := newResolver(fetcher, blobs)
	g, err := r.ResolveShallow(context.Background(), coord("example.com/target", "v1.0.0"))
	if err != nil {
		t.Fatalf("ResolveShallow: %v", err)
	}

	// Target + 2 direct deps = 3 nodes.
	if len(g.Nodes) != 3 {
		t.Errorf("node count = %d, want 3 (target + 2 deps)", len(g.Nodes))
	}
	ns := nodeSet(g.Nodes)
	for _, want := range []string{"example.com/target", "github.com/dep/one", "github.com/dep/other"} {
		if !ns[want] {
			t.Errorf("missing node %q", want)
		}
	}
}

func TestResolveShallow_NoDependencies(t *testing.T) {
	blobs := newFakeBlobStore()
	fetcher := newFakeFetcher()
	fetcher.add("example.com/target", "v1.0.0", `module example.com/target

go 1.21
`, blobs)

	r := newResolver(fetcher, blobs)
	g, err := r.ResolveShallow(context.Background(), coord("example.com/target", "v1.0.0"))
	if err != nil {
		t.Fatalf("ResolveShallow: %v", err)
	}

	if len(g.Nodes) != 1 {
		t.Errorf("node count = %d, want 1 (target only)", len(g.Nodes))
	}
	if g.Nodes[0].Coordinate.String() != "example.com/target@v1.0.0" {
		t.Errorf("unexpected node: %q", g.Nodes[0].Coordinate)
	}
	if !g.Partial {
		t.Error("graph should be marked Partial even with no deps")
	}
}

// a non-local replace now records the original require coordinate so
// downstream stages can distinguish the require from the replacement.
func TestResolve_replacePreservesOriginalCoordinate(t *testing.T) {
	blobs := newFakeBlobStore()
	fetcher := newFakeFetcher()
	fetcher.add("example.com/target", "v1.0.0", `module example.com/target

go 1.21

require example.com/dep v1.0.0

replace example.com/dep v1.0.0 => example.com/fork v2.0.0
`, blobs)
	fetcher.add("example.com/fork", "v2.0.0", `module example.com/fork

go 1.21
`, blobs)

	r := newResolver(fetcher, blobs)
	g, err := r.Resolve(context.Background(), coord("example.com/target", "v1.0.0"), domain3.DefaultDepthPolicy().FetchStage())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	forkNode := findNode(t, g.Nodes, "example.com/fork")
	if forkNode.ResolutionSource != domain3.ResolutionReplace {
		t.Errorf("ResolutionSource = %q, want replace", forkNode.ResolutionSource)
	}
	if forkNode.OriginalCoordinate.Path != "example.com/dep" || forkNode.OriginalCoordinate.Version != "v1.0.0" {
		t.Errorf("OriginalCoordinate = %v, want example.com/dep@v1.0.0", forkNode.OriginalCoordinate)
	}
}

// A local main module's filesystem replace produces a graph node + edge instead
// of being silently dropped. The node carries ResolutionLocalReplace, the local
// path, and the original require coordinate. Unlike a fetched target, the
// working tree is present, so these replaces are authoritative and honoured.
func TestResolveProject_LocalReplaceProducesNode(t *testing.T) {
	blobs := newFakeBlobStore()
	fetcher := newFakeFetcher()

	mainGoMod := `module example.com/project

go 1.21

require example.com/dep v1.0.0

replace example.com/dep => ../local/dep
`

	r := newResolver(fetcher, blobs)
	g, err := r.ResolveProject(context.Background(), coord("example.com/project", domain2.LocalVersion), []byte(mainGoMod), "/proj", domain3.DefaultDepthPolicy().FetchStage(), nil, false, false)
	if err != nil {
		t.Fatalf("ResolveProject: %v", err)
	}
	depNode := findNode(t, g.Nodes, "example.com/dep")
	if depNode.ResolutionSource != domain3.ResolutionLocalReplace {
		t.Errorf("ResolutionSource = %q, want local_replace", depNode.ResolutionSource)
	}
	if depNode.LocalPath != "../local/dep" {
		t.Errorf("LocalPath = %q, want ../local/dep", depNode.LocalPath)
	}
	if depNode.OriginalCoordinate.Path != "example.com/dep" || depNode.OriginalCoordinate.Version != "v1.0.0" {
		t.Errorf("OriginalCoordinate = %v, want example.com/dep@v1.0.0", depNode.OriginalCoordinate)
	}
	var found bool
	for _, e := range g.Edges {
		if e.From.Path == "example.com/project" && e.To.Path == "example.com/dep" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected project -> example.com/dep edge for local-replace node")
	}
	if !g.HasLocalReplace {
		t.Error("HasLocalReplace should be true")
	}
}

func TestResolveShallow_TargetFetchError(t *testing.T) {
	blobs := newFakeBlobStore()
	fetcher := newFakeFetcher()
	fetcher.addError("example.com/target", "v1.0.0", errors.New("proxy unavailable"))

	r := newResolver(fetcher, blobs)
	_, err := r.ResolveShallow(context.Background(), coord("example.com/target", "v1.0.0"))
	if err == nil {
		t.Fatal("expected error for target fetch failure, got nil")
	}
}

// TestResolveProject_RootIdentityAndClosure verifies that ResolveProject roots
// the graph at the local main module (version=local, ResolutionLocalMainModule)
// without fetching it, and resolves the union closure of every require entry.
func TestResolveProject_RootIdentityAndClosure(t *testing.T) {
	blobs := newFakeBlobStore()
	fetcher := newFakeFetcher()
	fetcher.add("example.com/dep/one", "v1.2.3", `module example.com/dep/one

go 1.21

require example.com/dep/two v0.5.0
`, blobs)
	fetcher.add("example.com/dep/two", "v0.5.0", `module example.com/dep/two

go 1.21
`, blobs)

	mainGoMod := []byte(`module example.com/project

go 1.21

require example.com/dep/one v1.2.3
`)
	target := coord("example.com/project", domain2.LocalVersion)

	r := newResolver(fetcher, blobs)
	g, err := r.ResolveProject(context.Background(), target, mainGoMod, "", domain3.DefaultDepthPolicy().FetchStage(), nil, false, false)
	if err != nil {
		t.Fatalf("ResolveProject: %v", err)
	}
	if g.Partial {
		t.Errorf("graph should not be partial: %s", g.PartialReason)
	}
	if g.Target != target {
		t.Errorf("graph target = %s, want %s", g.Target, target)
	}

	// Root node: local main module, unfetched, never marked as a fetched target.
	var root domain3.GraphNode
	foundRoot := false
	byPath := map[string]domain3.GraphNode{}
	for _, n := range g.Nodes {
		byPath[n.Coordinate.Path] = n
		if n.Coordinate == target {
			root, foundRoot = n, true
		}
	}
	if !foundRoot {
		t.Fatalf("main module node %s absent", target)
	}
	if root.ResolutionSource != domain3.ResolutionLocalMainModule {
		t.Errorf("root source = %s, want local_main_module", root.ResolutionSource)
	}

	// Closure: direct require plus its transitive dependency.
	if _, ok := byPath["example.com/dep/one"]; !ok {
		t.Errorf("direct require example.com/dep/one missing from closure")
	}
	if _, ok := byPath["example.com/dep/two"]; !ok {
		t.Errorf("transitive example.com/dep/two missing from closure")
	}
	// A project walk injects the synthetic standard-library node from the go.mod
	// directive (no toolchain build list is wired in this test).
	std, hasStd := byPath[domain3.StdlibModulePath]
	if !hasStd {
		t.Errorf("stdlib node missing from project closure")
	} else if std.ResolutionSource != domain3.ResolutionStdlib {
		t.Errorf("stdlib node source = %s, want stdlib", std.ResolutionSource)
	}
	if len(g.Nodes) != 4 {
		t.Errorf("node count = %d, want 4 (main + one + two + stdlib)", len(g.Nodes))
	}
}

// TestResolveProject_UnparseableGoModErrors verifies that ResolveProject
// surfaces a parse error for malformed go.mod bytes rather than a partial graph.
func TestResolveProject_UnparseableGoModErrors(t *testing.T) {
	blobs := newFakeBlobStore()
	fetcher := newFakeFetcher()
	target := coord("example.com/project", domain2.LocalVersion)

	r := newResolver(fetcher, blobs)
	_, err := r.ResolveProject(context.Background(), target, []byte("this is not a go.mod"), "", domain3.DefaultDepthPolicy().FetchStage(), nil, false, false)
	if err == nil {
		t.Fatalf("ResolveProject: expected error for malformed go.mod, got nil")
	}
}

// TestResolve_PrunesDeepRequiresOfGo117Module verifies Go 1.17+ module-graph
// pruning: the requirements of a go 1.17+ module that the target does not
// itself require (a non-root, reached only transitively) are not real build
// inputs and are dropped. Here target requires root; root requires mid (which
// the target does NOT require); mid requires deep. mid is reached and recorded,
// but because mid is go 1.17+ and not a root, deep is pruned — even though a
// fetchable record for deep exists. Without pruning, deep would appear, so this
// fails on the pre-1.2.0 resolver.
func TestResolve_PrunesDeepRequiresOfGo117Module(t *testing.T) {
	blobs := newFakeBlobStore()
	fetcher := newFakeFetcher()
	fetcher.add("example.com/target", "v1.0.0", `module example.com/target

go 1.21

require example.com/root v1.0.0
`, blobs)
	fetcher.add("example.com/root", "v1.0.0", `module example.com/root

go 1.21

require example.com/mid v1.0.0
`, blobs)
	fetcher.add("example.com/mid", "v1.0.0", `module example.com/mid

go 1.21

require example.com/deep v1.0.0
`, blobs)
	// A fetchable record for deep exists, so its absence proves pruning rather
	// than an unresolvable dependency.
	fetcher.add("example.com/deep", "v1.0.0", `module example.com/deep

go 1.21
`, blobs)

	r := newResolver(fetcher, blobs)
	g, err := r.Resolve(context.Background(), coord("example.com/target", "v1.0.0"), domain3.DefaultDepthPolicy().FetchStage())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	got := nodeSet(g.Nodes)
	for _, want := range []string{"example.com/target", "example.com/root", "example.com/mid"} {
		if !got[want] {
			t.Errorf("expected %q in graph; nodes=%v", want, got)
		}
	}
	if got["example.com/deep"] {
		t.Errorf("example.com/deep should be pruned (deep require of a go 1.17+ non-root); nodes=%v", got)
	}
}

// TestResolve_PrunesPrePruningModuleBelowGo117Boundary asserts that pruning is
// context-dependent: a pre-pruning module (go < 1.17) reached *below* a go 1.17+
// boundary is a node but its deep requirements are pruned. Here mid is go 1.16
// but is reached only as a non-root requirement of root (go 1.21). Because go
// loads root's requirements pruned, mid's own (old, large) tree is never a build
// input — deep must not appear, even though a fetchable record for it exists.
// A context-free "go < 1.17 always expands" predicate keeps deep, so this is the
// regression that distinguishes propagation from the per-module predicate.
func TestResolve_PrunesPrePruningModuleBelowGo117Boundary(t *testing.T) {
	blobs := newFakeBlobStore()
	fetcher := newFakeFetcher()
	fetcher.add("example.com/target", "v1.0.0", `module example.com/target

go 1.21

require example.com/root v1.0.0
`, blobs)
	fetcher.add("example.com/root", "v1.0.0", `module example.com/root

go 1.21

require example.com/mid v1.0.0
`, blobs)
	fetcher.add("example.com/mid", "v1.0.0", `module example.com/mid

go 1.16

require example.com/deep v1.0.0
`, blobs)
	fetcher.add("example.com/deep", "v1.0.0", `module example.com/deep

go 1.16
`, blobs)

	r := newResolver(fetcher, blobs)
	g, err := r.Resolve(context.Background(), coord("example.com/target", "v1.0.0"), domain3.DefaultDepthPolicy().FetchStage())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	got := nodeSet(g.Nodes)
	if !got["example.com/mid"] {
		t.Errorf("example.com/mid should be a node (root's immediate require); nodes=%v", got)
	}
	if got["example.com/deep"] {
		t.Errorf("example.com/deep should be pruned (deep require of a go 1.16 module below a go 1.17+ boundary); nodes=%v", got)
	}
}

// TestResolve_ExpandsPrePruningChain is the contrast case: a pre-pruning module
// reached via an unbroken go < 1.17 chain from a root IS fully expanded. root is
// a go 1.16 root, so it expands; mid (go 1.16) is reached while expanding a
// pre-pruning parent, so it expands; deep follows the same chain and is kept.
func TestResolve_ExpandsPrePruningChain(t *testing.T) {
	blobs := newFakeBlobStore()
	fetcher := newFakeFetcher()
	fetcher.add("example.com/target", "v1.0.0", `module example.com/target

go 1.21

require example.com/root v1.0.0
`, blobs)
	fetcher.add("example.com/root", "v1.0.0", `module example.com/root

go 1.16

require example.com/mid v1.0.0
`, blobs)
	fetcher.add("example.com/mid", "v1.0.0", `module example.com/mid

go 1.16

require example.com/deep v1.0.0
`, blobs)
	fetcher.add("example.com/deep", "v1.0.0", `module example.com/deep

go 1.16
`, blobs)

	r := newResolver(fetcher, blobs)
	g, err := r.Resolve(context.Background(), coord("example.com/target", "v1.0.0"), domain3.DefaultDepthPolicy().FetchStage())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	got := nodeSet(g.Nodes)
	for _, want := range []string{"example.com/root", "example.com/mid", "example.com/deep"} {
		if !got[want] {
			t.Errorf("%q should be kept (reached via a pre-pruning chain); nodes=%v", want, got)
		}
	}
}

// TestResolve_KeepsRootImmediateDepsAsNodes verifies that a root's immediate
// requirements are retained as nodes even when the root is a go 1.17+ module
// whose deeper subtree is pruned. target requires root (go 1.21); root requires
// dep (go 1.21, non-root); dep requires deep. dep is a real build input (a
// direct require of a root) so it stays, but the prune boundary cuts deep.
func TestResolve_KeepsRootImmediateDepsAsNodes(t *testing.T) {
	blobs := newFakeBlobStore()
	fetcher := newFakeFetcher()
	fetcher.add("example.com/target", "v1.0.0", `module example.com/target

go 1.21

require example.com/root v1.0.0
`, blobs)
	fetcher.add("example.com/root", "v1.0.0", `module example.com/root

go 1.21

require example.com/dep v1.0.0
`, blobs)
	fetcher.add("example.com/dep", "v1.0.0", `module example.com/dep

go 1.21

require example.com/deep v1.0.0
`, blobs)
	fetcher.add("example.com/deep", "v1.0.0", `module example.com/deep

go 1.21
`, blobs)

	r := newResolver(fetcher, blobs)
	g, err := r.Resolve(context.Background(), coord("example.com/target", "v1.0.0"), domain3.DefaultDepthPolicy().FetchStage())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	got := nodeSet(g.Nodes)
	if !got["example.com/dep"] {
		t.Errorf("example.com/dep should be kept (a root's immediate require); nodes=%v", got)
	}
	if got["example.com/deep"] {
		t.Errorf("example.com/deep should be pruned (deep require of a pruned go 1.17+ subtree); nodes=%v", got)
	}
}

// TestResolve_ReExpandsModuleReachedFirstAsNonExpanding guards the propagation
// rule against BFS discovery order: a module first reached on a non-expanding
// path must still expand when a later path qualifies it. shared (go 1.16) is
// first reached as a non-root requirement of A (go 1.21) — non-expanding — then
// again while expanding B (go 1.16, a root), which qualifies it. Its requirement
// deep must be discovered despite shared having been seen first as a leaf.
func TestResolve_ReExpandsModuleReachedFirstAsNonExpanding(t *testing.T) {
	blobs := newFakeBlobStore()
	fetcher := newFakeFetcher()
	fetcher.add("example.com/target", "v1.0.0", `module example.com/target

go 1.21

require (
	example.com/a v1.0.0
	example.com/b v1.0.0
)
`, blobs)
	fetcher.add("example.com/a", "v1.0.0", `module example.com/a

go 1.21

require example.com/shared v1.0.0
`, blobs)
	fetcher.add("example.com/b", "v1.0.0", `module example.com/b

go 1.16

require example.com/shared v1.0.0
`, blobs)
	fetcher.add("example.com/shared", "v1.0.0", `module example.com/shared

go 1.16

require example.com/deep v1.0.0
`, blobs)
	fetcher.add("example.com/deep", "v1.0.0", `module example.com/deep

go 1.16
`, blobs)

	r := newResolver(fetcher, blobs)
	g, err := r.Resolve(context.Background(), coord("example.com/target", "v1.0.0"), domain3.DefaultDepthPolicy().FetchStage())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	got := nodeSet(g.Nodes)
	if !got["example.com/shared"] {
		t.Fatalf("example.com/shared should be a node; nodes=%v", got)
	}
	if !got["example.com/deep"] {
		t.Errorf("example.com/deep should be kept: shared is reached on a qualifying (go 1.16 root) path and must re-expand; nodes=%v", got)
	}
}

// TestResolve_sharedDepParsedOnce verifies that a go.mod reached from
// multiple parents is parsed exactly once, not once per incoming path.
func TestResolve_sharedDepParsedOnce(t *testing.T) {
	blobs := newFakeBlobStore()
	fetcher := newFakeFetcher()

	// target → a@v1 → c@v1
	//        → b@v1 → c@v1   (c shared; should be parsed only once)
	fetcher.add("example.com/target", "v1.0.0", `module example.com/target

go 1.16

require (
	example.com/a v1.0.0
	example.com/b v1.0.0
)
`, blobs)
	fetcher.add("example.com/a", "v1.0.0", `module example.com/a

go 1.16

require example.com/c v1.0.0
`, blobs)
	fetcher.add("example.com/b", "v1.0.0", `module example.com/b

go 1.16

require example.com/c v1.0.0
`, blobs)
	fetcher.add("example.com/c", "v1.0.0", `module example.com/c

go 1.16
`, blobs)

	parser := newCountingParser()
	r := newResolverWithParser(parser, fetcher, blobs)
	g, err := r.Resolve(context.Background(), coord("example.com/target", "v1.0.0"), domain3.DefaultDepthPolicy().FetchStage())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	// 4 unique coordinates: target, a@v1, b@v1, c@v1
	if parser.callCount() != 4 {
		t.Errorf("parser called %d times, want 4 (one per unique coordinate); nodes=%v", parser.callCount(), nodeSet(g.Nodes))
	}
}

// TestResolve_supersededVersionNotParsed verifies that when MVS selects a
// higher version of a module, the lower (superseded) version's go.mod is
// never fetched or parsed.
func TestResolve_supersededVersionNotParsed(t *testing.T) {
	blobs := newFakeBlobStore()
	fetcher := newFakeFetcher()

	// target → a@v1.0 → c@v1.0
	//        → b@v1.0 → c@v1.1   (MVS selects c@v1.1; c@v1.0 must not be parsed)
	fetcher.add("example.com/target", "v1.0.0", `module example.com/target

go 1.16

require (
	example.com/a v1.0.0
	example.com/b v1.0.0
)
`, blobs)
	fetcher.add("example.com/a", "v1.0.0", `module example.com/a

go 1.16

require example.com/c v1.0.0
`, blobs)
	fetcher.add("example.com/b", "v1.0.0", `module example.com/b

go 1.16

require example.com/c v1.1.0
`, blobs)
	fetcher.add("example.com/c", "v1.0.0", `module example.com/c

go 1.16
`, blobs)
	fetcher.add("example.com/c", "v1.1.0", `module example.com/c

go 1.16
`, blobs)

	parser := newCountingParser()
	r := newResolverWithParser(parser, fetcher, blobs)
	g, err := r.Resolve(context.Background(), coord("example.com/target", "v1.0.0"), domain3.DefaultDepthPolicy().FetchStage())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	// 4 selected coordinates: target, a@v1.0, b@v1.0, c@v1.1 — c@v1.0 superseded before parse
	if parser.callCount() != 4 {
		t.Errorf("parser called %d times, want 4 (c@v1.0 superseded before parsing); nodes=%v", parser.callCount(), nodeSet(g.Nodes))
	}
	cNode := findNode(t, g.Nodes, "example.com/c")
	if cNode.Coordinate.Version != "v1.1.0" {
		t.Errorf("c version = %q, want v1.1.0 (MVS selected)", cNode.Coordinate.Version)
	}
}
