package application_test

import (
	"context"
	"strings"
	"testing"

	"code.eitanity.com/kanonarion/internal/coordinate"
	"code.eitanity.com/kanonarion/internal/coordinate/coordinatetest"
	fetchdomain "code.eitanity.com/kanonarion/internal/fetch/domain"
	"code.eitanity.com/kanonarion/internal/fetch/fetchtest"

	"code.eitanity.com/kanonarion/internal/vuln/application"
	walkdomain "code.eitanity.com/kanonarion/internal/walk/domain"
)

// seedFactNode records a node's zip and go.mod (declaring goVersion) in the
// fact/blob stores under the "v1" fetch pipeline version, so a scan finds it
// present and can read its declared go version.
func seedFactNode(t testing.TB, ctx context.Context, facts *fakeFacts, blobs *fakeBlob, coord coordinate.ModuleCoordinate, goVersion string) {
	goMod := "module " + coord.Path() + "\n\ngo " + goVersion + "\n"
	opts := []fetchtest.Option{
		fetchtest.Coordinate(coord),
		fetchtest.PipelineVersion("v1"),
		fetchtest.Content("zip-" + coord.Path() + "-" + coord.Version()),
		fetchtest.GoMod("gomod-" + coord.Path() + "-" + coord.Version()),
	}
	rec := fetchtest.Record(t, opts...)
	mustSucceed(t, blobs.Put(ctx, fetchtest.ZipIdentity(t, rec), strings.NewReader("zip-"+coord.Path()+"-"+coord.Version())))
	mustSucceed(t, blobs.Put(ctx, fetchtest.GoModIdentity(t, rec), strings.NewReader(goMod)))
	mustSucceed(t, facts.PutFetchRecord(ctx, fetchtest.Sealed(t, opts...)))
}

// supersededGraph builds a walk whose edge names a superseded intermediate
// version: stdr requires logr@v1.2.2 but MVS selected logr@v1.4.3. Each node's
// declared go version — which gates the superseded-go.mod population — is set
// separately via seedFactNode.
func supersededGraph(walkID string) (walkdomain.WalkRecord, coordinate.ModuleCoordinate) {
	logrSelected := coordinatetest.MustNew("github.com/go-logr/logr", "v1.4.3")
	stdr := coordinatetest.MustNew("github.com/go-logr/stdr", "v1.2.2")
	supersededLogr := coordinatetest.MustNew("github.com/go-logr/logr", "v1.2.2")

	rec := walkdomain.WalkRecord{
		ID: walkID,
		Graph: walkdomain.Graph{
			Nodes: []walkdomain.GraphNode{
				{Coordinate: logrSelected},
				{Coordinate: stdr},
			},
			Edges: []walkdomain.GraphEdge{
				{From: stdr, To: logrSelected, ConstraintVersion: "v1.2.2"},
			},
		},
	}
	return rec, supersededLogr
}

// TestScan_PopulatesSupersededGoMod_WhenPrePruningPresent verifies the gate: a
// graph with a pre-pruning (go 1.16) dependency causes the superseded
// intermediate go.mod version to be fetched (and thus populated) so the scan
// can rebuild the module graph offline.
func TestScan_PopulatesSupersededGoMod_WhenPrePruningPresent(t *testing.T) {
	ctx := t.Context()
	walkID := "w-superseded-firing"
	rec, superseded := supersededGraph(walkID)

	walkStore := newFakeWalkStore()
	mustSucceed(t, walkStore.PutWalk(ctx, rec))

	facts := newFakeFacts()
	blobs := newFakeBlob()
	// stdr is pre-pruning (go 1.16); logr's selected version is modern.
	seedFactNode(t, ctx, facts, blobs, rec.Graph.Nodes[0].Coordinate, "1.20") // logr@v1.4.3
	seedFactNode(t, ctx, facts, blobs, rec.Graph.Nodes[1].Coordinate, "1.16") // stdr@v1.2.2

	vulnStore := newFakeVulnStore()
	fetcher := &fakeFetcher{}
	uc := makePrefetchScanWalkUC(t, walkStore, vulnStore, facts, blobs, fetcher)

	if _, err := uc.Scan(ctx, application.ScanWalkParams{WalkID: walkID}); err != nil {
		t.Fatalf("Scan: %v", err)
	}

	// The superseded version is read only for its requirements, so it is acquired
	// through the go.mod-only path — never the full zip fetch.
	if !fetcher.wasFetchedGoModOnly(superseded) {
		t.Errorf("expected superseded go.mod version %s to be fetched (go.mod-only) for offline resolution, but it was not", superseded)
	}
	if fetcher.wasFetched(superseded) {
		t.Errorf("superseded go.mod version %s must not trigger a full zip fetch; its source is never analysed", superseded)
	}
}

// TestScan_SkipsSupersededGoMod_WhenFullyPruned verifies the gate's negative
// side: when no dependency is pre-pruning, the toolchain never reads a
// superseded go.mod, so the population (and its network fetch) is skipped.
func TestScan_SkipsSupersededGoMod_WhenFullyPruned(t *testing.T) {
	ctx := t.Context()
	walkID := "w-superseded-skipped"
	rec, superseded := supersededGraph(walkID)

	walkStore := newFakeWalkStore()
	mustSucceed(t, walkStore.PutWalk(ctx, rec))

	facts := newFakeFacts()
	blobs := newFakeBlob()
	// Both nodes are pruned (go >= 1.17), so no superseded go.mod is needed.
	seedFactNode(t, ctx, facts, blobs, rec.Graph.Nodes[0].Coordinate, "1.20") // logr@v1.4.3
	seedFactNode(t, ctx, facts, blobs, rec.Graph.Nodes[1].Coordinate, "1.20") // stdr@v1.2.2

	vulnStore := newFakeVulnStore()
	fetcher := &fakeFetcher{}
	uc := makePrefetchScanWalkUC(t, walkStore, vulnStore, facts, blobs, fetcher)

	if _, err := uc.Scan(ctx, application.ScanWalkParams{WalkID: walkID}); err != nil {
		t.Fatalf("Scan: %v", err)
	}

	if fetcher.wasFetched(superseded) || fetcher.wasFetchedGoModOnly(superseded) {
		t.Errorf("fully pruned graph must not fetch the superseded go.mod %s, but it did", superseded)
	}
}

// seedHeld records coord at the given fetch pipeline: its go.mod alone, as a
// go.mod-only fetch writes it, or with its zip when full.
func seedHeld(t testing.TB, ctx context.Context, facts *fakeFacts, blobs *fakeBlob, coord coordinate.ModuleCoordinate, pipeline string, full bool) {
	handle := "gomod-" + coord.Path() + "-" + coord.Version()
	opts := []fetchtest.Option{fetchtest.Coordinate(coord), fetchtest.PipelineVersion(pipeline), fetchtest.GoModOnly(handle)}
	if full {
		opts = []fetchtest.Option{fetchtest.Coordinate(coord), fetchtest.PipelineVersion(pipeline),
			fetchtest.GoMod(handle), fetchtest.Content("zip-" + coord.Path() + "-" + coord.Version())}
	}
	rec := fetchtest.Record(t, opts...)
	mustSucceed(t, blobs.Put(ctx, fetchtest.GoModIdentity(t, rec), strings.NewReader("module "+coord.Path()+"\n\ngo 1.16\n")))
	mustSucceed(t, facts.PutFetchRecord(ctx, fetchtest.Sealed(t, opts...)))
}

// supersededGoModFetched scans the pre-pruning superseded graph with the
// superseded go.mod already held at pipeline, and reports whether the scan
// fetched that go.mod again.
func supersededGoModFetched(t *testing.T, pipeline string) bool {
	t.Helper()
	return supersededHeldFetched(t, pipeline, false)
}

// supersededHeldFetched is supersededGoModFetched with the superseded version
// held as a full record when full.
func supersededHeldFetched(t *testing.T, pipeline string, full bool) bool {
	t.Helper()
	ctx := t.Context()
	rec, superseded := supersededGraph("w-superseded-held")
	walkStore := newFakeWalkStore()
	mustSucceed(t, walkStore.PutWalk(ctx, rec))
	facts := newFakeFacts()
	blobs := newFakeBlob()
	seedFactNode(t, ctx, facts, blobs, rec.Graph.Nodes[0].Coordinate, "1.20")
	seedFactNode(t, ctx, facts, blobs, rec.Graph.Nodes[1].Coordinate, "1.16")
	seedHeld(t, ctx, facts, blobs, superseded, pipeline, full)

	fetcher := &fakeFetcher{}
	uc := makePrefetchScanWalkUC(t, walkStore, newFakeVulnStore(), facts, blobs, fetcher)
	if _, err := uc.Scan(ctx, application.ScanWalkParams{WalkID: rec.ID}); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	return fetcher.wasFetchedGoModOnly(superseded)
}

// A go.mod-only record an older fetch pipeline wrote was verified by superseded
// rules, so the scan fetches the go.mod again and the fetch re-derives it.
func TestScan_SupersededGoModFromAnOlderFetchPipelineIsRefetched(t *testing.T) {
	if !supersededGoModFetched(t, "0.4.0") {
		t.Error("a go.mod-only record from an older fetch pipeline was reused; it must be re-fetched")
	}
}

// Control: a record the current fetch pipeline wrote spares the fetch.
func TestScan_SupersededGoModAtTheCurrentFetchPipelineIsNotRefetched(t *testing.T) {
	if supersededGoModFetched(t, fetchdomain.PipelineVersion) {
		t.Error("a go.mod-only record at the current fetch pipeline was fetched again")
	}
}

// A full record from an older pipeline spares the fetch: it outranks the
// go.mod-only record the fetch would write, so no read would serve that.
func TestScan_SupersededGoModHeldAsAnOlderFullRecordIsNotRefetched(t *testing.T) {
	if supersededHeldFetched(t, "0.4.0", true) {
		t.Error("a coordinate held as a full record was fetched go.mod-only; no read would serve the result")
	}
}
