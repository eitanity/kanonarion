package application_test

import (
	"context"
	"strings"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/vuln/application"
	walkdomain "github.com/eitanity/kanonarion/internal/walk/domain"
)

// seedFactNode records a node's zip and go.mod (declaring goVersion) in the
// fact/blob stores under the "v1" fetch pipeline version, so a scan finds it
// present and can read its declared go version.
func seedFactNode(ctx context.Context, facts *fakeFacts, blobs *fakeBlob, coord coordinate.ModuleCoordinate, goVersion string) {
	zipHandle, _ := blobs.Put(ctx, strings.NewReader("zip-"+coord.Path+"-"+coord.Version))
	goMod := "module " + coord.Path + "\n\ngo " + goVersion + "\n"
	modHandle, _ := blobs.Put(ctx, strings.NewReader(goMod))
	_ = facts.PutFetchRecord(ctx, fetchdomain.FactRecord{
		ModulePath: coord.Path, ModuleVersion: coord.Version,
		PipelineVersion: "v1",
		ContentLocation: string(zipHandle),
		GoModLocation:   string(modHandle),
	})
}

// supersededGraph builds a walk whose edge names a superseded intermediate
// version: stdr requires logr@v1.2.2 but MVS selected logr@v1.4.3. Each node's
// declared go version — which gates the superseded-go.mod population — is set
// separately via seedFactNode.
func supersededGraph(walkID string) (walkdomain.WalkRecord, coordinate.ModuleCoordinate) {
	logrSelected := coordinate.ModuleCoordinate{Path: "github.com/go-logr/logr", Version: "v1.4.3"}
	stdr := coordinate.ModuleCoordinate{Path: "github.com/go-logr/stdr", Version: "v1.2.2"}
	supersededLogr := coordinate.ModuleCoordinate{Path: "github.com/go-logr/logr", Version: "v1.2.2"}

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
	_ = walkStore.PutWalk(ctx, rec)

	facts := newFakeFacts()
	blobs := newFakeBlob()
	// stdr is pre-pruning (go 1.16); logr's selected version is modern.
	seedFactNode(ctx, facts, blobs, rec.Graph.Nodes[0].Coordinate, "1.20") // logr@v1.4.3
	seedFactNode(ctx, facts, blobs, rec.Graph.Nodes[1].Coordinate, "1.16") // stdr@v1.2.2

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
	_ = walkStore.PutWalk(ctx, rec)

	facts := newFakeFacts()
	blobs := newFakeBlob()
	// Both nodes are pruned (go >= 1.17), so no superseded go.mod is needed.
	seedFactNode(ctx, facts, blobs, rec.Graph.Nodes[0].Coordinate, "1.20") // logr@v1.4.3
	seedFactNode(ctx, facts, blobs, rec.Graph.Nodes[1].Coordinate, "1.20") // stdr@v1.2.2

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
