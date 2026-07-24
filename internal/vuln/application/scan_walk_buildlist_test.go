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

// seedFactNodeGoMod records a node's zip and a caller-supplied go.mod body in the
// fact/blob stores under the "v1" fetch pipeline version, so a scan finds the
// node present and reads the exact require directives given.
func seedFactNodeGoMod(ctx context.Context, facts *fakeFacts, blobs *fakeBlob, coord coordinate.ModuleCoordinate, goMod string) {
	zipHandle, _ := blobs.Put(ctx, strings.NewReader("zip-"+coord.Path+"-"+coord.Version))
	modHandle, _ := blobs.Put(ctx, strings.NewReader(goMod))
	_ = facts.PutFetchRecord(ctx, fetchdomain.FactRecord{
		ModulePath: coord.Path, ModuleVersion: coord.Version,
		PipelineVersion: "v1",
		ContentLocation: string(zipHandle),
		GoModLocation:   string(modHandle),
	})
}

// TestScan_PopulatesScannedNodeBuildListDeps verifies that a scannable node's own
// go.mod require block — versions the walk graph records no edge to — is supplied
// to the offline scan cache. A nested-ancestor module is fetched as full source
// (the toolchain reads it to disambiguate an import under the nested path), while
// a plain superseded require is fetched go.mod-only (read only for module-graph
// arithmetic, never compiled).
func TestScan_PopulatesScannedNodeBuildListDeps(t *testing.T) {
	ctx := t.Context()
	walkID := "w-buildlist-deps"

	consumer := coordinate.ModuleCoordinate{Path: "golang.org/x/oauth2", Version: "v0.16.0"}
	// The consumer's go.mod names three off-graph versions: a nested pair
	// (compute is a proper path-ancestor of compute/metadata) plus a plain
	// superseded require. None are walk nodes, so only the consumer's own go.mod
	// reveals them.
	ancestor := coordinate.ModuleCoordinate{Path: "cloud.google.com/go/compute", Version: "v1.20.1"}
	nested := coordinate.ModuleCoordinate{Path: "cloud.google.com/go/compute/metadata", Version: "v0.2.3"}
	plain := coordinate.ModuleCoordinate{Path: "golang.org/x/net", Version: "v0.20.0"}

	goMod := "module " + consumer.Path + "\n\ngo 1.18\n\nrequire (\n" +
		"\t" + nested.Path + " " + nested.Version + "\n" +
		"\t" + ancestor.Path + " " + ancestor.Version + " // indirect\n" +
		"\t" + plain.Path + " " + plain.Version + " // indirect\n" +
		")\n"

	walkStore := newFakeWalkStore()
	_ = walkStore.PutWalk(ctx, walkdomain.WalkRecord{
		ID: walkID,
		Graph: walkdomain.Graph{
			Nodes: []walkdomain.GraphNode{{Coordinate: consumer}},
		},
	})

	facts := newFakeFacts()
	blobs := newFakeBlob()
	seedFactNodeGoMod(ctx, facts, blobs, consumer, goMod)

	vulnStore := newFakeVulnStore()
	fetcher := &fakeFetcher{}
	uc := makePrefetchScanWalkUC(t, walkStore, vulnStore, facts, blobs, fetcher)

	if _, err := uc.Scan(ctx, application.ScanWalkParams{WalkID: walkID}); err != nil {
		t.Fatalf("Scan: %v", err)
	}

	// The nested-ancestor module needs its source (zip) so the toolchain can
	// prove it does not itself provide the package imported under the nested
	// path; a go.mod-only acquisition would leave the isolated scan unable to
	// resolve the import offline.
	if !fetcher.wasFetched(ancestor) {
		t.Errorf("expected nested-ancestor %s to be fetched as full source, but it was not", ancestor)
	}
	if fetcher.wasFetchedGoModOnly(ancestor) {
		t.Errorf("nested-ancestor %s must be fetched as source, not go.mod-only", ancestor)
	}

	// A plain superseded require is read only for module-graph arithmetic, so it
	// is acquired go.mod-only and never as a full zip.
	if !fetcher.wasFetchedGoModOnly(plain) {
		t.Errorf("expected plain build-list require %s to be fetched go.mod-only, but it was not", plain)
	}
	if fetcher.wasFetched(plain) {
		t.Errorf("plain build-list require %s must not trigger a full zip fetch", plain)
	}

	// The nested descendant is itself just another require: go.mod-only.
	if !fetcher.wasFetchedGoModOnly(nested) {
		t.Errorf("expected nested require %s to be fetched go.mod-only, but it was not", nested)
	}
}

// TestScan_SourcesSelfNestedAncestor verifies the self-nested shape: a scanned
// node whose own module path is nested under one of its requires (the require is
// a proper path-ancestor of the node itself) needs that ancestor's source, so
// the toolchain can disambiguate an import under the shared path prefix — the
// google.golang.org/genproto/googleapis/rpc → google.golang.org/genproto case.
func TestScan_SourcesSelfNestedAncestor(t *testing.T) {
	ctx := t.Context()
	walkID := "w-self-nested"

	consumer := coordinate.ModuleCoordinate{Path: "google.golang.org/genproto/googleapis/rpc", Version: "v0.0.0-20240213162025-012b6fc9bca9"}
	// The consumer requires its OWN path-ancestor; no descendant require exists,
	// so only the self-nested rule can surface it.
	ancestor := coordinate.ModuleCoordinate{Path: "google.golang.org/genproto", Version: "v0.0.0-20240205150955-31a09d347014"}

	goMod := "module " + consumer.Path + "\n\ngo 1.19\n\nrequire " + ancestor.Path + " " + ancestor.Version + "\n"

	walkStore := newFakeWalkStore()
	_ = walkStore.PutWalk(ctx, walkdomain.WalkRecord{
		ID:    walkID,
		Graph: walkdomain.Graph{Nodes: []walkdomain.GraphNode{{Coordinate: consumer}}},
	})

	facts := newFakeFacts()
	blobs := newFakeBlob()
	seedFactNodeGoMod(ctx, facts, blobs, consumer, goMod)

	vulnStore := newFakeVulnStore()
	fetcher := &fakeFetcher{}
	uc := makePrefetchScanWalkUC(t, walkStore, vulnStore, facts, blobs, fetcher)

	if _, err := uc.Scan(ctx, application.ScanWalkParams{WalkID: walkID}); err != nil {
		t.Fatalf("Scan: %v", err)
	}

	if !fetcher.wasFetched(ancestor) {
		t.Errorf("expected self-nested ancestor %s to be fetched as full source, but it was not", ancestor)
	}
	if fetcher.wasFetchedGoModOnly(ancestor) {
		t.Errorf("self-nested ancestor %s must be fetched as source, not go.mod-only", ancestor)
	}
}
