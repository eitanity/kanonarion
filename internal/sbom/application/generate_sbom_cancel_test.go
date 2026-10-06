package application_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/eitanity/kanonarion/internal/sbom/application"
	"github.com/eitanity/kanonarion/internal/sbom/domain"
)

// A vendored-tree read the run's cancellation stopped ends generation with the
// cancellation. Carrying on would emit, and persist, a document missing a scope
// statement that nothing failed to make.
func TestGenerateSBOM_VendorTreeReadStoppedByTheCancellationGeneratesNothing(t *testing.T) {
	walk := vendoredWalk(t, "/work/project")
	tree := &fakeVendorTree{err: fmt.Errorf("reading the verified module zip: %w", context.Canceled)}
	gen := &fakeSBOMGenerator{record: domain.SBOMRecord{ID: "sbom-1", WalkID: walk.ID}}
	uc := makeUC(&fakeWalkStore{walk: walk}, &fakeSBOMStore{}, gen).WithVendorTree(tree)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := uc.Generate(ctx, application.SBOMRequest{WalkID: walk.ID})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want the cancellation", err)
	}
	if gen.capturedNodes != nil {
		t.Error("a document was generated after the cancellation stopped its scope read")
	}
}
