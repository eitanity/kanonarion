package application_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/eitanity/kanonarion/internal/example/application"
	"github.com/eitanity/kanonarion/internal/example/ports"
)

// TestExecute_AConflictingLedgerIsACacheMissNotAFailure.
//
// Composition refuses to pick between two stored generations that disagree,
// which means no single one answers the coordinate. Refusing to SERVE that is
// right; refusing to MEASURE a new answer is not, so the extraction stage treats
// it as a cache miss and appends.
func TestExecute_AConflictingLedgerIsACacheMissNotAFailure(t *testing.T) {
	coord := mustCoord(t, "example.com/pkg", "v1.0.0")
	facts := &fakeFactStore{}
	blobs := &fakeBlobStore{}
	putFactWithBlob(t, facts, blobs, coord, buildModuleZip(t, coord, map[string]string{
		"example_test.go": "package pkg_test\n\nfunc ExampleNew() {}\n",
	}))
	examples := &fakeExampleStore{
		getErr: fmt.Errorf("%w: two generations", ports.ErrExampleConflict),
	}

	uc := buildUseCase(t, facts, blobs, examples)
	result, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: coord})
	if err != nil {
		t.Fatalf("a composition refusal was reported as an extraction failure: %v", err)
	}
	if result.FromCache {
		t.Error("extraction served a cached answer from a ledger that holds no single answer")
	}
	if _, ok := examples.records[exampleKey{coord.Path(), coord.Version(), application.PipelineVersion}]; !ok {
		t.Error("the measured generation was not appended")
	}
}

// TestExecute_AStoreFailureIsStillAnExtractionFailure is the other half of the
// rule. Only a composition refusal became a cache miss; a store that cannot be
// read at all is still a fault.
func TestExecute_AStoreFailureIsStillAnExtractionFailure(t *testing.T) {
	coord := mustCoord(t, "example.com/pkg", "v1.0.0")
	facts := &fakeFactStore{}
	blobs := &fakeBlobStore{}
	putFactWithBlob(t, facts, blobs, coord, buildModuleZip(t, coord, map[string]string{
		"example_test.go": "package pkg_test\n\nfunc ExampleNew() {}\n",
	}))
	unreadable := errors.New("store unavailable")

	uc := buildUseCase(t, facts, blobs, &fakeExampleStore{getErr: unreadable})
	if _, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: coord}); !errors.Is(err, unreadable) {
		t.Fatalf("Execute returned %v, want the store failure", err)
	}
}
