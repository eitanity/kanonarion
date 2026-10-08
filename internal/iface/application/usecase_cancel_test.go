package application_test

import (
	"context"
	"errors"
	"testing"

	"github.com/eitanity/kanonarion/internal/iface/application"
)

// A cancelled extraction failed nothing: it returns the cancellation and records
// no failed extraction. A corrupt zip is still recorded as ExtractionFailed (see
// TestExecute_CorruptZip).
func TestExecute_CancelledExtractionRecordsNothing(t *testing.T) {
	coord := mustCoord(t, "example.com/cancel", "v1.0.0")
	blobStore := &fakeBlobStore{}
	factStore := &fakeFactStore{}
	ifaceStore := &fakeInterfaceStore{}
	putFactWithBlob(t, factStore, blobStore, coord, buildModuleZip(t, coord, map[string]string{"c.go": "package c\n"}))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := buildUseCase(t, factStore, blobStore, ifaceStore, nil).Execute(ctx, application.ExtractRequest{Coordinate: coord})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Execute: err = %v, want the cancellation", err)
	}
	if len(ifaceStore.puts) != 0 {
		t.Errorf("a cancelled extraction wrote %d record(s): %+v", len(ifaceStore.puts), ifaceStore.puts)
	}
}
