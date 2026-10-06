package application_test

import (
	"context"
	"errors"
	"testing"

	"github.com/eitanity/kanonarion/internal/license/application"
)

// A licence detection the run's cancellation stopped failed nothing: Execute
// returns the cancellation and records no failed extraction. A corrupt zip is
// still recorded as ExtractionFailed (see TestExecute_CorruptZip).
func TestExecute_CancelledExtractionRecordsNothing(t *testing.T) {
	coord := mustCoord(t, "example.com/cancel", "v1.0.0")
	blobStore := &fakeBlobStore{}
	factStore := &fakeFactStore{}
	licenceStore := &fakeLicenseStore{}
	putFactWithBlob(t, factStore, blobStore, coord, buildModuleZip(t, coord, map[string]string{"LICENSE": "MIT"}))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := buildUseCase(t, factStore, blobStore, licenceStore).Execute(ctx, application.ExtractRequest{Coordinate: coord})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Execute: err = %v, want the cancellation", err)
	}
	if len(licenceStore.puts) != 0 {
		t.Errorf("a cancelled extraction wrote %d record(s): %+v", len(licenceStore.puts), licenceStore.puts)
	}
}
