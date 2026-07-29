package application_test

import (
	"context"
	"testing"

	domain2 "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/license/application"
	domain3 "github.com/eitanity/kanonarion/internal/license/domain"
)

// TestExecute_RecordsTheArtefactItWasDerivedFrom is the ticket's headline
// observable: the record does not merely sit beside a fetch record of the same
// coordinate, it names the measurement it was produced from, and that name
// matches the record the stage actually read.
//
// Asserted against the fetch store rather than against a literal, so it stays
// true if the fixture's hashes change: the point is agreement between the two
// records, not any particular hash.
func TestExecute_RecordsTheArtefactItWasDerivedFrom(t *testing.T) {
	coord := mustCoord(t, "example.com/pkg", "v1.0.0")
	factStore := &fakeFactStore{}
	blobStore := &fakeBlobStore{}
	licenceStore := &fakeLicenseStore{}

	zipData := buildModuleZip(t, coord, map[string]string{
		"client.go": "package client\ntype Client struct{}\n",
	})
	putFactWithBlob(t, factStore, blobStore, coord, zipData)

	uc := buildUseCase(t, factStore, blobStore, licenceStore)
	result, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: coord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}

	composite, ok, err := factStore.GetFetchRecord(context.Background(), coord, application.PipelineVersion)
	if err != nil || !ok {
		t.Fatalf("GetFetchRecord: ok=%v err=%v", ok, err)
	}
	fact := composite.FactRecord
	wantIdentity, err := domain2.ArtefactIdentityOf(fact)
	if err != nil {
		t.Fatalf("ArtefactIdentityOf: %v", err)
	}

	if result.Record.ArtefactIdentity != wantIdentity.String() {
		t.Errorf("ArtefactIdentity = %q, want %q", result.Record.ArtefactIdentity, wantIdentity.String())
	}
	if result.Record.SourceContentHash != fact.ContentHash {
		t.Errorf("SourceContentHash = %q, want the fetch record's own hash %q", result.Record.SourceContentHash, fact.ContentHash)
	}

	// The claim must survive persistence, not just the return value.
	stored, found, err := licenceStore.GetLicenseRecord(context.Background(), coord, application.PipelineVersion)
	if err != nil || !found {
		t.Fatalf("GetLicenseRecord: found=%v err=%v", found, err)
	}
	got, err := domain3.RecordArtefactIdentity(stored)
	if err != nil {
		t.Fatalf("RecordArtefactIdentity: %v", err)
	}
	if !got.Equal(wantIdentity) {
		t.Errorf("persisted identity = %v, want %v", got, wantIdentity)
	}
}

// TestExecute_FailedExtractionStillNamesTheArtefact covers the branch that is
// easy to miss: a failure record is still a claim about specific bytes, and one
// that cannot say which bytes failed is unfalsifiable.
func TestExecute_FailedExtractionStillNamesTheArtefact(t *testing.T) {
	coord := mustCoord(t, "example.com/corrupt", "v1.0.0")
	factStore := &fakeFactStore{}
	blobStore := &fakeBlobStore{}
	licenceStore := &fakeLicenseStore{}

	putFactWithBlob(t, factStore, blobStore, coord, []byte("not a zip"))

	uc := buildUseCase(t, factStore, blobStore, licenceStore)
	result, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: coord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Record.OverallStatus != domain3.LicenseStatusExtractionFailed {
		t.Fatalf("OverallStatus = %s, want ExtractionFailed", result.Record.OverallStatus)
	}
	if result.Record.ArtefactIdentity == "" {
		t.Error("a failed extraction recorded no artefact; it cannot say which bytes it failed on")
	}
	if result.Record.SourceContentHash == "" {
		t.Error("a failed extraction recorded no source measurement")
	}
}
