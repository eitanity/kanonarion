package application_test

import (
	"context"
	"testing"

	"github.com/eitanity/kanonarion/internal/callgraph/application"
	domain2 "github.com/eitanity/kanonarion/internal/callgraph/domain"
	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
)

// TestExecute_RecordsTheArtefactItWasDerivedFrom is the ticket's headline
// observable for the fetch-backed call-graph stage: the record names the
// measurement it was produced from, and that name matches the fetch record the
// stage actually read.
func TestExecute_RecordsTheArtefactItWasDerivedFrom(t *testing.T) {
	facts := &fakeFactStore{}
	blobs := &fakeBlobStore{}
	store := &fakeCallGraphStore{}
	analyser := &fakeAnalyser{}

	storeFetchRecord(t, facts, blobs, testCoord)

	uc := buildUseCase(facts, blobs, store, analyser)
	result, err := uc.Execute(context.Background(), application.ExtractRequest{Coordinate: testCoord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}

	composite, ok, err := facts.GetFetchRecord(context.Background(), testCoord, testFetchPipV)
	if err != nil || !ok {
		t.Fatalf("GetFetchRecord: ok=%v err=%v", ok, err)
	}
	fact := composite.FactRecord
	want, err := fetchdomain.ArtefactIdentityOf(fact)
	if err != nil {
		t.Fatalf("ArtefactIdentityOf: %v", err)
	}

	if result.Record.ArtefactIdentity != want.String() {
		t.Errorf("ArtefactIdentity = %q, want %q", result.Record.ArtefactIdentity, want.String())
	}
	if result.Record.SourceContentHash != fact.ContentHash {
		t.Errorf("SourceContentHash = %q, want the fetch record's own hash %q", result.Record.SourceContentHash, fact.ContentHash)
	}

	got, err := domain2.RecordArtefactIdentity(result.Record)
	if err != nil {
		t.Fatalf("RecordArtefactIdentity: %v", err)
	}
	if !got.Equal(want) {
		t.Errorf("identity read back = %v, want %v", got, want)
	}
}

// TestLocalExecute_RecordsNoArtefact pins the deliberate exception. The local
// stage analyses a working tree, so nothing was fetched and no measurement
// exists to point at. Empty is the honest answer; stamping a hash computed here
// would invent an artefact no fetch ever saw, and it would key rows in every
// table that composes on the identity.
func TestLocalExecute_RecordsNoArtefact(t *testing.T) {
	store := &fakeCallGraphStore{}
	analyser := &fakeAnalyser{}
	uc := buildLocalUseCase(store, analyser)

	result, err := uc.Execute(context.Background(), application.LocalExtractRequest{
		Dir:        t.TempDir(),
		Coordinate: testCoord,
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Record.ArtefactIdentity != "" {
		t.Errorf("ArtefactIdentity = %q, want empty: a working tree is not a fetched artefact", result.Record.ArtefactIdentity)
	}
	if result.Record.SourceContentHash != "" {
		t.Errorf("SourceContentHash = %q, want empty", result.Record.SourceContentHash)
	}

	// Absent, and readable as absent rather than as a corrupt value.
	id, err := domain2.RecordArtefactIdentity(result.Record)
	if err != nil {
		t.Fatalf("RecordArtefactIdentity: %v", err)
	}
	if !id.IsZero() {
		t.Errorf("RecordArtefactIdentity = %v, want the zero identity", id)
	}
}
