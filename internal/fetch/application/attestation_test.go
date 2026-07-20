package application_test

import (
	"context"
	"errors"
	"testing"

	"github.com/eitanity/kanonarion/internal/coordinate"
	"github.com/eitanity/kanonarion/internal/fetch/application"
	domain2 "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/fetch/ports"
)

// recordingAttestations is a fake ports.AttestationStore that captures writes.
type recordingAttestations struct {
	records []domain2.AttestationRecord
	putErr  error
}

func (r *recordingAttestations) PutAttestation(_ context.Context, rec domain2.AttestationRecord) error {
	if r.putErr != nil {
		return r.putErr
	}
	r.records = append(r.records, rec)
	return nil
}

func (r *recordingAttestations) ListAttestations(_ context.Context, _ coordinate.ModuleCoordinate, _ string) ([]domain2.AttestationRecord, error) {
	return r.records, nil
}

// fakeSigner returns a present attestation with a fixed bundle. present=false
// models the OSS no-op default. signErr models a signing failure.
type fakeSigner struct {
	present bool
	signErr error
	calls   []ports.SubjectDigest
}

func (f *fakeSigner) Sign(_ context.Context, subject ports.SubjectDigest) (ports.Attestation, error) {
	f.calls = append(f.calls, subject)
	if f.signErr != nil {
		return ports.Attestation{}, f.signErr
	}
	if !f.present {
		return ports.Attestation{Present: false}, nil
	}
	return ports.Attestation{Present: true, Subject: subject, Bundle: []byte("sig-" + subject.Hex)}, nil
}

func TestExecute_SignsBlobAndFact(t *testing.T) {
	blobs := newFakeBlob()
	facts := newFakeFacts()
	signer := &fakeSigner{present: true}
	store := &recordingAttestations{}

	uc := newUseCase(&fakeProxy{}, &fakeVCS{}, blobs, facts).WithSigner(signer, store)
	result, err := uc.Execute(context.Background(), application.FetchRequest{Coordinate: testCoord})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}

	if len(store.records) != 2 {
		t.Fatalf("persisted %d attestations, want 2 (blob + fact)", len(store.records))
	}

	byKind := map[domain2.SubjectKind]domain2.AttestationRecord{}
	for _, r := range store.records {
		byKind[r.SubjectKind] = r
	}

	// Blob attestation is over the canonical content digest of the received zip.
	wantBlob := domain2.ContentDigest([]byte("fake-zip"))
	blob, ok := byKind[domain2.SubjectBlob]
	if !ok {
		t.Fatal("no blob attestation persisted")
	}
	if "sha256:"+blob.SubjectDigest != wantBlob {
		t.Errorf("blob subject = sha256:%s, want %s", blob.SubjectDigest, wantBlob)
	}
	if blob.SubjectAlgorithm != "sha256" {
		t.Errorf("blob algorithm = %q, want sha256", blob.SubjectAlgorithm)
	}

	// Fact attestation is over the produced record's canonical ContentHash.
	fact, ok := byKind[domain2.SubjectFact]
	if !ok {
		t.Fatal("no fact attestation persisted")
	}
	if "sha256:"+fact.SubjectDigest != result.Record.ContentHash {
		t.Errorf("fact subject = sha256:%s, want %s", fact.SubjectDigest, result.Record.ContentHash)
	}
	if string(fact.Bundle) != "sig-"+fact.SubjectDigest {
		t.Errorf("fact bundle = %q, want sig-%s", fact.Bundle, fact.SubjectDigest)
	}
	if fact.Coordinate != testCoord {
		t.Errorf("fact coordinate = %+v, want %+v", fact.Coordinate, testCoord)
	}

	// Both call sites invoked the signer.
	if len(signer.calls) != 2 {
		t.Errorf("signer called %d times, want 2", len(signer.calls))
	}
}

func TestExecute_NoopSignerPersistsNothing(t *testing.T) {
	facts := newFakeFacts()
	signer := &fakeSigner{present: false} // OSS no-op default behaviour
	store := &recordingAttestations{}

	uc := newUseCase(&fakeProxy{}, &fakeVCS{}, newFakeBlob(), facts).WithSigner(signer, store)
	if _, err := uc.Execute(context.Background(), application.FetchRequest{Coordinate: testCoord}); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	if len(store.records) != 0 {
		t.Errorf("no-op signer persisted %d attestations, want 0", len(store.records))
	}
	// The signer is still invoked at both call sites — it just yields nothing.
	if len(signer.calls) != 2 {
		t.Errorf("signer called %d times, want 2", len(signer.calls))
	}
}

func TestExecute_NoSignerLeavesOutputUnchanged(t *testing.T) {
	// Two runs with the same fixed clock/inputs: one without a signer, one with
	// a no-op signer. The produced fact record must be byte-identical.
	run := func(withNoop bool) domain2.FactRecord {
		uc := newUseCase(&fakeProxy{}, &fakeVCS{}, newFakeBlob(), newFakeFacts())
		if withNoop {
			uc = uc.WithSigner(&fakeSigner{present: false}, &recordingAttestations{})
		}
		res, err := uc.Execute(context.Background(), application.FetchRequest{Coordinate: testCoord})
		if err != nil {
			t.Fatalf("Execute: %v", err)
		}
		return res.Record
	}
	if run(false).ContentHash != run(true).ContentHash {
		t.Error("no-op signer changed the produced record's content hash")
	}
}

func TestExecute_SignerErrorFailsFetch(t *testing.T) {
	signer := &fakeSigner{present: true, signErr: errors.New("kms unavailable")}
	uc := newUseCase(&fakeProxy{}, &fakeVCS{}, newFakeBlob(), newFakeFacts()).
		WithSigner(signer, &recordingAttestations{})

	_, err := uc.Execute(context.Background(), application.FetchRequest{Coordinate: testCoord})
	if err == nil {
		t.Fatal("expected Execute to fail when the signer errors")
	}
}

func TestExecute_PresentAttestationWithoutStoreFails(t *testing.T) {
	signer := &fakeSigner{present: true}
	// Signer configured but no attestation store: a wiring error.
	uc := newUseCase(&fakeProxy{}, &fakeVCS{}, newFakeBlob(), newFakeFacts()).
		WithSigner(signer, nil)

	_, err := uc.Execute(context.Background(), application.FetchRequest{Coordinate: testCoord})
	if err == nil {
		t.Fatal("expected Execute to fail when an attestation is produced but no store is set")
	}
}

func TestExecute_AttestationPersistErrorFailsFetch(t *testing.T) {
	signer := &fakeSigner{present: true}
	store := &recordingAttestations{putErr: errors.New("disk full")}
	uc := newUseCase(&fakeProxy{}, &fakeVCS{}, newFakeBlob(), newFakeFacts()).
		WithSigner(signer, store)

	_, err := uc.Execute(context.Background(), application.FetchRequest{Coordinate: testCoord})
	if err == nil {
		t.Fatal("expected Execute to fail when persisting the attestation errors")
	}
}
