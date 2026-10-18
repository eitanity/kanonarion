package application_test

import (
	"context"
	"errors"
	"io"
	"testing"

	"github.com/eitanity/kanonarion/internal/audit"
	"github.com/eitanity/kanonarion/internal/fetch/application"
	domain2 "github.com/eitanity/kanonarion/internal/fetch/domain"
	"github.com/eitanity/kanonarion/internal/fetch/fetchtest"
	"github.com/eitanity/kanonarion/internal/fetch/ports"
)

// refusingBlob is a verifying store's answer for held bytes that no longer hash
// to their identity: it refuses the identities named in refuse.
type refusingBlob struct {
	*countingBlob
	refuse map[ports.BlobIdentity]bool
}

func (b *refusingBlob) Get(ctx context.Context, identity ports.BlobIdentity) (io.ReadCloser, error) {
	if b.refuse[identity] {
		return nil, &ports.BlobTamperedError{Identity: identity, Observed: "h1:other"}
	}
	return b.countingBlob.Get(ctx, identity)
}

// A forced run over held bytes the store refuses keeps the behaviour it had for
// bytes it hashed itself: the disagreement is audited and a clean copy is
// downloaded, whichever of the two artefacts was refused.
func TestExecute_ForceOverRefusedArtefactsAuditsAndDownloads(t *testing.T) {
	for _, artefact := range []string{"zip", "go.mod"} {
		t.Run(artefact, func(t *testing.T) {
			facts := newFakeFacts()
			blobs := &refusingBlob{countingBlob: &countingBlob{fakeBlob: newFakeBlob()}, refuse: map[ports.BlobIdentity]bool{}}
			proxy, _ := realZipProxy(t, testCoord)
			sink := newFakeAudit()
			uc := newUseCase(proxy, &fakeVCS{}, blobs, facts).WithAudit(sink)
			ctx := context.Background()

			first, err := uc.Execute(ctx, application.FetchRequest{Coordinate: testCoord})
			if err != nil {
				t.Fatalf("first Execute: %v", err)
			}
			identity := fetchtest.ZipIdentity(t, first.Record.FactRecord)
			if artefact == "go.mod" {
				identity = fetchtest.GoModIdentity(t, first.Record.FactRecord)
			}
			blobs.refuse[identity] = true
			sink.events = nil
			zips := proxy.zipDownloads

			forced, err := uc.Execute(ctx, application.FetchRequest{Coordinate: testCoord, Force: true})
			if err != nil {
				t.Fatalf("forced Execute: %v", err)
			}
			if got := forced.Record.MeasurementKind; got != string(domain2.MeasurementAcquired) {
				t.Errorf("MeasurementKind = %q, want %q", got, domain2.MeasurementAcquired)
			}
			if proxy.zipDownloads == zips {
				t.Error("no clean copy was downloaded")
			}
			refusals := 0
			for _, e := range sink.events {
				if e.Type == audit.EventVerificationFailed {
					refusals++
				}
			}
			if refusals != 1 {
				t.Errorf("verification_failed events = %d, want 1", refusals)
			}
		})
	}
}

// Serve no longer hands out the identity of bytes the store refuses: it audits
// the refusal and returns it.
func TestServe_RefusesHeldBytesTheStoreRefuses(t *testing.T) {
	blobs := &refusingBlob{countingBlob: &countingBlob{fakeBlob: newFakeBlob()}, refuse: map[ports.BlobIdentity]bool{}}
	facts := newFakeFacts()
	seedRecord(t, blobs, facts, true, domain2.Verified)
	rec, ok, err := facts.GetFetchRecord(context.Background(), testCoord, "test-0.1.0")
	if err != nil || !ok {
		t.Fatalf("seeded record: ok %v, err %v", ok, err)
	}
	blobs.refuse[fetchtest.ZipIdentity(t, rec.FactRecord)] = true

	sink := newFakeAudit()
	_, err = newServe(blobs, facts).WithAudit(sink).Serve(context.Background(), application.ServeRequest{Coordinate: testCoord})
	if !errors.Is(err, ports.ErrBlobTampered) {
		t.Fatalf("Serve err = %v, want the refusal", err)
	}
	if ev := sink.only(t); ev.Type != audit.EventVerificationFailed {
		t.Errorf("event = %q, want %q", ev.Type, audit.EventVerificationFailed)
	}

	// An unaudited serve still refuses, and a failed append is not lost.
	if _, err := newServe(blobs, facts).Serve(context.Background(), application.ServeRequest{Coordinate: testCoord}); !errors.Is(err, ports.ErrBlobTampered) {
		t.Errorf("unaudited Serve err = %v, want the refusal", err)
	}
	failing := &fakeAudit{err: errors.New("log unwritable")}
	if _, err := newServe(blobs, facts).WithAudit(failing).Serve(context.Background(), application.ServeRequest{Coordinate: testCoord}); !errors.Is(err, ports.ErrBlobTampered) || !errors.Is(err, failing.err) {
		t.Errorf("Serve with an unwritable log = %v, want the refusal and the failed append", err)
	}
}
