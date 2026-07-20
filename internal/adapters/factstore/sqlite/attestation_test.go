package sqlite_test

import (
	"context"
	"testing"
	"time"

	"github.com/eitanity/kanonarion/internal/coordinate"

	domain2 "github.com/eitanity/kanonarion/internal/fetch/domain"
)

func sampleAttestation(path, version, pv string, kind domain2.SubjectKind, digest string) domain2.AttestationRecord {
	return domain2.AttestationRecord{
		Coordinate:       coordinate.ModuleCoordinate{Path: path, Version: version},
		PipelineVersion:  pv,
		SubjectKind:      kind,
		SubjectAlgorithm: "sha256",
		SubjectDigest:    digest,
		Bundle:           []byte("bundle-" + digest),
		SignedAt:         time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC),
	}
}

func TestPutListAttestations(t *testing.T) {
	s := openMemStore(t)
	ctx := context.Background()
	coord := coordinate.ModuleCoordinate{Path: "github.com/foo/bar", Version: "v1.0.0"}

	blob := sampleAttestation(coord.Path, coord.Version, "0.1.0", domain2.SubjectBlob, "bbbb")
	fact := sampleAttestation(coord.Path, coord.Version, "0.1.0", domain2.SubjectFact, "ffff")
	for _, a := range []domain2.AttestationRecord{fact, blob} {
		if err := s.PutAttestation(ctx, a); err != nil {
			t.Fatalf("PutAttestation: %v", err)
		}
	}

	got, err := s.ListAttestations(ctx, coord, "0.1.0")
	if err != nil {
		t.Fatalf("ListAttestations: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d attestations, want 2", len(got))
	}
	// Deterministic order: blob before fact.
	if got[0].SubjectKind != domain2.SubjectBlob || got[1].SubjectKind != domain2.SubjectFact {
		t.Errorf("order = %s,%s; want blob,fact", got[0].SubjectKind, got[1].SubjectKind)
	}
	if string(got[0].Bundle) != "bundle-bbbb" {
		t.Errorf("blob bundle = %q, want bundle-bbbb", got[0].Bundle)
	}
	if !got[0].SignedAt.Equal(blob.SignedAt) {
		t.Errorf("signed_at = %v, want %v", got[0].SignedAt, blob.SignedAt)
	}
}

func TestPutAttestation_IdempotentOnSubject(t *testing.T) {
	s := openMemStore(t)
	ctx := context.Background()
	coord := coordinate.ModuleCoordinate{Path: "github.com/foo/bar", Version: "v1.0.0"}

	first := sampleAttestation(coord.Path, coord.Version, "0.1.0", domain2.SubjectBlob, "bbbb")
	if err := s.PutAttestation(ctx, first); err != nil {
		t.Fatalf("PutAttestation: %v", err)
	}
	// Re-sign same subject with a new bundle: must overwrite, not duplicate.
	second := first
	second.Bundle = []byte("rotated")
	if err := s.PutAttestation(ctx, second); err != nil {
		t.Fatalf("PutAttestation (re-sign): %v", err)
	}

	got, err := s.ListAttestations(ctx, coord, "0.1.0")
	if err != nil {
		t.Fatalf("ListAttestations: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d attestations, want 1 (idempotent)", len(got))
	}
	if string(got[0].Bundle) != "rotated" {
		t.Errorf("bundle = %q, want rotated", got[0].Bundle)
	}
}

func TestListAttestations_EmptyNotError(t *testing.T) {
	s := openMemStore(t)
	ctx := context.Background()
	coord := coordinate.ModuleCoordinate{Path: "none", Version: "v0.0.0"}

	got, err := s.ListAttestations(ctx, coord, "0.1.0")
	if err != nil {
		t.Fatalf("ListAttestations: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("got %d, want 0", len(got))
	}
}
