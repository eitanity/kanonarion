package kanonarion_test

import (
	"context"
	"testing"

	"github.com/eitanity/kanonarion/pkg/kanonarion"
)

// NewNoopSigner satisfies the published Signer port.
var _ kanonarion.Signer = kanonarion.NewNoopSigner()

// TestNewNoopSigner_YieldsNoAttestation pins the OSS default behaviour through
// the public façade: an unconfigured signer reports no attestation rather than
// a signature with empty trust.
func TestNewNoopSigner_YieldsNoAttestation(t *testing.T) {
	t.Parallel()

	signer := kanonarion.NewNoopSigner()

	att, err := signer.Sign(context.Background(), kanonarion.SubjectDigest{
		Algorithm: "sha256",
		Hex:       "deadbeef",
	})
	if err != nil {
		t.Fatalf("Sign returned error: %v", err)
	}
	if att.Present {
		t.Errorf("Present = true, want false (no attestation)")
	}
	if att.Bundle != nil {
		t.Errorf("Bundle = %v, want nil", att.Bundle)
	}
}
