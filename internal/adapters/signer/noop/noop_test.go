package noop_test

import (
	"context"
	"testing"

	"github.com/eitanity/kanonarion/internal/adapters/signer/noop"
	"github.com/eitanity/kanonarion/internal/fetch/ports"
)

func TestSigner_YieldsNoAttestation(t *testing.T) {
	t.Parallel()

	subjects := []ports.SubjectDigest{
		{},
		{Algorithm: "sha256", Hex: "deadbeef"},
		{Algorithm: "sha512", Hex: ""},
	}

	for _, subject := range subjects {
		att, err := noop.New().Sign(context.Background(), subject)
		if err != nil {
			t.Fatalf("Sign(%+v) returned error: %v", subject, err)
		}
		if att.Present {
			t.Errorf("Sign(%+v): Present = true, want false (no attestation)", subject)
		}
		if att.Bundle != nil {
			t.Errorf("Sign(%+v): Bundle = %v, want nil", subject, att.Bundle)
		}
		if att.Subject != (ports.SubjectDigest{}) {
			t.Errorf("Sign(%+v): Subject = %+v, want zero", subject, att.Subject)
		}
	}
}
