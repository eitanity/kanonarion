// Package noop provides the OSS default ports.Signer: an unconfigured signer
// that yields no attestation. It is wired into the DI container default so the
// pipeline always has a Signer to call; enterprise replaces it with a keyed
// implementation. Returning a non-Present attestation (rather than an error or
// an empty-trust signature) keeps "absence of a key" distinct from "signed with
// empty trust".
package noop

import (
	"context"

	"github.com/eitanity/kanonarion/internal/fetch/ports"
)

// Signer is the no-op ports.Signer. It signs nothing and reports no attestation.
type Signer struct{}

var _ ports.Signer = Signer{}

// New returns the no-op signer.
func New() Signer { return Signer{} }

// Sign always returns a non-Present attestation and a nil error, regardless of
// the subject: an unconfigured signer yields no attestation.
func (Signer) Sign(_ context.Context, _ ports.SubjectDigest) (ports.Attestation, error) {
	return ports.Attestation{Present: false}, nil
}
