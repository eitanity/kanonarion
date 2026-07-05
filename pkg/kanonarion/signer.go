package kanonarion

import (
	"github.com/eitanity/kanonarion/internal/adapters/signer/noop"
	"github.com/eitanity/kanonarion/internal/fetch/ports"
)

// Signer signs a subject digest from the content-identity surface and returns
// an attestation over it. OSS ships a no-op default (see NewNoopSigner) and
// enterprise injects a keyed (e.g. sigstore-backed) implementation through the
// DI container. The keyed signature closes the T9 store-poisoning residual the
// keyless self-hash leaves open. A Signer attests provenance, never source
// authenticity or fact correctness (§2).
//
// Stability: substitution port (implemented by consumers); unstable pre-v1.
// Per the port-asymmetry rule this interface grows only by a new optional
// interface, never by adding a method (§4).
type Signer = ports.Signer

// SubjectDigest is the canonical digest of a record or blob that a Signer
// attests over, produced by the content-identity surface so a signature cannot
// drift from core's canonical digest.
//
// Stability: result type (received by consumers); unstable pre-v1. Fields may
// be added within a major; consumers must not assume field exhaustiveness
// (§4).
type SubjectDigest = ports.SubjectDigest

// Attestation is the result of signing a SubjectDigest. A non-Present
// Attestation means no attestation was produced (the no-op default), distinct
// from a present attestation carrying empty trust.
//
// Stability: result type (received by consumers); unstable pre-v1. Fields may
// be added within a major; consumers must not assume field exhaustiveness
// (§4).
type Attestation = ports.Attestation

// NewNoopSigner returns the OSS default Signer: an unconfigured signer that
// yields no attestation. It is the value the DI container wires by default, and
// is exported so consumers can request explicit no-attestation behaviour.
//
// Stability: constructor for the no-op default; unstable pre-v1.
func NewNoopSigner() Signer { return noop.New() }
