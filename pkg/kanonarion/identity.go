package kanonarion

import "github.com/eitanity/kanonarion/internal/fetch/application"

// ContentIdentity is the single source of canonical identity shared by signing,
// bundling, and integrity audit (§1). It exposes the canonical digest
// of a record/blob and the Merkle root + inclusion proof over a selected set of
// such digests, so an attestation, a delta bundle, and an integrity audit all
// commit to the same digests core produces — signatures cannot drift from
// core's identity. The internal *Hasher types are deliberately not reachable
// through this surface (§3).
//
// Stability: driver/identity use case (called by consumers); unstable pre-v1.
// Per §4 a use case may gain methods within a major version.
type ContentIdentity = application.ContentIdentityUseCase

// InclusionProof is a Merkle inclusion proof: the audit-path digests that,
// combined bottom-up with a member, reconstruct the set's root. Index and Size
// pin the member's position so a proof cannot be replayed at another position.
//
// Stability: result type (received by consumers); unstable pre-v1. Fields may
// be added within a major; consumers must not assume field exhaustiveness
// (§4).
type InclusionProof = application.InclusionProof

// NewContentIdentity constructs the content-identity use case. It is pure and
// stateless; a single value may be shared across goroutines.
//
// Stability: constructor for the content-identity use case; unstable pre-v1.
func NewContentIdentity() *ContentIdentity { return application.NewContentIdentityUseCase() }
