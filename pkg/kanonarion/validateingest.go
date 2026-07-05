package kanonarion

import (
	fetchapp "github.com/eitanity/kanonarion/internal/fetch/application"
)

// Validate-and-ingest / verify-on-read surface (§1,3). The consume side
// of the airgap bundle: imported fact records pass the same integrity invariants
// extracted records satisfy rather than being written raw, and every read
// re-verifies fail-closed so a tampered record is treated as unavailable
// never presented as a confident fact.

// ValidateAndIngestUseCase is the verified-fact boundary: records cross into the
// store (Ingest) and back out (ReadVerified) only if they pass the same
// integrity gate. Reach it through Driver.ValidateIngest, constructed by
// OpenDriver. It is a TYPE ALIAS to the internal use case.
//
// Stability: driver use case (called by consumers); unstable pre-v1. May gain
// methods within a major version (§4).
type ValidateAndIngestUseCase = fetchapp.ValidateAndIngestUseCase

// ErrVerificationFailed marks a fact record that failed its integrity
// verification. Ingest wraps it when refusing to persist a tampered record and
// ReadVerified wraps it when refusing to present one; match it with errors.Is to
// distinguish a tampered/unverifiable record (treat-as-unavailable, fail-closed)
// from a genuine absence or an infrastructure error.
//
// Stability: error sentinel (matched by consumers); unstable pre-v1 (§4).
var ErrVerificationFailed = fetchapp.ErrVerificationFailed
