package domain

import (
	"errors"
	"fmt"
)

// ErrMissingSchemaVersion is returned by VerifyFactRecord when a record carries
// no schema version. Without one a record cannot be canonicalised
// deterministically, so it is rejected rather than guessed at.
var ErrMissingSchemaVersion = errors.New("fact record has no schema version")

// VerifyFactRecord checks every integrity invariant a fact record must satisfy
// regardless of provenance — whether extracted locally or imported from an
// airgap bundle. It is the single verification gate shared by validate-and-ingest
// (write) and verify-on-read (read), so an imported record is held to exactly
// the same bar as a freshly extracted one.
//
// It enforces, in order:
// - the ecosystem invariant (kanonarion records are Go-only);
// - the presence of a schema version;
// - the canonical self-hash — ContentHash recomputes to the stored value,
// the keyless tamper-evidence check.
//
// Signature/Merkle anchoring against bundled signing material is layered on by
// later consumer work; this function is the invariant floor that work builds on.
func VerifyFactRecord(r FactRecord) error {
	if r.Ecosystem != EcosystemGo {
		return fmt.Errorf("%w: got %q, want %q", ErrUnsupportedEcosystem, r.Ecosystem, EcosystemGo)
	}
	if r.SchemaVersion == "" {
		return ErrMissingSchemaVersion
	}
	if err := (CanonicalHasher{}).VerifyContentHash(r); err != nil {
		return fmt.Errorf("verifying content hash: %w", err)
	}
	return nil
}
