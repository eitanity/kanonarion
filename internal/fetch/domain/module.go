package domain

import "time"

// VerificationStatus describes the outcome of cross-verifying a module zip
// against the checksum database and its git source.
type VerificationStatus string

const (
	// Verified means the zip hash matches both the checksum database entry
	// and the content extracted from the git commit. Strongest assurance.
	Verified VerificationStatus = "Verified"

	// VerifiedBySumDBOnly means the zip hash matches the checksum database
	// entry but the VCS could not be reached or a URL could not be inferred.
	// The record is authentic with respect to the transparency log.
	VerifiedBySumDBOnly VerificationStatus = "VerifiedBySumDBOnly"

	// VerifiedByGoSum means the module's computed zip (and go.mod) h1 matched
	// the walk root's local go.sum, but the network checksum database was
	// unavailable (offline, disabled, or without an entry). go.sum is itself
	// populated under a prior sum.golang.org transparency-log check, so this is
	// a positive, offline integrity signal — weaker than a live sumdb query
	// (VerifiedBySumDBOnly) yet stronger than no anchor at all
	// (UnverifiedNoSumDB). It complements, never replaces, the network path.
	VerifiedByGoSum VerificationStatus = "VerifiedByGoSum"

	// UnverifiedNoSumDB means the checksum database was disabled, unreachable,
	// or had no entry for this module version. No transparency-log guarantee.
	UnverifiedNoSumDB VerificationStatus = "UnverifiedNoSumDB"

	// UnverifiedMissingOrigin means the proxy did not provide origin metadata
	// and we could not infer a VCS URL from the module path. Only set when
	// sumdb is also unavailable; otherwise VerifiedBySumDBOnly is used.
	UnverifiedMissingOrigin VerificationStatus = "UnverifiedMissingOrigin"

	// UnverifiedHashMismatch means computed hash did not match either the
	// checksum database entry or the git commit tree. Possible tampering.
	UnverifiedHashMismatch VerificationStatus = "UnverifiedHashMismatch"

	// UnverifiedGoModInconsistent means the standalone go.mod served by the
	// proxy does not match the go.mod embedded in the module zip.
	UnverifiedGoModInconsistent VerificationStatus = "UnverifiedGoModInconsistent"

	// UnverifiedNoVCS means a VCS checkout was attempted but could not be
	// completed (e.g. the repository or commit was unreachable). The check ran
	// and could not confirm — distinct from UnverifiedVCSToolMissing.
	UnverifiedNoVCS VerificationStatus = "UnverifiedNoVCS"

	// UnverifiedVCSToolMissing means cross-verification never ran because the
	// VCS tool is absent from the host (e.g. no git binary in PATH). This is an
	// un-analysed/unknown outcome, not a negative result: it is
	// resolved by installing the tool, and the detail names --skip-vcs-verify.
	UnverifiedVCSToolMissing VerificationStatus = "UnverifiedVCSToolMissing"

	// LocalSource means the module artefact was created directly from a local
	// filesystem path rather than fetched from a module proxy. Checksum-database
	// and VCS verification are not applicable.
	LocalSource VerificationStatus = "LocalSource"
)

// IsVerified reports whether the status represents a record that was positively
// anchored to trust — matched against the checksum-database transparency log
// and/or its git source, or created from a local source where cross-verification
// does not apply. Every other status (mismatch, inconsistency, or an
// un-analysed/unknown outcome such as a missing sumdb entry or absent VCS tool)
// is *not* positively verified. It is the read/serve gate's classifier: a false
// result is the security-relevant "not positively verified" signal that the
// assurance log records, with the precise status preserved alongside it so a
// hard mismatch is never conflated with an un-analysed outcome.
func (s VerificationStatus) IsVerified() bool {
	switch s {
	case Verified, VerifiedBySumDBOnly, VerifiedByGoSum, LocalSource:
		return true
	default:
		return false
	}
}

// FetchedModule is the aggregate root for the fetch bounded context.
// It captures everything known about a module at a pinned version after
// ingestion: the artefacts, their hashes, the git provenance, and the
// verification outcome.
type FetchedModule struct {
	// Coordinate identifies the module and version.
	Coordinate ModuleCoordinate

	// ModuleHash is the h1 hash of the module zip, as reported by the proxy.
	ModuleHash ModuleHash

	// GoModHash is the h1 hash of the go.mod file, as reported by the proxy.
	GoModHash ModuleHash

	// Digests are the raw SHA-256/384/512 hashes of the module zip bytes,
	// computed at download from the same bytes as ModuleHash. They become the
	// SBOM component's <hashes>. Zero value when the artefact was not downloaded
	// (e.g. a local source).
	Digests ArtifactDigests

	// GitReference is the resolved git provenance. May be zero-value when
	// VerificationStatus is UnverifiedMissingOrigin.
	GitReference GitReference

	// VerificationStatus is the outcome of cross-verifying zip vs git source.
	VerificationStatus VerificationStatus

	// VerificationDetail provides a human-readable explanation when
	// VerificationStatus is not Verified.
	VerificationDetail string

	// FetchedAt is the UTC time at which the proxy was queried.
	FetchedAt time.Time

	// PipelineVersion identifies the pipeline code that produced this record.
	PipelineVersion string

	// ContentLocation is the opaque storage handle returned by BlobStore.Put for the zip.
	// It is not a filesystem path; treat it as an opaque identifier.
	ContentLocation string

	// GoModLocation is the opaque storage handle for the go.mod file.
	GoModLocation string

	// Retracted is true if the module version carries a retract directive
	// covering this version in its own go.mod.
	Retracted bool
}
