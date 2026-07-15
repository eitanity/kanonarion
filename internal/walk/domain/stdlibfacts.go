package domain

// StdlibFacts is the standard library's chain-of-custody evidence, carried on
// the synthetic stdlib graph node so downstream stages (SBOM, audit) read a real
// verification status, real artefact hashes, and a real licence instead of
// special-cased constants.
//
// The standard library ships with the toolchain rather than through the module
// proxy, so this chain is necessarily different-anchored from a module's: the
// integrity anchor is go.dev/dl's published source-tarball checksum plus a
// go.googlesource.com/go tag/commit — a published checksum, not a signed sumdb
// transparency-log entry, and never present in the project's go.sum. The
// VerificationStatus string reflects that (e.g. "VerifiedGoDevChecksum") so it
// never reads as equivalent to a module's sumdb verification.
//
// It is produced by a walkports.StdlibAcquirer during graph resolution. A nil
// pointer on a stdlib node means acquisition did not run or yielded nothing (an
// offline run, a missing toolchain release) — a best-effort coverage gap, never
// a fatal error. The digests live on GraphNode.Digests alongside every other
// node's, so the SBOM hash path is uniform.
type StdlibFacts struct {
	// LicenseSPDX is the SPDX identifier extracted from the tarball's LICENSE
	// file (BSD-3-Clause). Empty when it could not be identified.
	LicenseSPDX string
	// VerificationStatus records how the source tarball was verified against
	// go.dev/dl. Distinct from the fetch stage's module verification statuses.
	VerificationStatus string
	// VerificationDetail is a human-readable summary: the checksum source and,
	// when resolved, the googlesource commit.
	VerificationDetail string
	// PublishedSHA256 is the SHA-256 Go publishes for the source tarball.
	PublishedSHA256 string
	// SourceURL is the canonical tarball URL the bytes were acquired from.
	SourceURL string
	// VCSURL is the Go source repository the tag/commit anchor refers to.
	VCSURL string
	// VCSRef is the release tag in that repository ("go1.26.4").
	VCSRef string
	// VCSCommit is the commit the release tag resolves to; empty when the VCS
	// anchor was skipped or unresolved.
	VCSCommit string
}
