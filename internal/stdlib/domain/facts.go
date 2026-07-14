package domain

import (
	"strings"
	"time"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
)

// VerificationStatus records how far the standard-library source tarball was
// verified. The values are deliberately distinct from the fetch stage's
// module VerificationStatus (Verified, VerifiedBySumDBOnly, …): the stdlib
// anchor is go.dev/dl's published checksum plus a googlesource tag/commit, not
// a signed sumdb transparency-log entry, and the two must never read as
// equivalent.
type VerificationStatus string

const (
	// VerifiedGoDevChecksum means the SHA-256 of the downloaded source tarball
	// matched the digest Go publishes for it in the release manifest
	// (https://go.dev/dl/?mode=json&include=all). This is the strongest anchor
	// available for the standard library — a published checksum, not a
	// transparency log — so it is named to make that ceiling explicit.
	VerifiedGoDevChecksum VerificationStatus = "VerifiedGoDevChecksum"

	// GoDevChecksumMismatch means the downloaded tarball's SHA-256 did NOT match
	// the published manifest digest: tamper evidence or a corrupted download.
	GoDevChecksumMismatch VerificationStatus = "GoDevChecksumMismatch"

	// UnverifiedGoDevUnavailable means the release manifest could not be consulted
	// (offline, or the version is absent from go.dev/dl), so the tarball checksum
	// could not be matched against a published value.
	UnverifiedGoDevUnavailable VerificationStatus = "UnverifiedGoDevUnavailable"
)

// Verified reports whether the tarball checksum matched the published manifest.
func (s VerificationStatus) Verified() bool { return s == VerifiedGoDevChecksum }

// Facts is the persisted chain-of-custody evidence for one Go standard-library
// version. It is a value object keyed by GoVersion; once acquired and stored it
// is immutable until a --force re-acquisition overwrites it.
type Facts struct {
	// GoVersion is the canonical toolchain version the facts describe, in
	// go.dev/dl form ("go1.26.4").
	GoVersion string
	// Digests are the SHA-256/384/512 hashes over the exact source tarball bytes,
	// the same three algorithms the module SBOM emits. These become the stdlib
	// component's <hashes>.
	Digests fetchdomain.ArtifactDigests
	// PublishedSHA256 is the SHA-256 Go publishes for the source tarball in its
	// release manifest. When VerificationStatus is VerifiedGoDevChecksum it equals
	// Digests.SHA256; on a mismatch the two differ and both are retained.
	PublishedSHA256 string
	// VerificationStatus records how the tarball was verified against go.dev/dl.
	VerificationStatus VerificationStatus
	// VerificationDetail is a human-readable summary of the verification: the
	// checksum source and, when resolved, the googlesource commit.
	VerificationDetail string
	// LicenseSPDX is the SPDX identifier detected from the tarball's LICENSE file
	// (BSD-3-Clause for the standard library). Empty when the LICENSE file could
	// not be found or identified.
	LicenseSPDX string
	// SourceURL is the canonical tarball URL the bytes were acquired from.
	SourceURL string
	// VCSURL is the Go source repository the tag/commit anchor refers to.
	VCSURL string
	// VCSRef is the release tag in that repository ("go1.26.4").
	VCSRef string
	// VCSCommit is the commit the release tag resolves to. Empty when VCS
	// cross-verification was skipped (--skip-vcs-verify) or the lookup failed.
	VCSCommit string
	// ContentLocation is the blob handle of the cached source tarball, or empty
	// when the bytes were not retained.
	ContentLocation string
	// AcquiredAt is when the tarball was acquired and verified.
	AcquiredAt time.Time
}

// CanonicalGoVersion converts any toolchain version string the resolver may
// hold — "go1.26.4" (go env GOVERSION / a toolchain directive), "1.26.4" (a go
// directive), or "v1.26.4" (the injected node coordinate) — into the go.dev/dl
// release form "go1.26.4". It returns "" for an empty or version-less input so
// callers can skip acquisition rather than request a non-existent release.
//
// A version that names only a major.minor ("1.26", "go1.26") is returned as-is
// with a "go" prefix; go.dev/dl has no such release, so acquisition will report
// it absent and the node keeps its best-effort coverage gap.
func CanonicalGoVersion(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	v = strings.TrimPrefix(v, "v")
	if !strings.HasPrefix(v, "go") {
		v = "go" + v
	}
	if v == "go" {
		return ""
	}
	return v
}

// SourceTarballName returns the canonical source-tarball filename for a
// canonical Go version ("go1.26.4" → "go1.26.4.src.tar.gz").
func SourceTarballName(goVersion string) string {
	return goVersion + ".src.tar.gz"
}

// SourceTarballURL returns the canonical go.dev/dl download URL for the source
// tarball of a canonical Go version.
func SourceTarballURL(goVersion string) string {
	return "https://go.dev/dl/" + SourceTarballName(goVersion)
}

// VCSRepoURL is the Go source repository the standard library is anchored to.
const VCSRepoURL = "https://go.googlesource.com/go"

// ReleaseManifestURL is the JSON manifest of every published Go release,
// including the source tarball checksums.
const ReleaseManifestURL = "https://go.dev/dl/?mode=json&include=all"
