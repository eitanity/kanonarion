package domain

import (
	"errors"
	"strings"
	"time"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
)

// ErrNoGoVersion is returned when a measurement names no toolchain version.
//
// It is the stdlib counterpart of coordinate.ErrZeroCoordinate: a row keyed on
// the empty version reads back later as a genuine measurement of a toolchain
// that does not exist, and a read for no version is a question about nothing,
// which absence is the wrong answer to.
var ErrNoGoVersion = errors.New("stdlib facts name no go version")

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

	// VerifiedLocalToolchain means the chain of custody was established from the
	// local Go toolchain ($GOROOT/src and $GOROOT/LICENSE) in an offline
	// (--from-modcache) run — the artefact digests are over the on-disk source and
	// the licence is extracted from it, but go.dev/dl's published checksum was
	// deliberately NOT consulted (no network). It is a real anchor to the exact
	// toolchain that compiles the project, distinct from and never equivalent to
	// VerifiedGoDevChecksum: it makes no claim about the published checksum.
	VerifiedLocalToolchain VerificationStatus = "VerifiedLocalToolchain"
)

// Verified reports whether the tarball checksum matched the published manifest.
// It is deliberately false for VerifiedLocalToolchain: that anchor establishes
// custody from the local toolchain without consulting the published checksum, so
// it must never read as a go.dev/dl checksum match.
func (s VerificationStatus) Verified() bool { return s == VerifiedGoDevChecksum }

// AnchorLimitation states what a standard-library component's integrity rests
// on: the anchor the measurement actually reached, then — separately — whether
// the go.googlesource.com/go tag/commit anchor was established, then the ceiling
// that applies whatever the status.
//
// It lives here, beside the statuses, because it is a reading of the status set
// rather than a presentation choice. An SBOM emitting a fixed sentence about the
// anchor is the defect this replaces: an offline run records
// VerifiedLocalToolchain with the published checksum not consulted and the
// commit anchor skipped, and a fixed sentence asserted both of them three lines
// below the detail that said neither happened. That error runs in the unsafe
// direction — it is the stronger claim — inside an artefact written to be read
// where the store is not, so the wording is derived from the evidence.
//
// A status this build does not recognise, or none at all, names no anchor rather
// than falling through to the strongest one.
func AnchorLimitation(status VerificationStatus, vcsCommitResolved bool) string {
	var anchor string
	switch status {
	case VerifiedGoDevChecksum:
		anchor = "integrity anchored to the source-tarball checksum go.dev/dl publishes, which the acquired bytes matched"
	case GoDevChecksumMismatch:
		anchor = "integrity NOT anchored: the acquired source tarball did not match the checksum go.dev/dl publishes for it, so these bytes are unverified and the mismatch is retained as evidence"
	case UnverifiedGoDevUnavailable:
		anchor = "integrity not anchored to a published checksum: the go.dev/dl release manifest could not be consulted, so nothing was matched against it"
	case VerifiedLocalToolchain:
		anchor = "integrity rests on the locally-held toolchain source these digests were computed over; the checksum go.dev/dl publishes was not consulted"
	default:
		anchor = "integrity anchor not recorded: no standard-library verification status accompanies these bytes, so no anchor is claimed for them"
	}
	vcs := "no go.googlesource.com/go tag/commit anchor was established"
	if vcsCommitResolved {
		vcs = "cross-checked against a go.googlesource.com/go release tag and the commit it resolves to"
	}
	return anchor + "; " + vcs +
		"; on any of these routes the anchor is weaker than a module sumdb transparency-log entry and is never present in go.sum"
}

// Facts is the persisted chain-of-custody evidence for one Go standard-library
// version.
//
// It is one MEASUREMENT, not the answer. The store holds every measurement ever
// taken for a version and a read composes them, so a run that could not reach
// go.dev/dl no longer replaces the run that could. What identifies a measurement
// is the bytes it was taken over (Digests.SHA256) and the route it took to them
// (AcquisitionRoute); ContentHash seals the whole of it.
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
	// AcquisitionRoute names where the bytes came from — the published go.dev/dl
	// tarball, or the installed toolchain's own source tree. It is a dimension
	// rather than a ladder position, so composition never chooses between routes.
	//
	// Empty on records written before the field existed, which reads as "not
	// recorded" and never as "acquired from nowhere".
	AcquisitionRoute AcquisitionRoute
	// ContentHash is the seal over this measurement's canonical form, set by
	// FactsHasher. It is what makes a stored row checkable at all: before it,
	// stdlib_facts was the one record table whose rows could be edited in place
	// with nothing to detect it.
	//
	// Empty on records written before the field existed. Those rows are readable
	// and are reported as unsealed rather than as failing verification, because
	// they never carried a seal to fail.
	ContentHash string
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
