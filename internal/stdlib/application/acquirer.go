// Package application holds the standard-library chain-of-custody use-case: it
// acquires the canonical source tarball, verifies its integrity against Go's
// published checksum, records the VCS anchor, computes the artefact digests,
// extracts the licence, and caches the derived facts by Go version.
package application

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"

	fetchdomain "github.com/eitanity/kanonarion/internal/fetch/domain"
	fetchports "github.com/eitanity/kanonarion/internal/fetch/ports"
	"github.com/eitanity/kanonarion/internal/stdlib/domain"
	"github.com/eitanity/kanonarion/internal/stdlib/ports"
)

// ErrUndeterminableVersion means the supplied toolchain string yielded no usable
// Go version, so no release tarball can be requested.
var ErrUndeterminableVersion = errors.New("stdlib: undeterminable go version")

// Options controls a single acquisition.
type Options struct {
	// Force re-acquires and re-verifies even when cached facts exist.
	Force bool
	// SkipVCS skips the googlesource tag→commit lookup, consistent with the fetch
	// stage's --skip-vcs-verify.
	SkipVCS bool
}

// Acquirer establishes the standard library's chain of custody. It is safe for
// concurrent use once constructed.
type Acquirer struct {
	manifest ports.ManifestClient
	tarballs ports.TarballClient
	commits  ports.CommitResolver
	licenses ports.LicenseIdentifier
	store    ports.Store
	blobs    fetchports.BlobStore // optional; when nil the tarball bytes are not retained
	clock    fetchports.Clock
	logger   *slog.Logger
}

// NewAcquirer constructs an Acquirer. blobs may be nil, in which case the source
// tarball is verified and hashed but not cached in the blob store (the derived
// facts are still cached by the Store).
func NewAcquirer(
	manifest ports.ManifestClient,
	tarballs ports.TarballClient,
	commits ports.CommitResolver,
	licenses ports.LicenseIdentifier,
	store ports.Store,
	blobs fetchports.BlobStore,
	clock fetchports.Clock,
	logger *slog.Logger,
) *Acquirer {
	return &Acquirer{
		manifest: manifest,
		tarballs: tarballs,
		commits:  commits,
		licenses: licenses,
		store:    store,
		blobs:    blobs,
		clock:    clock,
		logger:   logger,
	}
}

// Acquire establishes (or serves from cache) the chain-of-custody facts for the
// standard library at goVersionRaw (any toolchain form: "go1.26.4", "1.26.4",
// "v1.26.4"). On a cache hit and without opts.Force it returns the stored facts
// unchanged. Otherwise it downloads the canonical source tarball, verifies its
// SHA-256 against the published release manifest, resolves the googlesource
// commit (unless opts.SkipVCS), computes the artefact digests, extracts the
// BSD-3-Clause licence, caches the tarball and facts, and returns them.
//
// A checksum mismatch is recorded as GoDevChecksumMismatch, not an error — the
// evidence is preserved for the SBOM rather than hidden. A missing manifest is
// recorded as UnverifiedGoDevUnavailable. Only an undeterminable version or a
// failed tarball download is a hard error, since without the bytes there are no
// digests to record.
func (a *Acquirer) Acquire(ctx context.Context, goVersionRaw string, opts Options) (domain.Facts, error) {
	version := domain.CanonicalGoVersion(goVersionRaw)
	if version == "" {
		return domain.Facts{}, fmt.Errorf("%w: %q", ErrUndeterminableVersion, goVersionRaw)
	}

	if !opts.Force {
		if facts, ok, err := a.store.Get(ctx, version); err != nil {
			return domain.Facts{}, fmt.Errorf("reading stdlib fact cache for %s: %w", version, err)
		} else if ok {
			a.logger.InfoContext(ctx, "stdlib.acquire.cache_hit", slog.String("go_version", version))
			return facts, nil
		}
	}

	publishedSHA := a.publishedChecksum(ctx, version)

	url := domain.SourceTarballURL(version)
	tarball, err := a.tarballs.Download(ctx, url)
	if err != nil {
		return domain.Facts{}, fmt.Errorf("downloading stdlib source tarball %s: %w", url, err)
	}

	digests := fetchdomain.ComputeArtifactDigests(tarball)
	status, detail := verifyChecksum(version, digests.SHA256, publishedSHA)

	facts := domain.Facts{
		GoVersion:          version,
		Digests:            digests,
		PublishedSHA256:    publishedSHA,
		VerificationStatus: status,
		LicenseSPDX:        a.identifyLicense(ctx, version, tarball),
		SourceURL:          url,
		VCSURL:             domain.VCSRepoURL,
		VCSRef:             version,
		AcquiredAt:         a.clock.Now().UTC(),
	}
	if !opts.SkipVCS {
		facts.VCSCommit = a.resolveCommit(ctx, version)
	}
	facts.VerificationDetail = detail + vcsDetail(opts.SkipVCS, facts.VCSCommit)
	facts.ContentLocation = a.cacheTarball(ctx, version, tarball)

	if err := a.store.Put(ctx, facts); err != nil {
		return domain.Facts{}, fmt.Errorf("caching stdlib facts for %s: %w", version, err)
	}
	a.logger.InfoContext(ctx, "stdlib.acquire.done",
		slog.String("go_version", version),
		slog.String("verification", string(status)),
		slog.String("license", facts.LicenseSPDX),
		slog.Bool("vcs_resolved", facts.VCSCommit != ""),
	)
	return facts, nil
}

// publishedChecksum returns the SHA-256 Go publishes for version's source
// tarball, or "" when the manifest is unavailable or the version is absent —
// a benign coverage gap the caller records as UnverifiedGoDevUnavailable.
func (a *Acquirer) publishedChecksum(ctx context.Context, version string) string {
	releases, err := a.manifest.FetchReleases(ctx)
	if err != nil {
		a.logger.WarnContext(ctx, "stdlib.manifest.unavailable",
			slog.String("go_version", version), slog.String("error", err.Error()))
		return ""
	}
	file, err := domain.FindSourceChecksum(releases, version)
	if err != nil {
		a.logger.WarnContext(ctx, "stdlib.manifest.release_absent",
			slog.String("go_version", version), slog.String("error", err.Error()))
		return ""
	}
	return file.SHA256
}

// identifyLicense extracts and classifies the tarball's LICENSE file. A missing
// or unclassifiable licence is a coverage gap (empty SPDX), never a failure.
func (a *Acquirer) identifyLicense(ctx context.Context, version string, tarball []byte) string {
	text, err := domain.ExtractLicense(tarball)
	if err != nil {
		a.logger.WarnContext(ctx, "stdlib.license.extract_failed",
			slog.String("go_version", version), slog.String("error", err.Error()))
		return ""
	}
	spdx, err := a.licenses.Identify(ctx, text)
	if err != nil {
		a.logger.WarnContext(ctx, "stdlib.license.identify_failed",
			slog.String("go_version", version), slog.String("error", err.Error()))
		return ""
	}
	return spdx
}

// resolveCommit looks up the release tag's commit in the Go source repository.
// A failed lookup is a coverage gap (empty commit), never a failure.
func (a *Acquirer) resolveCommit(ctx context.Context, version string) string {
	commit, err := a.commits.ResolveCommit(ctx, domain.VCSRepoURL, version)
	if err != nil {
		a.logger.WarnContext(ctx, "stdlib.vcs.unresolved",
			slog.String("go_version", version), slog.String("error", err.Error()))
		return ""
	}
	return commit
}

// cacheTarball stores the source tarball in the blob store and returns its
// handle, or "" when no blob store is wired or the write fails (a cache miss,
// not a failure — the derived facts are still cached by the Store).
func (a *Acquirer) cacheTarball(ctx context.Context, version string, tarball []byte) string {
	if a.blobs == nil {
		return ""
	}
	handle, err := a.blobs.Put(ctx, bytes.NewReader(tarball))
	if err != nil {
		a.logger.WarnContext(ctx, "stdlib.tarball.cache_failed",
			slog.String("go_version", version), slog.String("error", err.Error()))
		return ""
	}
	return string(handle)
}

// verifyChecksum classifies the tarball checksum against the published value and
// returns the status plus the leading half of the verification detail.
func verifyChecksum(version, computedSHA, publishedSHA string) (domain.VerificationStatus, string) {
	switch {
	case publishedSHA == "":
		return domain.UnverifiedGoDevUnavailable,
			fmt.Sprintf("go.dev/dl published checksum unavailable for %s.src.tar.gz", version)
	case computedSHA == publishedSHA:
		return domain.VerifiedGoDevChecksum,
			fmt.Sprintf("SHA-256 matched go.dev/dl published checksum for %s.src.tar.gz", version)
	default:
		return domain.GoDevChecksumMismatch,
			fmt.Sprintf("SHA-256 MISMATCH against go.dev/dl published checksum for %s.src.tar.gz (published %s, computed %s)",
				version, publishedSHA, computedSHA)
	}
}

// vcsDetail renders the VCS-anchor clause appended to the verification detail.
func vcsDetail(skipVCS bool, commit string) string {
	switch {
	case skipVCS:
		return "; googlesource commit anchor skipped (--skip-vcs-verify)"
	case commit == "":
		return "; googlesource commit anchor unresolved"
	default:
		return "; googlesource go tag → commit " + commit
	}
}
