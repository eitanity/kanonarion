// Package application holds the standard-library chain-of-custody use-case: it
// acquires the canonical source tarball, verifies its integrity against Go's
// published checksum, records the VCS anchor, computes the artefact digests,
// extracts the licence, and caches the derived facts by Go version.
package application

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
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
	audit    ports.AuditSink // optional; nil disables audit emission
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

// WithAudit wires an audit sink so acquisition appends one
// stdlib_custody_recorded event per persisted measurement. It is optional — a
// nil sink (the default) disables emission — and returns the receiver for
// chaining, mirroring the extraction stages' optional-dependency builders.
func (a *Acquirer) WithAudit(sink ports.AuditSink) *Acquirer {
	a.audit = sink
	return a
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
// evidence is preserved for the SBOM rather than hidden. A manifest that could
// not be read is recorded as UnverifiedGoDevUnavailable, and a manifest that was
// read and publishes no checksum for this version as
// UnverifiedGoDevNotPublished. Only an undeterminable version or a failed
// tarball download is a hard error, since without the bytes there are no digests
// to record.
func (a *Acquirer) Acquire(ctx context.Context, goVersionRaw string, opts Options) (domain.Facts, error) {
	version := domain.CanonicalGoVersion(goVersionRaw)
	if version == "" {
		return domain.Facts{}, fmt.Errorf("%w: %q", ErrUndeterminableVersion, goVersionRaw)
	}

	if !opts.Force {
		facts, ok, err := a.store.Get(ctx, version)
		if err != nil {
			return domain.Facts{}, fmt.Errorf("reading stdlib fact cache for %s: %w", version, err)
		}
		switch {
		case ok && domain.ServesAsCacheHit(facts):
			a.logger.InfoContext(ctx, "stdlib.acquire.cache_hit", slog.String("go_version", version))
			return facts, nil
		case ok:
			// The composed answer exists but rests on an anchor that was never
			// consulted, so it is a record of a run that could not establish custody
			// rather than a fact about the toolchain. Re-acquire: serving it would turn
			// one transient go.dev/dl failure into a permanent downgrade surviving every
			// later run until --force. The measurement is not deleted — it stays in the
			// ledger and loses to whatever this run establishes.
			a.logger.InfoContext(ctx, "stdlib.acquire.cache_ineligible",
				slog.String("go_version", version),
				slog.String("verification", string(facts.VerificationStatus)))
		}
	}

	publishedSHA, lookupErr := a.publishedChecksum(ctx, version)

	url := domain.SourceTarballURL(version)
	tarball, err := a.tarballs.Download(ctx, url)
	if err != nil {
		return domain.Facts{}, fmt.Errorf("downloading stdlib source tarball %s: %w", url, err)
	}

	digests := fetchdomain.ComputeArtifactDigests(tarball)
	status, detail := verifyChecksum(version, digests.SHA256, publishedSHA, lookupErr)
	licenseSPDX, licenseResult := a.identifyLicense(ctx, version, tarball)

	facts := domain.Facts{
		GoVersion:          version,
		Digests:            digests,
		PublishedSHA256:    publishedSHA,
		VerificationStatus: status,
		LicenseSPDX:        licenseSPDX,
		SourceURL:          url,
		VCSURL:             domain.VCSRepoURL,
		VCSRef:             version,
		AcquiredAt:         a.clock.Now().UTC(),
		// Stated, not inferred from the verification status. The status happens to
		// identify the route today; reading a dimension out of another field is how
		// the call-graph stage ended up encoding "this came from a working tree" in a
		// version string.
		AcquisitionRoute: domain.RouteGoDev,
	}
	if !opts.SkipVCS {
		facts.VCSCommit = a.resolveCommit(ctx, version)
	}
	facts.VerificationDetail = detail + vcsDetail(opts.SkipVCS, facts.VCSCommit) + licenseDetail(licenseResult)
	facts.ContentLocation = a.cacheTarball(ctx, version, tarball)

	// Sealed last, over the finished measurement: every field above is inside the
	// hash, so the row is checkable once written.
	facts, err = domain.FactsHasher{}.SetContentHash(facts)
	if err != nil {
		return domain.Facts{}, fmt.Errorf("sealing stdlib facts for %s: %w", version, err)
	}

	if err := a.store.Put(ctx, facts); err != nil {
		return domain.Facts{}, fmt.Errorf("caching stdlib facts for %s: %w", version, err)
	}
	a.logger.InfoContext(ctx, "stdlib.acquire.done",
		slog.String("go_version", version),
		slog.String("verification", string(status)),
		slog.String("license", facts.LicenseSPDX),
		slog.Bool("vcs_resolved", facts.VCSCommit != ""),
	)

	// Assurance log: one event per persisted measurement, so the custody the SBOM
	// and the verification-coverage report rest on has a dated observation behind
	// it and not only a row in a version-keyed cache. The measurement is written
	// first, so a failed append reports that the write is unlogged — it never
	// undoes it.
	if err := emitCustodyRecorded(a.audit, facts); err != nil {
		return domain.Facts{}, err
	}

	return facts, nil
}

// publishedChecksum returns the SHA-256 Go publishes for version's source
// tarball. The returned error is why there is none, and it is the caller's
// input rather than a failure: the acquisition continues either way.
//
// It distinguishes the two causes that used to arrive as one empty string.
// Wrapping domain.ErrReleaseNotFound or domain.ErrSourceFileMissing means the
// manifest was read and publishes no checksum for this version; any other error
// means the manifest itself could not be read. Those need different actions
// from whoever reads the record, so the record has to be able to say which
// happened, and a log line cannot — nothing stores it and no report shows it.
func (a *Acquirer) publishedChecksum(ctx context.Context, version string) (string, error) {
	releases, err := a.manifest.FetchReleases(ctx)
	if err != nil {
		a.logger.WarnContext(ctx, "stdlib.manifest.unavailable",
			slog.String("go_version", version), slog.String("error", err.Error()))
		return "", fmt.Errorf("reading the go.dev/dl release manifest: %w", err)
	}
	file, err := domain.FindSourceChecksum(releases, version)
	if err != nil {
		a.logger.WarnContext(ctx, "stdlib.manifest.release_absent",
			slog.String("go_version", version), slog.String("error", err.Error()))
		return "", fmt.Errorf("looking up %s in the go.dev/dl release manifest: %w", version, err)
	}
	return file.SHA256, nil
}

// licenseOutcome names what happened when an acquirer tried to identify the
// standard library's licence.
//
// Three different things leave the SPDX identifier empty, and a reader given
// one blank field cannot tell them apart or act on any of them. They are
// distinct values so the record can say which one it was.
type licenseOutcome int

const (
	// licenseIdentified: the LICENSE text was read and classified.
	licenseIdentified licenseOutcome = iota
	// licenseTextUnavailable: there was no LICENSE text to classify. The source
	// tarball carries no LICENSE file, or the toolchain's LICENSE could not be
	// read.
	licenseTextUnavailable
	// licenseClassifierFailed: the classifier could not run over the text, so
	// nothing has yet judged it.
	licenseClassifierFailed
	// licenseUnrecognised: the classifier ran over the text and matched no
	// licence it knows. This is a statement about the text, not a gap in the
	// measurement.
	licenseUnrecognised
)

// licenseDetail renders the clause the stdlib record carries about the licence.
//
// An identified licence adds nothing: the record already carries the SPDX
// identifier, so the sentence would repeat it. That is also what keeps the
// detail of a healthy measurement exactly the words it had before this
// distinction existed.
func licenseDetail(o licenseOutcome) string {
	switch o {
	case licenseTextUnavailable:
		return "; no LICENSE text was found to classify, so no licence is recorded"
	case licenseClassifierFailed:
		return "; the licence classifier could not run over the LICENSE text, so no licence is recorded"
	case licenseUnrecognised:
		return "; the licence classifier read the LICENSE text and matched no licence it knows"
	case licenseIdentified:
	}
	return ""
}

// identifyLicense extracts and classifies the tarball's LICENSE file. It returns
// the SPDX identifier and which of the outcomes above produced it. None of them
// is a failure: the tarball is still acquired, hashed and recorded.
func (a *Acquirer) identifyLicense(ctx context.Context, version string, tarball []byte) (string, licenseOutcome) {
	text, err := domain.ExtractLicense(tarball)
	if err != nil {
		a.logger.WarnContext(ctx, "stdlib.license.extract_failed",
			slog.String("go_version", version), slog.String("error", err.Error()))
		return "", licenseTextUnavailable
	}
	spdx, err := a.licenses.Identify(ctx, text)
	if err != nil {
		a.logger.WarnContext(ctx, "stdlib.license.identify_failed",
			slog.String("go_version", version), slog.String("error", err.Error()))
		return "", licenseClassifierFailed
	}
	if spdx == "" {
		// The classifier returns "" with no error when it recognises nothing. That
		// left the one outcome where something had actually read the text with no
		// trace anywhere — not in the record, and not even in the log.
		a.logger.WarnContext(ctx, "stdlib.license.unrecognised",
			slog.String("go_version", version))
		return "", licenseUnrecognised
	}
	return spdx, licenseIdentified
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
	// The tarball is addressed by what it is. A source tarball has no module h1,
	// so its identity is the SHA-256 of its bytes — the same digest the published
	// checksum is compared against.
	sum := sha256.Sum256(tarball)
	hash, err := fetchdomain.NewModuleHash("sha256", hex.EncodeToString(sum[:]))
	if err != nil {
		a.logger.WarnContext(ctx, "stdlib.tarball.cache_failed",
			slog.String("go_version", version), slog.String("error", err.Error()))
		return ""
	}
	identity, err := fetchports.NewBlobIdentity(fetchports.BlobKindZip, hash)
	if err != nil {
		a.logger.WarnContext(ctx, "stdlib.tarball.cache_failed",
			slog.String("go_version", version), slog.String("error", err.Error()))
		return ""
	}
	if err := a.blobs.Put(ctx, identity, bytes.NewReader(tarball)); err != nil {
		a.logger.WarnContext(ctx, "stdlib.tarball.cache_failed",
			slog.String("go_version", version), slog.String("error", err.Error()))
		return ""
	}
	return identity.String()
}

// verifyChecksum classifies the tarball checksum against the published value and
// returns the status plus the leading half of the verification detail.
//
// lookupErr is why there is no published checksum, and it decides between two
// statuses that used to be one. A manifest that could not be read leaves the
// anchor unconsulted and go.dev/dl genuinely unavailable. A manifest that WAS
// read and publishes no checksum for this version is a real answer about the
// version: the service was available, and reporting it as unavailable is a
// wrong sentence rather than a vague one.
//
// The last unverified case — no error, and still no checksum — is a manifest
// entry that named a source tarball without a digest. It keeps the wording it
// has always had, because it is what that wording says: no published checksum
// came back. It is guarded explicitly so it can never fall through to the
// comparison below and be reported as a MISMATCH, which is tamper evidence and
// must never be manufactured out of a missing value.
func verifyChecksum(version, computedSHA, publishedSHA string, lookupErr error) (domain.VerificationStatus, string) {
	switch {
	case errors.Is(lookupErr, domain.ErrReleaseNotFound):
		return domain.UnverifiedGoDevNotPublished,
			fmt.Sprintf("go.dev/dl lists no release %s, so no published checksum exists for %s",
				version, domain.SourceTarballName(version))
	case errors.Is(lookupErr, domain.ErrSourceFileMissing):
		return domain.UnverifiedGoDevNotPublished,
			fmt.Sprintf("go.dev/dl lists release %s but publishes no source tarball for it, so no published checksum exists for %s",
				version, domain.SourceTarballName(version))
	case lookupErr != nil || publishedSHA == "":
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
