package application

import (
	"context"
	"fmt"
	"log/slog"

	fetchports "github.com/eitanity/kanonarion/internal/fetch/ports"
	"github.com/eitanity/kanonarion/internal/stdlib/domain"
	"github.com/eitanity/kanonarion/internal/stdlib/ports"
)

// Acquisition is the chain-of-custody entry point shared by the online
// (go.dev/dl) Acquirer and the offline LocalAcquirer, so the walk bridge can wrap
// either without knowing which anchor established the facts.
type Acquisition interface {
	// Acquire establishes (or serves from cache) the chain-of-custody facts for
	// the standard library at goVersionRaw.
	Acquire(ctx context.Context, goVersionRaw string, opts Options) (domain.Facts, error)
}

// LocalAcquirer establishes the standard library's chain of custody from the
// local Go toolchain, without any network access. It is the offline
// (--from-modcache) counterpart to Acquirer: instead of downloading go.dev/dl's
// source tarball and matching its published checksum, it anchors to the
// toolchain the audit itself compiles with — $GOROOT/src for the artefact
// digests and $GOROOT/LICENSE for the licence — and records the result as
// VerifiedLocalToolchain, which never claims the go.dev/dl checksum was consulted.
type LocalAcquirer struct {
	toolchain ports.ToolchainInspector
	source    ports.LocalSourceReader
	licenses  ports.LicenseIdentifier
	store     ports.Store
	clock     fetchports.Clock
	logger    *slog.Logger
}

// NewLocalAcquirer constructs a LocalAcquirer over the toolchain inspector, the
// local source reader, the same licence detector the online path uses, and the
// version-keyed fact cache.
func NewLocalAcquirer(
	toolchain ports.ToolchainInspector,
	source ports.LocalSourceReader,
	licenses ports.LicenseIdentifier,
	store ports.Store,
	clock fetchports.Clock,
	logger *slog.Logger,
) *LocalAcquirer {
	return &LocalAcquirer{
		toolchain: toolchain,
		source:    source,
		licenses:  licenses,
		store:     store,
		clock:     clock,
		logger:    logger,
	}
}

// Acquire establishes (or serves from cache) the offline chain-of-custody facts
// for the standard library at goVersionRaw. On a cache hit without opts.Force it
// returns the stored facts unchanged — including facts a prior online run
// established, so a mixed pipeline never downgrades a stronger anchor. Otherwise
// it locates the local toolchain, computes the artefact digests over $GOROOT/src,
// extracts and classifies $GOROOT/LICENSE, and records the result as
// VerifiedLocalToolchain with the VCS anchor marked skipped (offline).
//
// opts.SkipVCS is accepted for interface parity but is always effectively true:
// the offline path never performs a VCS lookup. Only an undeterminable version,
// a failed toolchain probe, or an unreadable source tree is a hard error, since
// without those there are no digests to record.
func (a *LocalAcquirer) Acquire(ctx context.Context, goVersionRaw string, opts Options) (domain.Facts, error) {
	version := domain.CanonicalGoVersion(goVersionRaw)
	if version == "" {
		return domain.Facts{}, fmt.Errorf("%w: %q", ErrUndeterminableVersion, goVersionRaw)
	}

	if !opts.Force {
		if facts, ok, err := a.store.Get(ctx, version); err != nil {
			return domain.Facts{}, fmt.Errorf("reading stdlib fact cache for %s: %w", version, err)
		} else if ok {
			a.logger.InfoContext(ctx, "stdlib.acquire_local.cache_hit", slog.String("go_version", version))
			return facts, nil
		}
	}

	goRoot, goVersion, err := a.toolchain.Locate(ctx)
	if err != nil {
		return domain.Facts{}, fmt.Errorf("locating local toolchain for %s: %w", version, err)
	}
	if canon := domain.CanonicalGoVersion(goVersion); canon != "" && canon != version {
		// The node coordinate and the live toolchain disagree — record the
		// coordinate's version (what the rest of the walk pins to) but note the
		// divergence so a mismatched GOTOOLCHAIN switch is diagnosable.
		a.logger.WarnContext(ctx, "stdlib.acquire_local.version_mismatch",
			slog.String("coordinate_version", version), slog.String("toolchain_version", canon))
	}

	fsys, err := a.source.SourceFS(goRoot)
	if err != nil {
		return domain.Facts{}, fmt.Errorf("opening stdlib source under %s: %w", goRoot, err)
	}
	digests, err := domain.ComputeSourceDigests(fsys)
	if err != nil {
		return domain.Facts{}, fmt.Errorf("computing stdlib source digests under %s: %w", goRoot, err)
	}

	facts := domain.Facts{
		GoVersion:          version,
		Digests:            digests,
		VerificationStatus: domain.VerifiedLocalToolchain,
		VerificationDetail: fmt.Sprintf(
			"digests computed over local toolchain source %s/src; go.dev/dl published checksum not consulted (offline); googlesource commit anchor skipped (offline)",
			goRoot),
		LicenseSPDX: a.identifyLicense(ctx, version, goRoot),
		SourceURL:   goRoot + "/src",
		VCSURL:      domain.VCSRepoURL,
		VCSRef:      version,
		AcquiredAt:  a.clock.Now().UTC(),
	}

	if err := a.store.Put(ctx, facts); err != nil {
		return domain.Facts{}, fmt.Errorf("caching stdlib facts for %s: %w", version, err)
	}
	a.logger.InfoContext(ctx, "stdlib.acquire_local.done",
		slog.String("go_version", version),
		slog.String("goroot", goRoot),
		slog.String("verification", string(facts.VerificationStatus)),
		slog.String("license", facts.LicenseSPDX),
	)
	return facts, nil
}

// identifyLicense reads and classifies $GOROOT/LICENSE. A missing or
// unclassifiable licence is a coverage gap (empty SPDX), never a failure.
func (a *LocalAcquirer) identifyLicense(ctx context.Context, version, goRoot string) string {
	text, err := a.source.LicenseText(goRoot)
	if err != nil {
		a.logger.WarnContext(ctx, "stdlib.license.read_failed",
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

var _ Acquisition = (*LocalAcquirer)(nil)
var _ Acquisition = (*Acquirer)(nil)
