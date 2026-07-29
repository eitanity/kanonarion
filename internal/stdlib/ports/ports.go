// Package ports declares the boundaries the standard-library acquisition
// use-case drives: the go.dev/dl release manifest and tarball, the
// googlesource commit anchor, licence identification, and the fact cache.
package ports

import (
	"context"
	"errors"
	"io/fs"

	"github.com/eitanity/kanonarion/internal/stdlib/domain"
)

// ErrFactsConflict wraps a domain.FactsConflict surfaced through the store. It
// marks the answers composition refuses to produce by picking: one toolchain
// version whose measurements describe different bytes, or two definite and
// opposing statements about the same bytes.
var ErrFactsConflict = errors.New("conflicting stdlib facts")

// ErrFactsIntegrity is returned when a stored measurement carries a seal its own
// canonical form does not reproduce — the row was altered after it was written.
//
// A measurement carrying NO seal is not an integrity failure: rows written before
// the seal existed legitimately have none, and refusing them would make an
// un-migrated store unreadable.
var ErrFactsIntegrity = errors.New("stdlib facts integrity check failed")

// ManifestClient fetches Go's published release manifest — the source of the
// canonical source-tarball checksums the tarball integrity is matched against.
type ManifestClient interface {
	// FetchReleases returns every published release. Implementations read
	// https://go.dev/dl/?mode=json&include=all.
	FetchReleases(ctx context.Context) ([]domain.Release, error)
}

// TarballClient downloads the canonical source tarball bytes for a Go release.
type TarballClient interface {
	// Download fetches the full tarball at url into memory. The source tarball is
	// tens of MiB; callers hash it and may cache it, so it is returned whole
	// rather than streamed.
	Download(ctx context.Context, url string) ([]byte, error)
}

// CommitResolver resolves a repository tag to the commit it points at — the VCS
// anchor half of the stdlib chain of custody.
type CommitResolver interface {
	// ResolveCommit returns the commit SHA that tag resolves to in repoURL.
	ResolveCommit(ctx context.Context, repoURL, tag string) (string, error)
}

// ToolchainInspector resolves the local Go toolchain's install root and version
// — the anchor the offline (--from-modcache) custody path uses instead of
// go.dev/dl. Implementations read `go env GOROOT GOVERSION`.
type ToolchainInspector interface {
	// Locate returns the toolchain's GOROOT and GOVERSION ("go1.26.4"). An error
	// means the toolchain could not be probed, so offline custody is skipped.
	Locate(ctx context.Context) (goRoot, goVersion string, err error)
}

// LocalSourceReader exposes the local toolchain's standard-library source tree
// and licence file, the raw material the offline custody path derives digests
// and the licence from. All access is filesystem-only; no network is involved.
type LocalSourceReader interface {
	// SourceFS returns an fs.FS rooted at the toolchain's standard-library source
	// ($GOROOT/src), over which the artefact digests are computed.
	SourceFS(goRoot string) (fs.FS, error)
	// LicenseText returns the bytes of the toolchain's top-level LICENSE file
	// ($GOROOT/LICENSE), classified by the same detector the online path uses.
	LicenseText(goRoot string) ([]byte, error)
}

// LicenseIdentifier classifies licence text to an SPDX identifier. It is the
// same detection the licence extraction stage performs, applied to the
// standard library's LICENSE file so the licence is derived, not asserted.
type LicenseIdentifier interface {
	// Identify returns the SPDX identifier detected in content, or "" when no
	// licence could be identified.
	Identify(ctx context.Context, content []byte) (string, error)
}

// Store persists and retrieves acquired standard-library facts, keyed by the
// canonical Go version so a tarball is acquired and verified at most once per
// version across projects, until --force re-acquires it.
type Store interface {
	// Get returns the cached facts for goVersion. The bool is false on a cache
	// miss.
	Get(ctx context.Context, goVersion string) (domain.Facts, bool, error)
	// Put APPENDS a measurement. It never updates: the ledger key carries the
	// acquisition route, the artefact digest, the time of measurement and the
	// measurement's own seal, so two distinct acquisitions are two rows. Writing
	// the same measurement twice is a no-op rather than an error.
	Put(ctx context.Context, facts domain.Facts) error
}

// FactsLister is the optional history read a store may offer: every measurement
// the ledger holds for one toolchain version, in the order they were appended.
//
// It is separate from Store because it is what makes the ledger OBSERVABLE rather
// than what makes it work — no acquisition path needs it, and a store that cannot
// answer it is still a usable fact cache. Callers type-assert for it.
type FactsLister interface {
	ListFactsFor(ctx context.Context, goVersion string) ([]domain.Facts, error)
}

// RouteReader is the optional route-scoped read: the same question Get answers,
// restricted to one acquisition route.
//
// It exists because the route is a dimension rather than a ladder position, so
// "the published tarball or this machine's toolchain" is a real question the
// version cannot answer. Get applies a stated default; this is how a caller asks
// for the other one.
type RouteReader interface {
	GetVia(ctx context.Context, goVersion string, route domain.AcquisitionRoute) (domain.Facts, bool, error)
}
