// Package ports declares the boundaries the standard-library acquisition
// use-case drives: the go.dev/dl release manifest and tarball, the
// googlesource commit anchor, licence identification, and the fact cache.
package ports

import (
	"context"
	"io/fs"

	"github.com/eitanity/kanonarion/internal/stdlib/domain"
)

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
	// Put inserts or replaces the facts for their Go version.
	Put(ctx context.Context, facts domain.Facts) error
}
