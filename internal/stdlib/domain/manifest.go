package domain

import "errors"

// ErrReleaseNotFound means the requested Go version is absent from the release
// manifest, so no published checksum exists to verify a tarball against. It is a
// benign, expected condition (a development toolchain, or a major.minor-only
// version directive), not a failure: the caller records the coverage gap and
// continues.
var ErrReleaseNotFound = errors.New("stdlib: go version not found in release manifest")

// ErrSourceFileMissing means the release exists in the manifest but lists no
// source tarball file, so there is no canonical checksum to anchor to.
var ErrSourceFileMissing = errors.New("stdlib: release has no source tarball entry")

// Release is one entry in Go's published release manifest. Only the fields
// kanonarion anchors to are modelled; the rest of each object is ignored.
type Release struct {
	Version string        `json:"version"`
	Files   []ReleaseFile `json:"files"`
}

// ReleaseFile is one downloadable artefact of a release. The source tarball is
// the platform-independent, canonical artefact identified by Kind == "source".
type ReleaseFile struct {
	Filename string `json:"filename"`
	Kind     string `json:"kind"`
	SHA256   string `json:"sha256"`
}

// SourceFileKind is the manifest's Kind value for the canonical source tarball.
const SourceFileKind = "source"

// FindSourceChecksum locates the source-tarball entry for goVersion in the
// release manifest and returns its published filename and SHA-256. It matches
// the release by exact version and then the file by Kind == "source", the
// platform-independent canonical artefact (never a platform binary archive).
//
// It returns ErrReleaseNotFound when no release matches goVersion, and
// ErrSourceFileMissing when the matched release lists no source file.
func FindSourceChecksum(releases []Release, goVersion string) (ReleaseFile, error) {
	for _, r := range releases {
		if r.Version != goVersion {
			continue
		}
		for _, f := range r.Files {
			if f.Kind == SourceFileKind {
				return f, nil
			}
		}
		return ReleaseFile{}, ErrSourceFileMissing
	}
	return ReleaseFile{}, ErrReleaseNotFound
}
