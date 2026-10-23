// Package domain holds the TinyGo release-archive measurement: which archive
// GitHub publishes for a TinyGo release and host platform, whether the bytes
// downloaded match the digest published for it, and the SHA-256 of every file
// under the archive's src directory.
//
// The archive itself is never kept. A walk compares the installed files TinyGo's
// module zip does not carry against the manifest, so one measurement per release
// and asset is enough.
package domain

import (
	"cmp"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

// Outcome is what became of one attempt to measure a release archive.
type Outcome string

const (
	// DigestMatched: the archive's SHA-256 equals the published digest.
	DigestMatched Outcome = "digest_matched"
	// DigestMismatch: the archive's SHA-256 is not the published digest.
	DigestMismatch Outcome = "digest_mismatch"
	// NoDigest: the release lists the asset without a digest.
	NoDigest Outcome = "no_digest_published"
	// AssetAbsent: the release, or the asset in it, does not exist.
	AssetAbsent Outcome = "asset_absent"
	// Unavailable: the release could not be consulted, or the archive read.
	Unavailable Outcome = "unavailable"
)

// Kept reports whether the outcome is a fact about the release, worth keeping
// and serving without the network. Only Unavailable describes the moment, and
// is tried again on the next walk.
func (o Outcome) Kept() bool {
	return o == DigestMatched || o == DigestMismatch || o == NoDigest || o == AssetAbsent
}

// ReasonOffline is why the release leg reads not established offline with no
// held measurement.
const ReasonOffline = "release archive unavailable offline"

// RepositoryReleasesAPI is the GitHub API base TinyGo's releases are read from.
const RepositoryReleasesAPI = "https://api.github.com/repos/tinygo-org/tinygo/releases/tags/"

// Tag is the release tag of a TinyGo version, with or without its v.
func Tag(version string) string { return "v" + strings.TrimPrefix(strings.TrimSpace(version), "v") }

// AssetName is the release archive TinyGo publishes for a host platform:
// tinygo0.42.0.linux-amd64.tar.gz, or a .zip on windows.
func AssetName(version, goos, goarch string) string {
	ext := ".tar.gz"
	if goos == "windows" {
		ext = ".zip"
	}
	return "tinygo" + strings.TrimPrefix(Tag(version), "v") + "." + goos + "-" + goarch + ext
}

// ManifestEntry is one file under the archive's src directory.
type ManifestEntry struct {
	Path   string
	SHA256 string
}

// Measurement is one measurement of a release archive.
type Measurement struct {
	// Version is the TinyGo release without its v, as tinygo version prints it.
	Version string
	Asset   string
	URL     string
	// PublishedDigest is the SHA-256 GitHub publishes for the asset, hex;
	// ObservedDigest the SHA-256 of the bytes downloaded.
	PublishedDigest string
	ObservedDigest  string
	Outcome         Outcome
	// Reason says why an outcome other than DigestMatched was reached.
	Reason     string
	MeasuredAt time.Time
	// Manifest is set only on DigestMatched, sorted by path.
	Manifest []ManifestEntry
}

// ErrIncomplete refuses a measurement that names no release or asset, which
// would read back later as a measurement of nothing.
var ErrIncomplete = errors.New("a TinyGo release measurement names its version, asset and time")

// Validate refuses a measurement that could not be told apart from the zero
// value, and one whose manifest disagrees with its outcome.
func (m Measurement) Validate() error {
	if m.Version == "" || m.Asset == "" || m.MeasuredAt.IsZero() {
		return ErrIncomplete
	}
	if (m.Outcome == DigestMatched) != (len(m.Manifest) > 0) {
		return fmt.Errorf("a TinyGo release measurement carries a manifest exactly when its digest matched (outcome %q, %d files)", m.Outcome, len(m.Manifest))
	}
	return nil
}

// ManifestMap is the manifest keyed by path.
func (m Measurement) ManifestMap() map[string]string {
	if len(m.Manifest) == 0 {
		return nil
	}
	out := make(map[string]string, len(m.Manifest))
	for _, e := range m.Manifest {
		out[e.Path] = e.SHA256
	}
	return out
}

// SortManifest orders entries by path.
func SortManifest(entries []ManifestEntry) {
	slices.SortFunc(entries, func(a, b ManifestEntry) int {
		return cmp.Or(cmp.Compare(a.Path, b.Path), cmp.Compare(a.SHA256, b.SHA256))
	})
}

// FormatManifest writes the manifest as sha256sum does, one "<hex>  <path>"
// line per file, sorted by path.
func FormatManifest(entries []ManifestEntry) string {
	sorted := slices.Clone(entries)
	SortManifest(sorted)
	var b strings.Builder
	for _, e := range sorted {
		b.WriteString(e.SHA256)
		b.WriteString("  ")
		b.WriteString(e.Path)
		b.WriteByte('\n')
	}
	return b.String()
}

// ParseManifest reads what FormatManifest wrote.
func ParseManifest(text string) ([]ManifestEntry, error) {
	var out []ManifestEntry
	for i, line := range strings.Split(strings.TrimSuffix(text, "\n"), "\n") {
		if line == "" {
			continue
		}
		sum, path, ok := strings.Cut(line, "  ")
		if !ok || len(sum) != 64 || path == "" {
			return nil, fmt.Errorf("manifest line %d is not \"<sha256>  <path>\": %q", i+1, line)
		}
		out = append(out, ManifestEntry{Path: path, SHA256: sum})
	}
	return out, nil
}

// PublishedSHA256 reads GitHub's "sha256:<hex>" digest, empty for any other
// algorithm or for none.
func PublishedSHA256(digest string) string {
	hex, ok := strings.CutPrefix(strings.TrimSpace(digest), "sha256:")
	if !ok {
		return ""
	}
	return strings.ToLower(hex)
}
