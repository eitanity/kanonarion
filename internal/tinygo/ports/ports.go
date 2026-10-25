// Package ports declares the boundaries the TinyGo release measurement drives:
// GitHub's release listing, the archive download, the measurement store and
// the clock.
package ports

import (
	"context"
	"time"

	"github.com/eitanity/kanonarion/internal/tinygo/domain"
)

// Asset is one release asset as GitHub lists it. Digest is GitHub's
// "<algorithm>:<hex>" form, empty when none is published.
type Asset struct {
	Name   string
	URL    string
	Digest string
}

// ReleaseIndex reads the assets of one TinyGo release.
type ReleaseIndex interface {
	// Assets returns the release's assets. The bool is false when the release
	// does not exist; an error means it could not be asked.
	Assets(ctx context.Context, tag string) ([]Asset, bool, error)
}

// Archive is a downloaded release archive: the SHA-256 of all its bytes and
// the SHA-256 of every file under its src directory.
type Archive struct {
	SHA256   string
	Manifest []domain.ManifestEntry
}

// ArchiveReader downloads a release archive and measures it in one pass. The
// archive is not kept.
type ArchiveReader interface {
	Read(ctx context.Context, url, name string) (Archive, error)
}

// Store keeps release measurements, append-only.
type Store interface {
	// Latest returns the most recent measurement of version's asset; the bool
	// is false when none is held.
	Latest(ctx context.Context, version, asset string) (domain.Measurement, bool, error)
	// Append adds a measurement; the same measurement twice is one row.
	Append(ctx context.Context, m domain.Measurement) error
}

// Clock is the time a measurement is taken at.
type Clock interface {
	Now() time.Time
}
