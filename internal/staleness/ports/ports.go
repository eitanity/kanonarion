// Package ports declares the staleness context's driven interfaces.
package ports

import (
	"context"
	"errors"
	"time"

	"github.com/eitanity/kanonarion/internal/staleness/domain"
)

// ErrPathAbsent reports that the proxy has no such module path at all.
//
// It is a definitive answer, not a failure, and the distinction is the whole
// bound on the major probe: an absent /vN is what tells the probe to stop, and
// it is a cacheable negative. A timeout or a 5xx is neither — those are
// failures, and a failure is never written to the ledger.
var ErrPathAbsent = errors.New("module path not published")

// LatestInfo is the proxy's @latest answer for one path.
type LatestInfo struct {
	Version string
	// Time is the publication time, zero when the proxy supplied none.
	Time time.Time
}

// LatestResolver resolves @latest for a module path. Implementations MUST
// report an unknown path as ErrPathAbsent (wrapped is fine) so the probe can
// tell absence from failure.
type LatestResolver interface {
	LatestInfo(ctx context.Context, path string) (LatestInfo, error)
}

// Ledger persists resolved staleness rows, keyed on module path.
type Ledger interface {
	// GetStaleness returns the stored row for path. found is false, with no
	// error, when there is none.
	GetStaleness(ctx context.Context, path string) (domain.Record, bool, error)
	// PutStaleness inserts or replaces the row for rec.ModulePath.
	PutStaleness(ctx context.Context, rec domain.Record) error
}

// Clock supplies the wall-clock instant a lookup is stamped with and the TTL is
// measured against.
type Clock interface {
	Now() time.Time
}
