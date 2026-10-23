package driver

import (
	"context"

	staleapp "github.com/eitanity/kanonarion/internal/staleness/application"
)

// StalenessResolver answers, per module path and pinned version, how far
// behind the pin is, serving a ledger row younger than the TTL and asking the
// upstream otherwise. It holds the resolver `latest` uses for one path; the
// batched build-list source stays internal.
type StalenessResolver struct {
	r *staleapp.Resolver
}

// NewStalenessResolver wraps r.
func NewStalenessResolver(r *staleapp.Resolver) *StalenessResolver {
	return &StalenessResolver{r: r}
}

// Resolve returns the staleness answer for path pinned at pinnedVersion (empty
// for no pin). A lookup that failed writes nothing and returns its error; an
// absent newer major ends the probe and is stored as a negative.
func (s *StalenessResolver) Resolve(ctx context.Context, path, pinnedVersion string) (staleapp.Answer, error) {
	return s.r.Resolve(ctx, path, pinnedVersion) //nolint:wrapcheck // the resolver's error names the path already
}
