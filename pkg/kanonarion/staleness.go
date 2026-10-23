package kanonarion

import (
	"fmt"

	"github.com/eitanity/kanonarion/internal/composition"
	"github.com/eitanity/kanonarion/internal/driver"
	staleapp "github.com/eitanity/kanonarion/internal/staleness/application"
	stalenessports "github.com/eitanity/kanonarion/internal/staleness/ports"
)

// StalenessResolver answers, per module path and pinned version, how far
// behind the pin is — the same-major latest, a newer major, republication and
// deprecation — serving a ledger row younger than the TTL and asking the
// upstream otherwise, and writing what it learns through the ledger. It is the
// resolver `kanonarion latest` uses for one path.
//
// Stability: driver use case (called by consumers); unstable pre-v1. May gain
// methods within a major version (§4).
type StalenessResolver = driver.StalenessResolver

// StalenessResolverConfig is what a consumer may supply to a StalenessResolver: the
// upstream, the clock and the TTL. A zero field takes what `latest` uses: the
// module proxy $GOPROXY names, the system clock, and staleness.ttl — the
// store's for Driver.StalenessResolver, the built-in hour otherwise.
//
// Stability: request struct (passed by consumers); unstable pre-v1. Fields may
// be added within a major version (§4).
type StalenessResolverConfig = composition.StalenessResolverConfig

// StalenessAnswer is a resolved StalenessRecord and whether the whole answer
// was served from the ledger.
//
// Stability: result type (received by consumers); unstable pre-v1. Fields may be
// added within a major version (§4).
type StalenessAnswer = staleapp.Answer

// LatestResolver is the upstream a StalenessResolver asks for a path's
// @latest. An implementation reports an unpublished path as ErrPathAbsent and
// a lookup that settled nothing as ErrLookupFailed (wrapped is fine), and is
// safe for concurrent use.
//
// Stability: substitution port (implemented by consumers); unstable pre-v1.
// Grows only by a new optional interface, never by adding a method (§4).
type LatestResolver = stalenessports.LatestResolver

// LatestInfo is a LatestResolver's answer: the version and its publication
// time, zero when the upstream supplied none.
//
// Stability: port value type (returned by consumers); unstable pre-v1. Fields
// may be added within a major version (§4).
type LatestInfo = stalenessports.LatestInfo

// ErrPathAbsent is what a LatestResolver returns for a path that is not
// published: a definitive answer, which ends the newer-major probe and is
// stored as a negative.
//
// Stability: error sentinel (returned and matched by consumers); unstable
// pre-v1 (§4).
var ErrPathAbsent = stalenessports.ErrPathAbsent

// ErrLookupFailed is what a LatestResolver returns when the upstream could not
// be asked or answered nothing usable: a failure, which is reported and never
// written.
//
// Stability: error sentinel (returned and matched by consumers); unstable
// pre-v1 (§4).
var ErrLookupFailed = stalenessports.ErrLookupFailed

// NewStalenessResolver builds a StalenessResolver over a supplied ledger (nil
// makes every lookup live and unwritten). Driver.StalenessResolver builds one
// over the driver's own ledger instead. A GONOPROXY/GOPRIVATE path is never
// asked of the upstream.
//
// Stability: public driver composition entrypoint; unstable pre-v1 (§4).
func NewStalenessResolver(ledger StalenessLedger, cfg StalenessResolverConfig) (*StalenessResolver, error) {
	r, err := composition.NewStalenessResolver(ledger, cfg)
	if err != nil {
		return nil, fmt.Errorf("kanonarion: %w", err)
	}
	return r, nil
}
